//! Values attached to networks.
//!
//! Every distinct value is kept once, in its canonical *encoded* form (see [`encode`]). The
//! encoding is type-exact (`1`, `1.0` and `True` differ), so it serves as the deduplication key
//! and is written to disk with only its string ids renumbered. Next to it the store keeps a
//! *payload* of a generic type: the Python bindings use it for the read-only Python object
//! returned by lookups.
//!
//! Strings (`str` values and the keys of mappings and objects) are stored once per tree, in its
//! [`Strings`]; encodings refer to them by id. Equal strings have the same id, so equal values
//! still have equal encodings.
//!
//! Encoding, a tag byte followed by the payload (`varint` is unsigned LEB128):
//!
//! | tag | type     | payload                                                       |
//! |-----|----------|---------------------------------------------------------------|
//! | 0   | None     |                                                               |
//! | 1   | False    |                                                               |
//! | 2   | True     |                                                               |
//! | 3   | int      | zigzag varint (i64)                                           |
//! | 4   | int      | varint (u64 > i64::MAX)                                       |
//! | 5   | float    | f64 little endian                                             |
//! | 6   | str      | varint string id                                              |
//! | 7   | bytes    | varint length, bytes                                          |
//! | 8   | sequence | varint count, values                                          |
//! | 9   | mapping  | varint count, (varint key string id, value) pairs             |
//! | 10  | object   | varint type id, varint count, (key, value) pairs as for 9     |
//!
//! Version 1 files stored strings inline (varint byte length, UTF-8) instead of string ids; they
//! are converted when loaded (see [`Reader::transcode`]).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashTable;
use xxhash_rust::xxh3::xxh3_64_with_seed;

use crate::strings::{Strings, random_seed};

/// Maximum nesting depth of sequences/mappings/objects. Protects against stack exhaustion when
/// converting or decoding deeply nested (or malicious) data.
pub const MAX_DEPTH: usize = 64;

/// String-keyed fields, insertion order preserved.
pub type Fields = Box<[(Box<str>, Value)]>;

/// A decoded value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Any integer representable as `i64`.
    Int(i64),
    /// Integers larger than `i64::MAX`. Never holds a value `<= i64::MAX` (see [`Value::from_u64`]).
    UInt(u64),
    Float(f64),
    Str(Box<str>),
    Bytes(Box<[u8]>),
    Seq(Box<[Value]>),
    Map(Fields),
    /// An instance of a registered type (dataclass, pydantic model), see [`TypeDesc`].
    Object(u32, Fields),
}

impl Value {
    /// Builds an integer value using the canonical representation.
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        i64::try_from(v).map_or(Self::UInt(v), Self::Int)
    }
}

/// Kind of a registered type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TypeKind {
    /// Rebuilt with `cls(**fields)`.
    Dataclass = 1,
    /// Rebuilt with `cls.model_validate(fields)`.
    Pydantic = 2,
}

impl TypeKind {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Dataclass),
            2 => Some(Self::Pydantic),
            _ => None,
        }
    }
}

/// A registered type: its kind and fully qualified name (`module.QualName`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeDesc {
    pub kind: TypeKind,
    pub name: Box<str>,
}

/// Error decoding a value or a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

pub(crate) fn err<T>(msg: impl Into<String>) -> Result<T, DecodeError> {
    Err(DecodeError(msg.into()))
}

pub mod tag {
    pub const NULL: u8 = 0;
    pub const FALSE: u8 = 1;
    pub const TRUE: u8 = 2;
    pub const INT: u8 = 3;
    pub const UINT: u8 = 4;
    pub const FLOAT: u8 = 5;
    pub const STR: u8 = 6;
    pub const BYTES: u8 = 7;
    pub const SEQ: u8 = 8;
    pub const MAP: u8 = 9;
    pub const OBJECT: u8 = 10;
}

/// Destination of encoded data: a `Vec<u8>`, or [`Discard`] to only validate.
pub(crate) trait Sink {
    fn put(&mut self, bytes: &[u8]);
    fn byte(&mut self, b: u8);
    fn varint(&mut self, v: u128);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn byte(&mut self, b: u8) {
        self.push(b);
    }

    fn varint(&mut self, v: u128) {
        put_varint(self, v);
    }
}

/// A [`Sink`] which drops the data.
pub(crate) struct Discard;

impl Sink for Discard {
    fn put(&mut self, _: &[u8]) {}
    fn byte(&mut self, _: u8) {}
    fn varint(&mut self, _: u128) {}
}

pub(crate) fn put_varint(out: &mut Vec<u8>, mut v: u128) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn put_len(out: &mut Vec<u8>, len: usize) {
    put_varint(out, len as u128);
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    put_len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// Encodes values of one tree: maps object type ids and interns strings.
struct Encoder<'a, F> {
    out: Vec<u8>,
    types: Option<&'a [u32]>,
    intern: F,
}

impl<F: FnMut(&str) -> u32> Encoder<'_, F> {
    fn fields(&mut self, fields: &[(Box<str>, Value)]) {
        put_len(&mut self.out, fields.len());
        for (k, v) in fields {
            let id = (self.intern)(k);
            put_varint(&mut self.out, u128::from(id));
            self.value(v);
        }
    }

    fn value(&mut self, v: &Value) {
        let out = &mut self.out;
        match v {
            Value::Null => out.push(tag::NULL),
            Value::Bool(false) => out.push(tag::FALSE),
            Value::Bool(true) => out.push(tag::TRUE),
            Value::Int(i) => {
                out.push(tag::INT);
                #[allow(clippy::cast_sign_loss)]
                let zigzag = ((i << 1) ^ (i >> 63)) as u64;
                put_varint(out, u128::from(zigzag));
            }
            Value::UInt(u) => {
                out.push(tag::UINT);
                put_varint(out, u128::from(*u));
            }
            Value::Float(f) => {
                out.push(tag::FLOAT);
                out.extend_from_slice(&f.to_le_bytes());
            }
            Value::Str(s) => {
                out.push(tag::STR);
                let id = (self.intern)(s);
                put_varint(&mut self.out, u128::from(id));
            }
            Value::Bytes(b) => {
                out.push(tag::BYTES);
                put_len(out, b.len());
                out.extend_from_slice(b);
            }
            Value::Seq(items) => {
                out.push(tag::SEQ);
                put_len(out, items.len());
                for item in items {
                    self.value(item);
                }
            }
            Value::Map(fields) => {
                out.push(tag::MAP);
                self.fields(fields);
            }
            Value::Object(type_id, fields) => {
                out.push(tag::OBJECT);
                let id = self.types.map_or(*type_id, |map| map[*type_id as usize]);
                put_varint(out, u128::from(id));
                self.fields(fields);
            }
        }
    }
}

/// Encodes a value into its canonical form. `intern` returns the id of a string (in the tree's
/// [`Strings`]); `types`, if given, maps the object type ids of the value to the tree's.
pub fn encode(v: &Value, types: Option<&[u32]>, intern: impl FnMut(&str) -> u32) -> Vec<u8> {
    let mut encoder = Encoder { out: Vec::new(), types, intern };
    encoder.value(v);
    encoder.out
}

/// What encoded values refer to: the number of registered types and the strings.
#[derive(Debug, Clone, Copy)]
pub struct Refs<'a> {
    pub types: usize,
    pub strings: &'a Strings,
}

/// Sequential reader of encoded data with bounds checks.
pub(crate) struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return err("unexpected end of data");
        }
        let b = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    #[inline]
    pub fn varint(&mut self) -> Result<u128, DecodeError> {
        // fast path: most lengths, counts and small integers take a single byte
        if let Some(&byte) = self.data.get(self.pos)
            && byte < 0x80
        {
            self.pos += 1;
            return Ok(u128::from(byte));
        }
        self.varint_slow()
    }

    fn varint_slow(&mut self) -> Result<u128, DecodeError> {
        // the first 9 bytes (63 bits) are accumulated in a u64, which is much cheaper
        let mut low = 0u64;
        for shift in (0..63).step_by(7) {
            let byte = self.u8()?;
            low |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(u128::from(low));
            }
        }
        let mut v = u128::from(low);
        for shift in (63..128).step_by(7) {
            let byte = self.u8()?;
            let bits = u128::from(byte & 0x7f);
            if shift == 126 && bits > 0b11 {
                return err("varint overflow");
            }
            v |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(v);
            }
        }
        err("varint overflow")
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        u64::try_from(self.varint()?).or_else(|_| err("integer overflow"))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        u32::try_from(self.varint()?).or_else(|_| err("integer overflow"))
    }

    /// A length/count. Every item takes at least one byte, so anything larger than the remaining
    /// data is invalid; this bounds allocations for malicious input.
    pub fn count(&mut self) -> Result<usize, DecodeError> {
        let n = self.varint()?;
        match usize::try_from(n) {
            Ok(n) if n <= self.remaining() => Ok(n),
            _ => err("length exceeds data size"),
        }
    }

    /// An inline string: varint byte length, UTF-8.
    pub fn str(&mut self) -> Result<&'a str, DecodeError> {
        let n = self.count()?;
        let b = self.bytes(n)?;
        // most strings are short and ASCII: `is_ascii` is much cheaper than `from_utf8` for them
        if b.is_ascii() {
            return Ok(std::str::from_utf8(b).expect("ASCII"));
        }
        std::str::from_utf8(b).or_else(|_| err("invalid UTF-8 string"))
    }

    /// A string id, resolved.
    fn string(&mut self, strings: &Strings) -> Result<Box<str>, DecodeError> {
        let id = self.u32()?;
        strings.get(id).map(Box::from).map_or_else(|| err("invalid string id"), Ok)
    }

    fn fields(&mut self, depth: usize, refs: Refs<'_>) -> Result<Fields, DecodeError> {
        let n = self.count()?;
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            let k = self.string(refs.strings)?;
            fields.push((k, self.value(depth + 1, refs)?));
        }
        Ok(fields.into())
    }

    /// Decodes one value.
    pub fn value(&mut self, depth: usize, refs: Refs<'_>) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return err("values nested too deeply");
        }
        Ok(match self.u8()? {
            tag::NULL => Value::Null,
            tag::FALSE => Value::Bool(false),
            tag::TRUE => Value::Bool(true),
            tag::INT => {
                let z = self.u64()?;
                #[allow(clippy::cast_possible_wrap)]
                Value::Int((z >> 1) as i64 ^ -((z & 1) as i64))
            }
            tag::UINT => {
                let u = self.u64()?;
                if i64::try_from(u).is_ok() {
                    return err("non-canonical integer");
                }
                Value::UInt(u)
            }
            tag::FLOAT => Value::Float(f64::from_le_bytes(self.bytes(8)?.try_into().expect("8 bytes"))),
            tag::STR => Value::Str(self.string(refs.strings)?),
            tag::BYTES => {
                let n = self.count()?;
                Value::Bytes(self.bytes(n)?.into())
            }
            tag::SEQ => {
                let n = self.count()?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1, refs)?);
                }
                Value::Seq(items.into())
            }
            tag::MAP => Value::Map(self.fields(depth, refs)?),
            tag::OBJECT => {
                let type_id = self.u32()?;
                if type_id as usize >= refs.types {
                    return err("invalid type id");
                }
                Value::Object(type_id, self.fields(depth, refs)?)
            }
            t => return err(format!("unknown value tag {t}")),
        })
    }

    fn transcode_fields<S: Sink, F>(
        &mut self,
        out: &mut S,
        depth: usize,
        types: usize,
        string: &mut F,
    ) -> Result<(), DecodeError>
    where
        F: FnMut(&mut Self) -> Result<u32, DecodeError>,
    {
        let n = self.count()?;
        out.varint(n as u128);
        for _ in 0..n {
            let id = string(self)?;
            out.varint(u128::from(id));
            self.transcode(out, depth + 1, types, string)?;
        }
        Ok(())
    }

    /// Validates one value exactly like [`Reader::value`] (same errors, same end position), and
    /// writes it to `out` in canonical form, without building it. `string` reads a string (an
    /// id, or an inline string in version 1 data) and returns the id to write: it validates
    /// and maps the ids. `types` is the number of registered types.
    pub fn transcode<S: Sink, F>(
        &mut self,
        out: &mut S,
        depth: usize,
        types: usize,
        string: &mut F,
    ) -> Result<(), DecodeError>
    where
        F: FnMut(&mut Self) -> Result<u32, DecodeError>,
    {
        if depth > MAX_DEPTH {
            return err("values nested too deeply");
        }
        let t = self.u8()?;
        out.byte(t);
        match t {
            tag::NULL | tag::FALSE | tag::TRUE => {}
            tag::INT => out.varint(u128::from(self.u64()?)),
            tag::UINT => {
                let u = self.u64()?;
                if i64::try_from(u).is_ok() {
                    return err("non-canonical integer");
                }
                out.varint(u128::from(u));
            }
            tag::FLOAT => out.put(self.bytes(8)?),
            tag::STR => {
                let id = string(self)?;
                out.varint(u128::from(id));
            }
            tag::BYTES => {
                let n = self.count()?;
                out.varint(n as u128);
                out.put(self.bytes(n)?);
            }
            tag::SEQ => {
                let n = self.count()?;
                out.varint(n as u128);
                for _ in 0..n {
                    self.transcode(out, depth + 1, types, string)?;
                }
            }
            tag::MAP => self.transcode_fields(out, depth, types, string)?,
            tag::OBJECT => {
                let id = self.u32()?;
                if id as usize >= types {
                    return err("invalid type id");
                }
                out.varint(u128::from(id));
                self.transcode_fields(out, depth, types, string)?;
            }
            t => return err(format!("unknown value tag {t}")),
        }
        Ok(())
    }
}

/// Tag and, for objects, type id of an encoded value; `None` if the data is too short.
#[must_use]
pub fn head(encoded: &[u8]) -> Option<(u8, Option<u32>)> {
    let mut r = Reader::new(encoded);
    let t = r.u8().ok()?;
    if t == tag::OBJECT { r.u32().ok().map(|id| (t, Some(id))) } else { Some((t, None)) }
}

/// Decodes one complete encoded value.
///
/// # Errors
/// If the data is not exactly one valid value.
pub fn decode(data: &[u8], refs: Refs<'_>) -> Result<Value, DecodeError> {
    let mut r = Reader::new(data);
    let v = r.value(0, refs)?;
    if r.remaining() != 0 {
        return err("trailing data after value");
    }
    Ok(v)
}

/// Writes a valid encoded value to `out` with its string ids mapped by `map`.
pub(crate) fn remap_strings(encoded: &[u8], out: &mut Vec<u8>, types: usize, mut map: impl FnMut(u32) -> u32) {
    let mut string = |r: &mut Reader<'_>| r.u32().map(&mut map);
    Reader::new(encoded).transcode(out, 0, types, &mut string).expect("a valid encoded value");
}

/// Calls `f` with every string id of a valid encoded value, in order.
pub(crate) fn visit_strings(encoded: &[u8], types: usize, mut f: impl FnMut(u32)) {
    let mut string = |r: &mut Reader<'_>| r.u32().inspect(|&id| f(id));
    Reader::new(encoded).transcode(&mut Discard, 0, types, &mut string).expect("a valid encoded value");
}

/// The encodings of all values of a store, concatenated in one buffer: no allocation (and no
/// allocator overhead) per value.
#[derive(Debug, Clone, Default)]
pub(crate) struct Encodings {
    data: Vec<u8>,
    /// End of each encoding in `data`.
    ends: Vec<u64>,
}

impl Encodings {
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn get(&self, i: usize) -> &[u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        #[allow(clippy::cast_possible_truncation)] // offsets of data in memory fit usize
        &self.data[start as usize..self.ends[i] as usize]
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        (0..self.len()).map(|i| self.get(i))
    }

    pub fn push(&mut self, encoded: &[u8]) {
        self.data.extend_from_slice(encoded);
        self.end();
    }

    /// The buffer to write the next encoding to, completed with [`Encodings::end`].
    pub fn buffer(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Ends the encoding written to [`Encodings::buffer`].
    pub fn end(&mut self) {
        self.ends.push(self.data.len() as u64);
    }

    fn shrink(&mut self) {
        self.data.shrink_to_fit();
        self.ends.shrink_to_fit();
    }

    fn memory_usage(&self) -> usize {
        self.data.capacity() + self.ends.capacity() * size_of::<u64>()
    }
}

/// A stored value: its id, canonical encoding and payload. Dereferences to the payload.
#[derive(Debug)]
pub struct ValueRef<'a, P> {
    store: &'a ValueStore<P>,
    id: u32,
}

impl<P> Clone for ValueRef<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for ValueRef<'_, P> {}

impl<'a, P> ValueRef<'a, P> {
    /// The id of the value in its store.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The canonical encoding.
    #[must_use]
    pub fn encoded(&self) -> &'a [u8] {
        self.store.encoded(self.id)
    }

    #[must_use]
    pub fn payload(&self) -> &'a P {
        self.store.payload(self.id)
    }
}

impl<P> std::ops::Deref for ValueRef<'_, P> {
    type Target = P;

    fn deref(&self) -> &P {
        self.store.payload(self.id)
    }
}

/// Index of the stored values by encoding, for deduplication.
#[derive(Debug)]
struct Dedup {
    ids: HashTable<u32>,
    seed: u64,
}

/// Source of [`ValueStore::epoch`].
static EPOCHS: AtomicU64 = AtomicU64::new(0);

fn next_epoch() -> u64 {
    EPOCHS.fetch_add(1, Ordering::Relaxed)
}

/// Deduplicating storage of encoded values and their payloads, referenced by `u32` ids.
///
/// The encodings are shared by copies (e.g. a tree built from a builder) until one of them adds
/// a value.
#[derive(Debug)]
pub struct ValueStore<P> {
    encodings: Arc<Encodings>,
    payloads: Vec<P>,
    /// Lazily built index used for deduplication on insert. Dropped when not needed (e.g. after
    /// loading from disk) to save memory.
    dedup: Option<Dedup>,
    epoch: u64,
}

impl<P> Default for ValueStore<P> {
    fn default() -> Self {
        Self::from_encodings(Encodings::default(), Vec::new())
    }
}

impl<P> ValueStore<P> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store from unique encoded values and their payloads (e.g. decoded from disk).
    pub(crate) fn from_encodings(encodings: Encodings, payloads: Vec<P>) -> Self {
        assert_eq!(encodings.len(), payloads.len());
        Self { encodings: Arc::new(encodings), payloads, dedup: None, epoch: next_epoch() }
    }

    /// Identifies the store and the meaning of its ids: ids keep referring to the same values
    /// as long as the epoch is the same. Values are only added in an epoch; dropping values and
    /// encoding them again start a new one, and every store has its own. Lets a caller which
    /// released a lock check whether an id it got is still valid.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.payloads.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payloads.is_empty()
    }

    #[must_use]
    pub fn encoded(&self, id: u32) -> &[u8] {
        self.encodings.get(id as usize)
    }

    #[must_use]
    pub fn get(&self, id: u32) -> ValueRef<'_, P> {
        assert!((id as usize) < self.len(), "value id out of range");
        ValueRef { store: self, id }
    }

    #[must_use]
    pub fn payload(&self, id: u32) -> &P {
        &self.payloads[id as usize]
    }

    pub fn payloads(&self) -> impl Iterator<Item = &P> {
        self.payloads.iter()
    }

    /// All stored values, in id order.
    pub fn iter(&self) -> impl Iterator<Item = ValueRef<'_, P>> {
        // ids fit u32: `intern` never grows the store beyond u32::MAX values
        #[allow(clippy::cast_possible_truncation)]
        (0..self.len()).map(|id| ValueRef { store: self, id: id as u32 })
    }

    /// A copy with payloads produced by `clone` (e.g. `Py::clone_ref`, Python objects are not
    /// `Clone`). The encodings are shared; the deduplication index is rebuilt lazily by the copy.
    pub fn clone_with<Q>(&self, clone: impl FnMut(&P) -> Q) -> ValueStore<Q> {
        self.map_payloads(self.payloads.iter().map(clone).collect())
    }

    /// A store with the same values (sharing the encodings) and other payloads, by id.
    pub fn map_payloads<Q>(&self, payloads: Vec<Q>) -> ValueStore<Q> {
        assert_eq!(payloads.len(), self.len());
        ValueStore { encodings: Arc::clone(&self.encodings), payloads, dedup: None, epoch: next_epoch() }
    }

    /// Id of an already stored encoded value.
    pub fn find(&mut self, encoded: &[u8]) -> Option<u32> {
        let (dedup, encodings) = self.dedup_index();
        let hash = xxh3_64_with_seed(encoded, dedup.seed);
        dedup.ids.find(hash, |&id| encodings.get(id as usize) == encoded).copied()
    }

    fn dedup_index(&mut self) -> (&mut Dedup, &Encodings) {
        let encodings = &*self.encodings;
        let dedup = self.dedup.get_or_insert_with(|| {
            let seed = random_seed();
            let mut ids = HashTable::with_capacity(encodings.len());
            for (id, e) in encodings.iter().enumerate() {
                // ids fit u32: `intern` never grows the store beyond u32::MAX values
                #[allow(clippy::cast_possible_truncation)]
                ids.insert_unique(xxh3_64_with_seed(e, seed), id as u32, |&id| {
                    xxh3_64_with_seed(encodings.get(id as usize), seed)
                });
            }
            Dedup { ids, seed }
        });
        (dedup, encodings)
    }

    /// Returns the id of the encoded value, adding it with `payload` if it is new. If the value
    /// already exists, `payload` is handed back unused (dropping it is left to the caller, which
    /// matters for Python objects).
    ///
    /// # Panics
    /// If more than `u32::MAX - 1` distinct values are stored.
    pub fn intern(&mut self, encoded: &[u8], payload: P) -> (u32, Option<P>) {
        if let Some(id) = self.find(encoded) {
            return (id, Some(payload));
        }
        let id = u32::try_from(self.len()).ok().filter(|&id| id < u32::MAX).expect("too many distinct values");
        // copies the encodings if they are shared
        let encodings = Arc::make_mut(&mut self.encodings);
        encodings.push(encoded);
        self.payloads.push(payload);
        let dedup = self.dedup.as_mut().expect("built by find");
        let seed = dedup.seed;
        let rehash = |&id: &u32| xxh3_64_with_seed(encodings.get(id as usize), seed);
        dedup.ids.insert_unique(xxh3_64_with_seed(encoded, seed), id, rehash);
        (id, None)
    }

    /// Keeps only the values for which `keep[id]` is true. Returns the mapping
    /// `old id -> new id` (`u32::MAX` for removed values) and the removed payloads.
    pub fn retain(&mut self, keep: &[bool]) -> (Vec<u32>, Vec<P>) {
        debug_assert_eq!(keep.len(), self.len());
        let mut remap = vec![u32::MAX; self.len()];
        let mut removed = Vec::new();
        let mut encodings = Encodings::default();
        let mut payloads = Vec::with_capacity(keep.iter().filter(|&&k| k).count());
        for (id, payload) in std::mem::take(&mut self.payloads).into_iter().enumerate() {
            if keep[id] {
                remap[id] = u32::try_from(payloads.len()).expect("ids fit u32");
                encodings.push(self.encodings.get(id));
                payloads.push(payload);
            } else {
                removed.push(payload);
            }
        }
        encodings.shrink();
        *self = Self::from_encodings(encodings, payloads);
        (remap, removed)
    }

    /// Replaces the encoding of every value with the one `f` writes to the buffer it gets. `f`
    /// must keep distinct values distinct (e.g. renumber strings). The payloads are kept.
    pub fn rewrite_encodings(&mut self, mut f: impl FnMut(&[u8], &mut Vec<u8>)) {
        let mut encodings = Encodings::default();
        for e in self.encodings.iter() {
            f(e, encodings.buffer());
            encodings.end();
        }
        encodings.shrink();
        *self = Self::from_encodings(encodings, std::mem::take(&mut self.payloads));
    }

    /// Releases memory reserved for more values, unless the encodings are shared.
    pub fn shrink(&mut self) {
        if let Some(encodings) = Arc::get_mut(&mut self.encodings) {
            encodings.shrink();
        }
        self.payloads.shrink_to_fit();
    }

    /// Approximate memory used by the store in bytes, excluding what payloads point to. Shared
    /// encodings are counted by every copy.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        let payloads = self.payloads.capacity() * size_of::<P>();
        let dedup = self.dedup.as_ref().map_or(0, |d| d.ids.capacity() * (size_of::<u32>() + 1));
        self.encodings.memory_usage() + payloads + dedup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strings::StringSet;

    fn sample() -> Value {
        Value::Object(
            0,
            vec![
                ("int".into(), Value::Int(-15169)),
                ("big".into(), Value::UInt(u64::MAX)),
                ("min".into(), Value::Int(i64::MIN)),
                ("f".into(), Value::Float(1.5)),
                ("b".into(), Value::Bytes(b"\x00\xff".to_vec().into())),
                ("seq".into(), Value::Seq(vec![Value::Bool(true), Value::Bool(false), Value::Null].into())),
                ("map".into(), Value::Map(vec![("s".into(), Value::Str("ünïcode".into()))].into())),
                ("again".into(), Value::Str("ünïcode".into())),
            ]
            .into(),
        )
    }

    fn enc(set: &mut StringSet, v: &Value) -> Vec<u8> {
        encode(v, None, |s| set.intern(s))
    }

    fn refs(set: &StringSet, types: usize) -> Refs<'_> {
        Refs { types, strings: set.strings() }
    }

    #[test]
    fn roundtrip_and_canonical() {
        let mut set = StringSet::default();
        let v = sample();
        let e = enc(&mut set, &v);
        assert_eq!(decode(&e, refs(&set, 1)).unwrap(), v);
        // strings are stored once
        assert_eq!(set.strings().len(), 10);
        assert_eq!(set.strings().get(9), Some("again"));
        // canonical: the same value encodes the same way, with mapped type ids too
        assert_eq!(enc(&mut set, &v), e);
        let Value::Object(_, fields) = &v else { unreachable!() };
        let mapped = encode(&Value::Object(1, fields.clone()), Some(&[7, 0]), |s| set.intern(s));
        assert_eq!(mapped, e);
        // type-exact: values Python considers equal encode differently
        let ints = [Value::Int(1), Value::Float(1.0), Value::Bool(true)].map(|v| enc(&mut set, &v));
        assert!(ints[0] != ints[1] && ints[1] != ints[2] && ints[0] != ints[2]);
        assert_eq!(Value::from_u64(5), Value::Int(5));
        assert_eq!(Value::from_u64(u64::MAX), Value::UInt(u64::MAX));
        // renumbering strings
        let mut ids = Vec::new();
        visit_strings(&e, 1, |id| ids.push(id));
        assert_eq!(ids, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8]);
        let mut reversed = Vec::new();
        remap_strings(&e, &mut reversed, 1, |id| 9 - id);
        let mut strings = Strings::new();
        for s in set.strings().iter().collect::<Vec<_>>().into_iter().rev() {
            strings.push(s);
        }
        assert_eq!(decode(&reversed, Refs { types: 1, strings: &strings }).unwrap(), v);
    }

    #[test]
    fn decode_rejects_invalid() {
        let mut set = StringSet::default();
        let e = enc(&mut set, &sample());
        assert!(decode(&e, refs(&set, 0)).is_err(), "type id out of range");
        for len in 0..e.len() {
            assert!(decode(&e[..len], refs(&set, 1)).is_err(), "truncated at {len}");
        }
        let cases: &[&[u8]] = &[
            &[42],                                                                         // unknown tag
            &[tag::STR, 99],                                                               // string id out of range
            &[tag::MAP, 1, 99, tag::NULL],                                                 // key id out of range
            &[tag::UINT, 1],                                                               // non-canonical integer
            &[tag::SEQ, 0xff, 0xff, 0xff, 0x0f],                                           // count larger than data
            &[tag::NULL, tag::NULL],                                                       // trailing data
            &[tag::INT, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], // > u64
        ];
        for case in cases {
            assert!(decode(case, refs(&set, 1)).is_err(), "{case:?}");
        }
        let nested = |depth: usize| {
            let mut d: Vec<u8> = std::iter::repeat_n([tag::SEQ, 1], depth).flatten().collect();
            d.push(tag::NULL);
            d
        };
        assert!(decode(&nested(MAX_DEPTH), refs(&set, 0)).is_ok());
        assert!(decode(&nested(MAX_DEPTH + 1), refs(&set, 0)).is_err());
    }

    /// The allocation-free validator must accept exactly what the decoder accepts, end at the
    /// same position, and copy valid values in canonical form (e.g. minimal varints): checked
    /// for every truncation and every byte value at every position.
    #[test]
    fn transcode_agrees_with_value() {
        let mut set = StringSet::default();
        let mut e = enc(&mut set, &sample());
        e.push(tag::NULL); // a following value: the end position matters
        let strings = set.strings();
        let agree = |data: &[u8], types: usize| {
            let (mut a, mut b) = (Reader::new(data), Reader::new(data));
            let mut out = Vec::new();
            let mut string = |r: &mut Reader<'_>| {
                let id = r.u32()?;
                if strings.get(id).is_some() { Ok(id) } else { err("invalid string id") }
            };
            let (va, vb) = (a.value(0, Refs { types, strings }), b.transcode(&mut out, 0, types, &mut string));
            assert_eq!(va.is_ok(), vb.is_ok(), "{data:?}");
            if let Ok(v) = &va {
                assert_eq!(a.pos, b.pos, "{data:?}");
                // compared as text: NaN != NaN
                let copy = decode(&out, Refs { types, strings }).unwrap();
                assert_eq!(format!("{copy:?}"), format!("{v:?}"), "{data:?}");
                assert!(out.len() <= a.pos, "{data:?}");
            }
            usize::from(va.is_ok())
        };
        // a canonical value is copied unchanged
        let mut out = Vec::new();
        let mut string = |r: &mut Reader<'_>| r.u32();
        Reader::new(&e).transcode(&mut out, 0, 1, &mut string).unwrap();
        assert_eq!(out, e[..e.len() - 1]);
        let mut accepted = 0;
        for len in 0..=e.len() {
            accepted += agree(&e[..len], 1);
        }
        for i in 0..e.len() {
            for byte in 0..=255u8 {
                let mut d = e.clone();
                d[i] = byte;
                accepted += agree(&d, 1) + agree(&d, 0);
            }
        }
        assert!(accepted > e.len() * 50, "both valid and invalid variants were checked");
        assert_eq!(head(&e), Some((tag::OBJECT, Some(0))));
        assert_eq!(head(&[tag::STR, 0]), Some((tag::STR, None)));
        assert_eq!(head(&[]), None);
    }

    /// Version 1 data (inline strings) is converted to string ids.
    #[test]
    fn transcode_inline_strings() {
        let v1: &[u8] = &[tag::MAP, 2, 1, b'a', tag::STR, 2, b'h', b'i', 1, b'b', tag::STR, 1, b'a'];
        let mut set = StringSet::default();
        let mut out = Vec::new();
        let mut string = |r: &mut Reader<'_>| r.str().map(|s| set.intern(s));
        Reader::new(v1).transcode(&mut out, 0, 0, &mut string).unwrap();
        assert_eq!(out, [tag::MAP, 2, 0, tag::STR, 1, 2, tag::STR, 0]);
        let map = Value::Map(vec![("a".into(), Value::Str("hi".into())), ("b".into(), Value::Str("a".into()))].into());
        assert_eq!(decode(&out, refs(&set, 0)).unwrap(), map);
        let mut string = |r: &mut Reader<'_>| r.str().map(|_| 0);
        assert!(Reader::new(&[tag::STR, 1, 0xff]).transcode(&mut Discard, 0, 0, &mut string).is_err(), "invalid UTF-8");
    }

    #[test]
    fn varint_roundtrip() {
        // includes the boundaries of the u64 stage (63 bits) of the multi-byte decoder
        for v in [0u128, 1, 127, 128, 300, (1 << 63) - 1, 1 << 63, u128::from(u64::MAX), 1 << 126, u128::MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut r = Reader::new(&out);
            assert_eq!(r.varint().unwrap(), v);
            assert_eq!(r.remaining(), 0);
        }
        assert!(Reader::new(&[0xff; 20]).varint().is_err());
        let mut too_big = [0xff; 19];
        too_big[18] = 0x04; // bit 128
        assert!(Reader::new(&too_big).varint().is_err());
        too_big[18] = 0x03;
        assert_eq!(Reader::new(&too_big).varint(), Ok(u128::MAX));
    }

    #[test]
    fn store_dedups_and_compacts() {
        let mut store = ValueStore::new();
        let blob = |i: i64| encode(&Value::Int(i), None, |_| 0);
        assert_eq!(store.intern(&blob(1), "a"), (0, None));
        assert_eq!(store.intern(&blob(2), "b"), (1, None));
        assert_eq!(store.intern(&blob(1), "c"), (0, Some("c")), "duplicate hands the payload back");
        let epoch = store.epoch();
        let (remap, removed) = store.retain(&[false, true]);
        assert_eq!((remap, removed), (vec![u32::MAX, 0], vec!["a"]));
        assert_ne!(store.epoch(), epoch, "ids changed");
        assert_eq!(*store.payload(0), "b");
        let v = store.get(0);
        assert_eq!((v.id(), v.encoded(), *v.payload(), *v), (0, &blob(2)[..], "b", "b"));
        // the dedup index is rebuilt after compaction
        assert_eq!(store.intern(&blob(2), "d"), (0, Some("d")));
        let epoch = store.epoch();
        assert_eq!(store.intern(&blob(1), "e"), (1, None));
        assert_eq!(store.epoch(), epoch, "adding values keeps the ids");
        assert_eq!(store.len(), 2);
        // many values: the index grows
        for i in 3..10_000 {
            assert_eq!(store.intern(&blob(i), "x"), (u32::try_from(i).unwrap() - 1, None));
        }
        assert_eq!(store.find(&blob(5000)), Some(4999));
        assert_eq!(store.iter().map(|v| v.encoded().to_vec()).nth(4999), Some(blob(5000)));
        // re-encoding keeps payloads and rebuilds the index
        store.rewrite_encodings(|e, out| out.extend_from_slice(&[e, b"!"].concat()));
        assert_eq!(store.find(&blob(5000)), None);
        assert_eq!(store.find(&[&*blob(5000), b"!"].concat()), Some(4999));
        assert_eq!(*store.payload(1), "e");
        // copies share the encodings until they add a value, and keep the ids
        let mut copy = store.clone_with(|p| p.to_uppercase());
        assert!(Arc::ptr_eq(&store.encodings, &copy.encodings));
        assert_eq!(copy.payload(1), "E");
        assert_eq!(copy.intern(&blob(3), "F".to_owned()), (9999, None));
        assert!(!Arc::ptr_eq(&store.encodings, &copy.encodings));
        assert_eq!(store.len(), 9999);
        assert_eq!(copy.encoded(9999), blob(3));
        store.shrink();
        assert!(store.memory_usage() > 0);
    }
}
