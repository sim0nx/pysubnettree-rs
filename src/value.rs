//! Values attached to networks.
//!
//! Every distinct value is kept once, in its canonical *encoded* form (see [`encode`]). The
//! encoding is type-exact (`1`, `1.0` and `True` differ), so it serves as the deduplication key
//! and is written to disk as-is. Next to it the store keeps a *payload* of a generic type: the
//! Python bindings use it for the read-only Python object returned by lookups.
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
//! | 6   | str      | varint byte length, UTF-8                                     |
//! | 7   | bytes    | varint length, bytes                                          |
//! | 8   | sequence | varint count, values                                          |
//! | 9   | mapping  | varint count, (varint length, UTF-8 key, value) pairs         |
//! | 10  | object   | varint type id, varint count, (key, value) pairs as for 9     |

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

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

mod tag {
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

fn put_fields(out: &mut Vec<u8>, fields: &[(Box<str>, Value)]) {
    put_len(out, fields.len());
    for (k, v) in fields {
        put_str(out, k);
        encode_into(out, v);
    }
}

fn encode_into(out: &mut Vec<u8>, v: &Value) {
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
            put_str(out, s);
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
                encode_into(out, item);
            }
        }
        Value::Map(fields) => {
            out.push(tag::MAP);
            put_fields(out, fields);
        }
        Value::Object(type_id, fields) => {
            out.push(tag::OBJECT);
            put_varint(out, u128::from(*type_id));
            put_fields(out, fields);
        }
    }
}

/// Encodes a value into its canonical form.
#[must_use]
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, v);
    out
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

    pub fn varint(&mut self) -> Result<u128, DecodeError> {
        let mut v = 0u128;
        for shift in (0..128).step_by(7) {
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

    pub fn str(&mut self) -> Result<Box<str>, DecodeError> {
        let n = self.count()?;
        let b = self.bytes(n)?;
        std::str::from_utf8(b).map(Box::from).or_else(|_| err("invalid UTF-8 string"))
    }

    fn fields(&mut self, depth: usize, type_count: usize) -> Result<Fields, DecodeError> {
        let n = self.count()?;
        let mut fields = Vec::with_capacity(n);
        for _ in 0..n {
            let k = self.str()?;
            fields.push((k, self.value(depth + 1, type_count)?));
        }
        Ok(fields.into())
    }

    /// Decodes one value. `type_count` is the number of registered types (object type ids must
    /// be below it).
    pub fn value(&mut self, depth: usize, type_count: usize) -> Result<Value, DecodeError> {
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
            tag::STR => Value::Str(self.str()?),
            tag::BYTES => {
                let n = self.count()?;
                Value::Bytes(self.bytes(n)?.into())
            }
            tag::SEQ => {
                let n = self.count()?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1, type_count)?);
                }
                Value::Seq(items.into())
            }
            tag::MAP => Value::Map(self.fields(depth, type_count)?),
            tag::OBJECT => {
                let type_id = self.u32()?;
                if type_id as usize >= type_count {
                    return err("invalid type id");
                }
                Value::Object(type_id, self.fields(depth, type_count)?)
            }
            t => return err(format!("unknown value tag {t}")),
        })
    }
}

/// Decodes one complete encoded value.
///
/// # Errors
/// If the data is not exactly one valid value.
pub fn decode(data: &[u8], type_count: usize) -> Result<Value, DecodeError> {
    let mut r = Reader::new(data);
    let v = r.value(0, type_count)?;
    if r.remaining() != 0 {
        return err("trailing data after value");
    }
    Ok(v)
}

/// Deduplicating storage of encoded values and their payloads, referenced by `u32` ids.
#[derive(Debug)]
pub struct ValueStore<P> {
    entries: Vec<(Arc<[u8]>, P)>,
    /// Lazily built index used for deduplication on insert. Dropped when not needed (e.g. after
    /// loading from disk) to save memory.
    dedup: Option<HashMap<Arc<[u8]>, u32>>,
}

impl<P> Default for ValueStore<P> {
    fn default() -> Self {
        Self { entries: Vec::new(), dedup: None }
    }
}

impl<P> ValueStore<P> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a store from unique encoded values and their payloads (e.g. decoded from disk).
    #[must_use]
    pub fn from_entries(entries: Vec<(Arc<[u8]>, P)>) -> Self {
        Self { entries, dedup: None }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn encoded(&self, id: u32) -> &Arc<[u8]> {
        &self.entries[id as usize].0
    }

    #[must_use]
    pub fn payload(&self, id: u32) -> &P {
        &self.entries[id as usize].1
    }

    pub fn payloads(&self) -> impl Iterator<Item = &P> {
        self.entries.iter().map(|(_, p)| p)
    }

    /// Id of an already stored encoded value.
    pub fn find(&mut self, encoded: &[u8]) -> Option<u32> {
        self.dedup_index().get(encoded).copied()
    }

    fn dedup_index(&mut self) -> &mut HashMap<Arc<[u8]>, u32> {
        let entries = &self.entries;
        self.dedup.get_or_insert_with(|| {
            // ids fit u32: `intern` never grows the store beyond u32::MAX values
            #[allow(clippy::cast_possible_truncation)]
            entries.iter().enumerate().map(|(id, (e, _))| (Arc::clone(e), id as u32)).collect()
        })
    }

    /// Returns the id of the encoded value, adding it with `payload` if it is new. If the value
    /// already exists, `payload` is handed back unused (dropping it is left to the caller, which
    /// matters for Python objects).
    ///
    /// # Panics
    /// If more than `u32::MAX - 1` distinct values are stored.
    pub fn intern(&mut self, encoded: Arc<[u8]>, payload: P) -> (u32, Option<P>) {
        if let Some(id) = self.find(&encoded) {
            return (id, Some(payload));
        }
        let id = u32::try_from(self.entries.len()).ok().filter(|&id| id < u32::MAX).expect("too many distinct values");
        self.entries.push((Arc::clone(&encoded), payload));
        self.dedup_index().insert(encoded, id);
        (id, None)
    }

    /// Keeps only the values for which `keep[id]` is true. Returns the mapping
    /// `old id -> new id` (`u32::MAX` for removed values) and the removed payloads.
    pub fn retain(&mut self, keep: &[bool]) -> (Vec<u32>, Vec<P>) {
        debug_assert_eq!(keep.len(), self.entries.len());
        let mut remap = vec![u32::MAX; self.entries.len()];
        let mut removed = Vec::new();
        let mut kept = Vec::with_capacity(keep.iter().filter(|&&k| k).count());
        for (id, entry) in self.entries.drain(..).enumerate() {
            if keep[id] {
                remap[id] = u32::try_from(kept.len()).expect("ids fit u32");
                kept.push(entry);
            } else {
                removed.push(entry.1);
            }
        }
        self.entries = kept;
        self.dedup = None;
        (remap, removed)
    }

    /// Approximate memory used by the store in bytes, excluding what payloads point to.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        let arc_header = 2 * size_of::<usize>();
        let entries: usize = self.entries.iter().map(|(e, _)| arc_header + e.len()).sum();
        let slots = self.entries.capacity() * size_of::<(Arc<[u8]>, P)>();
        let dedup = self.dedup.as_ref().map_or(0, |t| t.capacity() * (size_of::<(Arc<[u8]>, u32)>() + 1));
        entries + slots + dedup
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ]
            .into(),
        )
    }

    #[test]
    fn roundtrip_and_canonical() {
        let v = sample();
        let enc = encode(&v);
        assert_eq!(decode(&enc, 1).unwrap(), v);
        // type-exact: values Python considers equal encode differently
        let ints = [Value::Int(1), Value::Float(1.0), Value::Bool(true)].map(|v| encode(&v));
        assert!(ints[0] != ints[1] && ints[1] != ints[2] && ints[0] != ints[2]);
        assert_eq!(Value::from_u64(5), Value::Int(5));
        assert_eq!(Value::from_u64(u64::MAX), Value::UInt(u64::MAX));
    }

    #[test]
    fn decode_rejects_invalid() {
        let enc = encode(&sample());
        assert!(decode(&enc, 0).is_err(), "type id out of range");
        for len in 0..enc.len() {
            assert!(decode(&enc[..len], 1).is_err(), "truncated at {len}");
        }
        let cases: &[&[u8]] = &[
            &[42],                                                                         // unknown tag
            &[tag::STR, 1, 0xff],                                                          // invalid UTF-8
            &[tag::UINT, 1],                                                               // non-canonical integer
            &[tag::SEQ, 0xff, 0xff, 0xff, 0x0f],                                           // count larger than data
            &[tag::NULL, tag::NULL],                                                       // trailing data
            &[tag::INT, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f], // > u64
        ];
        for case in cases {
            assert!(decode(case, 1).is_err(), "{case:?}");
        }
        let nested = |depth: usize| {
            let mut d: Vec<u8> = std::iter::repeat_n([tag::SEQ, 1], depth).flatten().collect();
            d.push(tag::NULL);
            d
        };
        assert!(decode(&nested(MAX_DEPTH), 0).is_ok());
        assert!(decode(&nested(MAX_DEPTH + 1), 0).is_err());
    }

    #[test]
    fn varint_roundtrip() {
        for v in [0u128, 1, 127, 128, 300, u128::from(u64::MAX), u128::MAX] {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut r = Reader::new(&out);
            assert_eq!(r.varint().unwrap(), v);
            assert_eq!(r.remaining(), 0);
        }
        assert!(Reader::new(&[0xff; 20]).varint().is_err());
    }

    #[test]
    fn store_dedups_and_compacts() {
        let mut store = ValueStore::new();
        let blob = |i: i64| Arc::from(encode(&Value::Int(i)));
        assert_eq!(store.intern(blob(1), "a"), (0, None));
        assert_eq!(store.intern(blob(2), "b"), (1, None));
        assert_eq!(store.intern(blob(1), "c"), (0, Some("c")), "duplicate hands the payload back");
        let (remap, removed) = store.retain(&[false, true]);
        assert_eq!((remap, removed), (vec![u32::MAX, 0], vec!["a"]));
        assert_eq!(*store.payload(0), "b");
        // the dedup index is rebuilt after compaction
        assert_eq!(store.intern(blob(2), "d"), (0, Some("d")));
        assert_eq!(store.intern(blob(1), "e"), (1, None));
        assert_eq!(store.len(), 2);
    }
}
