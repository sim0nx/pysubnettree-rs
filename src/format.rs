//! Compact on-disk format.
//!
//! All fixed size integers are little endian, `varint` is unsigned LEB128.
//!
//! ```text
//! header   magic "PYSTREE\0" (8 bytes) | version u16 | flags u16 (reserved, 0)
//! types    varint count | (u8 kind | varint length | UTF-8 "module.QualName")*
//! strings  varint count | (varint length | UTF-8)*
//! values   varint count | value*        (canonical value encoding, see `value`)
//! ipv4     varint count | entry*        entry = varint addr delta | u8 len | varint value id
//! ipv6     varint count | entry*
//! trailer  u64 XXH3-64 hash of everything before
//! ```
//!
//! Entries are sorted by `(address, prefix length)`; the address is stored as the difference to
//! the previous entry's address, which keeps typical routing tables at ~5 bytes per prefix.
//! Values are numbered in order of first use by the entries, strings in order of first use by
//! the values, so equal trees give equal files. Every string and value is used and unique.
//!
//! Version 1 has no strings section: values contain their strings inline. Version 1 files are
//! still read; they are converted to string ids when loaded.
//!
//! Decoding validates everything (checksum, ordering, value ids, type ids, string ids, nesting
//! depth, UTF-8), so a corrupted or malicious file results in an error, never in a panic or an
//! inconsistent tree.

use std::io::{self, Write};

use xxhash_rust::xxh3::{Xxh3Default, xxh3_64, xxh3_64_with_seed};

use crate::strings::{StringSet, Strings};
use crate::table::{Addr, PrefixTable};
use crate::tree::Tree;
use crate::value::{
    DecodeError, Encodings, Reader, TypeDesc, TypeKind, ValueStore, err, put_len, put_str, put_varint, visit_strings,
};

pub const MAGIC: &[u8; 8] = b"PYSTREE\0";
/// The version written.
pub const VERSION: u16 = 2;
/// The oldest version read.
const MIN_VERSION: u16 = 1;

const HEADER_LEN: usize = MAGIC.len() + 4;
const CHECKSUM_LEN: usize = 8;

/// Size of the buffer collecting the small pieces (headers, entries) before they are hashed and
/// written.
const BUFFER: usize = 64 * 1024;

/// Writes the output in pieces and computes the checksum along the way, so that a file is
/// written without holding all of it in memory.
struct Output<W: Write> {
    inner: W,
    hasher: Xxh3Default,
    buf: Vec<u8>,
}

impl<W: Write> Output<W> {
    fn new(inner: W) -> Self {
        Self { inner, hasher: Xxh3Default::new(), buf: Vec::with_capacity(BUFFER) }
    }

    /// Writes the buffer if it is (almost) full.
    fn spill(&mut self) -> io::Result<()> {
        if self.buf.len() >= BUFFER - 64 { self.flush_buf() } else { Ok(()) }
    }

    fn flush_buf(&mut self) -> io::Result<()> {
        self.hasher.update(&self.buf);
        self.inner.write_all(&self.buf)?;
        self.buf.clear();
        Ok(())
    }

    /// Appends bytes, large ones without copying them into the buffer.
    fn bytes(&mut self, b: &[u8]) -> io::Result<()> {
        if b.len() < BUFFER / 4 {
            self.buf.extend_from_slice(b);
            return self.spill();
        }
        self.flush_buf()?;
        self.hasher.update(b);
        self.inner.write_all(b)
    }

    /// Writes the checksum of everything written before, returns the writer.
    fn finish(mut self) -> io::Result<W> {
        self.flush_buf()?;
        self.inner.write_all(&self.hasher.digest().to_le_bytes())?;
        Ok(self.inner)
    }
}

fn encode_table<A: Addr, W: Write>(out: &mut Output<W>, table: &PrefixTable<A>, remap: &[u32]) -> io::Result<()> {
    put_len(&mut out.buf, table.len());
    let mut prev = 0u128;
    for (addr, len, val) in table.entries() {
        let addr = addr.to_u128();
        put_varint(&mut out.buf, addr - prev);
        prev = addr;
        out.buf.push(len);
        put_varint(&mut out.buf, u128::from(remap[val as usize]));
        out.spill()?;
    }
    Ok(())
}

/// Serializes a compiled tree. Only values referenced by a network are written.
///
/// # Panics
/// If the tree is not compiled.
#[must_use]
pub fn encode<P>(tree: &Tree<P>) -> Vec<u8> {
    let values: usize = tree.values().map(|v| v.encoded().len()).sum();
    let strings: usize = tree.strings().iter().map(|s| s.len() + 2).sum();
    let estimate = HEADER_LEN + tree.len() * 6 + values + strings;
    write(tree, Vec::with_capacity(estimate + CHECKSUM_LEN)).expect("writing to a Vec does not fail")
}

/// Serializes a compiled tree into a writer, piece by piece; see [`encode`]. Small writes are
/// buffered, so `out` does not need to be buffered. Returns the writer.
///
/// # Errors
/// The errors of the writer.
///
/// # Panics
/// If the tree is not compiled.
pub fn write<P, W: Write>(tree: &Tree<P>, out: W) -> io::Result<W> {
    assert!(!tree.is_dirty(), "tree must be compiled before encoding");
    // renumber the referenced values in order of first use
    let mut remap = vec![u32::MAX; tree.value_count()];
    let mut order = Vec::new();
    for id in tree.v4.value_ids().chain(tree.v6.value_ids()) {
        let slot = &mut remap[id as usize];
        if *slot == u32::MAX {
            *slot = u32::try_from(order.len()).expect("value ids fit u32");
            order.push(id);
        }
    }

    let mut out = Output::new(out);
    out.buf.extend_from_slice(MAGIC);
    out.buf.extend_from_slice(&VERSION.to_le_bytes());
    out.buf.extend_from_slice(&0u16.to_le_bytes());
    put_len(&mut out.buf, tree.types().len());
    for t in tree.types() {
        out.buf.push(t.kind as u8);
        put_str(&mut out.buf, &t.name);
        out.spill()?;
    }
    // the strings used by the written values, renumbered in order of first use
    let types = tree.types().len();
    let all = tree.strings();
    let mut string_ids = vec![u32::MAX; all.len()];
    let mut strings = Vec::new();
    for &id in &order {
        visit_strings(tree.encoded(id), types, |s| {
            let new = &mut string_ids[s as usize];
            if *new == u32::MAX {
                *new = u32::try_from(strings.len()).expect("string ids fit u32");
                strings.push(s);
            }
        });
    }
    put_len(&mut out.buf, strings.len());
    for &s in &strings {
        let s = all.get(s).expect("a string of the tree");
        put_len(&mut out.buf, s.len());
        out.bytes(s.as_bytes())?;
    }
    drop(strings);
    put_len(&mut out.buf, order.len());
    let mut string = |r: &mut Reader<'_>| r.u32().map(|id| string_ids[id as usize]);
    for &id in &order {
        Reader::new(tree.encoded(id)).transcode(&mut out.buf, 0, types, &mut string).expect("a valid encoded value");
        out.spill()?;
    }
    drop(order);
    encode_table(&mut out, &tree.v4, &remap)?;
    encode_table(&mut out, &tree.v6, &remap)?;
    out.finish()
}

fn decode_table<A: Addr>(r: &mut Reader<'_>, value_count: usize) -> Result<PrefixTable<A>, DecodeError> {
    let n = r.count()?;
    let mut entries = Vec::with_capacity(n);
    let mut prev = 0u128;
    for _ in 0..n {
        let Some(addr) = prev.checked_add(r.varint()?).and_then(A::from_u128) else {
            return err("address out of range");
        };
        prev = addr.to_u128();
        let len = r.u8()?;
        let val = r.u32()?;
        if val as usize >= value_count {
            return err("invalid value id");
        }
        entries.push((addr, len, val));
    }
    PrefixTable::from_sorted(entries).map_err(DecodeError)
}

/// True if two of the items are equal. Sorts seeded xxh3 hashes and compares bytes only where
/// hashes are equal; the random seed keeps crafted collisions (and so quadratic behaviour) out
/// of reach. Several times faster than a `HashSet` of slices.
fn has_duplicates<T: AsRef<[u8]>>(items: &[T]) -> bool {
    let seed = crate::strings::random_seed();
    let bytes = |i: usize| items[i].as_ref();
    let mut hashes: Vec<(u64, usize)> = (0..items.len()).map(|i| (xxh3_64_with_seed(bytes(i), seed), i)).collect();
    hashes.sort_unstable();
    hashes
        .chunk_by(|x, y| x.0 == y.0)
        .any(|run| run.iter().enumerate().any(|(k, &(_, i))| run[k + 1..].iter().any(|&(_, j)| bytes(i) == bytes(j))))
}

/// Deserializes a tree, validating the data. Payloads are `P::default()` (e.g. empty cells
/// filled on first use); [`Tree::with_payloads`] replaces them (the values are available via
/// [`Tree::encoded`]).
///
/// # Errors
/// If the data is not a valid, uncorrupted tree of a supported version.
pub fn decode<P: Default>(data: &[u8]) -> Result<Tree<P>, DecodeError> {
    if data.len() < HEADER_LEN + CHECKSUM_LEN || &data[..MAGIC.len()] != MAGIC {
        return err("not a subnet tree file");
    }
    let (body, checksum) = data.split_at(data.len() - CHECKSUM_LEN);
    let version = u16::from_le_bytes([body[8], body[9]]);
    if !(MIN_VERSION..=VERSION).contains(&version) {
        return err(format!("unsupported format version {version}"));
    }
    if xxh3_64(body) != u64::from_le_bytes(checksum.try_into().expect("8 bytes")) {
        return err("checksum mismatch, the data is corrupted");
    }
    let flags = u16::from_le_bytes([body[10], body[11]]);
    if flags != 0 {
        return err(format!("unsupported flags {flags:#x}"));
    }

    let mut r = Reader::new(body);
    r.pos = HEADER_LEN;
    let n = r.count()?;
    let mut types: Vec<TypeDesc> = Vec::with_capacity(n);
    for _ in 0..n {
        let Some(kind) = TypeKind::from_u8(r.u8()?) else {
            return err("unknown type kind");
        };
        let desc = TypeDesc { kind, name: r.str()?.into() };
        if types.contains(&desc) {
            return err("duplicate type");
        }
        types.push(desc);
    }

    // the values are validated without building them, and copied in canonical form
    let (strings, values) =
        if version == 1 { decode_v1_values(&mut r, &types)? } else { decode_values(&mut r, &types)? };
    if has_duplicates(&values.iter().collect::<Vec<_>>()) {
        return err("duplicate value");
    }
    let v4 = decode_table::<u32>(&mut r, values.len())?;
    let v6 = decode_table::<u128>(&mut r, values.len())?;
    if r.remaining() != 0 {
        return err("trailing data");
    }
    let payloads = std::iter::repeat_with(P::default).take(values.len()).collect();
    let mut tree = Tree { v4, v6, values: ValueStore::from_encodings(values, payloads), types, strings };
    // a hand-crafted file may contain unreferenced values, harmless but a waste of memory
    drop(tree.compact_values(true));
    Ok(tree)
}

type Values = Encodings;

/// The strings and values sections.
fn decode_values(r: &mut Reader<'_>, types: &[TypeDesc]) -> Result<(StringSet, Values), DecodeError> {
    let n = r.count()?;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        items.push(r.str()?);
    }
    if has_duplicates(&items) {
        return err("duplicate string");
    }
    let mut strings = Strings::new();
    for s in items {
        strings.push(s);
    }
    // strings are numbered in order of first use: each id is a used one, or the next one
    let mut next = 0;
    let mut string = |r: &mut Reader<'_>| {
        let id = r.u32()?;
        if id == next && (id as usize) < n {
            next += 1;
        } else if id >= next {
            return err("invalid string id");
        }
        Ok(id)
    };
    let values = transcode_values(r, types, &mut string)?;
    if next as usize != n {
        return err("unused string");
    }
    Ok((StringSet::new(strings), values))
}

/// The values section of version 1 (inline strings), converted to string ids.
fn decode_v1_values(r: &mut Reader<'_>, types: &[TypeDesc]) -> Result<(StringSet, Values), DecodeError> {
    let mut strings = StringSet::default();
    let mut string = |r: &mut Reader<'_>| r.str().map(|s| strings.intern(s));
    let values = transcode_values(r, types, &mut string)?;
    Ok((strings, values))
}

fn transcode_values<'a>(
    r: &mut Reader<'a>,
    types: &[TypeDesc],
    string: &mut impl FnMut(&mut Reader<'a>) -> Result<u32, DecodeError>,
) -> Result<Values, DecodeError> {
    let n = r.count()?;
    let mut values = Encodings::default();
    for _ in 0..n {
        r.transcode(values.buffer(), 0, types.len(), string)?;
        values.end();
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Network, parse_network};
    use crate::value::{Value, decode as decode_value};

    fn sample() -> Tree<Value> {
        let mut t = Tree::new();
        let route = TypeDesc { kind: TypeKind::Dataclass, name: "mod.Route".into() };
        let id = t.register_type(&route);
        assert_eq!(t.register_type(&route), id);
        let object = Value::Object(id, vec![("asn".into(), Value::Int(15169))].into());
        for (net, value) in [
            ("1.0.0.0/24", object),
            ("1.0.0.0/8", Value::Null),
            ("0.0.0.0/0", Value::Int(i64::MIN)),
            ("255.255.255.255/32", Value::Seq(vec![Value::Float(1.5)].into())),
            ("2001:db8::/32", Value::Str("v6".into())),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", Value::Str("v6".into())),
            ("9.9.9.9/32", Value::Int(1)),
        ] {
            t.insert_value(parse_network(net).unwrap(), value);
        }
        t.remove(parse_network("9.9.9.9/32").unwrap());
        let _ = t.compile();
        t
    }

    fn load(data: &[u8]) -> Result<Tree<Value>, DecodeError> {
        decode::<()>(data)?.with_payloads(|_, encoded, refs| decode_value(encoded, refs))
    }

    #[test]
    fn roundtrip() {
        let t = sample();
        let data = encode(&t);
        let t2 = load(&data).unwrap();
        assert_eq!(t2.types(), t.types());
        let a: Vec<(Network, &Value)> = t.entries().map(|(n, v)| (n, v.payload())).collect();
        let b: Vec<(Network, &Value)> = t2.entries().map(|(n, v)| (n, v.payload())).collect();
        assert_eq!(a, b);
        // the unreferenced Int(1) was not written, re-encoding is deterministic
        assert_eq!(t2.value_count(), 5);
        assert_eq!(encode(&t2), data);
        // strings are stored once, numbered in order of first use
        assert_eq!(t2.strings().iter().collect::<Vec<_>>(), ["asn", "v6"]);
        assert!(load(&encode(&Tree::<()>::new())).unwrap().is_empty());
    }

    /// Streaming in small and large pieces gives the same bytes as one buffer: values larger
    /// than the buffer, and tables spanning many buffer flushes.
    #[test]
    fn streaming_write() {
        let mut t = sample();
        t.insert_value(parse_network("1.0.0.0/8").unwrap(), Value::Bytes(vec![7; 3 * BUFFER].into()));
        t.insert_value(parse_network("2.0.0.0/8").unwrap(), Value::Str("x".repeat(BUFFER / 4).into()));
        for i in 0..40_000u32 {
            let net = Network::V4(0x6400_0000 + (i << 8), 24);
            t.insert_value(net, Value::Int(i64::from(i % 1000)));
        }
        let _ = t.compile();
        let data = encode(&t);
        assert!(data.len() > 4 * BUFFER);
        assert_eq!(load(&data).unwrap().len(), t.len());

        /// Accepts at most 1000 bytes per call.
        struct Trickle(Vec<u8>);
        impl Write for Trickle {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let n = buf.len().min(1000);
                self.0.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(write(&t, Trickle(Vec::new())).unwrap().0, data);

        /// Fails after some bytes.
        struct Full(usize);
        impl Write for Full {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0 = self.0.checked_sub(buf.len()).ok_or_else(|| io::Error::other("disk full"))?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(write(&t, Full(data.len() / 2)).is_err());
        assert!(write(&t, Full(data.len())).is_ok());
    }

    #[test]
    fn rejects_corruption() {
        let data = encode(&sample());
        assert!(decode::<()>(&data[..data.len() - 1]).is_err());
        assert!(decode::<()>(b"").is_err());
        assert!(decode::<()>(b"PYSTREE\0garbage!garbage").is_err());
        for i in 0..data.len() {
            let mut d = data.clone();
            d[i] ^= 0x10;
            assert!(decode::<()>(&d).is_err(), "flipped byte {i} not detected");
        }
    }

    /// A file with a valid checksum.
    fn file(version: u16, body: &[u8]) -> Vec<u8> {
        let mut data = MAGIC.to_vec();
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(body);
        let checksum = xxh3_64(&data);
        data.extend_from_slice(&checksum.to_le_bytes());
        data
    }

    /// Version 1 files (strings inline in the values) are converted when loaded.
    #[test]
    fn reads_version_1() {
        const STR: u8 = 6;
        const MAP: u8 = 9;
        // types | values: "a", {"a": "b"} | ipv4: 0.0.0.0/8 -> 0, 1.0.0.0/8 -> 1 | ipv6
        let body = [0, 2, STR, 1, b'a', MAP, 1, 1, b'a', STR, 1, b'b', 2, 0, 8, 0, 0x80, 0x80, 0x80, 0x08, 8, 1, 0];
        let v1 = load(&file(1, &body)).unwrap();
        let mut t = Tree::new();
        let map = Value::Map(vec![("a".into(), Value::Str("b".into()))].into());
        t.insert_value(parse_network("0.0.0.0/8").unwrap(), Value::Str("a".into()));
        t.insert_value(parse_network("1.0.0.0/8").unwrap(), map.clone());
        let _ = t.compile();
        let values: Vec<_> = v1.entries().map(|(n, v)| (n.to_string(), v.payload().clone())).collect();
        assert_eq!(values, [("0.0.0.0/8".into(), Value::Str("a".into())), ("1.0.0.0/8".into(), map)]);
        assert_eq!(v1.strings().iter().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(encode(&v1), encode(&t), "written as the current version");
        assert_eq!(&encode(&v1)[8..10], &VERSION.to_le_bytes());
    }

    /// Structurally invalid files with a valid checksum, so the validation itself is exercised.
    #[test]
    fn rejects_invalid_structure() {
        const NULL: u8 = 0;
        const STR: u8 = 6;
        const MAP: u8 = 9;
        const OBJECT: u8 = 10;
        let cases: &[(&str, &[u8])] = &[
            // types | strings | values | ipv4 | ipv6
            ("huge count", &[0, 0xff, 0xff, 0xff, 0x0f]),
            ("unknown type kind", &[1, 9, 1, b'a', 0, 0, 0, 0]),
            ("duplicate type", &[2, 1, 1, b'a', 1, 1, b'a', 0, 0, 0, 0]),
            ("type id out of range", &[0, 0, 1, OBJECT, 0, 0, 0, 0]),
            ("duplicate value", &[0, 0, 2, NULL, NULL, 0, 0]),
            ("bad value", &[0, 0, 1, 42, 0, 0]),
            ("value id out of range", &[0, 0, 1, NULL, 1, 0, 8, 1, 0]),
            ("unsorted", &[0, 0, 1, NULL, 2, 0, 16, 0, 0, 8, 0, 0]),
            ("duplicate prefix", &[0, 0, 1, NULL, 2, 0, 8, 0, 0, 8, 0, 0]),
            ("host bits", &[0, 0, 1, NULL, 1, 1, 8, 0, 0]),
            ("prefix length", &[0, 0, 1, NULL, 1, 0, 33, 0, 0]),
            ("v4 address range", &[0, 0, 1, NULL, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 32, 0, 0]),
            ("trailing", &[0, 0, 0, 0, 0, 0]),
            ("truncated", &[0, 0, 1, NULL, 1]),
            ("duplicate string", &[0, 2, 1, b'a', 1, b'a', 2, STR, 0, STR, 1, 0, 0]),
            ("unused string", &[0, 2, 1, b'a', 1, b'b', 1, STR, 0, 0, 0]),
            ("strings not in order of use", &[0, 2, 1, b'a', 1, b'b', 2, STR, 1, STR, 0, 0, 0]),
            ("string id out of range", &[0, 1, 1, b'a', 1, STR, 1, 0, 0]),
            ("key id out of range", &[0, 1, 1, b'a', 1, MAP, 1, 1, NULL, 0, 0]),
            ("invalid UTF-8 string", &[0, 1, 1, 0xff, 1, STR, 0, 0, 0]),
        ];
        let valid: &[u8] = &[0, 2, 1, b'a', 1, b'b', 2, STR, 0, MAP, 1, 1, STR, 0, 0, 0];
        assert!(decode::<()>(&file(VERSION, valid)).is_ok());
        for (name, body) in cases {
            assert!(decode::<()>(&file(VERSION, body)).is_err(), "{name} not rejected");
        }
        // version 1: inline strings
        let cases: &[(&str, &[u8])] = &[
            ("invalid UTF-8", &[0, 1, STR, 1, 0xff, 0, 0]),
            ("duplicate value", &[0, 2, STR, 1, b'a', STR, 1, b'a', 0, 0]),
            ("truncated string", &[0, 1, STR, 2, b'a']),
        ];
        assert!(decode::<()>(&file(1, &[0, 2, STR, 1, b'a', STR, 1, b'b', 0, 0])).is_ok());
        for (name, body) in cases {
            assert!(decode::<()>(&file(1, body)).is_err(), "version 1: {name} not rejected");
        }
        for version in [0, VERSION + 1] {
            assert!(decode::<()>(&file(version, &[0, 0, 0, 0, 0])).is_err(), "version {version}");
        }
    }
}
