//! Compact on-disk format.
//!
//! All fixed size integers are little endian, `varint` is unsigned LEB128.
//!
//! ```text
//! header   magic "PYSTREE\0" (8 bytes) | version u16 | flags u16 (reserved, 0)
//! types    varint count | (u8 kind | varint length | UTF-8 "module.QualName")*
//! values   varint count | value*        (canonical value encoding, see `value`)
//! ipv4     varint count | entry*        entry = varint addr delta | u8 len | varint value id
//! ipv6     varint count | entry*
//! trailer  u64 XXH3-64 hash of everything before
//! ```
//!
//! Entries are sorted by `(address, prefix length)`; the address is stored as the difference to
//! the previous entry's address, which keeps typical routing tables at ~5 bytes per prefix.
//!
//! Decoding validates everything (checksum, ordering, value ids, type ids, nesting depth,
//! UTF-8), so a corrupted or malicious file results in an error, never in a panic or an
//! inconsistent tree.

use std::sync::Arc;

use xxhash_rust::xxh3::{xxh3_64, xxh3_64_with_seed};

use crate::table::{Addr, PrefixTable};
use crate::tree::Tree;
use crate::value::{DecodeError, Reader, TypeDesc, TypeKind, ValueStore, err, put_len, put_str, put_varint};

pub const MAGIC: &[u8; 8] = b"PYSTREE\0";
pub const VERSION: u16 = 1;

const HEADER_LEN: usize = MAGIC.len() + 4;
const CHECKSUM_LEN: usize = 8;

fn encode_table<A: Addr>(out: &mut Vec<u8>, table: &PrefixTable<A>, remap: &[u32]) {
    put_len(out, table.len());
    let mut prev = 0u128;
    for (addr, len, val) in table.entries() {
        let addr = addr.to_u128();
        put_varint(out, addr - prev);
        prev = addr;
        out.push(len);
        put_varint(out, u128::from(remap[val as usize]));
    }
}

/// Serializes a compiled tree. Only values referenced by a network are written.
///
/// # Panics
/// If the tree is not compiled.
#[must_use]
pub fn encode<P>(tree: &Tree<P>) -> Vec<u8> {
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

    let mut out = Vec::with_capacity(HEADER_LEN + tree.len() * 6 + order.len() * 8);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    put_len(&mut out, tree.types().len());
    for t in tree.types() {
        out.push(t.kind as u8);
        put_str(&mut out, &t.name);
    }
    put_len(&mut out, order.len());
    for &id in &order {
        out.extend_from_slice(tree.encoded(id));
    }
    encode_table(&mut out, &tree.v4, &remap);
    encode_table(&mut out, &tree.v6, &remap);
    let checksum = xxh3_64(&out);
    out.extend_from_slice(&checksum.to_le_bytes());
    out
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

/// True if two of the byte ranges `body[start..end]` are equal. Sorts seeded xxh3 hashes and
/// compares bytes only where hashes are equal; the random seed keeps crafted collisions (and so
/// quadratic behaviour) out of reach. Several times faster than a `HashSet` of slices.
fn has_duplicates(body: &[u8], ranges: &[(usize, usize)]) -> bool {
    let seed = std::hash::BuildHasher::hash_one(&std::collections::hash_map::RandomState::new(), 0u8);
    let bytes = |i: usize| &body[ranges[i].0..ranges[i].1];
    let mut hashes: Vec<(u64, usize)> = (0..ranges.len()).map(|i| (xxh3_64_with_seed(bytes(i), seed), i)).collect();
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
    if version != VERSION {
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
        let desc = TypeDesc { kind, name: r.str()? };
        if types.contains(&desc) {
            return err("duplicate type");
        }
        types.push(desc);
    }

    // validate without building the values, keep their positions
    let n = r.count()?;
    let mut ranges = Vec::with_capacity(n);
    for _ in 0..n {
        let start = r.pos;
        r.skip_value(0, types.len())?;
        ranges.push((start, r.pos));
    }
    if has_duplicates(body, &ranges) {
        return err("duplicate value");
    }
    let values: Vec<_> = ranges.into_iter().map(|(a, b)| (Arc::from(&body[a..b]), P::default())).collect();
    let v4 = decode_table::<u32>(&mut r, values.len())?;
    let v6 = decode_table::<u128>(&mut r, values.len())?;
    if r.remaining() != 0 {
        return err("trailing data");
    }
    let mut tree = Tree { v4, v6, values: ValueStore::from_entries(values), types };
    // a hand-crafted file may contain unreferenced values, harmless but a waste of memory
    drop(tree.compact_values(true));
    Ok(tree)
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
        let t = decode::<()>(data)?;
        let types = t.types().len();
        t.with_payloads(|_, encoded| decode_value(encoded, types))
    }

    #[test]
    fn roundtrip() {
        let t = sample();
        let data = encode(&t);
        let t2 = load(&data).unwrap();
        assert_eq!(t2.types(), t.types());
        let a: Vec<(Network, &Value)> = t.entries().map(|(n, v)| (n, &**v)).collect();
        let b: Vec<(Network, &Value)> = t2.entries().map(|(n, v)| (n, &**v)).collect();
        assert_eq!(a, b);
        // the unreferenced Int(1) was not written, re-encoding is deterministic
        assert_eq!(t2.value_count(), 5);
        assert_eq!(encode(&t2), data);
        assert!(load(&encode(&Tree::<()>::new())).unwrap().is_empty());
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

    /// Structurally invalid files with a valid checksum, so the validation itself is exercised.
    #[test]
    fn rejects_invalid_structure() {
        const NULL: u8 = 0;
        const OBJECT: u8 = 10;
        let cases: &[(&str, &[u8])] = &[
            // types | values | ipv4 | ipv6
            ("huge count", &[0, 0xff, 0xff, 0xff, 0x0f]),
            ("unknown type kind", &[1, 9, 1, b'a', 0, 0, 0]),
            ("duplicate type", &[2, 1, 1, b'a', 1, 1, b'a', 0, 0, 0]),
            ("type id out of range", &[0, 1, OBJECT, 0, 0, 0, 0]),
            ("duplicate value", &[0, 2, NULL, NULL, 0, 0]),
            ("bad value", &[0, 1, 42, 0, 0]),
            ("value id out of range", &[0, 1, NULL, 1, 0, 8, 1, 0]),
            ("unsorted", &[0, 1, NULL, 2, 0, 16, 0, 0, 8, 0, 0]),
            ("duplicate prefix", &[0, 1, NULL, 2, 0, 8, 0, 0, 8, 0, 0]),
            ("host bits", &[0, 1, NULL, 1, 1, 8, 0, 0]),
            ("prefix length", &[0, 1, NULL, 1, 0, 33, 0, 0]),
            ("v4 address range", &[0, 1, NULL, 1, 0x80, 0x80, 0x80, 0x80, 0x10, 32, 0, 0]),
            ("trailing", &[0, 0, 0, 0, 0]),
            ("truncated", &[0, 1, NULL, 1]),
        ];
        for (name, body) in cases {
            let mut data = MAGIC.to_vec();
            data.extend_from_slice(&VERSION.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(body);
            let checksum = xxh3_64(&data);
            data.extend_from_slice(&checksum.to_le_bytes());
            assert!(decode::<()>(&data).is_err(), "{name} not rejected");
        }
    }
}
