# File format

Version 1. All fixed-size integers are little endian. `varint` is unsigned LEB128.

```text
header   magic "PYSTREE\0" (8 bytes) | version u16 | flags u16 (reserved, 0)
types    varint count | (u8 kind | varint length | UTF-8 "module.QualName")*
values   varint count | value*
ipv4     varint count | entry*        entry = varint address delta | u8 prefix length | varint value id
ipv6     varint count | entry*
trailer  u64 XXH3-64 hash of everything before
```

Entries are sorted by `(address, prefix length)` without duplicates. The address is stored as the
difference to the previous entry's address, so a full IPv4 routing table takes about 5 bytes per
network. Host bits must be zero.

## Values

A value is a tag byte followed by its payload.

| Tag | Type | Payload |
|---:|---|---|
| 0 | `None` | none |
| 1 | `False` | none |
| 2 | `True` | none |
| 3 | `int` | zigzag-encoded varint (`i64`) |
| 4 | `int` | varint (`u64` greater than `i64::MAX` only) |
| 5 | `float` | `f64` |
| 6 | `str` | varint byte length, UTF-8 |
| 7 | `bytes` | varint length, bytes |
| 8 | sequence (`list`/`tuple`) | varint count, values |
| 9 | mapping (`dict`) | varint count, then (varint length, UTF-8 key, value) pairs |
| 10 | object | varint type id, then fields as for tag 9 |

Type kinds: `1` is a dataclass, rebuilt with `cls(**fields)`; `2` is a pydantic model, stored as
`model_dump(mode='json')` and rebuilt with `cls.model_validate(fields)`. The file contains only
type names. Loading resolves them against the classes passed to `load()` and never imports
anything.

Each value is stored in its canonical encoding, so equal values have identical bytes. A file with
duplicate values is rejected.

Nesting is limited to 64 levels.

## Validation

The decoder rejects any file that has:

- a wrong magic, version, flags, or checksum;
- truncated data or trailing bytes;
- lengths or counts larger than the remaining data (this bounds memory allocation);
- unsorted or duplicate entries, host bits set, prefix lengths out of range, or addresses out of
  range;
- value ids out of range, unknown tags, invalid UTF-8, or non-canonical integers;
- unknown type kinds, duplicate types or values, or type ids out of range;
- nesting deeper than 64 levels.

Invalid input always produces an error. It never causes a crash or an inconsistent tree.
