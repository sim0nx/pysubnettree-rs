# File format

Version 2. All fixed-size integers are little endian. `varint` is unsigned LEB128.

```text
header   magic "PYSTREE\0" (8 bytes) | version u16 | flags u16 (reserved, 0)
types    varint count | (u8 kind | varint length | UTF-8 "module.QualName")*
strings  varint count | (varint length | UTF-8)*
values   varint count | value*
ipv4     varint count | entry*        entry = varint address delta | u8 prefix length | varint value id
ipv6     varint count | entry*
trailer  u64 XXH3-64 hash of everything before
```

Entries are sorted by `(address, prefix length)` without duplicates. The address is stored as the
difference to the previous entry's address, so a full IPv4 routing table takes about 5 bytes per
network. Host bits must be zero.

## Strings

Each distinct string of the values, `str` values as well as the keys of mappings and objects, is
stored once in the strings section. Values refer to strings by id, their index in that section.
In a table like an IP-to-AS mapping, where many networks repeat the same AS and organisation
names and every value repeats the field names of its type, this makes the file a fraction of the
size (for example 78 MiB instead of 205 MiB for 1.44 million distinct values).

Strings are numbered in order of first use: reading the values in order, every string id is
either one seen before or the next one. Every string is used, and no string appears twice.

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
| 6 | `str` | varint string id |
| 7 | `bytes` | varint length, bytes |
| 8 | sequence (`list`/`tuple`) | varint count, values |
| 9 | mapping (`dict`) | varint count, then (varint key string id, value) pairs |
| 10 | object | varint type id, then fields as for tag 9 |

Type kinds: `1` is a dataclass, rebuilt with `cls(**fields)`; `2` is a pydantic model, stored as
`model_dump(mode='json')` and rebuilt with `cls.model_validate(fields)`. The file contains only
type names. Loading resolves them against the classes passed to `load()` and never imports
anything.

Each value is stored in its canonical encoding, so equal values have identical bytes. A file with
duplicate values is rejected. Values are numbered in order of first use by the entries, so equal
trees produce identical files.

Nesting is limited to 64 levels.

## Validation

The decoder rejects any file that has:

- a wrong magic, version, flags, or checksum;
- truncated data or trailing bytes;
- lengths or counts larger than the remaining data (this bounds memory allocation);
- unsorted or duplicate entries, host bits set, prefix lengths out of range, or addresses out of
  range;
- string ids out of range or not in order of first use, unused or duplicate strings;
- value ids out of range, unknown tags, invalid UTF-8, or non-canonical integers;
- unknown type kinds, duplicate types or values, or type ids out of range;
- nesting deeper than 64 levels.

Invalid input always produces an error. It never causes a crash or an inconsistent tree.

## Version 1

Written by pysubnettree-rs 0.2.0 and earlier, and still read. It has no strings section: values
contain their strings inline, tag 6 and mapping keys as varint byte length and UTF-8. Loading
converts them to string ids. Saving always writes the current version.
