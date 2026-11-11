# Design

## Goals

- Fast longest-prefix-match lookups for large tables, such as full BGP feeds.
- Low memory use: no per-network heap allocations and no pointers.
- Safe code only (`#![forbid(unsafe_code)]` in this crate).
- A compact, validated on-disk format.

## Data layout

Each address family (IPv4 as `u32`, IPv6 as `u128`) has a `PrefixTable`. The structure and
its parameters were chosen by benchmark; see [Lookup algorithms](algorithms.md).

- **Entries**: networks sorted by `(address, prefix length)` in struct-of-arrays form: `addrs`,
  `lens`, `vals` (value ids), and `parents` (the enclosing network).
- **Intervals**: the nested networks flattened into disjoint address ranges. `starts[i]` is the
  first address of range `i`, and `ivals[i]` is the **value id** of the longest network
  covering it, if any. Adjacent ranges with the same value merge. In a routing table, neighbouring
  networks often have the same origin AS, so this removes more than half of the ranges.
- **Index**, for tables with at least 256 ranges: a bucket number from 16 address bits
  narrows the binary search to a few ranges.
  - IPv4 uses the top 16 bits.
  - IPv6 prefixes all start with the same bits (`2000::/4`) and cluster in a few `/16`s. The
    IPv6 index therefore uses the 16 bits *after* the leading bits that all prefixes share, and
    crowded buckets get a second 8-bit level. Addresses outside that region fall into two extra
    buckets, so no unpredictable branch is needed.

A value lookup (`get`, `[]`, `in`) reads the index, binary-searches a short slice of `starts`,
and reads the value id. It does not touch the entries.

Lookups that return the matched network (`lookup`, `lookup_all`, network keys) use the entries.
The longest network containing an address is the first one on the parent chain, starting from
the last entry that begins at or before the address, that contains the address.

Memory on the 2016 routeviews table:

| | IPv4 (615,842 networks) | IPv6 (28,744 networks) |
|---|---:|---:|
| entries and parents | 13 B per network | 25 B per network |
| intervals | ~0.45 per network, 8 B each | ~1.1 per network, 20 B each |
| index | 256 KiB | < 1 MiB (two levels) |

## Mutations

Only a `SubnetTreeBuilder` can be modified. Inserts and removals go into a hash map of pending
changes. Length tracking and exact queries (`has_network`, `get_exact`, `remove`) work without
rebuilding. The next lookup or `build()` merges the pending changes into the sorted entries and
rebuilds the intervals in a single linear pass, using a stack of open networks.

`build()` copies the compiled data into a `SubnetTreeRS`. Copying the value objects only
increments their reference counts, and the encodings are shared. Each object owns its data
exclusively, which keeps memory management and garbage collection simple. `dump()` on the builder
writes the file without the copy.

`dump()` streams the file: the encoded values are written as they are stored, and the checksum
is computed along the way, so the file is never held in memory.

## Values

Each distinct value is stored once, as two things:

- its **canonical encoding**, a compact type-exact byte string. This is the deduplication key,
  and it is written to disk with only its string ids renumbered.
- one **read-only Python object**, built from the encoding. Lookups return it directly. Building
  it from the encoding means a lookup returns the same thing whether the tree was filled by
  inserts or loaded from disk. It lives in a once-cell (`std::sync::OnceLock`) next to the
  encoding, filled when a lookup first returns the value. Concurrent first lookups may both
  build an object; the first one stored wins and is returned to everyone, the other one is
  dropped. Building happens outside any lock and is not cached when it fails. A builder looks
  up under its lock, builds the missing objects after releasing it, and stores them under the
  lock again, unless the value was dropped meanwhile.

  Building objects lazily keeps a builder small: for a value per network, such as an IP-to-AS
  table, the objects would take more memory than everything else. Exact instances of `str`,
  `int`, `float`, `bool`, `bytes` and `None` are their own object and are stored on insert. A
  value with dataclasses or models is built once on insert and dropped, so that errors raised
  while building it are raised by the insert.

Strings are stored once per tree: every distinct `str` value and every key of a mapping or
object is kept in a string table (all strings concatenated, plus their end offsets), and
encodings refer to it by `u32` id. Values of a type repeat its field names, and values of
neighbouring networks often repeat the same names: storing them once makes the encodings a
fraction of their size. A builder and the trees built from it share the table until the builder
adds a string (copy on write). The ids are part of the canonical encoding: since every distinct
string has one id, equal values still have equal encodings. When values are dropped, strings no
longer used are dropped too (when at least a quarter is unused), and the remaining values are
encoded again with the new ids. A file stores only the strings its values use, numbered in order
of first use, so equal trees produce equal files.

The encodings of all values are stored in one buffer, back to back, with the end offset of each:
no allocation per value, which would cost more than a typical encoding (an ASN, a few string
ids). Like the string table, the buffer is shared by a builder and the trees built from it until
the builder adds a value. Removing values rewrites the buffer (when at least a quarter is unused,
see below), which renumbers the values; a builder that released its lock to build an object
checks the store's *epoch*, which changes whenever ids change, before storing the object.

Networks reference values by `u32` id. The Rust core is generic over the payload: `Tree<P>`
holds the Python object in the bindings and `()` after decoding a file. Dataclasses and pydantic
models are encoded as objects that reference a type table. The file stores only the kind and the
qualified name of each type, and `load()` resolves names against the classes passed in.

Loading validates every value without building it (a walk over the encoding that copies it in
canonical form), rejects duplicate values and strings by sorting seeded xxh3 hashes, and checks `value_type` on the encodings: the
class that each kind of encoded value turns into (one per tag, or the object's type) is checked
once with `issubclass`.

The deduplication indexes of values and strings are built lazily: a tree loaded from disk does
not keep them until the next insert. They are hash tables of `u32` ids (`hashbrown::HashTable`),
hashed by content with a seeded xxh3, about 5 bytes per entry. Values that are no longer
referenced are dropped when at least a quarter of all values are unused.

## Concurrency

`SubnetTreeRS` has no interior mutability and no lock: it is compiled when created and never
changes. pyo3 only accepts a frozen class whose contents are `Sync`, so sharing it between
threads is safe by construction. On free-threaded Python, its lookups scale with the threads
(see [Usage](usage.md#threads) for numbers).

`SubnetTreeBuilder` wraps its data in a `RwLock`. Lookups take a read lock, and if changes are
pending, upgrade to a write lock to compile first. The lock is never held while calling into
Python, and never drops a Python object, because a `__del__` could re-enter the builder and
deadlock. Keys and values are converted before the lock is taken, and results are converted
after it is released. Payloads discarded by compaction or deduplication are dropped after the
lock is released. The locks detach from the interpreter while blocking, so they cannot deadlock
with the GIL.

Both classes report their Python references to the cycle garbage collector (`__traverse__`).
The builder can also break cycles (`__clear__`). The tree is immutable and doesn't need to: every
cycle through it passes a class object, which the collector clears.
