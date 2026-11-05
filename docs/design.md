# Design

## Goals

- Fast longest-prefix-match lookups for large tables, such as full BGP feeds.
- Low memory use: no per-network heap allocations and no pointers.
- Safe code only (`#![forbid(unsafe_code)]` in this crate).
- A compact, validated on-disk format.

## Data layout

Each address family (IPv4 as `u32`, IPv6 as `u128`) has a `PrefixTable`:

- **Entries**: networks sorted by `(address, prefix length)` in struct-of-arrays form: `addrs`,
  `lens`, `vals` (value ids), and `parents` (the enclosing network).
- **Intervals**: the nested networks flattened into disjoint address ranges. `starts[i]` is the
  first address of range `i`, and `ids[i]` is the entry that matches it, if any. Adjacent ranges
  with the same entry are merged.
- **Index**: for tables with at least 256 ranges, `index[b]` holds the first range whose top 16
  address bits are `>= b`. This narrows the binary search to a handful of ranges.

A lookup reads one index slot, binary-searches a short slice of `starts`, then reads `ids` and
`vals`. That is roughly five memory accesses, independent of the table size.

Approximate memory per network:

| | IPv4 | IPv6 |
|---|---:|---:|
| entries | 13 B | 25 B |
| intervals (~1–2 per network) | 8–16 B | 20–40 B |

The index adds a fixed 256 KiB per family.

## Mutations

Inserts and removals go into a hash map of pending changes. Length tracking and exact queries
(`has_network`, `get_exact`, `remove`) work without rebuilding. The next lookup merges the
pending changes into the sorted entries and rebuilds the intervals in a single linear pass, using
a stack of open networks.

## Values

Each distinct value is stored once, as two things:

- its **canonical encoding**, a compact type-exact byte string. This is the deduplication key,
  and it is written to disk as-is.
- one **read-only Python object**, built from the encoding. Lookups return it directly. Building
  it from the encoding means a lookup returns the same thing whether the tree was filled by
  inserts or loaded from disk.

Networks reference values by `u32` id. The Rust core is generic over the payload: `Tree<P>`
holds the Python object in the bindings and `()` after decoding a file. Dataclasses and pydantic
models are encoded as objects that reference a type table. The file stores only the kind and the
qualified name of each type, and `load()` resolves names against the classes passed in.

The deduplication index is built lazily: a tree loaded from disk does not keep it until the next
insert. Values that are no longer referenced are dropped when at least a quarter of all values
are unused.

## Concurrency

On free-threaded Python, lookups scale from 4.8 M/s on one thread to 10.8 M/s on four (shared
`RwLock` reader counter; a lock-free snapshot is a planned improvement).


The Python class is `frozen` and wraps the tree in a `RwLock`. Lookups take a read lock, and if
changes are pending, upgrade to a write lock to rebuild first. The lock is never held while
calling into Python, and never drops a Python object, since a `__del__` could re-enter the tree.
Values are converted before the lock is taken. Payloads that compaction or deduplication
discard are returned and dropped after the lock is released. The locks detach from the interpreter while blocking, so they cannot deadlock with the
GIL.
