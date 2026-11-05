# pysubnettree-rs

Fast, memory-efficient longest-prefix-match lookups of IPv4 and IPv6 subnets for Python,
written in safe Rust (`#![forbid(unsafe_code)]`) using [PyO3](https://pyo3.rs).

Load a large collection of networks (for example a full BGP routing table), attach a value to
each one, and find the most specific network for any IP address. The loaded structure can be saved
to a compact, checksummed file (XXH3-64) and loaded again quickly.

Build a tree with `SubnetTreeBuilder`, then query the immutable `SubnetTreeRS`:

```python
from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS

builder = SubnetTreeBuilder()
builder['10.0.0.0/8'] = {'name': 'private', 'asn': 64512}
builder['10.1.0.0/16'] = {'name': 'office'}
builder.insert('2001:db8::/32', 'documentation')
builder.insert('192.0.2.0/24')  # no value: lookups return None
tree = builder.build()          # immutable, lock-free copy
del builder                     # frees the builder's memory

tree['10.1.2.3']          # mappingproxy({'name': 'office'}), values are read-only
tree['192.0.2.1']         # None (found, no value)
tree.get('172.16.0.1')    # None (not found), tree['172.16.0.1'] raises KeyError
'2001:db8::1' in tree     # True
tree.lookup('10.1.2.3')   # ('10.1.0.0/16', mappingproxy({'name': 'office'}))

tree.dump('networks.pst')
tree = SubnetTreeRS.load('networks.pst')
```

The tree can't be modified, so it needs no locking and can be shared between threads freely.
To change it, use `tree.to_builder()` or `SubnetTreeBuilder.load(path)` to get a modifiable copy.

### Typed values

A tree can be restricted to one value type, such as a frozen dataclass or a frozen pydantic
model. Inserts are then checked at runtime, and type checkers see that type in every method:

```python
from dataclasses import dataclass

from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS


@dataclass(frozen=True, slots=True)
class Route:
    asn: int
    country: str | None = None
    tags: tuple[str, ...] = ()


builder = SubnetTreeBuilder(value_type=Route)   # SubnetTreeBuilder[Route]
builder['10.0.0.0/8'] = Route(asn=64512, country='LU')
builder.insert('10.1.0.0/16')                   # no value
builder['192.0.2.0/24'] = {'asn': 1}            # mypy error, TypeError at runtime
tree = builder.build()                          # SubnetTreeRS[Route]

route = tree['10.200.0.1']                      # Route | None
tree['10.0.0.0/8'] = Route(asn=1)               # mypy error, TypeError: the tree is immutable

tree.dump('routes.pst')
tree = SubnetTreeRS.load('routes.pst', value_type=Route)
```

## Features

- Longest prefix match for IPv4 and IPv6 in one structure. IPv4-mapped IPv6 addresses
  (`::ffff:a.b.c.d`) are treated as IPv4.
- Keys can be `str` (`'10.0.0.0/8'`, `'10.1.2.3'`), packed `bytes` (4 or 16 bytes), or
  `ipaddress` address and network objects.
- Values can be `None`, `bool`, `int` (64 bit), `float`, `str`, `bytes`, `list`/`tuple`, `dict`
  with `str` keys, frozen dataclasses, and frozen pydantic models, nested in any combination.
  Every supported value can be saved to disk without `pickle`.
- Values are read-only. Lookups return immutable objects: `list` and `tuple` come back as
  `tuple`, and `dict` as `types.MappingProxyType`. Equal values are stored once and returned as
  the same object, with no copying or conversion per lookup.
- Optional value type, `SubnetTreeBuilder(value_type=Route)`, with generic typing
  (`SubnetTreeBuilder[Route]` builds a `SubnetTreeRS[Route]`).
- An immutable tree class for queries: no locks, safe to share between threads. On
  free-threaded Python, lookups scale with the number of threads.
- A compact binary on-disk format with an XXH3-64 checksum. Untrusted files are fully validated,
  and classes are never imported by name from a file.
- Works with `pickle` and with free-threaded Python (3.14t).
- Releases the GIL while building the lookup structure and during file I/O.

## API

`SubnetTreeRS` (immutable, for queries) and `SubnetTreeBuilder` (modifiable) share the read
methods. Lookups on the builder are a convenience: they take a lock and compile pending changes
first.

| Method | `SubnetTreeRS` | `SubnetTreeBuilder` | Description |
|---|:-:|:-:|---|
| `SubnetTreeBuilder(value_type=None)` | | ✓ | Create an empty builder, optionally restricted to one value type. |
| `build()` | | ✓ | An immutable `SubnetTreeRS` with a copy of the contents. |
| `to_builder()` | ✓ | | A modifiable copy. |
| `insert(network, value=None)` / `b[network] = value` | | ✓ | Add or replace a network. Host bits are ignored. |
| `insert_many(mapping_or_pairs)` | | ✓ | Bulk insert, faster than repeated `insert`. |
| `remove(network)` / `del b[network]`, `clear()` | | ✓ | Remove networks. |
| `t[key]` | ✓ | ✓ | Value of the longest match, `KeyError` if there is none. |
| `get(key, default=None)` | ✓ | ✓ | Value of the longest match, or `default`. |
| `lookup(key)` | ✓ | ✓ | `(network, value)` of the longest match, or `None`. |
| `lookup_all(key)` | ✓ | ✓ | All matching `(network, value)` pairs, most specific first. |
| `key in t` | ✓ | ✓ | True if any network matches. |
| `has_network(network)` / `get_exact(network, default=None)` | ✓ | ✓ | Exact network match. |
| `len(t)`, `iter(t)`, `items()` | ✓ | ✓ | Container protocol. |
| `stats()`, `memory_usage()` | ✓ | ✓ | Sizes and approximate memory use. |
| `to_bytes()` / `dump(path)` | ✓ | | Serialize to `bytes` or a file (written atomically). |
| `from_bytes(data, value_type=None, types=())` / `load(path, ...)` | ✓ | ✓ | Deserialize, as an immutable tree or as a builder to modify it. |

A lookup key can be an address or a network. For a network such as `'10.1.2.0/24'`, the result is
the most specific stored network that contains the whole key network.

When loading data that contains dataclasses or pydantic models, pass their classes: the value
type as `value_type`, and any other classes, such as nested ones, in `types`.

## Performance

Full 2016 routeviews table, IPv4 and IPv6, with AS numbers as values. The table is generated by
`benchmarks/bench.py --update README.md` (see [Development](#development)), so anyone can
reproduce it.

<!-- bench:start -->
AMD Ryzen 9 3900X 12-Core Processor, Python 3.14.5, pysubnettree-rs 0.1.0, pysubnettree 0.38.1; 1,000,000 lookups per set, median of 3 passes in each of 3 processes.

| | pysubnettree-rs | [pysubnettree](https://github.com/zeek/pysubnettree) |
|---|---:|---:|
| Load 644,586 networks | 0.31 s | 0.35 s |
| Lookup, addresses inside table networks | 195 ns | 1226 ns |
| Lookup, random addresses | 132 ns | 800 ns |
| of which Python loop and call overhead | 29 ns | 29 ns |
| Memory (RSS increase) | 18 MB | 98 MB |
| Save to file (size) | 0.012 s (4.1 MB) | n/a |
| Load from file | 0.042 s | n/a |
<!-- bench:end -->

### Compared to other algorithms

The table above measures the whole Python API against pysubnettree. For an in-depth comparison
of the data structure itself, in Rust and without Python overhead, see
**[Lookup algorithms](docs/algorithms.md)**. It covers Tree Bitmap (as in NLnet Labs'
rotonda-store), Poptrie (including the `poptrie` crate), DIR-24-8, a binary trie, hash tables
per prefix length and several index variants. It reports memory, build time, and lookup
throughput and latency for IPv4 and IPv6 on three CPU targets. Those tables are generated too
(`research/lpm-bench`), so they can be reproduced on any machine.

## How it works

The networks of each address family are kept in sorted arrays without pointers, and flattened
into disjoint address ranges that carry the value directly. A lookup is a binary search over a
few ranges, selected by a direct index on 16 address bits. For IPv6, the index uses the bits
after the prefix all networks share (`2000::/4`) and has a second level. This was chosen by
benchmarking it against Tree Bitmap, Poptrie, DIR-24-8 and others; see
[docs/algorithms.md](docs/algorithms.md).

The structure is designed for "load in bulk, then query". A builder buffers modifications and
merges them when it is built or queried. Interleaving single inserts with lookups on a builder
rebuilds the structure on every lookup, which costs `O(n)`. Insert everything, call `build()`,
then query the tree.

## Development

Requires Rust (stable, edition 2024) and [uv](https://docs.astral.sh/uv/).

```shell
uv sync                     # build the extension in debug mode and install dev tools
uv run pytest               # Python tests
cargo test --no-default-features   # Rust core tests (no libpython needed)
uv run prek run --all-files # linters (ruff, mypy, rustfmt, clippy, ...)
uv run --group docs zensical serve                # documentation

# benchmark against pysubnettree and regenerate the table in this README; build in release
# mode and don't let uv rebuild in debug mode
uv run --group bench maturin develop --release --uv
uv run --no-sync python benchmarks/bench.py --update README.md

# data structure benchmarks without Python, regenerates docs/algorithms.md (see there)
(cd research/lpm-bench && cargo run --release -- --update ../../docs/algorithms.md)

# combined Rust + Python coverage (needs cargo-llvm-cov) -> coverage.lcov
./scripts/coverage.sh
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
