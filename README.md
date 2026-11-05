# pysubnettree-rs

Fast, memory-efficient longest-prefix-match lookups of IPv4 and IPv6 subnets for Python,
written in safe Rust (`#![forbid(unsafe_code)]`) using [PyO3](https://pyo3.rs).

Load a large collection of networks (for example a full BGP routing table), attach a value to
each one, and find the most specific network for any IP address. The loaded structure can be saved
to a compact, checksummed file (XXH3-64) and loaded again quickly.

```python
from pysubnettree_rs import SubnetTreeRS

tree = SubnetTreeRS()
tree['10.0.0.0/8'] = {'name': 'private', 'asn': 64512}
tree['10.1.0.0/16'] = {'name': 'office'}
tree.insert('2001:db8::/32', 'documentation')
tree.insert('192.0.2.0/24')  # no value: lookups return None

tree['10.1.2.3']          # mappingproxy({'name': 'office'}), values are read-only
tree['192.0.2.1']         # None (found, no value)
tree.get('172.16.0.1')    # None (not found), tree['172.16.0.1'] raises KeyError
'2001:db8::1' in tree     # True
tree.lookup('10.1.2.3')   # ('10.1.0.0/16', mappingproxy({'name': 'office'}))

tree.dump('networks.pst')
tree = SubnetTreeRS.load('networks.pst')
```

### Typed values

A tree can be restricted to one value type, such as a frozen dataclass or a frozen pydantic
model. Inserts are then checked at runtime, and type checkers see that type in every method:

```python
from dataclasses import dataclass

from pysubnettree_rs import SubnetTreeRS


@dataclass(frozen=True, slots=True)
class Route:
    asn: int
    country: str | None = None
    tags: tuple[str, ...] = ()


tree = SubnetTreeRS(value_type=Route)       # SubnetTreeRS[Route]
tree['10.0.0.0/8'] = Route(asn=64512, country='LU')
tree.insert('10.1.0.0/16')                  # no value

route = tree['10.200.0.1']                  # Route | None
tree['192.0.2.0/24'] = {'asn': 1}           # mypy error, TypeError at runtime

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
- Optional value type, `SubnetTreeRS(value_type=Route)`, with generic typing
  (`SubnetTreeRS[Route]`).
- A compact binary on-disk format with an XXH3-64 checksum. Untrusted files are fully validated,
  and classes are never imported by name from a file.
- Works with `pickle` and with free-threaded Python (3.14t); lookups run in parallel.
- Releases the GIL while building the lookup structure and during file I/O.

## API

| Method | Description |
|---|---|
| `SubnetTreeRS(value_type=None)` | Create an empty tree, optionally restricted to one value type. |
| `insert(network, value=None)` / `tree[network] = value` | Add or replace a network. Host bits are ignored. |
| `insert_many(mapping_or_pairs)` | Bulk insert, faster than repeated `insert`. |
| `tree[key]` | Value of the longest match, `KeyError` if there is none. |
| `get(key, default=None)` | Value of the longest match, or `default`. |
| `lookup(key)` | `(network, value)` of the longest match, or `None`. |
| `lookup_all(key)` | All matching `(network, value)` pairs, most specific first. |
| `key in tree` | True if any network matches. |
| `has_network(network)` / `get_exact(network, default=None)` | Exact network match. |
| `remove(network)` / `del tree[network]` | Remove a network. |
| `len(tree)`, `iter(tree)`, `items()`, `clear()` | Container protocol. |
| `compile()` | Build the lookup structure now instead of on the first lookup. |
| `to_bytes()` / `SubnetTreeRS.from_bytes(data, value_type=None, types=())` | Serialize to and from `bytes`. |
| `dump(path)` / `SubnetTreeRS.load(path, value_type=None, types=())` | Save to and load from a file (writes atomically). |
| `stats()`, `memory_usage()` | Sizes and approximate memory use. |

A lookup key can be an address or a network. For a network such as `'10.1.2.0/24'`, the result is
the most specific stored network that contains the whole key network.

When loading data that contains dataclasses or pydantic models, pass their classes: the value
type as `value_type`, and any other classes, such as nested ones, in `types`.

## Performance

Full 2016 routeviews table (644,586 IPv4 and IPv6 prefixes, AS numbers as values), Python 3.14,
release build, `benchmarks/bench.py`:

| | pysubnettree-rs | [pysubnettree](https://github.com/zeek/pysubnettree) |
|---|---:|---:|
| Load | 0.27 s | 0.34 s |
| Lookup (random addresses, incl. ~20 ns loop overhead) | ~240 ns | ~1,230 ns |
| Memory (RSS) | 24 MB | 98 MB |
| File size / reload | 4.1 MB / 0.035 s | n/a |

## How it works

The networks of each address family are kept in sorted arrays without pointers. The structure is
designed for "load in bulk, then query". Modifications are buffered. The next lookup merges them
and flattens the nested networks into disjoint address intervals. A lookup is then a binary
search, narrowed by a direct index on the top 16 address bits. This uses about 21 bytes per IPv4
network and about 33 bytes per IPv6 network, plus each distinct value once: its encoding plus one cached Python object.

Interleaving single inserts with lookups rebuilds the structure on every lookup, which costs
`O(n)`. Insert everything first, then query.

## Development

Requires Rust (stable, edition 2024) and [uv](https://docs.astral.sh/uv/).

```shell
uv sync                     # build the extension in debug mode and install dev tools
uv run pytest               # Python tests
cargo test --no-default-features   # Rust core tests (no libpython needed)
uv run prek run --all-files # linters (ruff, mypy, rustfmt, clippy, ...)
uv run --group docs zensical serve                # documentation

# benchmark (against pysubnettree too); build in release mode and don't let uv rebuild in debug mode
uv run --group bench maturin develop --release --uv
uv run --no-sync python benchmarks/bench.py

# combined Rust + Python coverage (needs cargo-llvm-cov) -> coverage.lcov
./scripts/coverage.sh
```

## License

Apache License 2.0, see [LICENSE](LICENSE).
