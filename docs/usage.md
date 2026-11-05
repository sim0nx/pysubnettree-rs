# Usage

## Building a tree

A new `SubnetTreeRS` is empty. Add networks in CIDR notation. A plain address is a host route
(`/32` or `/128`). Host bits are ignored, so `10.1.2.3/8` is stored as `10.0.0.0/8`.

```python
from pysubnettree_rs import SubnetTreeRS

tree = SubnetTreeRS()
tree.insert('10.0.0.0/8', {'asn': 64512})
tree['192.0.2.0/24'] = 'documentation'   # same as insert
tree.insert('2001:db8::/32')              # no value, lookups return None

# bulk loading is faster: from a mapping or an iterable of (network, value) pairs
tree.insert_many({'198.51.100.0/24': 1, '203.0.113.0/24': 2})
tree.insert_many((row.network, row.value) for row in rows)
```

Networks and lookup keys can also be given as `ipaddress` objects or as packed `bytes` (4 or 16
bytes).

!!! tip "Load first, query second"
    Modifications are buffered, and the next lookup rebuilds the lookup structure in `O(n)`.
    Insert everything first, then call `compile()` (optional), then query.

## Values

Each network has a value, or `None`. Supported values, nested in any combination up to 64
levels deep:

- `None`, `bool`, `int` (from -2^63 to 2^64 - 1), `float`, `str`, `bytes`
- `list` and `tuple`
- `dict` with `str` keys
- frozen dataclasses: `@dataclass(frozen=True)`, with all fields in `__init__`
- frozen pydantic models: `model_config = ConfigDict(frozen=True)`

Anything else raises `TypeError` on insert. This ensures every tree can be saved to disk without
`pickle`.

### Values are read-only

Lookups return immutable objects: `list` and `tuple` come back as `tuple`, and `dict` comes back
as a read-only `types.MappingProxyType`. This applies inside dataclasses too. Equal values are
stored once and every lookup returns the same object, with no copying or conversion. Equality is
type-exact: `1`, `1.0` and `True` are kept apart, although Python considers them equal.

!!! note
    A `mappingproxy` is not a `dict`: `json.dumps` and `pickle` do not accept it. Use
    `dict(value)` if you need one.

    pydantic models rebuild their fields themselves, so a `list` field of a model is a `list`.
    Use `tuple[...]` fields to keep models immutable.

### Typed trees

```python
from dataclasses import dataclass

from pysubnettree_rs import SubnetTreeRS


@dataclass(frozen=True, slots=True)
class Route:
    asn: int
    country: str | None = None


tree = SubnetTreeRS(value_type=Route)    # mypy: SubnetTreeRS[Route]
tree['10.0.0.0/8'] = Route(asn=64512)
route = tree['10.1.2.3']                 # mypy: Route | None
tree['192.0.2.0/24'] = 'x'               # mypy error, TypeError at runtime
```

With `value_type`, every value must be an instance of that type, or `None`. Without it, any
supported value is accepted and type checkers see `Any`.

When the same dataclass or model instance is inserted for many networks, `insert_many` converts
it only once per call, which matters for pydantic models (`model_dump` costs ~2 µs).

## Lookups

| Expression | Result when a network matches | Result when nothing matches |
|---|---|---|
| `tree[key]` | the value | `KeyError` |
| `tree.get(key, default=None)` | the value | `default` |
| `tree.lookup(key)` | `(network, value)` | `None` |
| `tree.lookup_all(key)` | all matching `[(network, value), ...]`, most specific first | `[]` |
| `key in tree` | `True` | `False` |

A network with no value matches and returns `None`. Use `tree[key]` or `key in tree` to tell
"matched, no value" apart from "no match".

If the key is a network, for example `'10.1.2.0/24'`, the result is the most specific stored
network that contains the whole key network.

IPv4-mapped IPv6 addresses and networks (`::ffff:192.0.2.1`, `::ffff:192.0.2.0/120`) are treated
as IPv4. As a consequence, IPv6 networks shorter than `/96` that cover the mapped range, such as
`::/0`, do not match IPv4-mapped addresses. (pysubnettree stores IPv4 inside one IPv6 tree and
behaves differently here.)

Exact matches without longest prefix matching: `has_network(network)` and
`get_exact(network, default=None)`.

## Removing networks

```python
tree.remove('10.0.0.0/8')    # returns the value, KeyError if the network does not exist
del tree['192.0.2.0/24']
tree.clear()
```

## Saving and loading

```python
tree.dump('networks.pst')                 # written atomically (temporary file + rename)
tree = SubnetTreeRS.load('networks.pst')

data = tree.to_bytes()
tree = SubnetTreeRS.from_bytes(data)

# data with dataclasses / pydantic models: pass the classes, they are never imported by name
tree = SubnetTreeRS.load('routes.pst', value_type=Route, types=[Geo])
```

Loading checks the checksum and the structure of the data and raises `ValueError` for corrupted
or invalid input. Trees also support `pickle`.

## Threads

A `SubnetTreeRS` can be used from several threads at once. Lookups run in parallel on
free-threaded Python. Modifications take an exclusive lock. Building the lookup structure and
file I/O release the GIL.

## Inspection

`len(tree)`, `iter(tree)` (networks as strings, IPv4 first, sorted), `tree.items()`,
`tree.stats()`, and `tree.memory_usage()`.
