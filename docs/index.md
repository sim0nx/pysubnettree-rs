# pysubnettree-rs

pysubnettree-rs finds the most specific network that contains an IP address (longest prefix match),
fast and with little memory. It handles IPv4 and IPv6 and is written in safe Rust.

```python
from pysubnettree_rs import SubnetTreeBuilder

builder = SubnetTreeBuilder()
builder['10.0.0.0/8'] = {'name': 'private'}
builder['10.1.0.0/16'] = {'name': 'office'}
tree = builder.build()   # immutable and lock-free

tree['10.1.2.3']     # mappingproxy({'name': 'office'}), values are read-only
tree.dump('networks.pst')
```

## Installation

```shell
pip install pysubnettree-rs
```

Requires Python 3.11 or newer. Free-threaded Python (3.14t) is supported.

## Compared to pysubnettree

Measured on a full 2016 routeviews table (644,586 IPv4 and IPv6 prefixes with AS numbers as
values), pysubnettree-rs 0.4.1, Python 3.13, release build. Run `benchmarks/bench.py` to reproduce.

| | pysubnettree-rs | pysubnettree |
|---|---:|---:|
| Load | 0.24 s | 0.32 s |
| Lookup (random addresses, incl. ~30 ns loop overhead) | ~110 ns | ~750 ns |
| Memory (RSS) | 16 MB | 98 MB |
| Save / load from file | 4.3 MB / 0.031 s | not supported |
