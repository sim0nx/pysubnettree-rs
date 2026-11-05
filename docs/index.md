# pysubnettree-rs

pysubnettree_rs finds the most specific network that contains an IP address (longest prefix match),
fast and with little memory. It handles IPv4 and IPv6 and is written in safe Rust.

```python
from pysubnettree_rs import SubnetTreeRS

tree = SubnetTreeRS()
tree['10.0.0.0/8'] = {'name': 'private'}
tree['10.1.0.0/16'] = {'name': 'office'}

tree['10.1.2.3']     # mappingproxy({'name': 'office'}), values are read-only
tree.dump('networks.pst')
```

## Installation

```shell
pip install pysubnettree_rs
```

Requires Python 3.11 or newer. Free-threaded Python (3.14t) is supported.

## Compared to pysubnettree

Measured on a full 2016 routeviews table (644,586 IPv4 and IPv6 prefixes with AS numbers as
values), Python 3.14, release build. Run `benchmarks/bench.py` to reproduce.

| | pysubnettree-rs | pysubnettree |
|---|---:|---:|
| Load | 0.27 s | 0.34 s |
| Lookup (random addresses, incl. ~20 ns loop overhead) | ~240 ns | ~1,230 ns |
| Memory (RSS) | 24 MB | 98 MB |
| Save / load from file | 4.1 MB / 0.035 s | not supported |
