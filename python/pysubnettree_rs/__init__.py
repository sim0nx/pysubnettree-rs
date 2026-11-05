"""Fast, memory-efficient longest-prefix-match lookups of IPv4/IPv6 subnets.

The heavy lifting is implemented in Rust, see :class:`SubnetTreeRS`.
"""

from importlib.metadata import version as _version

from pysubnettree_rs._pysubnettree_rs import FORMAT_VERSION, SubnetTreeRS
from pysubnettree_rs._types import Key, Network

__all__ = ['FORMAT_VERSION', 'Key', 'Network', 'SubnetTreeRS']
__version__ = _version('pysubnettree-rs')
