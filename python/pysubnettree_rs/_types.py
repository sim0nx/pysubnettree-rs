"""Type aliases used by the public API."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import TypeAlias

#: A network: CIDR string (``'10.0.0.0/8'``; a plain address is a host route), packed address or ``ipaddress`` object.
Network: TypeAlias = str | bytes | IPv4Network | IPv6Network | IPv4Address | IPv6Address

#: A lookup key: an address (``'10.1.2.3'``) or a network (``'10.1.2.0/24'``) whose longest containing network is wanted.
Key: TypeAlias = Network
