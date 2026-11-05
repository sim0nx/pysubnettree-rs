"""Property based tests comparing SubnetTreeRS against a naive reference implementation."""

import ipaddress
import types

from hypothesis import given, settings
from hypothesis import strategies as st

from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS


def networks(version: int):
    bits = 32 if version == 4 else 128
    # few distinct high bits to get plenty of nesting/overlap
    addr = st.tuples(st.integers(0, 7), st.integers(0, 2 ** (bits - 3) - 1)).map(lambda t: (t[0] << (bits - 3)) | t[1])
    return st.tuples(addr, st.integers(0, bits)).map(lambda t: ipaddress.ip_network((t[0], t[1]), strict=False))


any_network = st.one_of(networks(4), networks(6))
values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**63), 2**64 - 1) | st.floats(allow_nan=False) | st.text() | st.binary(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=5), children, max_size=4),
    max_leaves=10,
)


MAPPED = ipaddress.IPv6Network('::ffff:0:0/96')


def normalize(obj):
    """IPv4-mapped IPv6 addresses and networks (/96 and longer) are IPv4, as in SubnetTreeRS."""
    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped:
        return obj.ipv4_mapped
    if isinstance(obj, ipaddress.IPv6Network) and obj.prefixlen >= 96 and obj.subnet_of(MAPPED):
        mapped = obj.network_address.ipv4_mapped
        assert mapped is not None
        return ipaddress.ip_network((mapped, obj.prefixlen - 96))
    return obj


class Reference:
    def __init__(self):
        self.data: dict = {}

    def lookup(self, addr):
        addr = normalize(addr)
        best = None
        for net, value in self.data.items():
            if net.version == addr.version and addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, value)
        return best


def addresses_near(nets):
    """Interesting probe addresses: network boundaries and their neighbours."""
    for net in nets:
        first, last = int(net.network_address), int(net.broadcast_address)
        maximum = 2**net.max_prefixlen - 1
        for a in (first, last, first - 1, last + 1):
            if 0 <= a <= maximum:
                yield ipaddress.ip_address(a) if net.version == 4 else ipaddress.IPv6Address(a)


@settings(max_examples=300, deadline=None)
@given(
    st.lists(st.tuples(st.sampled_from(['insert', 'remove']), any_network, st.integers(0, 5)), max_size=60),
    st.lists(st.one_of(networks(4), networks(6)), max_size=10),
)
def test_matches_reference(ops, probes):
    tree = SubnetTreeBuilder()
    ref = Reference()
    for op, raw_net, value in ops:
        net = normalize(raw_net)
        if op == 'insert':
            assert tree.insert(raw_net, value) == (net not in ref.data)
            ref.data[net] = value
        elif net in ref.data:
            assert tree.remove(raw_net) == ref.data.pop(net)
        else:
            assert not tree.has_network(raw_net)
        assert len(tree) == len(ref.data)

    probe_addrs = list(addresses_near(list(ref.data) + probes)) + [p.network_address for p in probes]
    for addr in probe_addrs:
        expected = ref.lookup(addr)
        got = tree.lookup(str(addr))
        if expected is None:
            assert got is None, addr
        else:
            assert got == (str(expected[0]), expected[1]), addr

    assert list(tree) == [str(n) for n in sorted(ref.data, key=lambda n: (n.version, n.network_address, n.prefixlen))]

    built = tree.build()
    assert built.items() == tree.items()
    restored = SubnetTreeRS.from_bytes(built.to_bytes())
    assert restored.items() == built.items()


def frozen(value):
    """The read-only form a lookup returns."""
    if isinstance(value, list | tuple):
        return tuple(frozen(v) for v in value)
    if isinstance(value, dict):
        return types.MappingProxyType({k: frozen(v) for k, v in value.items()})
    return value


@settings(max_examples=200, deadline=None)
@given(values)
def test_value_roundtrip(value):
    tree = SubnetTreeBuilder()
    tree['192.0.2.0/24'] = value
    expected = frozen(value)
    assert tree['192.0.2.1'] == expected
    assert SubnetTreeRS.from_bytes(tree.build().to_bytes())['192.0.2.1'] == expected


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=200))
def test_arbitrary_bytes_never_crash(data):
    try:
        SubnetTreeRS.from_bytes(b'PYSTREE\x00\x01\x00\x00\x00' + data)
    except ValueError:
        pass
