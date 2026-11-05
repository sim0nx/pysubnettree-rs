"""Lookup semantics, key types and mutations."""

import ipaddress

import pytest

from pysubnettree_rs import SubnetTreeRS

OFFICE = {'name': 'office', 'tags': ('a', 'b')}


def test_lookup_semantics(tree):
    # most specific network wins, for IPv4 and IPv6
    assert tree['10.200.0.1'] == 'ten'
    assert tree['10.1.200.1'] == OFFICE
    assert tree['2001:db8:2::1'] == 'doc'
    assert tree.lookup('2001:db8:1::5') == ('2001:db8:1::/48', 48)
    # found without value -> None, distinguishable from "not found"
    assert tree['10.1.2.3'] is None
    assert '10.1.2.3' in tree
    assert tree.lookup('10.1.2.3') == ('10.1.2.0/24', None)
    with pytest.raises(KeyError):
        tree['11.0.0.1']
    assert '11.0.0.1' not in tree
    assert tree.get('11.0.0.1') is None
    assert tree.get('11.0.0.1', 'default') == 'default'
    assert tree.get('10.0.0.1', 'default') == 'ten'
    assert tree.lookup('11.0.0.1') is None
    # all matches, most specific first
    assert [n for n, _ in tree.lookup_all('10.1.2.3')] == ['10.1.2.0/24', '10.1.0.0/16', '10.0.0.0/8']
    assert tree.lookup_all('11.0.0.1') == []
    # a network key matches the most specific network containing all of it
    assert tree.lookup('10.1.2.0/24')[0] == '10.1.2.0/24'
    assert tree.lookup('10.1.2.0/23')[0] == '10.1.0.0/16'
    assert tree.lookup('10.0.0.0/7') is None
    assert '10.0.0.0/9' in tree
    assert '10.0.0.0/7' not in tree
    assert [n for n, _ in tree.lookup_all('10.1.0.0/16')] == ['10.1.0.0/16', '10.0.0.0/8']


@pytest.mark.parametrize(
    ('key', 'expected'),
    [
        (ipaddress.ip_address('10.1.200.1'), '10.1.0.0/16'),
        (ipaddress.ip_address('2001:db8::1'), '2001:db8::/32'),
        (ipaddress.ip_network('10.1.2.0/23'), '10.1.0.0/16'),
        (ipaddress.ip_interface('10.1.2.3/8'), '10.1.2.0/24'),  # an interface is its address
        (ipaddress.ip_address('10.0.0.1').packed, '10.0.0.0/8'),
        (ipaddress.ip_address('2001:db8::1').packed, '2001:db8::/32'),
        ('::ffff:10.0.0.1', '10.0.0.0/8'),  # IPv4-mapped IPv6 is IPv4
        (ipaddress.ip_address('::ffff:10.0.0.1'), '10.0.0.0/8'),
    ],
)
def test_key_types(tree, key, expected):
    assert tree.lookup(key)[0] == expected


@pytest.mark.parametrize(
    ('key', 'error'),
    [
        *[(k, ValueError) for k in ['', 'foo', '10.0.0', '10.0.0.256', '10.0.0.0/33', '::/129', '10.0.0.0/', '10.0.0.0/+8', ':::']],
        (b'\x01\x02\x03', ValueError),
        *[(k, TypeError) for k in [None, 1, 1.5, [], object()]],
    ],
)
def test_invalid_keys(tree, key, error):
    for operation in (tree.get, tree.__contains__, tree.lookup, tree.insert, tree.has_network):
        with pytest.raises(error):
            operation(key)


def test_edges_of_the_address_space():
    t = SubnetTreeRS()
    for net in ['0.0.0.0/0', '::/0', '255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', '0.0.0.0/32']:
        t[net] = net
    assert t['0.0.0.0'] == '0.0.0.0/32'
    assert t['0.0.0.1'] == t['255.255.255.254'] == '0.0.0.0/0'
    assert t['255.255.255.255'] == '255.255.255.255'
    assert t['::'] == t['ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe'] == '::/0'
    assert t['ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'] == 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    empty = SubnetTreeRS()
    assert len(empty) == 0
    assert not empty
    assert '1.2.3.4' not in empty
    assert '::1' not in empty
    assert list(empty) == []


def test_mutations():
    t = SubnetTreeRS()
    assert t.insert('10.0.0.0/8', 1) is True
    assert t.insert('10.0.0.0/8', 2) is False
    assert t['10.0.0.1'] == 2
    # host bits are ignored, plain addresses are host routes, mapped IPv6 networks are IPv4
    t['10.1.2.3/16'] = 3
    t['192.0.2.1'] = 4
    t[ipaddress.ip_address('2001:db8::1')] = 5
    t[b'\xc0\x00\x02\x02'] = 6
    t['::ffff:198.51.100.0/120'] = 7
    t[ipaddress.ip_network('::ffff:203.0.113.0/120')] = 8
    assert list(t) == ['10.0.0.0/8', '10.1.0.0/16', '192.0.2.1/32', '192.0.2.2/32', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::1/128']
    assert len(t) == 7
    # exact matches
    assert t.has_network('10.1.0.0/16')
    assert not t.has_network('10.1.0.0/17')
    assert t.get_exact('10.1.0.0/16') == 3
    assert t.get_exact('10.1.0.0/17', 'x') == 'x'
    # remove
    assert t.remove('10.1.0.0/16') == 3
    assert t['10.1.0.1'] == 2
    del t['10.0.0.0/8']
    assert '10.1.0.1' not in t
    with pytest.raises(KeyError):
        t.remove('10.0.0.0/8')
    with pytest.raises(KeyError):
        del t['10.0.0.0/9']
    assert len(t) == 5
    t.clear()
    assert len(t) == 0
    assert '192.0.2.1' not in t
    t['10.0.0.0/8'] = 1
    assert t['10.0.0.1'] == 1


def test_insert_many_and_interleaving():
    t = SubnetTreeRS()
    assert t.insert_many({'10.0.0.0/8': 1, '11.0.0.0/8': 2}) == 2
    assert t.insert_many([('10.0.0.0/8', 3), ('12.0.0.0/8', None)]) == 1
    # more than one internal chunk
    n = 40_000
    assert t.insert_many((f'{100 + (i >> 16)}.{(i >> 8) & 255}.{i & 255}.0/24', i) for i in range(n)) == n
    assert len(t) == n + 3
    assert t['10.0.0.1'] == 3
    assert t['100.1.2.3'] == 258
    for bad, match in [([1, 2], 'pairs'), ([('10.0.0.0/8',)], 'pairs'), ([('10.0.0.0/8', 1), ('bad', 2)], 'invalid')]:
        before = len(t)
        with pytest.raises((TypeError, ValueError), match=match):
            t.insert_many(bad)  # type: ignore[arg-type]
        assert len(t) == before, 'nothing is stored if a chunk fails'
    # lookups between single inserts see every insert (each lookup recompiles)
    t = SubnetTreeRS()
    for i in range(100):
        t[f'10.{i}.0.0/16'] = i
        assert t[f'10.{i}.1.1'] == i
        assert len(t) == i + 1
    t.compile()
    t.compile()
    assert t['10.99.0.1'] == 99


def test_container_protocol(tree):
    assert len(tree) == 5
    assert bool(tree)
    assert list(tree) == ['10.0.0.0/8', '10.1.0.0/16', '10.1.2.0/24', '2001:db8::/32', '2001:db8:1::/48']
    assert tree.items()[0] == ('10.0.0.0/8', 'ten')
    assert dict(tree.items())['2001:db8:1::/48'] == 48
    assert repr(tree) == 'SubnetTreeRS(ipv4_networks=3, ipv6_networks=2)'
    stats = tree.stats()
    assert stats == {'ipv4_networks': 3, 'ipv6_networks': 2, 'distinct_values': 5, 'memory_usage': tree.memory_usage()}
    assert stats['memory_usage'] > 0
