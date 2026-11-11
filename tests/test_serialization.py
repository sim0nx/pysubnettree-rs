"""Files, bytes and corruption handling."""

import dataclasses
import datetime as dt
import gc
import pickle
import threading
import weakref
from pathlib import Path
from typing import ClassVar

import pytest

import pysubnettree_rs
from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS

from .conftest import Geo, Model, Owner, Route

SAMPLE = Path(__file__).parent.parent / 'sample' / 'routeviews-rv6-20160202-1200.pfx2as'


def test_bytes_file_and_pickle(tree, tmp_path):
    data = tree.to_bytes()
    assert data.startswith(b'PYSTREE\x00')
    for restored in (
        SubnetTreeRS.from_bytes(data),
        pickle.loads(pickle.dumps(tree)),  # noqa: S301
    ):
        assert restored.items() == tree.items()
        assert restored.to_bytes() == data, 'encoding is deterministic'
    path = tmp_path / 'tree.pst'
    tree.dump(path)
    tree.dump(str(path))  # overwrite, str path
    assert list(tmp_path.iterdir()) == [path], 'no temporary file left behind'
    assert SubnetTreeRS.load(path).items() == tree.items()
    # a loaded tree is immutable; loading as a builder allows modifications (the deduplication
    # index is rebuilt: the existing value 'ten' is reused)
    with pytest.raises(TypeError):
        SubnetTreeRS.load(str(path))['11.0.0.0/8'] = 'new'  # type: ignore[index]
    loaded = SubnetTreeBuilder.load(str(path))
    loaded['10.1.2.0/24'] = 'ten'
    loaded['11.0.0.0/8'] = 'new'
    assert loaded['10.1.2.3'] is loaded['10.0.0.1']
    assert loaded.stats()['distinct_values'] == 6
    assert len(SubnetTreeRS.from_bytes(SubnetTreeBuilder().build().to_bytes())) == 0
    with pytest.raises(FileNotFoundError):
        SubnetTreeRS.load(tmp_path / 'missing')
    with pytest.raises(FileNotFoundError):
        tree.dump(tmp_path / 'missing' / 'tree.pst')


def test_invalid_and_corrupted_data():
    for data in [b'', b'garbage', b'PYSTREE\x00' + bytes(20)]:
        with pytest.raises(ValueError, match='subnet tree|checksum|version'):
            SubnetTreeRS.from_bytes(data)
    t = SubnetTreeBuilder()
    t['10.0.0.0/8'] = Route(asn=1, geo=Geo('LU'), extra={'a': 1})
    t['2001:db8::/32'] = {'x': [1.5, b'y']}
    data = t.build().to_bytes()
    for i in range(len(data)):
        corrupted = bytearray(data)
        corrupted[i] ^= 0x01
        with pytest.raises(ValueError):
            SubnetTreeRS.from_bytes(bytes(corrupted), types=[Route, Geo])


def test_lazy_loading():
    """Loaded trees build a value's object on first use and return that object from then on."""

    @dataclasses.dataclass(frozen=True)
    class Strict:
        asn: int
        built: ClassVar[int] = 0
        reject: ClassVar[bool] = False

        def __post_init__(self) -> None:
            type(self).built += 1
            if type(self).reject and self.asn < 0:
                raise ValueError('negative asn')

    b = SubnetTreeBuilder(value_type=Strict)
    b.insert_many({f'10.{i}.0.0/16': Strict(i - 1) for i in range(64)} | {'2001:db8::/32': None})
    data = b.build().to_bytes()
    Strict.built = 0
    Strict.reject = True

    # nothing is built on load; the bad value only fails when it is returned
    t = SubnetTreeRS.from_bytes(data, value_type=Strict)
    assert Strict.built == 0
    first = t['10.5.1.1']
    assert Strict.built == 1
    assert t.get('10.5.0.0/24') is first
    assert t.lookup('10.5.1.1') == ('10.5.0.0/16', first)
    assert t.lookup_all('10.5.1.1')[0][1] is first
    assert t.get_exact('10.5.0.0/16') is first
    assert t.has_network('10.0.0.0/16'), 'no object needed'
    assert '10.0.0.1' in t
    assert Strict.built == 1
    assert t['2001:db8::1'] is None
    for call in (lambda: t['10.0.0.1'], lambda: t.get('10.0.0.1'), t.items, t.materialize, t.to_builder):
        with pytest.raises(ValueError, match='negative asn'):
            call()
    # errors are not cached, eager loading raises them up front
    with pytest.raises(ValueError, match='negative asn'):
        SubnetTreeRS.from_bytes(data, value_type=Strict, eager=True)
    with pytest.raises(ValueError, match='negative asn'):
        SubnetTreeBuilder.from_bytes(data, value_type=Strict)
    Strict.reject = False
    assert t['10.0.0.1'] == Strict(-1)
    built = Strict.built
    t.materialize()
    t.materialize()
    assert Strict.built == built + 62, 'each of the remaining values is built once'
    assert [v for _, v in t.items()][5] is first
    builder = t.to_builder()
    assert builder['10.5.1.1'] is first, 'the builder shares the built objects'
    assert SubnetTreeRS.from_bytes(data, value_type=Strict, eager=True).to_bytes() == data

    # concurrent first lookups all return the same object, also on a builder
    def concurrent_first_lookups(t: SubnetTreeRS[Strict] | SubnetTreeBuilder[Strict]) -> None:
        barrier = threading.Barrier(8)
        found: list[object] = []

        def lookup() -> None:
            barrier.wait()
            found.extend(t[f'10.{i}.0.1'] for i in range(64))

        threads = [threading.Thread(target=lookup) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        assert len(found) == 8 * 64
        assert all(found[i] is found[i % 64] for i in range(len(found)))

    loaded = SubnetTreeRS.from_bytes(data, value_type=Strict)
    concurrent_first_lookups(loaded)
    lazy_builder = SubnetTreeBuilder(value_type=Strict)
    lazy_builder.insert_many(loaded.items())
    concurrent_first_lookups(lazy_builder)

    # the value type is still checked on load, without building objects (bool is an int)
    plain = SubnetTreeBuilder()
    plain.insert_many({'10.0.0.0/8': True, '11.0.0.0/8': 7, '12.0.0.0/8': None})
    plain_data = plain.build().to_bytes()
    assert SubnetTreeRS.from_bytes(plain_data, value_type=int)['10.0.0.1'] is True
    with pytest.raises(ValueError, match='type bool, expected str'):
        SubnetTreeRS.from_bytes(plain_data, value_type=str)


def test_concurrent_readers_and_writer():
    t = SubnetTreeBuilder()
    t.insert_many((f'10.{i}.0.0/16', i) for i in range(256))
    errors = []

    def reader():
        try:
            for _ in range(200):
                for i in range(0, 256, 17):
                    assert t[f'10.{i}.1.1'] == i
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def writer():
        try:
            for i in range(200):
                t[f'11.{i}.0.0/16'] = {'i': i}
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(4)] + [threading.Thread(target=writer)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == []
    assert len(t) == 456


def test_garbage_collection():
    def cycle(kind: str) -> weakref.ref[object]:
        @dataclasses.dataclass(frozen=True)
        class Node:
            name: str

        # a cycle through the value class: tree -> Node instance -> Node class -> tree
        t = SubnetTreeBuilder(value_type=Node)
        t['10.0.0.0/8'] = Node('x')
        t['11.0.0.0/8'] = Node('y')
        tree: object = t
        if kind == 'loaded':  # one value built (it is in the cycle), the other one not
            loaded = SubnetTreeRS.from_bytes(t.build().to_bytes(), value_type=Node)
            assert loaded['10.0.0.1'] == Node('x')
            tree = loaded
        Node.tree = tree  # type: ignore[attr-defined]
        return weakref.ref(tree)

    for kind in ('builder', 'loaded'):
        ref = cycle(kind)
        gc.collect()
        assert ref() is None, f'the cycle through the {kind} tree is collected'


@pytest.mark.skipif(not SAMPLE.exists(), reason='sample data not available')
def test_sample_data():
    import ipaddress

    rows = [(f'{p}/{n}', asn) for p, n, asn in (line.split('\t') for line in SAMPLE.read_text().splitlines())]
    t = SubnetTreeBuilder()
    assert t.insert_many(rows) == len(dict(rows))
    restored = SubnetTreeRS.from_bytes(t.build().to_bytes())
    for net, asn in rows[::50]:
        network = ipaddress.ip_network(net)
        found_net, found = restored.lookup(str(network.network_address)) or ('', None)
        assert ipaddress.ip_network(found_net).prefixlen >= network.prefixlen
        if found_net == str(network):
            assert found == asn


def test_builder_dump_and_to_bytes(tree, tmp_path):
    builder = tree.to_builder()
    builder['11.0.0.0/8'] = 'eleven'  # pending: saving compiles first
    path = tmp_path / 'builder.pst'
    builder.dump(path)
    assert list(tmp_path.iterdir()) == [path], 'no temporary file left behind'
    expected = builder.build()
    assert SubnetTreeRS.load(path).to_bytes() == builder.to_bytes() == expected.to_bytes()
    assert SubnetTreeRS.from_bytes(builder.to_bytes()).items() == expected.items()
    with pytest.raises(FileNotFoundError):
        builder.dump(tmp_path / 'missing' / 'tree.pst')


def test_builder_builds_objects_lazily():
    """A builder builds a value's object on first use, but raises building errors on insert."""

    @dataclasses.dataclass(frozen=True)
    class Counted:
        asn: int
        built: ClassVar[int] = 0
        reject: ClassVar[bool] = False

        def __post_init__(self) -> None:
            type(self).built += 1
            if type(self).reject and self.asn < 0:
                raise ValueError('negative asn')

    b = SubnetTreeBuilder(value_type=Counted)
    values = [Counted(i) for i in range(64)]
    Counted.built = 0
    b.insert_many({f'10.{i}.0.0/16': v for i, v in enumerate(values)})
    b['11.0.0.0/8'] = values[1]  # an existing value
    assert Counted.built == 65, 'each value is built once on insert, to check it, and dropped'
    Counted.built = 0
    first = b['10.5.1.1']
    assert first == values[5]
    assert first is not values[5], 'lookups return a read-only copy'
    assert Counted.built == 1
    assert b.get('10.5.0.0/24') is first
    assert b.lookup('10.5.1.1') == ('10.5.0.0/16', first)
    assert b.lookup_all('10.5.1.1')[0][1] is first
    assert b.get_exact('10.5.0.0/16') is first
    assert b['11.1.1.1'] is b['10.1.0.1'], 'equal values share one object'
    assert Counted.built == 2
    items = b.items()
    assert Counted.built == 64, 'each remaining value is built once'
    assert items[5][1] is first
    assert b.build()['10.5.1.1'] is first, 'the tree shares the built objects'
    assert b.remove('10.5.0.0/16') is first
    assert b.remove('10.6.0.0/16') == values[6]
    assert Counted.built == 64

    # an unbuilt value of a removed network is still built on removal
    b['12.0.0.0/8'] = Counted(99)
    assert b.remove('12.0.0.0/8') == Counted(99)

    # an error raised while building the value of remove() leaves the network in place; del
    # needs no object
    negative = Counted(-1)
    b['14.0.0.0/8'] = negative
    b['15.0.0.0/8'] = negative
    Counted.reject = True
    with pytest.raises(ValueError, match='negative asn'):
        b.remove('14.0.0.0/8')
    assert b.has_network('14.0.0.0/8')
    del b['14.0.0.0/8']
    assert not b.has_network('14.0.0.0/8')
    Counted.reject = False
    assert b.remove('15.0.0.0/8') == negative
    with pytest.raises(KeyError):
        b.remove('15.0.0.0/8')
    with pytest.raises(KeyError):
        del b['15.0.0.0/8']

    # errors raised while building are raised on insert, the builder is left unchanged
    Counted.reject = True
    with pytest.raises(ValueError, match='negative asn'):
        b['13.0.0.0/8'] = negative
    with pytest.raises(ValueError, match='negative asn'):
        b.insert_many([('13.0.0.0/8', negative)])
    Counted.reject = False
    assert '13.0.0.1' not in b


DATA = Path(__file__).parent / 'data'


def format_v1_items() -> dict[str, object]:
    """The contents of ``data/format_v1.pst``, written by version 0.2.0 (file format 1)."""
    items: dict[str, object] = {
        '0.0.0.0/0': None,
        '10.0.0.0/8': 'ten',
        '10.1.0.0/16': {'name': 'office', 'tags': ['a', 'b'], 'nested': {'ten': 'ten'}},
        '10.2.0.0/16': ['ten', 'ünïcode ✓', '', b'\x00bytes', 1.5, True, False, -(2**63), 2**64 - 1],
        '10.3.0.0/16': Route(asn=64512, geo=Geo('LU', 'Luxembourg'), tags=('ten', 'LU'), extra={'LU': 1}),
        '10.4.0.0/16': Model(asn=1, owner=Owner(name='ten', since=dt.date(2016, 2, 2)), tags=('a',)),
        '2001:db8::/32': 'ten',
        '2001:db8:1::/48': {'': ''},
    }
    for i in range(300):
        items[f'192.168.{i % 256}.{i // 256 * 128}/25'] = Route(asn=i % 7, geo=Geo(['LU', 'DE', 'FR'][i % 3]))
    return items


def test_reads_format_1(tmp_path):
    """Files written by earlier versions are read and written again in the current format."""
    expected = SubnetTreeBuilder()
    expected.insert_many(format_v1_items())
    data = (DATA / 'format_v1.pst').read_bytes()
    assert data[8:10] == (1).to_bytes(2, 'little')
    for loaded in (
        SubnetTreeRS.from_bytes(data, types=[Route, Geo, Model, Owner]),
        SubnetTreeRS.load(DATA / 'format_v1.pst', types=[Route, Geo, Model, Owner], eager=True),
        SubnetTreeBuilder.from_bytes(data, types=[Route, Geo, Model, Owner]),
    ):
        assert loaded.items() == expected.items()
        assert loaded.stats()['distinct_values'] == expected.stats()['distinct_values']
        assert loaded.to_bytes() == expected.to_bytes(), 'converted to the canonical current format'
    path = tmp_path / 'v2.pst'
    SubnetTreeRS.from_bytes(data, types=[Route, Geo, Model, Owner]).dump(path)
    assert path.read_bytes()[8:10] == pysubnettree_rs.FORMAT_VERSION.to_bytes(2, 'little')
    assert len(path.read_bytes()) < len(data), 'repeated strings are stored once'
