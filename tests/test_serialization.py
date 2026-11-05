"""Files, bytes and corruption handling."""

import dataclasses
import gc
import pickle
import threading
import weakref
from pathlib import Path

import pytest

from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS

from .conftest import Geo, Route

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
    @dataclasses.dataclass(frozen=True)
    class Node:
        name: str

    # a cycle through the value class: tree -> Node instance -> Node class -> tree
    t = SubnetTreeBuilder(value_type=Node)
    t['10.0.0.0/8'] = Node('x')
    Node.tree = t  # type: ignore[attr-defined]
    ref = weakref.ref(t)
    del t, Node
    gc.collect()
    assert ref() is None, 'the cycle is collected'


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
