"""The builder / immutable tree split: immutability, copy semantics, threads, GC, pickle."""

import dataclasses
import gc
import pickle
import threading
import weakref

import pytest

from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS


def test_tree_is_immutable(tree):
    for name in ('insert', 'insert_many', 'remove', 'clear', 'compile'):
        assert not hasattr(tree, name), name
    with pytest.raises(TypeError):
        tree['11.0.0.0/8'] = 1
    with pytest.raises(TypeError):
        del tree['10.0.0.0/8']
    with pytest.raises(TypeError):
        SubnetTreeRS()  # only built, loaded or decoded
    assert tree['10.200.0.1'] == 'ten'


def test_build_copies():
    builder = SubnetTreeBuilder()
    builder.insert_many({'10.0.0.0/8': 'ten', '10.1.0.0/16': {'a': [1]}})
    tree = builder.build()
    # the builder answers the same lookups (it compiles pending changes first)
    for key in ('10.1.2.3', '10.2.0.1', '11.0.0.1', '10.1.0.0/20'):
        assert builder.get(key, 'missing') == tree.get(key, 'missing')
        assert builder.lookup(key) == tree.lookup(key)
        assert (key in builder) == (key in tree)
    assert builder.items() == tree.items()
    # the tree has no deduplication index (only needed for inserts), so it is smaller
    assert tree.memory_usage() < builder.memory_usage()

    # later modifications of the builder do not affect the tree, and vice versa for to_builder()
    builder['10.1.0.0/16'] = 'changed'
    builder.remove('10.0.0.0/8')
    builder['12.0.0.0/8'] = 'new'
    assert tree.items() == [('10.0.0.0/8', 'ten'), ('10.1.0.0/16', {'a': (1,)})]
    assert builder.build().items() == [('10.1.0.0/16', 'changed'), ('12.0.0.0/8', 'new')]
    copy = tree.to_builder()
    copy.clear()
    assert len(copy) == 0
    assert len(tree) == 2
    builder.clear()
    assert len(tree) == 2

    # an unused builder is freed right away (no reference cycles), the tree stays valid
    ref = weakref.ref(builder)
    del builder, copy
    assert ref() is None
    assert tree['10.1.0.1'] == {'a': (1,)}


def test_pickle_and_load_keep_the_kind(tmp_path):
    builder = SubnetTreeBuilder()
    builder['10.0.0.0/8'] = 'ten'
    tree = builder.build()
    assert type(pickle.loads(pickle.dumps(builder))) is SubnetTreeBuilder  # noqa: S301
    assert type(pickle.loads(pickle.dumps(tree))) is SubnetTreeRS  # noqa: S301
    tree.dump(tmp_path / 't.pst')
    assert type(SubnetTreeRS.load(tmp_path / 't.pst')) is SubnetTreeRS
    loaded = SubnetTreeBuilder.from_bytes(tree.to_bytes())
    loaded['11.0.0.0/8'] = 'eleven'  # a decoded builder is modifiable
    assert loaded.build()['11.0.0.1'] == 'eleven'


def test_tree_shared_between_threads():
    builder = SubnetTreeBuilder()
    builder.insert_many((f'10.{i}.0.0/16', {'i': i}) for i in range(256))
    tree = builder.build()
    errors = []
    stop = threading.Event()

    def reader():
        try:
            while not stop.is_set():
                for i in range(0, 256, 7):
                    assert tree[f'10.{i}.1.1'] == {'i': i}
                    assert tree.lookup(f'10.{i}.0.0/24') == (f'10.{i}.0.0/16', {'i': i})
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    readers = [threading.Thread(target=reader) for _ in range(4)]
    for th in readers:
        th.start()
    # meanwhile the builder is modified and rebuilt; the shared tree must not notice
    for i in range(200):
        builder[f'10.{i}.0.0/16'] = 'changed'
        builder.build()
    stop.set()
    for th in readers:
        th.join()
    assert errors == []


def test_garbage_collection_of_cycles():
    @dataclasses.dataclass(frozen=True)
    class Node:
        name: str

    # cycles through the value class: tree/builder -> Node instance -> Node class -> tree/builder
    builder = SubnetTreeBuilder(value_type=Node)
    builder['10.0.0.0/8'] = Node('x')
    tree = builder.build()
    Node.tree = tree  # type: ignore[attr-defined]
    Node.builder = builder  # type: ignore[attr-defined]
    refs = weakref.ref(tree), weakref.ref(builder)
    gc.collect()
    assert tree['10.0.0.1'] == Node('x'), 'collections leave live objects alone'
    del tree, builder, Node
    gc.collect()
    assert [r() for r in refs] == [None, None], 'the cycles are collected'
