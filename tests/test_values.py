"""Values: supported types, read-only results, typed trees, deduplication, serialization."""

import dataclasses
import datetime as dt
import enum
import pickle
import types

import pydantic
import pytest

import pysubnettree_rs
from pysubnettree_rs import SubnetTreeRS

from .conftest import Geo, Model, Owner, Route

ROUTE = Route(asn=64512, geo=Geo('LU', 'Centre'), tags=('a', 'b'), extra={'x': 1})
MODEL = Model(asn=15169, owner=Owner(name='Google', since=dt.date(2000, 1, 2)), tags=('t',))


def roundtrips(value, value_type=None, types_=()):
    """Stores `value` and returns it as seen after insert, bytes, file-less pickle and copy."""
    t = SubnetTreeRS(value_type) if value_type else SubnetTreeRS()
    t['192.0.2.0/24'] = value
    data = t.to_bytes()
    return [
        t['192.0.2.1'],
        SubnetTreeRS.from_bytes(data, value_type=value_type, types=types_)['192.0.2.1'],
        pickle.loads(pickle.dumps(t))['192.0.2.1'],  # noqa: S301
    ]


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        # scalars are returned as they are
        *[(v, v) for v in [None, True, False, 0, -1, 2**63 - 1, -(2**63), 2**64 - 1, 1.5, float('inf'), '', 'ünïcødé ✓', b'', b'\x00\xff']],
        # containers become read-only: list/tuple -> tuple, dict -> mappingproxy (deeply)
        ([], ()),
        ([1, [2, (3, {'x': None})]], (1, (2, (3, types.MappingProxyType({'x': None}))))),
        ({'b': 1, 'a': [2]}, types.MappingProxyType({'b': 1, 'a': (2,)})),
        # frozen dataclasses (nested) and pydantic models
        (ROUTE, ROUTE),
        (MODEL, MODEL),
    ],
)
def test_supported_values_roundtrip(value, expected):
    for result in roundtrips(value, types_=(Route, Geo, Model)):
        assert result == expected
        assert type(result) is type(expected)
    if isinstance(expected, types.MappingProxyType):
        assert list(result) == list(expected), 'key order is preserved'


def test_values_are_read_only_and_shared():
    t = SubnetTreeRS()
    t['10.0.0.0/8'] = {'tags': ['a']}
    t['11.0.0.0/8'] = {'tags': ['a']}
    first = t['10.0.0.1']
    with pytest.raises(TypeError):
        first['tags'] = ()  # type: ignore[index]
    with pytest.raises(AttributeError):
        first['tags'].append('b')  # type: ignore[index]
    # equal values are stored once and returned as the same object
    assert first is t['11.0.0.1'] is t['10.255.0.1']
    assert t.stats()['distinct_values'] == 1
    # deduplication is type-exact although 1 == 1.0 == True in Python
    for i, v in enumerate([1, 1.0, True, (1,), [1.0]]):
        t[f'192.0.{i}.0/24'] = v
    assert [type(t[f'192.0.{i}.1']) for i in range(5)] == [int, float, bool, tuple, tuple]
    assert t['192.0.4.1'] == (1.0,)
    assert type(t['192.0.4.1'][0]) is float
    # returned values can be inserted again
    t['12.0.0.0/8'] = first
    assert t['12.0.0.1'] is first
    # replaced values are released
    for i in range(100):
        t['13.0.0.0/8'] = i
    assert t.stats()['distinct_values'] == 7


def test_typed_tree():
    t = SubnetTreeRS(value_type=Route)
    assert t.value_type is Route
    assert repr(t) == 'SubnetTreeRS(ipv4_networks=0, ipv6_networks=0, value_type=Route)'
    t['10.0.0.0/8'] = ROUTE
    t.insert('10.1.0.0/16')
    assert t['10.1.0.1'] is None
    with pytest.raises(TypeError, match='must be of type Route'):
        t['11.0.0.0/8'] = {'asn': 1}  # type: ignore[assignment]
    with pytest.raises(TypeError, match='must be of type Route'):
        t.insert_many([('11.0.0.0/8', Geo('LU'))])  # type: ignore[list-item]
    # generic alias at runtime, as used in annotations
    assert SubnetTreeRS[Route] is not None
    # loading checks the value type
    data = t.to_bytes()
    assert SubnetTreeRS.load.__name__ == 'load'
    with pytest.raises(ValueError, match='types='):
        SubnetTreeRS.from_bytes(data)  # Route unknown
    with pytest.raises(ValueError, match='types='):
        SubnetTreeRS.from_bytes(data, value_type=Route)  # Geo (nested) unknown
    assert SubnetTreeRS.from_bytes(data, value_type=Route, types=[Geo])['10.0.0.1'] == ROUTE
    with pytest.raises(ValueError, match='expected Geo'):
        SubnetTreeRS.from_bytes(data, value_type=Geo, types=[Route])
    untyped = SubnetTreeRS()
    untyped['10.0.0.0/8'] = 'not a route'
    with pytest.raises(ValueError, match='expected Route'):
        SubnetTreeRS.from_bytes(untyped.to_bytes(), value_type=Route)


def test_unsupported_values():
    @dataclasses.dataclass
    class Mutable:
        x: int

    @dataclasses.dataclass(frozen=True)
    class NoInit:
        x: int = dataclasses.field(init=False, default=1)

    class MutableModel(pydantic.BaseModel):
        x: int

    class Color(enum.Enum):
        RED = 1

    for cls in (Mutable, NoInit, MutableModel):
        with pytest.raises(TypeError, match='frozen|init=False'):
            SubnetTreeRS(value_type=cls)
    nested: list = []
    for _ in range(70):
        nested = [nested]
    recursive: list = []
    recursive.append(recursive)
    for value, error in [
        (object(), TypeError),
        ({1: 'x'}, TypeError),
        ({'a': {1, 2}}, TypeError),
        (1j, TypeError),
        (Color.RED, TypeError),
        (dt.date(2000, 1, 1), TypeError),
        (Mutable(1), TypeError),
        (2**64, OverflowError),
        (-(2**63) - 1, OverflowError),
        (nested, ValueError),
        (recursive, ValueError),
    ]:
        t = SubnetTreeRS()
        with pytest.raises(error):
            t['10.0.0.0/8'] = value
        assert len(t) == 0

    class Shade(enum.IntEnum):
        DARK = 1

    t = SubnetTreeRS()
    t['10.0.0.0/8'] = Shade.DARK  # int subclasses are stored as int
    assert type(t['10.0.0.1']) is int
    # two different classes with the same qualified name can not be mixed in one tree
    t['11.0.0.0/8'] = Geo('LU')
    impostor = dataclasses.make_dataclass('Geo', [('country', str)], frozen=True)
    impostor.__module__ = Geo.__module__
    impostor.__qualname__ = Geo.__qualname__
    with pytest.raises(TypeError, match='same name'):
        t['12.0.0.0/8'] = impostor('LU')


def test_insert_many_reuses_objects():
    calls = 0

    class Counted(pydantic.BaseModel):
        model_config = pydantic.ConfigDict(frozen=True)
        asn: int

        def model_dump(self, **kwargs):
            nonlocal calls
            calls += 1
            return super().model_dump(**kwargs)

    shared = Counted(asn=1)
    t = SubnetTreeRS(value_type=Counted)
    assert t.insert_many((f'10.{i}.0.0/16', shared) for i in range(256)) == 256
    assert calls == 1, 'the same object is converted once per call'
    assert t['10.7.0.1'] == shared


def test_module_metadata():
    assert pysubnettree_rs.FORMAT_VERSION == 1
    assert pysubnettree_rs.__version__
    assert SubnetTreeRS.__module__ == 'pysubnettree_rs'
