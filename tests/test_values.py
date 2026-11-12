"""Values: supported types, read-only results, typed trees, deduplication, serialization."""

import collections
import dataclasses
import datetime as dt
import enum
import pickle
import types
import typing

import pydantic
import pytest

import pysubnettree_rs
from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS

from .conftest import Geo, Model, Owner, Route

ROUTE = Route(asn=64512, geo=Geo('LU', 'Centre'), tags=('a', 'b'), extra={'x': 1})
MODEL = Model(asn=15169, owner=Owner(name='Google', since=dt.date(2000, 1, 2)), tags=('t',))


def roundtrips(value, value_type=None, types_=()):
    """Stores `value` and returns it as seen after insert, bytes, file-less pickle and copy."""
    t = SubnetTreeBuilder(value_type) if value_type else SubnetTreeBuilder()
    t['192.0.2.0/24'] = value
    tree = t.build()
    data = tree.to_bytes()
    return [
        t['192.0.2.1'],
        tree['192.0.2.1'],
        SubnetTreeRS.from_bytes(data, value_type=value_type, types=types_)['192.0.2.1'],
        pickle.loads(pickle.dumps(tree))['192.0.2.1'],  # noqa: S301
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
    t = SubnetTreeBuilder()
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
    t = SubnetTreeBuilder(value_type=Route)
    assert t.value_type is Route
    assert repr(t) == 'SubnetTreeBuilder(ipv4_networks=0, ipv6_networks=0, value_type=Route)'
    assert repr(t.build()) == 'SubnetTreeRS(ipv4_networks=0, ipv6_networks=0, value_type=Route)'
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
    data = t.build().to_bytes()
    assert SubnetTreeRS.load.__name__ == 'load'
    with pytest.raises(ValueError, match='types='):
        SubnetTreeRS.from_bytes(data)  # Route unknown
    with pytest.raises(ValueError, match='types='):
        SubnetTreeRS.from_bytes(data, value_type=Route)  # Geo (nested) unknown
    assert SubnetTreeRS.from_bytes(data, value_type=Route, types=[Geo])['10.0.0.1'] == ROUTE
    with pytest.raises(ValueError, match='expected Geo'):
        SubnetTreeRS.from_bytes(data, value_type=Geo, types=[Route])
    untyped = SubnetTreeBuilder()
    untyped['10.0.0.0/8'] = 'not a route'
    with pytest.raises(ValueError, match='expected Route'):
        SubnetTreeRS.from_bytes(untyped.build().to_bytes(), value_type=Route)


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
            SubnetTreeBuilder(value_type=cls)
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
        (dt.date(2000, 1, 1), TypeError),
        (Mutable(1), TypeError),
        (2**64, OverflowError),
        (-(2**63) - 1, OverflowError),
        (nested, ValueError),
        (recursive, ValueError),
    ]:
        t = SubnetTreeBuilder()
        with pytest.raises(error):
            t['10.0.0.0/8'] = value
        assert len(t) == 0

    # subclasses of built-in types could not be restored: rejected, also nested
    class Name(str):
        __slots__ = ()

    class Number(int):
        pass

    class Pair(typing.NamedTuple):
        a: int
        b: int

    class Plain(collections.abc.Mapping):
        def __getitem__(self, key):
            return 1

        def __iter__(self):
            return iter(['a'])

        def __len__(self):
            return 1

    for value in [
        Pair(1, 2),
        collections.OrderedDict(a=1),
        collections.defaultdict(int),
        Name('x'),
        Number(1),
        Plain(),
        [Name('x')],
        {'a': Number(1)},
        {Rir.RIPE: 1},  # restored as a str key
        {Name('k'): 1},
        Route(asn=1, tags=(Name('x'),)),
    ]:
        t = SubnetTreeBuilder()
        with pytest.raises(TypeError, match='unsupported value type|mapping keys must be str'):
            t['10.0.0.0/8'] = value
        assert len(t) == 0

    t = SubnetTreeBuilder()
    t['10.0.0.0/8'] = Color.RED  # enums are supported
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
    t = SubnetTreeBuilder(value_type=Counted)
    assert t.insert_many((f'10.{i}.0.0/16', shared) for i in range(256)) == 256
    assert calls == 1, 'the same object is converted once per call'
    assert t['10.7.0.1'] == shared


def test_module_metadata():
    assert pysubnettree_rs.FORMAT_VERSION == 3
    assert pysubnettree_rs.__version__
    assert SubnetTreeRS.__module__ == 'pysubnettree_rs'


class Rir(enum.StrEnum):
    RIPE = 'ripe'
    ARIN = 'arin'


class Kind(enum.IntEnum):
    TRANSIT = 1
    STUB = 2


class Perm(enum.IntFlag):
    R = 1
    W = 2


class Color(enum.Enum):
    RED = (255, 0, 0)
    GREEN = (0, 255, 0)


@dataclasses.dataclass(frozen=True)
class ASNet:
    rir: Rir
    kind: Kind
    perm: Perm
    color: Color | None = None


class ASModel(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True)

    rir: Rir
    kinds: tuple[Kind, ...] = ()


ENUM_TYPES = [ASNet, ASModel, Rir, Kind, Perm, Color]


def test_enums():
    """Enum members are stored as members of their enum and restored as the same members."""
    value = ASNet(Rir.RIPE, Kind.TRANSIT, Perm.R | Perm.W, Color.GREEN)
    for result in roundtrips(value, ASNet, ENUM_TYPES):
        assert result == value
        assert result.rir is Rir.RIPE
        assert result.kind is Kind.TRANSIT
        assert result.perm is Perm.R | Perm.W, 'combined flags'
        assert result.color is Color.GREEN
    for member in (Rir.ARIN, Kind.STUB, Perm.W, Color.RED, Perm(0)):
        assert all(r is member for r in roundtrips(member, None, ENUM_TYPES))
    for result in roundtrips((Kind.STUB, {'rir': Rir.ARIN}), None, ENUM_TYPES):
        assert result == (Kind.STUB, types.MappingProxyType({'rir': Rir.ARIN}))
        assert result[0] is Kind.STUB
        assert result[1]['rir'] is Rir.ARIN
    # pydantic restores its enums itself
    model = ASModel(rir=Rir.RIPE, kinds=(Kind.STUB,))
    for result in roundtrips(model, ASModel, ENUM_TYPES):
        assert result == model
        assert result.rir is Rir.RIPE
        assert result.kinds[0] is Kind.STUB

    # members are distinct from their values (type-exact, like 1 and True)
    t = SubnetTreeBuilder()
    t.insert_many({'10.0.0.0/8': Kind.TRANSIT, '11.0.0.0/8': 1, '12.0.0.0/8': Rir.RIPE, '13.0.0.0/8': 'ripe'})
    assert t.stats()['distinct_values'] == 4
    assert type(t['11.0.0.1']) is int
    assert type(t['13.0.0.1']) is str
    assert t['10.0.0.1'] is Kind.TRANSIT

    # the enum classes must be passed to load, like dataclasses; value_type checks them too
    data = t.build().to_bytes()
    with pytest.raises(ValueError, match='Kind; pass the class'):
        SubnetTreeRS.from_bytes(data, types=[Rir])
    with pytest.raises(ValueError, match='expected int'):
        SubnetTreeRS.from_bytes(data, value_type=int, types=[Rir, Kind])
    typed = SubnetTreeBuilder(value_type=Kind)
    typed['10.0.0.0/8'] = Kind.STUB
    with pytest.raises(TypeError, match='must be of type Kind'):
        typed['11.0.0.0/8'] = 2  # type: ignore[assignment]
    assert SubnetTreeRS.from_bytes(typed.build().to_bytes(), value_type=Kind)['10.0.0.1'] is Kind.STUB
    with pytest.raises(ValueError, match='expected Rir'):
        SubnetTreeRS.from_bytes(typed.build().to_bytes(), value_type=Rir, types=[Kind])
    # a pickled tree passes its enum classes along
    assert pickle.loads(pickle.dumps(t.build()))['12.0.0.1'] is Rir.RIPE  # noqa: S301

    # the value of a member must be storable itself
    class Opaque(enum.Enum):
        THING = object()

    with pytest.raises(TypeError, match='unsupported value type object'):
        SubnetTreeBuilder()['10.0.0.0/8'] = Opaque.THING
