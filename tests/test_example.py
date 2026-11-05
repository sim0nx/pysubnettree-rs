"""The typed usage example from the README; mypy checks the `assert_type` lines."""

from dataclasses import dataclass
from typing import Any, assert_type

import pydantic

from pysubnettree_rs import SubnetTreeBuilder, SubnetTreeRS


@dataclass(frozen=True, slots=True)
class Route:
    asn: int
    country: str | None = None
    tags: tuple[str, ...] = ()


class Owner(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True)

    name: str
    asn: int


def test_typed_dataclass_tree(tmp_path) -> None:
    builder = SubnetTreeBuilder(value_type=Route)
    assert_type(builder, SubnetTreeBuilder[Route])
    builder['10.0.0.0/8'] = Route(asn=64512, country='LU')
    builder.insert('10.1.0.0/16')  # no value
    builder.insert_many({'192.0.2.0/24': Route(asn=64496, tags=('doc',))})

    tree = builder.build()  # immutable and lock-free
    assert_type(tree, SubnetTreeRS[Route])
    del builder  # frees the builder's copy

    route = tree['10.200.0.1']
    assert_type(route, Route | None)
    assert route is not None
    assert route.asn == 64512
    assert tree['10.1.0.1'] is None
    assert_type(tree.get('172.16.0.1', 'fallback'), Route | str | None)
    assert_type(tree.lookup('192.0.2.1'), tuple[str, Route | None] | None)

    tree.dump(tmp_path / 'routes.pst')
    loaded = SubnetTreeRS.load(tmp_path / 'routes.pst', value_type=Route)
    assert_type(loaded, SubnetTreeRS[Route])
    assert loaded.items() == tree.items()

    # modify a saved tree: load it as a builder (or use tree.to_builder())
    editable = SubnetTreeBuilder.load(tmp_path / 'routes.pst', value_type=Route)
    assert_type(editable, SubnetTreeBuilder[Route])
    editable.remove('10.1.0.0/16')
    assert len(editable.build()) == len(tree) - 1


def test_typed_pydantic_tree() -> None:
    builder: SubnetTreeBuilder[Owner] = SubnetTreeBuilder(Owner)
    builder['2001:db8::/32'] = Owner(name='doc', asn=64496)
    owner = builder.build()['2001:db8::1']
    assert owner is not None
    assert owner.name == 'doc'


def test_untyped_tree() -> None:
    builder = SubnetTreeBuilder()
    assert_type(builder, SubnetTreeBuilder[Any])
    builder['10.0.0.0/8'] = {'asn': 64512, 'tags': ['a']}
    tree = builder.build()
    assert_type(tree, SubnetTreeRS[Any])
    assert tree['10.0.0.1'] == {'asn': 64512, 'tags': ('a',)}  # read-only: mappingproxy and tuple
