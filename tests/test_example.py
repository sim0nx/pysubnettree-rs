"""The typed usage example from the README; mypy checks the `assert_type` lines."""

from dataclasses import dataclass
from typing import Any, assert_type

import pydantic

from pysubnettree_rs import SubnetTreeRS


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
    tree = SubnetTreeRS(value_type=Route)
    assert_type(tree, SubnetTreeRS[Route])
    tree['10.0.0.0/8'] = Route(asn=64512, country='LU')
    tree.insert('10.1.0.0/16')  # no value
    tree.insert_many({'192.0.2.0/24': Route(asn=64496, tags=('doc',))})

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


def test_typed_pydantic_tree() -> None:
    tree: SubnetTreeRS[Owner] = SubnetTreeRS(Owner)
    tree['2001:db8::/32'] = Owner(name='doc', asn=64496)
    owner = tree['2001:db8::1']
    assert owner is not None
    assert owner.name == 'doc'


def test_untyped_tree() -> None:
    tree = SubnetTreeRS()
    assert_type(tree, SubnetTreeRS[Any])
    tree['10.0.0.0/8'] = {'asn': 64512, 'tags': ['a']}
    assert tree['10.0.0.1'] == {'asn': 64512, 'tags': ('a',)}  # read-only: mappingproxy and tuple
