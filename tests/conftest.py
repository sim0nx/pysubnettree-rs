import dataclasses
import datetime as dt

import pydantic
import pytest

from pysubnettree_rs import SubnetTreeRS


@dataclasses.dataclass(frozen=True, slots=True)
class Geo:
    country: str
    region: str | None = None


@dataclasses.dataclass(frozen=True)
class Route:
    asn: int
    geo: Geo | None = None
    tags: tuple[str, ...] = ()
    extra: dict[str, int] = dataclasses.field(default_factory=dict, hash=False)


class Owner(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True)

    name: str
    since: dt.date | None = None


class Model(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(frozen=True)

    asn: int
    owner: Owner | None = None
    tags: tuple[str, ...] = ()


@pytest.fixture
def tree() -> SubnetTreeRS:
    t = SubnetTreeRS()
    t.insert_many(
        {
            '10.0.0.0/8': 'ten',
            '10.1.0.0/16': {'name': 'office', 'tags': ['a', 'b']},
            '10.1.2.0/24': None,
            '2001:db8::/32': 'doc',
            '2001:db8:1::/48': 48,
        },
    )
    return t
