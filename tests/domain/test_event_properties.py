"""T01 事件规范化与重建的属性 RED 测试。"""

from __future__ import annotations

import string
from typing import Literal

from hypothesis import given, settings
from hypothesis import strategies as st

from ._event_contract import EventsApi, authorization_events

ASCII_KEYS = st.text(alphabet=string.ascii_letters, min_size=1, max_size=12)
EXCLUDED_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.text(alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES), max_size=30),
)
OBJECTIVES = st.text(
    alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES),
    min_size=1,
    max_size=40,
)


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(ASCII_KEYS, JSON_SCALARS, min_size=1, max_size=12))
def test_canonicalization_is_independent_of_mapping_insertion_order(
    value: dict[str, object],
) -> None:
    api = EventsApi()
    reversed_insertion = dict(reversed(list(value.items())))

    assert api.canonical_json_bytes(value) == api.canonical_json_bytes(reversed_insertion)


@settings(max_examples=200, deadline=None)
@given(OBJECTIVES)
def test_rebuild_is_deterministic_for_same_authoritative_event_bytes(objective: str) -> None:
    api = EventsApi()
    events = authorization_events(objective=objective)

    first = api.restore_task_projection(events)
    second = api.restore_task_projection(events)

    assert first == second
