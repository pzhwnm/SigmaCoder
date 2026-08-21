"""T01 事件规范化、哈希链和语义校验的 RED 合同。"""

from __future__ import annotations

from copy import deepcopy

import pytest

from ._event_contract import (
    EVENT_IDS,
    EventsApi,
    as_mapping,
    assert_validation_error,
    authorization_events,
    event_hash_oracle,
    rehash_chain,
)


@pytest.fixture
def events_api() -> EventsApi:
    """在测试执行期加载产品接口，避免缺模块导致 collection error。"""

    return EventsApi()


def test_canonical_json_bytes_has_exact_nfc_sorted_compact_encoding(
    events_api: EventsApi,
) -> None:
    value = {
        "z": "Cafe\u0301",
        "a": [1, True, None],
        "nested": {"β": "值"},
    }

    actual = events_api.canonical_json_bytes(value)

    assert actual == '{"a":[1,true,null],"nested":{"β":"值"},"z":"Café"}'.encode()


@pytest.mark.parametrize("invalid", [1.5, float("nan"), b"bytes", {1: "非字符串键"}])
def test_canonical_json_bytes_rejects_values_outside_restricted_json(
    events_api: EventsApi,
    invalid: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        events_api.canonical_json_bytes({"value": invalid})


def test_event_hash_excludes_only_event_hash_and_matches_independent_oracle(
    events_api: EventsApi,
) -> None:
    event = authorization_events()[0]
    expected = event_hash_oracle(event)
    event_with_stale_hash = {**event, "event_hash": "f" * 64}

    assert events_api.calculate_event_hash(event) == expected
    assert events_api.calculate_event_hash(event_with_stale_hash) == expected


def test_restore_accepts_physical_row_reordering_but_uses_logical_sequence(
    events_api: EventsApi,
) -> None:
    events = authorization_events()

    ordered = events_api.restore_task_projection(events)
    reversed_rows = events_api.restore_task_projection(list(reversed(events)))

    assert reversed_rows == ordered


def test_missing_sequence_fails_closed(events_api: EventsApi) -> None:
    events = authorization_events()
    missing_middle = [events[0], events[2]]

    assert_validation_error(
        lambda: events_api.restore_task_projection(missing_middle),
        "EVENT_SEQUENCE_GAP",
    )


def test_duplicate_sequence_fails_closed(events_api: EventsApi) -> None:
    events = authorization_events()
    duplicate = deepcopy(events[2])
    duplicate["event_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaa99"
    duplicate["sequence"] = 2
    duplicated_chain = rehash_chain([events[0], events[1], duplicate])

    assert_validation_error(
        lambda: events_api.restore_task_projection(duplicated_chain),
        "EVENT_SEQUENCE_DUPLICATE",
    )


def test_previous_hash_mismatch_fails_before_event_hash(events_api: EventsApi) -> None:
    events = authorization_events()
    events[1]["previous_hash"] = "f" * 64

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_PREVIOUS_HASH_MISMATCH",
    )


def test_payload_change_without_rehash_fails_with_hash_mismatch(events_api: EventsApi) -> None:
    events = authorization_events()
    payload = as_mapping(events[0]["payload"])
    payload["objective"] = "被静默篡改"
    events[0]["payload"] = payload

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_HASH_MISMATCH",
    )


def test_unsupported_schema_fails_without_downgrade(events_api: EventsApi) -> None:
    events = authorization_events()
    events[1]["schema_version"] = 99
    events = rehash_chain(events)

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "UNSUPPORTED_EVENT_SCHEMA",
    )


def test_hash_valid_typed_payload_error_fails_closed(events_api: EventsApi) -> None:
    events = authorization_events()
    payload = as_mapping(events[0]["payload"])
    payload.pop("objective")
    events[0]["payload"] = payload
    events = rehash_chain(events)

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_PAYLOAD_INVALID",
    )


def test_hash_valid_causation_error_fails_closed(events_api: EventsApi) -> None:
    events = authorization_events()
    events[1]["causation_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    events = rehash_chain(events)

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_CAUSATION_INVALID",
    )


def test_hash_valid_transition_error_fails_closed(events_api: EventsApi) -> None:
    events = authorization_events()
    second_type = events[1]["event_type"]
    second_payload = events[1]["payload"]
    events[1]["event_type"] = events[2]["event_type"]
    events[1]["payload"] = events[2]["payload"]
    events[2]["event_type"] = second_type
    events[2]["payload"] = second_payload
    events = rehash_chain(events)

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_TRANSITION_INVALID",
    )


def test_duplicate_event_id_fails_before_reducer(events_api: EventsApi) -> None:
    events = authorization_events()
    events[2]["event_id"] = EVENT_IDS[1]
    events = rehash_chain(events)

    assert_validation_error(
        lambda: events_api.restore_task_projection(events),
        "EVENT_ID_DUPLICATE",
    )
