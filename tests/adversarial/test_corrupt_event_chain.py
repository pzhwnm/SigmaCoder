"""T01 损坏事件链与畸形信封的对抗合同。"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from tests.support.event_contract import (
    EventsApi,
    as_mapping,
    assert_validation_error,
    authorization_events,
    rehash_chain,
)

from sigmacoder.domain import events as event_domain


def _mutated_event(
    mutate: Callable[[dict[str, object]], None],
    *,
    rehash: bool = False,
) -> list[dict[str, object]]:
    events = authorization_events()
    mutate(events[0])
    return rehash_chain(events) if rehash else events


def test_canonical_json_rejects_unicode_normalization_key_collision() -> None:
    with pytest.raises(ValueError, match="碰撞"):
        EventsApi().canonical_json_bytes({"é": 1, "e\u0301": 2})


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (lambda event: event.__setitem__("unexpected", True), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("event_id", "NOT-A-UUID"), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("event_id", "not-a-uuid"), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("sequence", 0), "EVENT_ENVELOPE_INVALID"),
        (
            lambda event: event.__setitem__("event_type", "UnknownEventV1"),
            "UNSUPPORTED_EVENT_SCHEMA",
        ),
        (lambda event: event.__setitem__("occurred_at", None), "EVENT_ENVELOPE_INVALID"),
        (
            lambda event: event.__setitem__("occurred_at", "2026-13-21T00:00:01.000000Z"),
            "EVENT_ENVELOPE_INVALID",
        ),
        (lambda event: event.__setitem__("actor", "model"), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("correlation_id", "not-a-uuid"), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("causation_id", 7), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("workspace_revision", "rev-1"), "EVENT_ENVELOPE_INVALID"),
        (lambda event: event.__setitem__("payload", []), "EVENT_PAYLOAD_INVALID"),
        (lambda event: event.__setitem__("previous_hash", "F" * 64), "EVENT_ENVELOPE_INVALID"),
    ],
)
def test_malformed_envelope_fails_closed(
    mutate: Callable[[dict[str, object]], None],
    expected_code: str,
) -> None:
    events = _mutated_event(mutate)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        expected_code,
    )


def test_non_string_oid_is_rejected_by_typed_payload_schema() -> None:
    def mutate(event: dict[str, object]) -> None:
        payload = as_mapping(event["payload"])
        payload["baseline_commit"] = 7
        event["payload"] = payload

    events = _mutated_event(mutate, rehash=True)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_PAYLOAD_INVALID",
    )


def test_invalid_typed_payload_value_fails_closed_after_valid_hash() -> None:
    def mutate(event: dict[str, object]) -> None:
        payload = as_mapping(event["payload"])
        payload["objective"] = ""
        event["payload"] = payload

    events = _mutated_event(mutate, rehash=True)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_PAYLOAD_INVALID",
    )


def test_different_valid_task_ids_cannot_share_one_stream() -> None:
    events = authorization_events()
    events[1]["task_id"] = "99999999-9999-4999-8999-999999999999"

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_TASK_ID_MISMATCH",
    )


def test_noncanonical_payload_fails_as_hash_mismatch_not_uncaught_type_error() -> None:
    events = authorization_events()
    payload = as_mapping(events[0]["payload"])
    payload["objective"] = object()
    events[0]["payload"] = payload

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_HASH_MISMATCH",
    )


def test_empty_stream_and_non_mapping_member_fail_closed() -> None:
    assert_validation_error(
        lambda: EventsApi().restore_task_projection([]),
        "EVENT_SEQUENCE_GAP",
    )
    assert_validation_error(
        lambda: EventsApi().restore_task_projection([object()]),
        "EVENT_ENVELOPE_INVALID",
    )


def test_reducer_defensively_ignores_created_event_as_a_tail_transition() -> None:
    """语义校验不会产生该输入，但 reducer 必须保持确定性而非猜测。"""

    created = authorization_events()[0]
    projection = event_domain._initial_projection(created)

    event_domain._apply_event(projection, created)

    assert as_mapping(projection["event_position"])["sequence"] == 1
