"""T01 投影与 CheckpointV1 恢复语义的 RED 合同。"""

from __future__ import annotations

from copy import deepcopy
from enum import Enum

import pytest
from tests.support.event_contract import (
    EventsApi,
    as_mapping,
    assert_validation_error,
    authorization_events,
    canonical_oracle,
    checkpoint_hash_oracle,
    field,
    prepared_events,
)

PREPARED_EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4"


def enum_text(value: object) -> str:
    """允许产品用字符串或字符串 Enum 表达稳定状态。"""

    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def test_authorized_event_stream_builds_preparing_projection() -> None:
    api = EventsApi()
    events = authorization_events()

    result = api.restore_task_projection(events)
    projection = field(result, "projection")

    assert field(projection, "task_id") == events[0]["task_id"]
    assert enum_text(field(projection, "lifecycle_state")) == "PREPARING"
    assert field(result, "through_sequence") == 3
    assert field(result, "through_event_hash") == events[-1]["event_hash"]
    assert enum_text(field(result, "load_mode")) == "FULL_REPLAY"


def test_valid_old_checkpoint_replays_only_authoritative_tail() -> None:
    api = EventsApi()
    events = prepared_events(authorization_events(), event_id=PREPARED_EVENT_ID)
    prefix_result = api.restore_task_projection(events[:3])
    old_checkpoint = field(prefix_result, "checkpoint")

    from_checkpoint = api.restore_task_projection(events, checkpoint=old_checkpoint)
    from_full_replay = api.restore_task_projection(events)

    assert enum_text(field(from_checkpoint, "load_mode")) == "CHECKPOINT"
    assert canonical_oracle(as_mapping(field(from_checkpoint, "projection"))) == canonical_oracle(
        as_mapping(field(from_full_replay, "projection"))
    )
    assert field(from_checkpoint, "through_sequence") == 4


def test_corrupt_checkpoint_hash_falls_back_to_full_replay() -> None:
    api = EventsApi()
    events = authorization_events()
    original = api.restore_task_projection(events)
    checkpoint = as_mapping(field(original, "checkpoint"))
    checkpoint["checkpoint_hash"] = "f" * 64

    rebuilt = api.restore_task_projection(events, checkpoint=checkpoint)

    assert enum_text(field(rebuilt, "load_mode")) == "FULL_REPLAY"
    assert canonical_oracle(as_mapping(field(rebuilt, "projection"))) == canonical_oracle(
        as_mapping(field(original, "projection"))
    )


@pytest.mark.parametrize("location", ["checkpoint", "projection"])
def test_non_string_checkpoint_keys_fall_back_to_full_replay(location: str) -> None:
    api = EventsApi()
    events = prepared_events(authorization_events(), event_id=PREPARED_EVENT_ID)
    original = api.restore_task_projection(events)
    checkpoint = as_mapping(field(original, "checkpoint"))
    if location == "checkpoint":
        checkpoint[7] = "untrusted"
    else:
        projection = as_mapping(checkpoint["projection"])
        projection[7] = "untrusted"
        checkpoint["projection"] = projection

    rebuilt = api.restore_task_projection(events, checkpoint=checkpoint)

    assert enum_text(field(rebuilt, "load_mode")) == "FULL_REPLAY"


@pytest.mark.parametrize("field_name", ["workspace", "preparation"])
def test_checkpoint_projection_requires_mapping_sections(field_name: str) -> None:
    api = EventsApi()
    events = prepared_events(authorization_events(), event_id=PREPARED_EVENT_ID)
    original = api.restore_task_projection(events)
    checkpoint = as_mapping(field(original, "checkpoint"))
    projection = as_mapping(checkpoint["projection"])
    projection[field_name] = []
    checkpoint["projection"] = projection
    checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)

    rebuilt = api.restore_task_projection(events, checkpoint=checkpoint)

    assert enum_text(field(rebuilt, "load_mode")) == "FULL_REPLAY"


def test_cross_task_checkpoint_with_valid_hash_is_not_trusted() -> None:
    api = EventsApi()
    events = authorization_events()
    original = api.restore_task_projection(events)
    checkpoint = as_mapping(field(original, "checkpoint"))
    checkpoint["task_id"] = "99999999-9999-4999-8999-999999999999"
    checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)

    rebuilt = api.restore_task_projection(events, checkpoint=checkpoint)

    assert enum_text(field(rebuilt, "load_mode")) == "FULL_REPLAY"
    assert field(field(rebuilt, "projection"), "task_id") == events[0]["task_id"]


def test_checkpoint_is_deterministic_derived_data() -> None:
    api = EventsApi()
    events = authorization_events()

    first = as_mapping(field(api.restore_task_projection(events), "checkpoint"))
    second = as_mapping(field(api.restore_task_projection(events), "checkpoint"))

    assert canonical_oracle(first) == canonical_oracle(second)
    assert first["through_sequence"] == 3
    assert first["through_event_hash"] == events[-1]["event_hash"]
    assert first["checkpoint_hash"] == checkpoint_hash_oracle(first)


def test_valid_checkpoint_never_masks_corrupt_authoritative_tail() -> None:
    api = EventsApi()
    events = prepared_events(authorization_events(), event_id=PREPARED_EVENT_ID)
    prefix = api.restore_task_projection(events[:3])
    checkpoint = field(prefix, "checkpoint")
    corrupt_events = deepcopy(events)
    corrupt_events[3]["payload"] = {
        **as_mapping(corrupt_events[3]["payload"]),
        "head_oid": "f" * 40,
    }

    assert_validation_error(
        lambda: api.restore_task_projection(corrupt_events, checkpoint=checkpoint),
        "EVENT_HASH_MISMATCH",
    )
