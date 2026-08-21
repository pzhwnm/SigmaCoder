"""T01 事件语义、终态投影与 Checkpoint 退避合同。"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, cast

import pytest
from tests.support.event_contract import (
    BASELINE_OID,
    CORRELATION_ID,
    OWNERSHIP_NONCE,
    TASK_ID,
    WORKSPACE_RELATIVE_PATH,
    EventsApi,
    as_mapping,
    assert_validation_error,
    authorization_events,
    checkpoint_hash_oracle,
    event_hash_oracle,
    field,
    rehash_chain,
)

from sigmacoder.domain import events as event_domain

PREPARED_EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4"
ATTENTION_EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5"


def _append_event(
    events: list[dict[str, object]],
    event_type: str,
    payload: Mapping[str, object],
    *,
    event_id: str,
) -> None:
    """按权威前序事件构造一个规范事件。"""

    previous = events[-1]
    sequence = len(events) + 1
    event: dict[str, object] = {
        "event_id": event_id,
        "task_id": TASK_ID,
        "sequence": sequence,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": f"2026-08-21T00:00:{sequence:02d}.000000Z",
        "actor": "local_user",
        "correlation_id": CORRELATION_ID,
        "causation_id": previous["event_id"],
        "workspace_revision": None,
        "sensitivity": "INTERNAL",
        "payload": dict(payload),
        "previous_hash": previous["event_hash"],
    }
    event["event_hash"] = event_hash_oracle(event)
    events.append(event)


def _prepared_events(**overrides: object) -> list[dict[str, object]]:
    events = authorization_events()
    authorization = as_mapping(events[2]["payload"])
    payload: dict[str, object] = {
        "action_digest": authorization["action_digest"],
        "ownership_nonce": OWNERSHIP_NONCE,
        "workspace_relative_path": WORKSPACE_RELATIVE_PATH,
        "mode": "DETACHED",
        "head_oid": BASELINE_OID,
        "git_pointer_digest": "2" * 64,
        "recovered_after_interruption": False,
    }
    payload.update(overrides)
    _append_event(
        events,
        "TaskWorkspacePreparedV1",
        payload,
        event_id=PREPARED_EVENT_ID,
    )
    return events


def _failure_events(
    *,
    resource_state: str = "NOT_CREATED",
    include_attention: bool = True,
    attention_reason: str | None = None,
    **overrides: object,
) -> list[dict[str, object]]:
    events = authorization_events()
    authorization = as_mapping(events[2]["payload"])
    payload: dict[str, object] = {
        "action_digest": authorization["action_digest"],
        "failure_stage": "git_worktree_add",
        "error_code": "WORKSPACE_CREATE_FAILED",
        "resource_state": resource_state,
        "diagnostic": "受控诊断",
    }
    payload.update(overrides)
    _append_event(
        events,
        "TaskWorkspaceProvisioningFailedV1",
        payload,
        event_id=PREPARED_EVENT_ID,
    )
    if include_attention:
        reason = attention_reason or (
            "WORKSPACE_PROVISIONING_FAILED"
            if resource_state == "NOT_CREATED"
            else "WORKSPACE_PROVISIONING_UNCERTAIN"
        )
        _append_event(
            events,
            "TaskAttentionRequiredV1",
            {"reason": reason},
            event_id=ATTENTION_EVENT_ID,
        )
    return events


def _checkpoint(events: list[dict[str, object]]) -> dict[str, Any]:
    return as_mapping(field(EventsApi().restore_task_projection(events), "checkpoint"))


def _rehash_checkpoint(checkpoint: dict[str, Any]) -> dict[str, Any]:
    checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)
    return checkpoint


def test_single_created_event_is_a_valid_rebuild_prefix() -> None:
    result = EventsApi().restore_task_projection(authorization_events()[:1])

    assert field(result, "through_sequence") == 1
    assert field(field(result, "projection"), "lifecycle_state") == "CREATED"


def test_prepared_terminal_event_builds_available_workspace_projection() -> None:
    result = EventsApi().restore_task_projection(_prepared_events())
    projection = as_mapping(field(result, "projection"))
    workspace = as_mapping(projection["workspace"])
    preparation = as_mapping(projection["preparation"])

    assert workspace["availability"] == "AVAILABLE"
    assert workspace["head_oid"] == BASELINE_OID
    assert workspace["git_pointer_digest"] == "2" * 64
    assert preparation["workspace"] == "READY"


@pytest.mark.parametrize(
    ("resource_state", "reason", "preparation_state"),
    [
        ("NOT_CREATED", "WORKSPACE_PROVISIONING_FAILED", "FAILED"),
        ("UNVERIFIED", "WORKSPACE_PROVISIONING_UNCERTAIN", "RECOVERY_REQUIRED"),
    ],
)
def test_failure_and_attention_events_build_fail_closed_projection(
    resource_state: str,
    reason: str,
    preparation_state: str,
) -> None:
    result = EventsApi().restore_task_projection(
        _failure_events(resource_state=resource_state, attention_reason=reason)
    )
    projection = as_mapping(field(result, "projection"))
    workspace = as_mapping(projection["workspace"])
    preparation = as_mapping(projection["preparation"])
    failure = as_mapping(projection["failure"])

    assert projection["lifecycle_state"] == "NEEDS_ATTENTION"
    assert projection["health"] == "NEEDS_ATTENTION"
    assert workspace["availability"] == resource_state
    assert preparation["workspace"] == preparation_state
    assert failure["reason"] == reason


def test_failure_without_attention_is_a_valid_terminal_prefix() -> None:
    result = EventsApi().restore_task_projection(_failure_events(include_attention=False))
    projection = as_mapping(field(result, "projection"))

    assert projection["lifecycle_state"] == "PREPARING"
    assert projection["health"] == "NEEDS_ATTENTION"


@pytest.mark.parametrize(
    ("builder", "expected_message"),
    [
        (
            lambda: _prepared_events(action_digest="f" * 64),
            "EVENT_PAYLOAD_INVALID",
        ),
        (
            lambda: _prepared_events(ownership_nonce="f" * 32),
            "EVENT_PAYLOAD_INVALID",
        ),
        (
            lambda: _failure_events(action_digest="f" * 64, include_attention=False),
            "EVENT_PAYLOAD_INVALID",
        ),
        (
            lambda: _failure_events(attention_reason="WORKSPACE_PROVISIONING_UNCERTAIN"),
            "EVENT_PAYLOAD_INVALID",
        ),
    ],
)
def test_terminal_facts_must_bind_authorized_action_and_resource_state(
    builder: Any,
    expected_message: str,
) -> None:
    assert_validation_error(
        lambda: EventsApi().restore_task_projection(builder()),
        expected_message,
    )


def test_preparation_digest_must_be_recomputable_from_authoritative_facts() -> None:
    events = authorization_events()
    payload = as_mapping(events[1]["payload"])
    payload["proposed_action_digest"] = "f" * 64
    events[1]["payload"] = payload
    events = rehash_chain(events)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_PAYLOAD_INVALID",
    )


def test_authorization_must_bind_preparation_and_baseline() -> None:
    events = authorization_events()
    payload = as_mapping(events[2]["payload"])
    payload["workspace_relative_path"] = "tasks/other/workspace"
    events[2]["payload"] = payload
    events = rehash_chain(events)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_PAYLOAD_INVALID",
    )


def test_first_event_cannot_claim_a_cause() -> None:
    events = authorization_events()
    events[0]["causation_id"] = CORRELATION_ID
    events = rehash_chain(events)

    assert_validation_error(
        lambda: EventsApi().restore_task_projection(events),
        "EVENT_CAUSATION_INVALID",
    )


def test_attention_reducer_is_defensive_when_failure_projection_is_absent() -> None:
    """覆盖 reducer 的防御分支；语义校验仍会拒绝孤立 Attention。"""

    created = authorization_events()[0]
    projection = event_domain._initial_projection(created)
    attention = _failure_events()[-1]

    event_domain._apply_event(projection, attention)

    assert projection["failure"] is None
    assert projection["lifecycle_state"] == "NEEDS_ATTENTION"


@pytest.mark.parametrize(
    "checkpoint",
    [None, "不是对象"],
)
def test_absent_or_non_mapping_checkpoint_falls_back_to_full_replay(
    checkpoint: object,
) -> None:
    result = EventsApi().restore_task_projection(
        authorization_events(),
        checkpoint=checkpoint,
    )

    assert field(result, "load_mode") == "FULL_REPLAY"


def test_checkpoint_missing_required_field_falls_back_to_full_replay() -> None:
    events = authorization_events()
    checkpoint = _checkpoint(events)
    checkpoint.pop("projection")

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert field(result, "load_mode") == "FULL_REPLAY"


def test_checkpoint_with_non_string_extra_key_falls_back_to_full_replay() -> None:
    events = authorization_events()
    checkpoint = cast(dict[object, object], _checkpoint(events))
    checkpoint[1] = "未获准键"

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert field(result, "load_mode") == "FULL_REPLAY"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("checkpoint_version", 2),
        ("projection_schema_version", 2),
        ("checkpoint_hash", "不是摘要"),
        ("through_sequence", False),
        ("through_sequence", 0),
        ("through_sequence", 4),
        ("through_event_hash", "f" * 64),
        ("projection", []),
    ],
)
def test_invalid_checkpoint_header_position_or_projection_falls_back(
    field_name: str,
    value: object,
) -> None:
    events = authorization_events()
    checkpoint = _checkpoint(events)
    checkpoint[field_name] = value
    if field_name != "checkpoint_hash":
        _rehash_checkpoint(checkpoint)

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert field(result, "load_mode") == "FULL_REPLAY"


def test_checkpoint_projection_must_equal_authoritative_prefix() -> None:
    events = authorization_events()
    checkpoint = _checkpoint(events)
    projection = as_mapping(checkpoint["projection"])
    projection["health"] = "伪造为未知状态"
    checkpoint["projection"] = projection
    _rehash_checkpoint(checkpoint)

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert field(result, "load_mode") == "FULL_REPLAY"


def test_checkpoint_canonicalization_error_falls_back_to_full_replay() -> None:
    events = authorization_events()
    checkpoint = _checkpoint(events)
    checkpoint["checkpoint_hash"] = "f" * 64
    checkpoint["untrusted_extension"] = object()

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert field(result, "load_mode") == "FULL_REPLAY"


def test_old_checkpoint_replays_prepared_tail() -> None:
    events = _prepared_events()
    checkpoint = _checkpoint(events[:3])

    result = EventsApi().restore_task_projection(events, checkpoint=checkpoint)
    workspace = as_mapping(field(field(result, "projection"), "workspace"))

    assert field(result, "load_mode") == "CHECKPOINT"
    assert workspace["availability"] == "AVAILABLE"


def test_checkpoint_inputs_are_not_mutated_during_restore() -> None:
    events = authorization_events()
    checkpoint = _checkpoint(events)
    before = deepcopy(checkpoint)

    EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    assert checkpoint == before
