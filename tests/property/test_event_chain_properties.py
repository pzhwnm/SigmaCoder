"""T01 事件规范化与重建的属性 RED 测试。"""

from __future__ import annotations

import json
import string
from collections.abc import Callable, Mapping
from copy import deepcopy
from itertools import permutations
from typing import Any, Literal, cast

import pytest
from hypothesis import strategies as st
from tests.support.event_contract import (
    BASELINE_OID,
    CORRELATION_ID,
    OWNERSHIP_NONCE,
    TASK_ID,
    WORKSPACE_RELATIVE_PATH,
    EventsApi,
    as_mapping,
    authorization_events,
    canonical_oracle,
    checkpoint_hash_oracle,
    event_hash_oracle,
    rehash_chain,
)
from tests.support.event_property_cases import EventCase

from sigmacoder.application.task_service import TaskService

ASCII_KEYS = st.text(alphabet=string.ascii_letters, min_size=1, max_size=12)
EXCLUDED_CATEGORIES: tuple[Literal["Cs"], ...] = ("Cs",)
JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    st.text(alphabet=st.characters(exclude_categories=EXCLUDED_CATEGORIES), max_size=30),
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=6),
        st.dictionaries(ASCII_KEYS, children, max_size=6),
    ),
    max_leaves=20,
)
PREPARED_EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4"
ATTENTION_EVENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5"


def _append_event(
    events: list[dict[str, object]],
    event_type: str,
    payload: Mapping[str, object],
    *,
    event_id: str,
) -> None:
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


def _expected_projection(events: list[dict[str, object]]) -> dict[str, object]:
    events = sorted(events, key=lambda event: int(event["sequence"]))
    normalized_events = json.loads(canonical_oracle(events))
    if not isinstance(normalized_events, list):
        raise AssertionError("事件规范化预言机必须返回列表。")
    events = normalized_events
    created = as_mapping(events[0]["payload"])
    projection: dict[str, object] = {
        "projection_schema_version": 1,
        "task_id": events[0]["task_id"],
        "objective": created["objective"],
        "lifecycle_state": "CREATED",
        "health": "HEALTHY",
        "baseline": {
            "repository_realpath": created["repository_realpath"],
            "git_common_dir_realpath": created["git_common_dir_realpath"],
            "object_format": created["object_format"],
            "commit_oid": created["baseline_commit"],
            "source_dirty": created["source_dirty"],
            "dirty_content_included": created["dirty_content_included"],
        },
        "workspace": {
            "kind": "git_linked_worktree",
            "mode": "DETACHED",
            "relative_path": None,
            "head_oid": None,
            "availability": "NOT_CREATED",
            "ownership_nonce": None,
            "action_digest": None,
            "git_pointer_digest": None,
        },
        "preparation": {
            "workspace": "NOT_STARTED",
            "event_store": "READY",
            "sandbox": "NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS",
            "agent_run": "NOT_STARTED",
        },
        "failure": None,
        "event_position": {
            "sequence": events[0]["sequence"],
            "event_hash": events[0]["event_hash"],
        },
        "runtime": {
            "process_restored": False,
            "terminal_restored": False,
            "memory_restored": False,
            "network_transaction_restored": False,
        },
    }
    workspace = as_mapping(projection["workspace"])
    preparation = as_mapping(projection["preparation"])
    for event in events[1:]:
        event_type = event["event_type"]
        payload = as_mapping(event["payload"])
        if event_type == "TaskPreparationStartedV1":
            projection["lifecycle_state"] = "PREPARING"
            workspace["relative_path"] = payload["workspace_relative_path"]
            workspace["ownership_nonce"] = payload["ownership_nonce"]
            workspace["action_digest"] = payload["proposed_action_digest"]
            preparation["workspace"] = "PREPARING"
        elif event_type == "WorkspaceProvisioningAuthorizedV1":
            workspace["relative_path"] = payload["workspace_relative_path"]
            workspace["ownership_nonce"] = payload["ownership_nonce"]
            workspace["action_digest"] = payload["action_digest"]
        elif event_type == "TaskWorkspacePreparedV1":
            workspace["head_oid"] = payload["head_oid"]
            workspace["availability"] = "AVAILABLE"
            workspace["git_pointer_digest"] = payload["git_pointer_digest"]
            preparation["workspace"] = "READY"
        elif event_type == "TaskWorkspaceProvisioningFailedV1":
            resource_state = payload["resource_state"]
            projection["health"] = "NEEDS_ATTENTION"
            workspace["availability"] = resource_state
            workspace["head_oid"] = None
            preparation["workspace"] = (
                "FAILED" if resource_state == "NOT_CREATED" else "RECOVERY_REQUIRED"
            )
            projection["failure"] = {
                "stage": payload["failure_stage"],
                "error_code": payload["error_code"],
                "diagnostic": payload["diagnostic"],
                "reason": None,
            }
        elif event_type == "TaskAttentionRequiredV1":
            projection["lifecycle_state"] = "NEEDS_ATTENTION"
            projection["health"] = "NEEDS_ATTENTION"
            failure = as_mapping(projection["failure"])
            failure["reason"] = payload["reason"]
            projection["failure"] = failure
        projection["workspace"] = workspace
        projection["preparation"] = preparation
        projection["event_position"] = {
            "sequence": event["sequence"],
            "event_hash": event["event_hash"],
        }
    return projection


def _assert_exact_restore(
    events: list[dict[str, object]],
    *,
    checkpoint: object | None = None,
    load_mode: str = "FULL_REPLAY",
) -> None:
    ordered = sorted(events, key=lambda event: int(event["sequence"]))
    actual = as_mapping(EventsApi().restore_task_projection(events, checkpoint=checkpoint))
    projection = _expected_projection(ordered)
    expected_checkpoint: dict[str, object] = {
        "checkpoint_version": 1,
        "task_id": ordered[0]["task_id"],
        "through_sequence": ordered[-1]["sequence"],
        "through_event_hash": ordered[-1]["event_hash"],
        "projection_schema_version": 1,
        "projection": deepcopy(projection),
    }
    expected_checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(expected_checkpoint)

    assert actual == {
        "projection": projection,
        "through_sequence": ordered[-1]["sequence"],
        "through_event_hash": ordered[-1]["event_hash"],
        "load_mode": load_mode,
        "checkpoint": expected_checkpoint,
    }


def _assert_domain_failure(
    events: list[dict[str, object]] | list[object],
    expected_code: str,
    expected_message: str,
    *,
    checkpoint: object | None = None,
) -> None:
    with pytest.raises(Exception) as captured:
        EventsApi().restore_task_projection(events, checkpoint=checkpoint)
    error = captured.value
    assert type(error).__name__ == "DomainValidationError"
    assert getattr(error, "code", None) == expected_code
    assert str(error) == expected_message


def _assert_public_multi_malformed_failure(
    events: list[dict[str, object]],
    applicable_codes: frozenset[str],
    *,
    checkpoint: object | None = None,
) -> None:
    """断言公开的多重畸形契约，不约束私有首错与诊断文案。"""

    events_before = deepcopy(events)
    checkpoint_before = deepcopy(checkpoint)
    projection_before = (
        deepcopy(checkpoint.get("projection")) if isinstance(checkpoint, Mapping) else None
    )

    with pytest.raises(Exception) as captured:
        EventsApi().restore_task_projection(events, checkpoint=checkpoint)

    error = captured.value
    assert type(error).__name__ == "DomainValidationError"
    assert getattr(error, "code", None) in applicable_codes
    assert events == events_before
    assert checkpoint == checkpoint_before
    if isinstance(checkpoint, Mapping):
        assert checkpoint.get("projection") == projection_before


DAMAGE_KINDS = (
    "DELETE_MIDDLE_SEQUENCE",
    "DUPLICATE_SEQUENCE",
    "PAYLOAD_WITHOUT_REHASH",
    "PREVIOUS_HASH",
    "EVENT_HASH",
    "TYPED_PAYLOAD_WITH_REHASH",
    "CAUSATION_WITH_REHASH",
    "TRANSITION_WITH_REHASH",
    "PHYSICAL_ROTATION",
)


def _different_digest(value: object) -> str:
    return "e" * 64 if value == "f" * 64 else "f" * 64


def _delete_middle_sequence(
    events: list[dict[str, object]], case: EventCase
) -> list[dict[str, object]]:
    del case
    events.pop(1)
    return events


def _duplicate_sequence(
    events: list[dict[str, object]], case: EventCase
) -> list[dict[str, object]]:
    del case
    events[2]["sequence"] = 2
    return events


def _change_payload_without_rehash(
    events: list[dict[str, object]], case: EventCase
) -> list[dict[str, object]]:
    del case
    payload = as_mapping(events[0]["payload"])
    payload["objective"] = f"{payload['objective']}被篡改"
    events[0]["payload"] = payload
    return events


def _change_previous_hash(
    events: list[dict[str, object]], case: EventCase
) -> list[dict[str, object]]:
    del case
    events[1]["previous_hash"] = _different_digest(events[1]["previous_hash"])
    return events


def _change_event_hash(events: list[dict[str, object]], case: EventCase) -> list[dict[str, object]]:
    del case
    events[-1]["event_hash"] = _different_digest(events[-1]["event_hash"])
    return events


def _change_typed_payload(
    events: list[dict[str, object]], case: EventCase
) -> list[dict[str, object]]:
    del case
    payload = as_mapping(events[0]["payload"])
    payload["source_dirty"] = 1
    events[0]["payload"] = payload
    return rehash_chain(events)


def _change_causation(events: list[dict[str, object]], case: EventCase) -> list[dict[str, object]]:
    events[1]["causation_id"] = case.correlation_id
    return rehash_chain(events)


def _change_transition(events: list[dict[str, object]], case: EventCase) -> list[dict[str, object]]:
    del case
    second_type, second_payload = events[1]["event_type"], events[1]["payload"]
    events[1]["event_type"], events[1]["payload"] = (
        events[2]["event_type"],
        events[2]["payload"],
    )
    events[2]["event_type"], events[2]["payload"] = second_type, second_payload
    return rehash_chain(events)


DAMAGE_MUTATORS: dict[
    str, Callable[[list[dict[str, object]], EventCase], list[dict[str, object]]]
] = {
    "DELETE_MIDDLE_SEQUENCE": _delete_middle_sequence,
    "DUPLICATE_SEQUENCE": _duplicate_sequence,
    "PAYLOAD_WITHOUT_REHASH": _change_payload_without_rehash,
    "PREVIOUS_HASH": _change_previous_hash,
    "EVENT_HASH": _change_event_hash,
    "TYPED_PAYLOAD_WITH_REHASH": _change_typed_payload,
    "CAUSATION_WITH_REHASH": _change_causation,
    "TRANSITION_WITH_REHASH": _change_transition,
}

DAMAGE_ERRORS = {
    "DELETE_MIDDLE_SEQUENCE": (
        "EVENT_SEQUENCE_GAP",
        "事件流的逻辑 sequence 存在缺口。",
    ),
    "DUPLICATE_SEQUENCE": (
        "EVENT_SEQUENCE_DUPLICATE",
        "事件流包含重复逻辑 sequence。",
    ),
    "PAYLOAD_WITHOUT_REHASH": (
        "EVENT_HASH_MISMATCH",
        "事件 event_hash 与规范化内容不一致。",
    ),
    "PREVIOUS_HASH": (
        "EVENT_PREVIOUS_HASH_MISMATCH",
        "事件 previous_hash 与前序事实不一致。",
    ),
    "EVENT_HASH": (
        "EVENT_HASH_MISMATCH",
        "事件 event_hash 与规范化内容不一致。",
    ),
    "TYPED_PAYLOAD_WITH_REHASH": (
        "EVENT_PAYLOAD_INVALID",
        "TaskCreatedV1 payload 字段类型或取值不合法。",
    ),
    "CAUSATION_WITH_REHASH": (
        "EVENT_CAUSATION_INVALID",
        "事件没有因果指向直接前序事实。",
    ),
    "TRANSITION_WITH_REHASH": (
        "EVENT_TRANSITION_INVALID",
        "事件类型不符合 T01 状态转换协议。",
    ),
}


def test_all_durable_terminal_paths_match_full_spec_oracle() -> None:
    streams = [
        authorization_events(),
        _prepared_events(),
        _failure_events(),
        _failure_events(resource_state="UNVERIFIED"),
    ]

    for events in streams:
        for reordered in permutations(events):
            _assert_exact_restore(list(reordered))


@pytest.mark.parametrize(
    ("value", "error_type", "message"),
    [
        (object(), TypeError, "不受支持的 JSON 值类型：object"),
        (1.5, TypeError, "不受支持的 JSON 值类型：float"),
        ({1: "值"}, TypeError, "规范化对象的键必须是字符串。"),
        (
            {"é": 1, "e\u0301": 2},
            ValueError,
            "对象键经过 Unicode NFC 规范化后发生碰撞。",
        ),
    ],
)
def test_canonicalization_rejects_non_spec_values_with_exact_error(
    value: object,
    error_type: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error_type) as captured:
        EventsApi().canonical_json_bytes(value)
    assert str(captured.value) == message


def test_envelope_validation_matrix_has_stable_codes_and_messages() -> None:
    cases: list[tuple[str, object, str, str]] = [
        (
            "event_id",
            "NOT-A-UUID",
            "EVENT_ENVELOPE_INVALID",
            "事件标识和任务标识必须是规范 UUIDv4。",
        ),
        (
            "task_id",
            "99999999-9999-3999-8999-999999999999",
            "EVENT_ENVELOPE_INVALID",
            "事件标识和任务标识必须是规范 UUIDv4。",
        ),
        (
            "sequence",
            False,
            "EVENT_ENVELOPE_INVALID",
            "事件 sequence 必须是从 1 开始的正整数。",
        ),
        (
            "sequence",
            0,
            "EVENT_ENVELOPE_INVALID",
            "事件 sequence 必须是从 1 开始的正整数。",
        ),
        (
            "event_type",
            "UnknownEventV1",
            "UNSUPPORTED_EVENT_SCHEMA",
            "事件类型或 schema_version 不受支持。",
        ),
        (
            "event_type",
            7,
            "UNSUPPORTED_EVENT_SCHEMA",
            "事件类型或 schema_version 不受支持。",
        ),
        (
            "event_id",
            7,
            "EVENT_ENVELOPE_INVALID",
            "事件标识和任务标识必须是规范 UUIDv4。",
        ),
        (
            "schema_version",
            False,
            "UNSUPPORTED_EVENT_SCHEMA",
            "事件类型或 schema_version 不受支持。",
        ),
        (
            "schema_version",
            2,
            "UNSUPPORTED_EVENT_SCHEMA",
            "事件类型或 schema_version 不受支持。",
        ),
        (
            "occurred_at",
            None,
            "EVENT_ENVELOPE_INVALID",
            "occurred_at 必须是含六位微秒的 UTC RFC 3339。",
        ),
        (
            "occurred_at",
            "2026-13-21T00:00:01.000000Z",
            "EVENT_ENVELOPE_INVALID",
            "occurred_at 必须是含六位微秒的 UTC RFC 3339。",
        ),
        (
            "actor",
            "model",
            "EVENT_ENVELOPE_INVALID",
            "actor 或 sensitivity 不符合 T01 固定语义。",
        ),
        (
            "sensitivity",
            "PUBLIC",
            "EVENT_ENVELOPE_INVALID",
            "actor 或 sensitivity 不符合 T01 固定语义。",
        ),
        (
            "correlation_id",
            "not-a-uuid",
            "EVENT_ENVELOPE_INVALID",
            "correlation_id 必须是规范 UUIDv4。",
        ),
        (
            "correlation_id",
            7,
            "EVENT_ENVELOPE_INVALID",
            "correlation_id 必须是规范 UUIDv4。",
        ),
        (
            "causation_id",
            7,
            "EVENT_ENVELOPE_INVALID",
            "causation_id 必须为 null 或规范 UUIDv4。",
        ),
        (
            "causation_id",
            "not-a-uuid",
            "EVENT_ENVELOPE_INVALID",
            "causation_id 必须为 null 或规范 UUIDv4。",
        ),
        (
            "workspace_revision",
            "revision",
            "EVENT_ENVELOPE_INVALID",
            "T01 的 workspace_revision 必须为 null。",
        ),
        (
            "payload",
            [],
            "EVENT_PAYLOAD_INVALID",
            "事件 payload 必须是对象。",
        ),
        (
            "previous_hash",
            "F" * 64,
            "EVENT_ENVELOPE_INVALID",
            "事件哈希必须是 64 位小写十六进制。",
        ),
        (
            "event_hash",
            "f" * 63,
            "EVENT_ENVELOPE_INVALID",
            "事件哈希必须是 64 位小写十六进制。",
        ),
    ]
    for field_name, value, code, message in cases:
        events = authorization_events()
        if field_name == "task_id":
            for event in events:
                event[field_name] = value
        else:
            events[0][field_name] = value
        _assert_domain_failure(events, code, message)

    for mutate in (
        lambda event: event.pop("actor"),
        lambda event: event.__setitem__("unexpected", True),
    ):
        events = authorization_events()
        mutate(events[0])
        _assert_domain_failure(
            events,
            "EVENT_ENVELOPE_INVALID",
            "事件信封字段不完整或包含未获准字段。",
        )


def test_public_multi_malformed_contract_fails_closed_without_side_effects() -> None:
    """公开契约只约束稳定失败集合；前置畸形之间的首错选择是私有细节。"""

    cases: list[tuple[list[dict[str, object]], frozenset[str]]] = []

    schema_and_identifier = authorization_events()
    schema_and_identifier[0]["event_type"] = "UnknownEventV1"
    schema_and_identifier[0]["event_id"] = "not-a-uuid"
    cases.append(
        (
            schema_and_identifier,
            frozenset({"UNSUPPORTED_EVENT_SCHEMA", "EVENT_ENVELOPE_INVALID"}),
        )
    )

    row_schema_and_envelope = authorization_events()
    row_schema_and_envelope[0]["actor"] = "model"
    row_schema_and_envelope[1]["event_type"] = "UnknownEventV1"
    cases.append(
        (
            row_schema_and_envelope,
            frozenset({"EVENT_ENVELOPE_INVALID", "UNSUPPORTED_EVENT_SCHEMA"}),
        )
    )

    task_and_identifier = authorization_events()
    task_and_identifier[1]["task_id"] = "99999999-9999-4999-8999-999999999999"
    task_and_identifier[1]["event_id"] = "not-a-uuid"
    cases.append(
        (
            task_and_identifier,
            frozenset({"EVENT_TASK_ID_MISMATCH", "EVENT_ENVELOPE_INVALID"}),
        )
    )

    identity_and_sequence = authorization_events()
    identity_and_sequence[2]["event_id"] = identity_and_sequence[1]["event_id"]
    identity_and_sequence[2]["sequence"] = 2
    cases.append(
        (
            identity_and_sequence,
            frozenset({"EVENT_ID_DUPLICATE", "EVENT_SEQUENCE_DUPLICATE"}),
        )
    )

    sequence_and_chain = authorization_events()
    sequence_and_chain.pop(1)
    sequence_and_chain[1]["previous_hash"] = "f" * 64
    cases.append(
        (
            sequence_and_chain,
            frozenset({"EVENT_SEQUENCE_GAP", "EVENT_PREVIOUS_HASH_MISMATCH"}),
        )
    )

    previous_and_hash = authorization_events()
    previous_and_hash[1]["previous_hash"] = "f" * 64
    previous_and_hash[1]["event_hash"] = "f" * 64
    cases.append(
        (
            previous_and_hash,
            frozenset({"EVENT_PREVIOUS_HASH_MISMATCH", "EVENT_HASH_MISMATCH"}),
        )
    )

    hash_phases = authorization_events()
    hash_phases[0]["event_hash"] = "f" * 64
    hash_phases[2]["previous_hash"] = "e" * 64
    cases.append(
        (
            hash_phases,
            frozenset({"EVENT_PREVIOUS_HASH_MISMATCH", "EVENT_HASH_MISMATCH"}),
        )
    )

    hash_and_payload = authorization_events()
    payload = as_mapping(hash_and_payload[0]["payload"])
    payload["source_dirty"] = 1
    hash_and_payload[0]["payload"] = payload
    cases.append(
        (
            hash_and_payload,
            frozenset({"EVENT_HASH_MISMATCH", "EVENT_PAYLOAD_INVALID"}),
        )
    )

    payload_and_causation = authorization_events()
    payload = as_mapping(payload_and_causation[1]["payload"])
    payload["proposed_action_digest"] = "f" * 64
    payload_and_causation[1]["payload"] = payload
    payload_and_causation[1]["causation_id"] = CORRELATION_ID
    payload_and_causation = rehash_chain(payload_and_causation)
    cases.append(
        (
            payload_and_causation,
            frozenset({"EVENT_PAYLOAD_INVALID", "EVENT_CAUSATION_INVALID"}),
        )
    )

    causation_and_transition = authorization_events()
    second_type = causation_and_transition[1]["event_type"]
    second_payload = causation_and_transition[1]["payload"]
    causation_and_transition[1]["event_type"] = causation_and_transition[2]["event_type"]
    causation_and_transition[1]["payload"] = causation_and_transition[2]["payload"]
    causation_and_transition[2]["event_type"] = second_type
    causation_and_transition[2]["payload"] = second_payload
    causation_and_transition[1]["causation_id"] = CORRELATION_ID
    causation_and_transition = rehash_chain(causation_and_transition)
    cases.append(
        (
            causation_and_transition,
            frozenset({"EVENT_CAUSATION_INVALID", "EVENT_TRANSITION_INVALID"}),
        )
    )

    restored = as_mapping(EventsApi().restore_task_projection(authorization_events()))
    checkpoint_template = deepcopy(as_mapping(restored["checkpoint"]))

    for events, applicable_codes in cases:
        for physical_order in (events, list(reversed(events))):
            candidate = deepcopy(physical_order)
            checkpoint = deepcopy(checkpoint_template)
            _assert_public_multi_malformed_failure(
                candidate,
                applicable_codes,
                checkpoint=checkpoint,
            )


def test_private_regression_compound_failures_keep_current_first_error_priority() -> None:
    """私有回归锁定当前诊断便利性，不发布为多重畸形的首错协议。"""

    cases: list[tuple[list[dict[str, object]], str, str]] = []

    schema_before_uuid = authorization_events()
    schema_before_uuid[0]["event_type"] = "UnknownEventV1"
    schema_before_uuid[0]["event_id"] = "not-a-uuid"
    cases.append(
        (
            schema_before_uuid,
            "UNSUPPORTED_EVENT_SCHEMA",
            "事件类型或 schema_version 不受支持。",
        )
    )

    schema_row_order = authorization_events()
    schema_row_order[0]["actor"] = "model"
    schema_row_order[1]["event_type"] = "UnknownEventV1"
    cases.append(
        (
            schema_row_order,
            "EVENT_ENVELOPE_INVALID",
            "actor 或 sensitivity 不符合 T01 固定语义。",
        )
    )

    task_before_uuid = authorization_events()
    task_before_uuid[1]["task_id"] = "99999999-9999-4999-8999-999999999999"
    task_before_uuid[1]["event_id"] = "not-a-uuid"
    cases.append(
        (
            task_before_uuid,
            "EVENT_TASK_ID_MISMATCH",
            "同一事件流包含不同 task_id。",
        )
    )

    identity_before_sequence = authorization_events()
    identity_before_sequence[2]["event_id"] = identity_before_sequence[1]["event_id"]
    identity_before_sequence[2]["sequence"] = 2
    cases.append(
        (
            identity_before_sequence,
            "EVENT_ID_DUPLICATE",
            "事件流包含重复 event_id。",
        )
    )

    sequence_before_chain = authorization_events()
    sequence_before_chain.pop(1)
    sequence_before_chain[1]["previous_hash"] = "f" * 64
    cases.append(
        (
            sequence_before_chain,
            "EVENT_SEQUENCE_GAP",
            "事件流的逻辑 sequence 存在缺口。",
        )
    )

    previous_before_hash = authorization_events()
    previous_before_hash[1]["previous_hash"] = "f" * 64
    previous_before_hash[1]["event_hash"] = "f" * 64
    cases.append(
        (
            previous_before_hash,
            "EVENT_PREVIOUS_HASH_MISMATCH",
            "事件 previous_hash 与前序事实不一致。",
        )
    )

    previous_phase_before_event_hash_phase = authorization_events()
    previous_phase_before_event_hash_phase[0]["event_hash"] = "f" * 64
    previous_phase_before_event_hash_phase[2]["previous_hash"] = "e" * 64
    cases.append(
        (
            previous_phase_before_event_hash_phase,
            "EVENT_PREVIOUS_HASH_MISMATCH",
            "事件 previous_hash 与前序事实不一致。",
        )
    )

    hash_before_payload = authorization_events()
    payload = as_mapping(hash_before_payload[0]["payload"])
    payload["source_dirty"] = 1
    hash_before_payload[0]["payload"] = payload
    cases.append(
        (
            hash_before_payload,
            "EVENT_HASH_MISMATCH",
            "事件 event_hash 与规范化内容不一致。",
        )
    )

    payload_before_causation = authorization_events()
    payload = as_mapping(payload_before_causation[1]["payload"])
    payload["proposed_action_digest"] = "f" * 64
    payload_before_causation[1]["payload"] = payload
    payload_before_causation[1]["causation_id"] = CORRELATION_ID
    payload_before_causation = rehash_chain(payload_before_causation)
    cases.append(
        (
            payload_before_causation,
            "EVENT_PAYLOAD_INVALID",
            "workspace 提议的 action_digest 无法由权威事实重算。",
        )
    )

    causation_before_transition = authorization_events()
    second_type = causation_before_transition[1]["event_type"]
    second_payload = causation_before_transition[1]["payload"]
    causation_before_transition[1]["event_type"] = causation_before_transition[2]["event_type"]
    causation_before_transition[1]["payload"] = causation_before_transition[2]["payload"]
    causation_before_transition[2]["event_type"] = second_type
    causation_before_transition[2]["payload"] = second_payload
    causation_before_transition[1]["causation_id"] = CORRELATION_ID
    causation_before_transition = rehash_chain(causation_before_transition)
    cases.append(
        (
            causation_before_transition,
            "EVENT_CAUSATION_INVALID",
            "事件没有因果指向直接前序事实。",
        )
    )

    for events, code, message in cases:
        _assert_domain_failure(events, code, message)
        _assert_domain_failure(list(reversed(events)), code, message)


def test_payload_schema_matrix_rejects_every_value_family() -> None:
    cases: list[
        tuple[
            Any,
            int,
            str,
            object,
        ]
    ] = [
        (authorization_events, 0, "objective", ""),
        (authorization_events, 0, "object_format", "sha2"),
        (authorization_events, 0, "baseline_commit", "1" * 39),
        (authorization_events, 0, "source_dirty", 1),
        (authorization_events, 0, "dirty_content_included", True),
        (authorization_events, 1, "workspace_relative_path", ""),
        (authorization_events, 1, "ownership_nonce", "A" * 32),
        (authorization_events, 1, "proposed_action_digest", "A" * 64),
        (authorization_events, 2, "bootstrap_policy_id", "other"),
        (authorization_events, 2, "decision", "MANUAL"),
        (authorization_events, 2, "mode", "ATTACHED"),
        (_prepared_events, 3, "git_pointer_digest", "A" * 64),
        (_prepared_events, 3, "recovered_after_interruption", 0),
        (_failure_events, 3, "failure_stage", ""),
        (_failure_events, 3, "error_code", "lowercase"),
        (_failure_events, 3, "resource_state", "UNKNOWN"),
        (_failure_events, 3, "diagnostic", 7),
        (_failure_events, 4, "reason", "UNKNOWN"),
    ]
    for builder, event_index, field_name, value in cases:
        events = builder()
        payload = as_mapping(events[event_index]["payload"])
        payload[field_name] = value
        event_type = str(events[event_index]["event_type"])
        events[event_index]["payload"] = payload
        events = rehash_chain(events)
        _assert_domain_failure(
            events,
            "EVENT_PAYLOAD_INVALID",
            f"{event_type} payload 字段类型或取值不合法。",
        )

    for builder, event_index in (
        (authorization_events, 0),
        (authorization_events, 1),
        (authorization_events, 2),
        (_prepared_events, 3),
        (_failure_events, 3),
        (_failure_events, 4),
    ):
        events = builder()
        payload = as_mapping(events[event_index]["payload"])
        payload.pop(next(iter(payload)))
        event_type = str(events[event_index]["event_type"])
        events[event_index]["payload"] = payload
        events = rehash_chain(events)
        _assert_domain_failure(
            events,
            "EVENT_PAYLOAD_INVALID",
            f"{event_type} payload 字段不符合 schema v1。",
        )


@pytest.mark.parametrize(
    "value",
    [
        7,
        "relative/repository",
        "/fixture//repository",
        "/fixture/./repository",
        "/fixture/../repository",
        "/fixture/cafe\u0301",
        r"C:\fixture/repository",
        r"C:\fixture\..\repository",
    ],
)
def test_absolute_repository_path_boundaries_fail_closed(value: object) -> None:
    events = authorization_events(repository_realpath=cast(Any, value))

    _assert_domain_failure(
        events,
        "EVENT_PAYLOAD_INVALID",
        "TaskCreatedV1 payload 字段类型或取值不合法。",
    )


@pytest.mark.parametrize(
    "value",
    [
        "/fixture/XX.XX/repository",
        r"C:\fixture\XX.XX\repository",
    ],
)
def test_absolute_repository_path_positive_controls_preserve_bytes(value: str) -> None:
    actual = as_mapping(
        EventsApi().restore_task_projection(authorization_events(repository_realpath=value))
    )
    projection = as_mapping(actual["projection"])
    baseline = as_mapping(projection["baseline"])

    assert baseline["repository_realpath"] == value


@pytest.mark.parametrize(
    "value",
    [
        7,
        "tasks/cafe\u0301",
        r"tasks\name",
        "tasks/../name",
        "tasks//name",
        "/tasks/name",
        "tasks/CON",
        "tasks/con.txt",
        "tasks/CON.foo.bar",
        "tasks/name.",
        "tasks/name ",
    ],
)
def test_workspace_relative_path_boundaries_fail_closed(value: object) -> None:
    events = authorization_events(workspace_relative_path=cast(Any, value))

    _assert_domain_failure(
        events,
        "EVENT_PAYLOAD_INVALID",
        "TaskPreparationStartedV1 payload 字段类型或取值不合法。",
    )


@pytest.mark.parametrize("value", ["tasks/nameX", "tasks/XX.XX", "tasks/XX..XX"])
def test_portable_relative_path_positive_controls_preserve_bytes(value: str) -> None:
    actual = as_mapping(
        EventsApi().restore_task_projection(authorization_events(workspace_relative_path=value))
    )
    projection = as_mapping(actual["projection"])
    workspace = as_mapping(projection["workspace"])

    assert workspace["relative_path"] == value


def test_non_string_oid_and_uppercase_uuid4_fail_closed() -> None:
    _assert_domain_failure(
        authorization_events(baseline_commit=cast(Any, 7)),
        "EVENT_PAYLOAD_INVALID",
        "TaskCreatedV1 payload 字段类型或取值不合法。",
    )
    _assert_domain_failure(
        authorization_events(task_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
        "EVENT_ENVELOPE_INVALID",
        "事件标识和任务标识必须是规范 UUIDv4。",
    )


def test_stream_hash_causation_transition_and_binding_matrix() -> None:
    _assert_domain_failure(
        _failure_events(include_attention=False),
        "EVENT_TRANSITION_INVALID",
        "失败事实必须与注意状态在同一耐久事务完成。",
    )
    events = authorization_events()
    events[1]["task_id"] = "99999999-9999-4999-8999-999999999999"
    _assert_domain_failure(
        events,
        "EVENT_TASK_ID_MISMATCH",
        "同一事件流包含不同 task_id。",
    )

    events = authorization_events()
    events[2]["event_id"] = events[1]["event_id"]
    _assert_domain_failure(events, "EVENT_ID_DUPLICATE", "事件流包含重复 event_id。")

    events = authorization_events()
    events[2]["sequence"] = 2
    _assert_domain_failure(
        events,
        "EVENT_SEQUENCE_DUPLICATE",
        "事件流包含重复逻辑 sequence。",
    )

    events = authorization_events()
    _assert_domain_failure(
        [events[0], events[2]],
        "EVENT_SEQUENCE_GAP",
        "事件流的逻辑 sequence 存在缺口。",
    )

    events = authorization_events()
    events[1]["previous_hash"] = "f" * 64
    _assert_domain_failure(
        events,
        "EVENT_PREVIOUS_HASH_MISMATCH",
        "事件 previous_hash 与前序事实不一致。",
    )

    events = authorization_events()
    events[-1]["event_hash"] = "f" * 64
    _assert_domain_failure(
        events,
        "EVENT_HASH_MISMATCH",
        "事件 event_hash 与规范化内容不一致。",
    )

    events = authorization_events()
    payload = as_mapping(events[0]["payload"])
    payload["objective"] = object()
    events[0]["payload"] = payload
    _assert_domain_failure(
        events,
        "EVENT_HASH_MISMATCH",
        "事件无法按规范重新计算哈希。",
    )

    events = authorization_events()
    events[0]["causation_id"] = CORRELATION_ID
    events = rehash_chain(events)
    _assert_domain_failure(
        events,
        "EVENT_CAUSATION_INVALID",
        "首事件 causation_id 必须为 null。",
    )

    events = authorization_events()
    events[1]["causation_id"] = CORRELATION_ID
    events = rehash_chain(events)
    _assert_domain_failure(
        events,
        "EVENT_CAUSATION_INVALID",
        "事件没有因果指向直接前序事实。",
    )

    events = authorization_events()
    second_type, second_payload = events[1]["event_type"], events[1]["payload"]
    events[1]["event_type"], events[1]["payload"] = (
        events[2]["event_type"],
        events[2]["payload"],
    )
    events[2]["event_type"], events[2]["payload"] = second_type, second_payload
    events = rehash_chain(events)
    _assert_domain_failure(
        events,
        "EVENT_TRANSITION_INVALID",
        "事件类型不符合 T01 状态转换协议。",
    )

    binding_cases: list[tuple[Any, int, str, object, str]] = [
        (
            authorization_events,
            1,
            "proposed_action_digest",
            "f" * 64,
            "workspace 提议的 action_digest 无法由权威事实重算。",
        ),
        (
            authorization_events,
            2,
            "workspace_relative_path",
            "tasks/other/workspace",
            "workspace 授权没有逐字节绑定提议与 Task 事实。",
        ),
        (
            _prepared_events,
            3,
            "action_digest",
            "f" * 64,
            "workspace 终态没有绑定获准 action_digest。",
        ),
        (
            _prepared_events,
            3,
            "head_oid",
            "f" * 40,
            "Prepared 事实没有绑定授权或 baseline。",
        ),
        (
            _failure_events,
            3,
            "action_digest",
            "f" * 64,
            "workspace 终态没有绑定获准 action_digest。",
        ),
        (
            _failure_events,
            4,
            "reason",
            "WORKSPACE_PROVISIONING_UNCERTAIN",
            "Attention 原因与 workspace 资源状态不一致。",
        ),
    ]
    for builder, event_index, field_name, value, message in binding_cases:
        events = builder()
        payload = as_mapping(events[event_index]["payload"])
        payload[field_name] = value
        events[event_index]["payload"] = payload
        events = rehash_chain(events)
        _assert_domain_failure(events, "EVENT_PAYLOAD_INVALID", message)


def test_incomplete_transaction_prefixes_do_not_become_false_invalid_locations() -> None:
    assert TaskService._first_invalid_sequence(authorization_events()) is None
    assert TaskService._first_invalid_sequence(_failure_events()) is None


def test_empty_and_non_mapping_stream_members_fail_with_exact_errors() -> None:
    _assert_domain_failure(
        [],
        "EVENT_SEQUENCE_GAP",
        "事件流为空，缺少 sequence 1。",
    )
    _assert_domain_failure(
        [object()],
        "EVENT_ENVELOPE_INVALID",
        "事件流成员必须是对象。",
    )


def test_checkpoint_matrix_uses_only_verified_authoritative_prefixes() -> None:
    events = _prepared_events()
    for complete_events, through in (
        (events, 1),
        (events, 2),
        (_failure_events(), 4),
    ):
        prefix_projection = _expected_projection(complete_events[:through])
        prefix_checkpoint: dict[str, object] = {
            "checkpoint_version": 1,
            "task_id": complete_events[0]["task_id"],
            "through_sequence": through,
            "through_event_hash": complete_events[through - 1]["event_hash"],
            "projection_schema_version": 1,
            "projection": deepcopy(prefix_projection),
        }
        prefix_checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(prefix_checkpoint)
        checkpoint_before = deepcopy(prefix_checkpoint)
        _assert_exact_restore(
            complete_events,
            checkpoint=prefix_checkpoint,
            load_mode="CHECKPOINT",
        )
        assert prefix_checkpoint == checkpoint_before

    prefix_result = as_mapping(EventsApi().restore_task_projection(events[:3]))
    prefix_checkpoint = deepcopy(as_mapping(prefix_result["checkpoint"]))
    _assert_exact_restore(events, checkpoint=prefix_checkpoint, load_mode="CHECKPOINT")

    full_result = as_mapping(EventsApi().restore_task_projection(events))
    valid_checkpoint = deepcopy(as_mapping(full_result["checkpoint"]))
    corruptions: list[tuple[str, object, bool]] = [
        ("checkpoint_version", 2, True),
        ("projection_schema_version", 2, True),
        ("task_id", "99999999-9999-4999-8999-999999999999", True),
        ("checkpoint_hash", "f" * 64, False),
        ("through_sequence", False, True),
        ("through_sequence", 0, True),
        ("through_sequence", len(events) + 1, True),
        ("through_event_hash", "f" * 64, True),
        ("projection", [], True),
    ]
    for field_name, value, rehash in corruptions:
        checkpoint = deepcopy(valid_checkpoint)
        checkpoint[field_name] = value
        if rehash:
            checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)
        _assert_exact_restore(events, checkpoint=checkpoint)

    checkpoint_with_nonstring_key: dict[object, object] = dict(valid_checkpoint)
    checkpoint_with_nonstring_key[1] = "非法键"
    _assert_exact_restore(events, checkpoint=checkpoint_with_nonstring_key)

    checkpoint = deepcopy(valid_checkpoint)
    projection_with_nonstring_key: dict[object, object] = dict(as_mapping(checkpoint["projection"]))
    projection_with_nonstring_key[1] = "非法键"
    checkpoint["projection"] = projection_with_nonstring_key
    _assert_exact_restore(events, checkpoint=checkpoint)

    for nested_name in ("workspace", "preparation"):
        checkpoint = deepcopy(valid_checkpoint)
        projection = as_mapping(checkpoint["projection"])
        projection[nested_name] = []
        checkpoint["projection"] = projection
        checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)
        _assert_exact_restore(events, checkpoint=checkpoint)

    checkpoint = deepcopy(valid_checkpoint)
    projection = as_mapping(checkpoint["projection"])
    projection["health"] = "伪造状态"
    checkpoint["projection"] = projection
    checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)
    _assert_exact_restore(events, checkpoint=checkpoint)
