"""T01 事件域纯 Hypothesis 属性；供 property-only mutation 独立选择。"""

from __future__ import annotations

import json
import string
import unicodedata
from copy import deepcopy
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.property.test_event_chain_properties import (
    ASCII_KEYS,
    DAMAGE_ERRORS,
    DAMAGE_KINDS,
    DAMAGE_MUTATORS,
    JSON_SCALARS,
    JSON_VALUES,
    _assert_domain_failure,
    _assert_exact_restore,
)
from tests.support.event_contract import (
    EventsApi,
    as_mapping,
    authorization_events,
    canonical_oracle,
    checkpoint_hash_oracle,
    failed_events,
    rehash_chain,
)
from tests.support.event_property_cases import EventCase, event_cases

NFC_PAIR_PARTS = st.text(alphabet=string.ascii_letters + string.digits + "_-", max_size=12)


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(ASCII_KEYS, JSON_SCALARS, min_size=1, max_size=12))
def test_canonicalization_is_independent_of_mapping_insertion_order(
    value: dict[str, object],
) -> None:
    api = EventsApi()
    reversed_insertion = dict(reversed(list(value.items())))

    assert api.canonical_json_bytes(value) == api.canonical_json_bytes(reversed_insertion)


@settings(max_examples=200, deadline=None)
@given(JSON_VALUES)
def test_canonicalization_matches_independent_spec_oracle(value: object) -> None:
    assert EventsApi().canonical_json_bytes(value) == canonical_oracle(value)


@settings(max_examples=200, deadline=None)
@given(
    prefix=NFC_PAIR_PARTS,
    suffix=NFC_PAIR_PARTS,
    projected_field=st.sampled_from(("OBJECTIVE", "FAILURE_DIAGNOSTIC")),
)
def test_nfd_and_nfc_event_twins_restore_to_identical_python_objects(
    prefix: str,
    suffix: str,
    projected_field: str,
) -> None:
    nfd_value = f"{prefix}e\u0301{suffix}"
    nfc_value = unicodedata.normalize("NFC", nfd_value)
    assert nfd_value != nfc_value

    if projected_field == "OBJECTIVE":
        nfd_events = authorization_events(objective=nfd_value)
        nfc_events = authorization_events(objective=nfc_value)
    else:
        nfd_events = failed_events(
            authorization_events(),
            failure_event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
            attention_event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5",
            resource_state="NOT_CREATED",
        )
        nfc_events = deepcopy(nfd_events)
        for events, value in ((nfd_events, nfd_value), (nfc_events, nfc_value)):
            payload = as_mapping(events[3]["payload"])
            payload["diagnostic"] = value
            events[3]["payload"] = payload
        nfd_events = rehash_chain(nfd_events)
        nfc_events = rehash_chain(nfc_events)

    assert nfd_events != nfc_events
    assert canonical_oracle(nfd_events) == canonical_oracle(nfc_events)
    nfd_result = as_mapping(EventsApi().restore_task_projection(nfd_events))
    nfc_result = as_mapping(EventsApi().restore_task_projection(nfc_events))
    assert nfd_result == nfc_result
    assert canonical_oracle(nfd_result) == canonical_oracle(nfc_result)

    checkpoint = deepcopy(as_mapping(nfc_result["checkpoint"]))
    checkpoint_projection = as_mapping(checkpoint["projection"])
    if projected_field == "OBJECTIVE":
        checkpoint_projection["objective"] = nfd_value
    else:
        failure = as_mapping(checkpoint_projection["failure"])
        failure["diagnostic"] = nfd_value
        checkpoint_projection["failure"] = failure
    checkpoint["projection"] = checkpoint_projection
    checkpoint["checkpoint_hash"] = checkpoint_hash_oracle(checkpoint)

    from_checkpoint = as_mapping(
        EventsApi().restore_task_projection(nfc_events, checkpoint=checkpoint)
    )
    assert from_checkpoint["load_mode"] == "CHECKPOINT"
    assert from_checkpoint["projection"] == nfc_result["projection"]
    assert from_checkpoint["checkpoint"] == nfc_result["checkpoint"]


@settings(max_examples=200, deadline=None)
@given(event_cases())
def test_same_authoritative_event_bytes_have_exact_projection_and_round_trip(
    case: EventCase,
) -> None:
    wire_bytes = canonical_oracle(case.events)
    first_events = json.loads(wire_bytes)
    second_events = json.loads(wire_bytes)
    assert isinstance(first_events, list)
    assert isinstance(second_events, list)

    _assert_exact_restore(first_events)
    first = as_mapping(EventsApi().restore_task_projection(first_events))
    second = as_mapping(EventsApi().restore_task_projection(second_events))
    assert canonical_oracle(first) == canonical_oracle(second)

    projection = as_mapping(first["projection"])
    baseline = as_mapping(projection["baseline"])
    workspace = as_mapping(projection["workspace"])
    assert (
        PurePosixPath(case.repository_realpath).is_absolute()
        or PureWindowsPath(case.repository_realpath).is_absolute()
    )
    assert (
        PurePosixPath(case.git_common_dir_realpath).is_absolute()
        or PureWindowsPath(case.git_common_dir_realpath).is_absolute()
    )
    assert projection["task_id"] == case.task_id
    assert projection["objective"] == unicodedata.normalize("NFC", case.objective)
    assert baseline["repository_realpath"] == unicodedata.normalize("NFC", case.repository_realpath)
    assert baseline["git_common_dir_realpath"] == unicodedata.normalize(
        "NFC", case.git_common_dir_realpath
    )
    assert baseline["object_format"] == case.object_format
    assert baseline["commit_oid"] == case.baseline_commit
    if len(first_events) >= 2:
        assert workspace["relative_path"] == unicodedata.normalize(
            "NFC", case.workspace_relative_path
        )


@settings(max_examples=200, deadline=None)
@given(
    case=event_cases(terminal_kinds=("authorized",)),
    violation=st.sampled_from(
        ("OID_FORMAT", "REPOSITORY_RELATIVE", "GIT_COMMON_RELATIVE", "WORKSPACE_ESCAPE")
    ),
)
def test_generated_cross_field_and_path_violations_fail_closed(
    case: EventCase,
    violation: str,
) -> None:
    object_format = case.object_format
    repository_realpath = case.repository_realpath
    git_common_dir_realpath = case.git_common_dir_realpath
    workspace_relative_path = case.workspace_relative_path
    if violation == "OID_FORMAT":
        object_format = "sha256" if object_format == "sha1" else "sha1"
    elif violation == "REPOSITORY_RELATIVE":
        repository_realpath = "generated/repos/relative"
    elif violation == "GIT_COMMON_RELATIVE":
        git_common_dir_realpath = "generated/repos/relative/.git"
    else:
        workspace_relative_path = f"../outside-{case.ownership_nonce}"

    events = authorization_events(
        objective=case.objective,
        task_id=case.task_id,
        correlation_id=case.correlation_id,
        event_ids=case.event_ids[:3],
        repository_realpath=repository_realpath,
        git_common_dir_realpath=git_common_dir_realpath,
        object_format=object_format,
        baseline_commit=case.baseline_commit,
        workspace_relative_path=workspace_relative_path,
        ownership_nonce=case.ownership_nonce,
    )
    _assert_domain_failure(
        events,
        "EVENT_PAYLOAD_INVALID",
        "TaskCreatedV1 payload 字段类型或取值不合法。"
        if violation != "WORKSPACE_ESCAPE"
        else "TaskPreparationStartedV1 payload 字段类型或取值不合法。",
    )


@settings(max_examples=200, deadline=None)
@given(
    case=event_cases(),
    damage_kind=st.sampled_from(DAMAGE_KINDS),
    data=st.data(),
)
def test_generated_damage_fails_closed_and_physical_order_is_irrelevant(
    case: EventCase,
    damage_kind: str,
    data: Any,
) -> None:
    events = deepcopy(case.events)
    order = data.draw(
        st.permutations(tuple(range(len(events)))),
        label="physical_order",
    )
    reordered = [events[index] for index in order]
    _assert_exact_restore(reordered)

    compound_schema = deepcopy(events)
    compound_schema[0]["actor"] = "model"
    compound_schema[1]["event_type"] = "UnknownEventV1"
    reordered_schema = [compound_schema[index] for index in order]
    _assert_domain_failure(
        reordered_schema,
        "EVENT_ENVELOPE_INVALID",
        "actor 或 sensitivity 不符合 T01 固定语义。",
    )

    compound_hash_phases = deepcopy(events)
    compound_hash_phases[0]["event_hash"] = "f" * 64
    compound_hash_phases[2]["previous_hash"] = "e" * 64
    reordered_hashes = [compound_hash_phases[index] for index in order]
    _assert_domain_failure(
        reordered_hashes,
        "EVENT_PREVIOUS_HASH_MISMATCH",
        "事件 previous_hash 与前序事实不一致。",
    )

    if damage_kind == "PHYSICAL_ROTATION":
        return
    damaged = DAMAGE_MUTATORS[damage_kind](events, case)
    expected_code, expected_message = DAMAGE_ERRORS[damage_kind]
    damaged_order = data.draw(
        st.permutations(tuple(range(len(damaged)))),
        label="damaged_physical_order",
    )
    reordered_damage = [damaged[index] for index in damaged_order]
    _assert_domain_failure(reordered_damage, expected_code, expected_message)


@settings(max_examples=200, deadline=None)
@given(
    case=event_cases(terminal_kinds=("authorized",)),
    incomplete_boundary=st.sampled_from(("created", "preparing", "failed")),
)
def test_incomplete_transaction_boundaries_are_never_recoverable(
    case: EventCase,
    incomplete_boundary: str,
) -> None:
    if incomplete_boundary == "created":
        events = deepcopy(case.events[:1])
        message = "初始授权事实必须在同一耐久事务完整提交。"
    elif incomplete_boundary == "preparing":
        events = deepcopy(case.events[:2])
        message = "初始授权事实必须在同一耐久事务完整提交。"
    else:
        events = failed_events(
            case.events,
            failure_event_id=case.event_ids[3],
            attention_event_id=case.event_ids[4],
            resource_state="NOT_CREATED",
        )[:4]
        message = "失败事实必须与注意状态在同一耐久事务完成。"
    _assert_domain_failure(events, "EVENT_TRANSITION_INVALID", message)


@settings(max_examples=200, deadline=None)
@given(
    case=event_cases(
        terminal_kinds=(
            "authorized",
            "prepared",
            "failed_attention",
            "uncertain_attention",
        )
    ),
    data=st.data(),
)
def test_checkpoint_replay_is_idempotent_for_generated_legal_prefixes(
    case: EventCase,
    data: Any,
) -> None:
    allowed_positions = [3]
    if len(case.events) > 3:
        allowed_positions.append(len(case.events))
    through = data.draw(st.sampled_from(allowed_positions), label="through_sequence")
    events = deepcopy(case.events)
    events_before = deepcopy(events)
    prefix_result = as_mapping(EventsApi().restore_task_projection(events[:through]))
    checkpoint = deepcopy(as_mapping(prefix_result["checkpoint"]))
    checkpoint_before = deepcopy(checkpoint)

    via_prefix = as_mapping(EventsApi().restore_task_projection(events, checkpoint=checkpoint))
    via_latest = as_mapping(
        EventsApi().restore_task_projection(
            events,
            checkpoint=deepcopy(as_mapping(via_prefix["checkpoint"])),
        )
    )
    full_replay = as_mapping(EventsApi().restore_task_projection(events))

    assert via_prefix["load_mode"] == "CHECKPOINT"
    assert via_latest["load_mode"] == "CHECKPOINT"
    for result in (via_prefix, via_latest, full_replay):
        comparable = dict(result)
        comparable["load_mode"] = "IGNORED_FOR_EQUIVALENCE"
        expected = dict(full_replay)
        expected["load_mode"] = "IGNORED_FOR_EQUIVALENCE"
        assert canonical_oracle(comparable) == canonical_oracle(expected)
    assert events == events_before
    assert checkpoint == checkpoint_before
