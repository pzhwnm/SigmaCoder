"""T01 属性测试的参数化合法事件场景。"""

from __future__ import annotations

import hashlib
import string
from dataclasses import dataclass
from typing import Any

from hypothesis import strategies as st
from tests.support.event_contract import authorization_events, failed_events, prepared_events

TERMINAL_KINDS = (
    "authorized",
    "prepared",
    "failed_attention",
    "uncertain_attention",
)
SAFE_PATH_ALPHABET = string.ascii_letters + string.digits + "_-路径仓库éΩ"
SAFE_SEGMENTS = st.text(alphabet=SAFE_PATH_ALPHABET, min_size=1, max_size=12)
PORTABLE_SEGMENTS = st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_-]{0,11}", fullmatch=True)
OBJECTIVES = st.text(
    alphabet=st.characters(exclude_categories=("Cs",)),
    min_size=1,
    max_size=48,
)


@dataclass(frozen=True)
class EventCase:
    """一条独立生成、可追溯到输入事实的合法事件流。"""

    task_id: str
    correlation_id: str
    event_ids: tuple[str, str, str, str, str]
    objective: str
    repository_realpath: str
    git_common_dir_realpath: str
    object_format: str
    baseline_commit: str
    workspace_relative_path: str
    ownership_nonce: str
    terminal_kind: str
    events: list[dict[str, object]]


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _build_case(
    draw: Any,
    identifiers: tuple[str, str, str, str, str, str, str],
    terminal_kinds: tuple[str, ...],
) -> EventCase:
    task_id, correlation_id, *raw_event_ids = identifiers
    event_ids = tuple(raw_event_ids)
    if len(event_ids) != 5:
        raise AssertionError("属性场景必须分配五个 event_id。")
    typed_event_ids = (
        event_ids[0],
        event_ids[1],
        event_ids[2],
        event_ids[3],
        event_ids[4],
    )
    objective = draw(OBJECTIVES)
    repository_segment = draw(SAFE_SEGMENTS)
    workspace_segment = draw(PORTABLE_SEGMENTS)
    object_format = draw(st.sampled_from(("sha1", "sha256")))
    oid_material = draw(st.binary(min_size=32, max_size=32)).hex()
    baseline_commit = oid_material[:40] if object_format == "sha1" else oid_material
    ownership_nonce = draw(st.binary(min_size=16, max_size=16)).hex()
    repository_realpath = draw(
        st.sampled_from(
            (
                f"C:/generated/repos/{repository_segment}",
                f"/generated/repos/{repository_segment}",
                f"/generated/repos/{repository_segment}" + r"\component",
            )
        )
    )
    git_common_dir_realpath = f"{repository_realpath}/.git"
    workspace_relative_path = (
        f"tasks/{task_id}/{workspace_segment}-workspace-{ownership_nonce[:16]}"
    )
    terminal_kind = draw(st.sampled_from(terminal_kinds))
    events = authorization_events(
        objective=objective,
        task_id=task_id,
        correlation_id=correlation_id,
        event_ids=(typed_event_ids[0], typed_event_ids[1], typed_event_ids[2]),
        repository_realpath=repository_realpath,
        git_common_dir_realpath=git_common_dir_realpath,
        object_format=object_format,
        baseline_commit=baseline_commit,
        workspace_relative_path=workspace_relative_path,
        ownership_nonce=ownership_nonce,
    )
    if terminal_kind == "prepared":
        events = prepared_events(
            events,
            event_id=typed_event_ids[3],
            git_pointer_digest=_digest_text(f"{task_id}:git-pointer"),
            recovered_after_interruption=draw(st.booleans()),
        )
    elif terminal_kind in {"failed_attention", "uncertain_attention"}:
        resource_state = "NOT_CREATED" if terminal_kind == "failed_attention" else "UNVERIFIED"
        events = failed_events(
            events,
            failure_event_id=typed_event_ids[3],
            attention_event_id=typed_event_ids[4],
            resource_state=resource_state,
        )
    return EventCase(
        task_id=task_id,
        correlation_id=correlation_id,
        event_ids=typed_event_ids,
        objective=objective,
        repository_realpath=repository_realpath,
        git_common_dir_realpath=git_common_dir_realpath,
        object_format=object_format,
        baseline_commit=baseline_commit,
        workspace_relative_path=workspace_relative_path,
        ownership_nonce=ownership_nonce,
        terminal_kind=terminal_kind,
        events=events,
    )


@st.composite
def event_cases(
    draw: Any,
    *,
    terminal_kinds: tuple[str, ...] = TERMINAL_KINDS,
) -> EventCase:
    """生成单 Task 的合法事件流。"""

    identifiers = tuple(
        str(value)
        for value in draw(st.lists(st.uuids(version=4), min_size=7, max_size=7, unique=True))
    )
    if len(identifiers) != 7:
        raise AssertionError("Hypothesis 未生成七个唯一 UUIDv4。")
    return _build_case(
        draw,
        (
            identifiers[0],
            identifiers[1],
            identifiers[2],
            identifiers[3],
            identifiers[4],
            identifiers[5],
            identifiers[6],
        ),
        terminal_kinds,
    )


@st.composite
def two_event_cases(
    draw: Any,
    *,
    first_terminal_kinds: tuple[str, ...] = (
        "prepared",
        "failed_attention",
        "uncertain_attention",
    ),
    second_terminal_kinds: tuple[str, ...] = ("authorized",),
) -> tuple[EventCase, EventCase]:
    """生成身份集合完全不相交的两个 Task 场景。"""

    identifiers = tuple(
        str(value)
        for value in draw(st.lists(st.uuids(version=4), min_size=14, max_size=14, unique=True))
    )
    if len(identifiers) != 14:
        raise AssertionError("Hypothesis 未生成十四个唯一 UUIDv4。")
    first_ids = identifiers[:7]
    second_ids = identifiers[7:]
    first = _build_case(
        draw,
        (
            first_ids[0],
            first_ids[1],
            first_ids[2],
            first_ids[3],
            first_ids[4],
            first_ids[5],
            first_ids[6],
        ),
        first_terminal_kinds,
    )
    second = _build_case(
        draw,
        (
            second_ids[0],
            second_ids[1],
            second_ids[2],
            second_ids[3],
            second_ids[4],
            second_ids[5],
            second_ids[6],
        ),
        second_terminal_kinds,
    )
    return first, second


__all__ = ["EventCase", "event_cases", "two_event_cases"]
