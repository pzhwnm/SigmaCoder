"""T01 事件域测试使用的独立契约与数据构造器。"""

from __future__ import annotations

import hashlib
import importlib
import json
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from typing import Any

import pytest

ZERO_HASH = "0" * 64
TASK_ID = "11111111-1111-4111-8111-111111111111"
CORRELATION_ID = "22222222-2222-4222-8222-222222222222"
EVENT_IDS = (
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3",
)
BASELINE_OID = "1" * 40
WORKSPACE_RELATIVE_PATH = "tasks/11111111/workspace-0123456789abcdef"
OWNERSHIP_NONCE = "".join(("01234567", "89abcdef")) * 2
GIT_COMMON_DIR = "C:/fixture/repository/.git"


def _normalize_oracle(item: object) -> object:
    """递归规范化测试预言机输入。"""

    if item is None or isinstance(item, bool | int):
        return item
    if isinstance(item, str):
        return unicodedata.normalize("NFC", item)
    if isinstance(item, list | tuple):
        return [_normalize_oracle(member) for member in item]
    if isinstance(item, Mapping):
        normalized: dict[str, object] = {}
        for key, member in item.items():
            if not isinstance(key, str):
                raise TypeError("规范化对象的键必须是字符串。")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise ValueError("键经过 Unicode NFC 后发生碰撞。")
            normalized[normalized_key] = _normalize_oracle(member)
        return normalized
    raise TypeError(f"不受支持的 JSON 值类型：{type(item).__name__}")


def canonical_oracle(value: object) -> bytes:
    """独立实现 SPEC r4 的受限 JSON 规范化，作为测试预言机。"""

    normalized = _normalize_oracle(value)
    text = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return text.encode("utf-8")


def digest_oracle(value: object) -> str:
    """对独立规范化结果计算 SHA-256。"""

    return hashlib.sha256(canonical_oracle(value)).hexdigest()


def event_hash_oracle(event: Mapping[str, object]) -> str:
    """计算事件哈希，明确排除 event_hash 自身。"""

    material = dict(event)
    material.pop("event_hash", None)
    return digest_oracle(material)


def checkpoint_hash_oracle(checkpoint: Mapping[str, object]) -> str:
    """计算检查点哈希，明确排除 checkpoint_hash 自身。"""

    material = dict(checkpoint)
    material.pop("checkpoint_hash", None)
    return digest_oracle(material)


def action_digest(
    *,
    task_id: str = TASK_ID,
    git_common_dir_realpath: str = GIT_COMMON_DIR,
    baseline_commit: str = BASELINE_OID,
    workspace_relative_path: str = WORKSPACE_RELATIVE_PATH,
    ownership_nonce: str = OWNERSHIP_NONCE,
) -> str:
    """生成前三个授权事件共同绑定的 action digest。"""

    return digest_oracle(
        {
            "task_id": task_id,
            "git_common_dir_identity": git_common_dir_realpath,
            "baseline_commit": baseline_commit,
            "workspace_relative_path": workspace_relative_path,
            "ownership_nonce": ownership_nonce,
            "mode": "DETACHED",
            "bootstrap_policy_id": "builtin.workspace-provision.v1",
        }
    )


def authorization_events(
    *,
    objective: str = "实现可靠的事件恢复",
    task_id: str = TASK_ID,
    correlation_id: str = CORRELATION_ID,
    event_ids: tuple[str, str, str] = EVENT_IDS,
    repository_realpath: str = "C:/fixture/repository",
    git_common_dir_realpath: str = GIT_COMMON_DIR,
    object_format: str = "sha1",
    baseline_commit: str = BASELINE_OID,
    workspace_relative_path: str = WORKSPACE_RELATIVE_PATH,
    ownership_nonce: str = OWNERSHIP_NONCE,
) -> list[dict[str, object]]:
    """构造 schema、哈希、因果关系均合法的前三个 T01 事件。"""

    digest = action_digest(
        task_id=task_id,
        git_common_dir_realpath=git_common_dir_realpath,
        baseline_commit=baseline_commit,
        workspace_relative_path=workspace_relative_path,
        ownership_nonce=ownership_nonce,
    )
    payloads: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "TaskCreatedV1",
            {
                "objective": objective,
                "repository_realpath": repository_realpath,
                "git_common_dir_realpath": git_common_dir_realpath,
                "object_format": object_format,
                "baseline_commit": baseline_commit,
                "source_dirty": False,
                "dirty_content_included": False,
            },
        ),
        (
            "TaskPreparationStartedV1",
            {
                "workspace_relative_path": workspace_relative_path,
                "ownership_nonce": ownership_nonce,
                "proposed_action_digest": digest,
            },
        ),
        (
            "WorkspaceProvisioningAuthorizedV1",
            {
                "bootstrap_policy_id": "builtin.workspace-provision.v1",
                "decision": "AUTO_ALLOWED",
                "workspace_relative_path": workspace_relative_path,
                "ownership_nonce": ownership_nonce,
                "action_digest": digest,
                "mode": "DETACHED",
                "baseline_commit": baseline_commit,
            },
        ),
    )

    events: list[dict[str, object]] = []
    previous_hash = ZERO_HASH
    previous_event_id: str | None = None
    for index, ((event_type, payload), event_id) in enumerate(
        zip(payloads, event_ids, strict=True),
        start=1,
    ):
        event: dict[str, object] = {
            "event_id": event_id,
            "task_id": task_id,
            "sequence": index,
            "event_type": event_type,
            "schema_version": 1,
            "occurred_at": f"2026-08-21T00:00:0{index}.000000Z",
            "actor": "local_user",
            "correlation_id": correlation_id,
            "causation_id": previous_event_id,
            "workspace_revision": None,
            "sensitivity": "INTERNAL",
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event["event_hash"] = event_hash_oracle(event)
        events.append(event)
        previous_hash = str(event["event_hash"])
        previous_event_id = event_id
    return events


def append_event(
    events: Sequence[Mapping[str, object]],
    event_type: str,
    payload: Mapping[str, object],
    *,
    event_id: str,
) -> list[dict[str, object]]:
    """以独立 oracle 为合法测试流追加一条事件，不调用产品实现。"""

    if not events:
        raise ValueError("追加测试事件前必须已有权威前序事件。")
    result = [deepcopy(dict(event)) for event in events]
    previous = result[-1]
    sequence = len(result) + 1
    event: dict[str, object] = {
        "event_id": event_id,
        "task_id": previous["task_id"],
        "sequence": sequence,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": f"2026-08-21T00:00:{sequence:02d}.000000Z",
        "actor": "local_user",
        "correlation_id": previous["correlation_id"],
        "causation_id": previous["event_id"],
        "workspace_revision": None,
        "sensitivity": "INTERNAL",
        "payload": dict(payload),
        "previous_hash": previous["event_hash"],
    }
    event["event_hash"] = event_hash_oracle(event)
    result.append(event)
    return result


def prepared_events(
    events: Sequence[Mapping[str, object]],
    *,
    event_id: str,
    git_pointer_digest: str = "2" * 64,
    recovered_after_interruption: bool = False,
) -> list[dict[str, object]]:
    """为授权流追加合法 Prepared 终态。"""

    authorization = events[2]["payload"]
    created = events[0]["payload"]
    if not isinstance(authorization, Mapping) or not isinstance(created, Mapping):
        raise TypeError("测试授权流 payload 必须是对象。")
    return append_event(
        events,
        "TaskWorkspacePreparedV1",
        {
            "action_digest": authorization["action_digest"],
            "ownership_nonce": authorization["ownership_nonce"],
            "workspace_relative_path": authorization["workspace_relative_path"],
            "mode": authorization["mode"],
            "head_oid": created["baseline_commit"],
            "git_pointer_digest": git_pointer_digest,
            "recovered_after_interruption": recovered_after_interruption,
        },
        event_id=event_id,
    )


def failed_events(
    events: Sequence[Mapping[str, object]],
    *,
    failure_event_id: str,
    attention_event_id: str,
    resource_state: str,
) -> list[dict[str, object]]:
    """为授权流原子语义地追加 Failed 与 Attention 事实。"""

    authorization = events[2]["payload"]
    if not isinstance(authorization, Mapping):
        raise TypeError("测试授权流 payload 必须是对象。")
    failed = append_event(
        events,
        "TaskWorkspaceProvisioningFailedV1",
        {
            "action_digest": authorization["action_digest"],
            "failure_stage": "git_worktree_add",
            "error_code": "WORKSPACE_CREATE_FAILED",
            "resource_state": resource_state,
            "diagnostic": "受控诊断",
        },
        event_id=failure_event_id,
    )
    reason = (
        "WORKSPACE_PROVISIONING_FAILED"
        if resource_state == "NOT_CREATED"
        else "WORKSPACE_PROVISIONING_UNCERTAIN"
    )
    return append_event(
        failed,
        "TaskAttentionRequiredV1",
        {"reason": reason},
        event_id=attention_event_id,
    )


def rehash_chain(events: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    """按给定逻辑顺序重建 previous_hash 和 event_hash。"""

    rebuilt = [deepcopy(dict(event)) for event in events]
    previous_hash = ZERO_HASH
    for event in rebuilt:
        event["previous_hash"] = previous_hash
        event["event_hash"] = event_hash_oracle(event)
        previous_hash = str(event["event_hash"])
    return rebuilt


def as_mapping(value: object) -> dict[str, Any]:
    """允许产品结果使用不可变 dataclass 或普通 mapping。"""

    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    pytest.fail(f"RED：期望 mapping 或 dataclass，实际为 {type(value).__name__}。", pytrace=False)


def field(value: object, name: str) -> Any:
    """从 mapping 或具名结果中读取字段。"""

    if isinstance(value, Mapping):
        if name not in value:
            pytest.fail(f"RED：结果缺少字段 {name}。", pytrace=False)
        return value[name]
    if hasattr(value, name):
        return getattr(value, name)
    pytest.fail(f"RED：结果缺少字段 {name}。", pytrace=False)


class EventsApi:
    """事件域最小行为契约，不规定实现使用函数还是内部类。"""

    def __init__(self) -> None:
        self.canonical_json_bytes = self._lazy_callable("canonical_json_bytes")
        self.calculate_event_hash = self._lazy_callable("calculate_event_hash")
        self.restore_task_projection = self._lazy_callable("restore_task_projection")

    @staticmethod
    def _lazy_callable(name: str) -> Callable[..., Any]:
        def invoke(*args: object, **kwargs: object) -> Any:
            try:
                module = importlib.import_module("sigmacoder.domain.events")
            except ModuleNotFoundError:
                pytest.fail("RED：sigmacoder.domain.events 尚未实现。", pytrace=False)
            candidate = getattr(module, name, None)
            if not callable(candidate):
                pytest.fail(
                    f"RED：sigmacoder.domain.events.{name} 尚未实现。",
                    pytrace=False,
                )
            return candidate(*args, **kwargs)

        return invoke


def assert_validation_error(call: Callable[[], object], expected_code: str) -> None:
    """断言事件验证以稳定错误码 fail closed。"""

    try:
        call()
    except Exception as error:  # noqa: BLE001 - RED 合同必须检查产品异常的稳定 code
        actual_code = getattr(error, "code", None)
        if actual_code is None and error.args and isinstance(error.args[0], Mapping):
            actual_code = error.args[0].get("code")
        assert actual_code == expected_code, (
            f"期望稳定错误码 {expected_code}，实际异常为 {type(error).__name__}({error!s})"
        )
    else:
        pytest.fail(f"RED：损坏事件链未以 {expected_code} 拒绝。", pytrace=False)
