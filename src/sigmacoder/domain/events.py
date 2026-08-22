"""T01 只增事件的规范化、验证、投影与检查点规则。"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Final, cast
from uuid import UUID

type JsonScalar = None | bool | int | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type Validator = Callable[[object], bool]

ZERO_HASH: Final = "0" * 64
PROJECTION_SCHEMA_VERSION: Final = 1
CHECKPOINT_VERSION: Final = 1
BOOTSTRAP_POLICY_ID: Final = "builtin.workspace-provision.v1"
DURABLE_BOUNDARY_INCOMPLETE_REASON: Final = "DURABLE_BOUNDARY_INCOMPLETE"

_LOWER_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_RFC3339_MICROSECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_STABLE_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_PORTABLE_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_WINDOWS_RESERVED_NAMES: Final = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}

_EVENT_FIELDS: Final = frozenset(
    {
        "event_id",
        "task_id",
        "sequence",
        "event_type",
        "schema_version",
        "occurred_at",
        "actor",
        "correlation_id",
        "causation_id",
        "workspace_revision",
        "sensitivity",
        "payload",
        "previous_hash",
        "event_hash",
    }
)


class DomainValidationError(ValueError):
    """携带稳定错误码的 fail-closed 领域异常。"""

    def __init__(self, code: str, message: str, *, reason: str | None = None) -> None:
        self.code = code
        self.reason = reason
        super().__init__(message)


@dataclass(frozen=True)
class ProjectionRestoreResult:
    """一次可信事件重建的确定性结果。"""

    projection: dict[str, object]
    through_sequence: int
    through_event_hash: str
    load_mode: str
    checkpoint: dict[str, object]


def _normalize_json(value: object) -> JsonValue:
    """把受限 JSON 值递归转换为 NFC 规范形式。"""

    if value is None:
        return None
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list | tuple):
        return [_normalize_json(item) for item in value]
    if isinstance(value, Mapping):
        return _normalize_mapping(value)
    raise TypeError(f"不受支持的 JSON 值类型：{type(value).__name__}")


def _normalize_mapping(value: Mapping[object, object]) -> dict[str, JsonValue]:
    """规范化对象键和值，并拒绝 NFC 后的键碰撞。"""

    normalized: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("规范化对象的键必须是字符串。")
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ValueError("对象键经过 Unicode NFC 规范化后发生碰撞。")
        normalized[normalized_key] = _normalize_json(item)
    return normalized


def canonical_json_bytes(value: object) -> bytes:
    """按 SPEC r4 生成无 BOM、无换行的确定性 UTF-8 JSON。"""

    normalized = _normalize_json(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return encoded.encode("utf-8")


def _normalized_event_copy(event: Mapping[str, object]) -> dict[str, object]:
    """生成供 reducer 使用的独立 NFC 事件副本，不改写权威输入。"""

    untyped_event = cast(Mapping[object, object], event)
    return cast(dict[str, object], _normalize_mapping(untyped_event))


def _hash_without_field(value: Mapping[str, object], excluded_field: str) -> str:
    material = dict(value)
    material.pop(excluded_field, None)
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def calculate_event_hash(event: Mapping[str, object]) -> str:
    """计算事件信封哈希，且只排除 event_hash 自身。"""

    return _hash_without_field(event, "event_hash")


def calculate_checkpoint_hash(checkpoint: Mapping[str, object]) -> str:
    """计算 CheckpointV1 哈希，且只排除 checkpoint_hash 自身。"""

    return _hash_without_field(checkpoint, "checkpoint_hash")


def _is_nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_text(value: object) -> bool:
    return isinstance(value, str)


def _is_exact_bool(value: object) -> bool:
    return type(value) is bool


def _is_false(value: object) -> bool:
    return value is False


def _is_nonce(value: object) -> bool:
    return isinstance(value, str) and _LOWER_HEX_32.fullmatch(value) is not None


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _LOWER_HEX_64.fullmatch(value) is not None


def _is_oid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return _LOWER_HEX_40.fullmatch(value) is not None or _LOWER_HEX_64.fullmatch(value) is not None


def _is_normalized_absolute_path(value: object) -> bool:
    """接受当前平台生成的 POSIX/Windows 绝对实路径字面量。"""

    if not isinstance(value, str) or not value:
        return False
    if unicodedata.normalize("NFC", value) != value or any(char in value for char in "\x00\r\n"):
        return False

    if value.startswith("/"):
        posix = PurePosixPath(value)
        return (
            posix.is_absolute()
            and posix.as_posix() == value
            and all(part not in {".", ".."} for part in posix.parts)
        )

    if "/" in value and "\\" in value:
        return False

    windows = PureWindowsPath(value)
    normalized_separators = value.replace("\\", "/")
    return (
        windows.is_absolute()
        and windows.as_posix() == normalized_separators
        and all(part not in {".", ".."} for part in windows.parts)
    )


def _is_portable_relative_path(value: object) -> bool:
    """复现 workspace 适配器的跨平台、未折叠相对路径契约。"""

    if not isinstance(value, str) or not value:
        return False
    if unicodedata.normalize("NFC", value) != value or "\\" in value:
        return False
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value or not relative.parts:
        return False
    for part in relative.parts:
        reserved = part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        if (
            not part
            or part in {".", ".."}
            or part.rstrip(" .") != part
            or _PORTABLE_COMPONENT_RE.fullmatch(part) is None
            or reserved
        ):
            return False
    return True


def _oid_matches_object_format(payload: Mapping[str, object]) -> bool:
    object_format = payload.get("object_format")
    oid = payload.get("baseline_commit")
    if not isinstance(oid, str):
        return False
    if object_format == "sha1":
        return _LOWER_HEX_40.fullmatch(oid) is not None
    if object_format == "sha256":
        return _LOWER_HEX_64.fullmatch(oid) is not None
    return False


def _is_bootstrap_policy(value: object) -> bool:
    return type(value) is str and value == BOOTSTRAP_POLICY_ID


def _is_auto_allowed(value: object) -> bool:
    return type(value) is str and value == "AUTO_ALLOWED"


def _is_detached(value: object) -> bool:
    return type(value) is str and value == "DETACHED"


_PAYLOAD_RULES: Final[dict[str, dict[str, Validator]]] = {
    "TaskCreatedV1": {
        "objective": _is_nonempty_text,
        "repository_realpath": _is_normalized_absolute_path,
        "git_common_dir_realpath": _is_normalized_absolute_path,
        "object_format": lambda value: isinstance(value, str) and value in {"sha1", "sha256"},
        "baseline_commit": _is_oid,
        "source_dirty": _is_exact_bool,
        "dirty_content_included": _is_false,
    },
    "TaskPreparationStartedV1": {
        "workspace_relative_path": _is_portable_relative_path,
        "ownership_nonce": _is_nonce,
        "proposed_action_digest": _is_digest,
    },
    "WorkspaceProvisioningAuthorizedV1": {
        "bootstrap_policy_id": _is_bootstrap_policy,
        "decision": _is_auto_allowed,
        "workspace_relative_path": _is_portable_relative_path,
        "ownership_nonce": _is_nonce,
        "action_digest": _is_digest,
        "mode": _is_detached,
        "baseline_commit": _is_oid,
    },
    "TaskWorkspacePreparedV1": {
        "action_digest": _is_digest,
        "ownership_nonce": _is_nonce,
        "workspace_relative_path": _is_portable_relative_path,
        "mode": _is_detached,
        "head_oid": _is_oid,
        "git_pointer_digest": _is_digest,
        "recovered_after_interruption": _is_exact_bool,
    },
    "TaskWorkspaceProvisioningFailedV1": {
        "action_digest": _is_digest,
        "failure_stage": _is_nonempty_text,
        "error_code": lambda value: (
            isinstance(value, str) and _STABLE_ERROR_CODE.fullmatch(value) is not None
        ),
        "resource_state": lambda value: (
            isinstance(value, str) and value in {"NOT_CREATED", "UNVERIFIED"}
        ),
        "diagnostic": _is_text,
    },
    "TaskAttentionRequiredV1": {
        "reason": lambda value: (
            isinstance(value, str)
            and value in {"WORKSPACE_PROVISIONING_FAILED", "WORKSPACE_PROVISIONING_UNCERTAIN"}
        ),
    },
}

_ALLOWED_NEXT_EVENT: Final[dict[str | None, frozenset[str]]] = {
    None: frozenset({"TaskCreatedV1"}),
    "TaskCreatedV1": frozenset({"TaskPreparationStartedV1"}),
    "TaskPreparationStartedV1": frozenset({"WorkspaceProvisioningAuthorizedV1"}),
    "WorkspaceProvisioningAuthorizedV1": frozenset(
        {"TaskWorkspacePreparedV1", "TaskWorkspaceProvisioningFailedV1"}
    ),
    "TaskWorkspaceProvisioningFailedV1": frozenset({"TaskAttentionRequiredV1"}),
    "TaskWorkspacePreparedV1": frozenset(),
    "TaskAttentionRequiredV1": frozenset(),
}
_DURABLE_TAIL_EVENTS: Final = frozenset(
    {
        "WorkspaceProvisioningAuthorizedV1",
        "TaskWorkspacePreparedV1",
        "TaskAttentionRequiredV1",
    }
)


def _is_uuid4(value: object) -> bool:
    if not isinstance(value, str) or value != value.lower():
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return parsed.version == 4 and str(parsed) == value


def _is_occurred_at(value: object) -> bool:
    if not isinstance(value, str) or _RFC3339_MICROSECONDS.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _raise(code: str, message: str, *, reason: str | None = None) -> None:
    raise DomainValidationError(code, message, reason=reason)


def _validate_envelope_shape(event: Mapping[str, object]) -> None:
    keys = set(event)
    if keys != _EVENT_FIELDS or any(not isinstance(key, str) for key in keys):
        _raise("EVENT_ENVELOPE_INVALID", "事件信封字段不完整或包含未获准字段。")


def _validate_envelope_schema_support(event: Mapping[str, object]) -> None:
    event_type = event["event_type"]
    schema_version = event["schema_version"]
    if not isinstance(event_type, str) or event_type not in _PAYLOAD_RULES:
        _raise("UNSUPPORTED_EVENT_SCHEMA", "事件类型或 schema_version 不受支持。")
    if type(schema_version) is not int or schema_version != 1:
        _raise("UNSUPPORTED_EVENT_SCHEMA", "事件类型或 schema_version 不受支持。")
    if not _is_occurred_at(event["occurred_at"]):
        _raise("EVENT_ENVELOPE_INVALID", "occurred_at 必须是含六位微秒的 UTC RFC 3339。")
    if event["actor"] != "local_user" or event["sensitivity"] != "INTERNAL":
        _raise("EVENT_ENVELOPE_INVALID", "actor 或 sensitivity 不符合 T01 固定语义。")
    if event["workspace_revision"] is not None:
        _raise("EVENT_ENVELOPE_INVALID", "T01 的 workspace_revision 必须为 null。")
    try:
        _event_payload(event)
    except TypeError:
        _raise("EVENT_PAYLOAD_INVALID", "事件 payload 必须是对象。")
    if not _is_digest(event["previous_hash"]) or not _is_digest(event["event_hash"]):
        _raise("EVENT_ENVELOPE_INVALID", "事件哈希必须是 64 位小写十六进制。")


def _validated_event_id(event: Mapping[str, object]) -> str:
    try:
        event_id = _event_text(event, "event_id")
        task_id = _event_text(event, "task_id")
    except TypeError:
        _raise("EVENT_ENVELOPE_INVALID", "事件标识和任务标识必须是规范 UUIDv4。")
    if not _is_uuid4(event_id) or not _is_uuid4(task_id):
        _raise("EVENT_ENVELOPE_INVALID", "事件标识和任务标识必须是规范 UUIDv4。")
    return event_id


def _validate_correlation_id(event: Mapping[str, object]) -> None:
    try:
        correlation_id = _event_text(event, "correlation_id")
    except TypeError:
        _raise("EVENT_ENVELOPE_INVALID", "correlation_id 必须是规范 UUIDv4。")
    if not _is_uuid4(correlation_id):
        _raise("EVENT_ENVELOPE_INVALID", "correlation_id 必须是规范 UUIDv4。")


def _validate_causation_id(event: Mapping[str, object]) -> None:
    if event["causation_id"] is None:
        return
    try:
        causation_id = _event_text(event, "causation_id")
    except TypeError:
        _raise("EVENT_ENVELOPE_INVALID", "causation_id 必须为 null 或规范 UUIDv4。")
    if not _is_uuid4(causation_id):
        _raise("EVENT_ENVELOPE_INVALID", "causation_id 必须为 null 或规范 UUIDv4。")


def _validate_identifiers(events: Sequence[Mapping[str, object]]) -> None:
    event_ids: list[str] = []
    for event in events:
        event_ids.append(_validated_event_id(event))
        _validate_correlation_id(event)
        _validate_causation_id(event)
    if len(set(event_ids)) != len(event_ids):
        _raise("EVENT_ID_DUPLICATE", "事件流包含重复 event_id。")


def _event_text(event: Mapping[str, object], field: str) -> str:
    value = event[field]
    if not isinstance(value, str):
        raise TypeError(f"{field} 必须是字符串。")
    return value


def _event_int(event: Mapping[str, object], field: str) -> int:
    value = event[field]
    if type(value) is not int:
        raise TypeError(f"{field} 必须是整数。")
    return value


def _event_payload(event: Mapping[str, object]) -> Mapping[str, object]:
    payload = event["payload"]
    if not isinstance(payload, Mapping):
        raise TypeError("payload 必须是对象。")
    return payload


def _validate_task_identity(events: Sequence[Mapping[str, object]]) -> None:
    task_id = events[0]["task_id"]
    if any(event["task_id"] != task_id for event in events):
        _raise("EVENT_TASK_ID_MISMATCH", "同一事件流包含不同 task_id。")


def _fallback_sort_atom(value: object) -> str:
    if value is None or type(value) in {bool, int, float, str}:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    value_type = type(value)
    return f"<{value_type.__module__}.{value_type.__qualname__}>"


def _prevalidation_token(event: object) -> bytes:
    try:
        return canonical_json_bytes(event)
    except (TypeError, ValueError, UnicodeError):
        if not isinstance(event, Mapping):
            return _fallback_sort_atom(event).encode("utf-8")
        parts = sorted(
            f"{_fallback_sort_atom(key)}={_fallback_sort_atom(value)}"
            for key, value in event.items()
        )
        return "|".join(parts).encode("utf-8")


def _prevalidation_order_key(event: object) -> tuple[int, int, bytes]:
    token = _prevalidation_token(event)
    if not isinstance(event, Mapping):
        return 2, 0, token
    sequence = event.get("sequence")
    if type(sequence) is int:
        return 0, sequence, token
    return 1, 0, token


def _order_by_sequence(events: Sequence[Mapping[str, object]]) -> list[Mapping[str, object]]:
    try:
        sequences = [_event_int(event, "sequence") for event in events]
    except TypeError:
        _raise("EVENT_ENVELOPE_INVALID", "事件 sequence 必须是从 1 开始的正整数。")
    if any(sequence < 1 for sequence in sequences):
        _raise("EVENT_ENVELOPE_INVALID", "事件 sequence 必须是从 1 开始的正整数。")
    if len(set(sequences)) != len(sequences):
        _raise("EVENT_SEQUENCE_DUPLICATE", "事件流包含重复逻辑 sequence。")
    ordered = sorted(events, key=lambda event: _event_int(event, "sequence"))
    expected = list(range(1, len(ordered) + 1))
    if [_event_int(event, "sequence") for event in ordered] != expected:
        _raise("EVENT_SEQUENCE_GAP", "事件流的逻辑 sequence 存在缺口。")
    return ordered


def _validate_previous_hashes(events: Sequence[Mapping[str, object]]) -> None:
    previous_hash = ZERO_HASH
    for event in events:
        if _event_text(event, "previous_hash") != previous_hash:
            _raise("EVENT_PREVIOUS_HASH_MISMATCH", "事件 previous_hash 与前序事实不一致。")
        previous_hash = _event_text(event, "event_hash")


def _validate_event_hashes(events: Sequence[Mapping[str, object]]) -> None:
    for event in events:
        try:
            calculated = calculate_event_hash(event)
        except (TypeError, ValueError, UnicodeError) as error:
            raise DomainValidationError(
                "EVENT_HASH_MISMATCH", "事件无法按规范重新计算哈希。"
            ) from error
        if _event_text(event, "event_hash") != calculated:
            _raise("EVENT_HASH_MISMATCH", "事件 event_hash 与规范化内容不一致。")


def _validate_payload_shape(event: Mapping[str, object]) -> None:
    event_type = _event_text(event, "event_type")
    payload = _event_payload(event)
    rules = _PAYLOAD_RULES[event_type]
    if set(payload) != set(rules):
        _raise("EVENT_PAYLOAD_INVALID", f"{event_type} payload 字段不符合 schema v1。")
    if any(not validator(payload[name]) for name, validator in rules.items()):
        _raise("EVENT_PAYLOAD_INVALID", f"{event_type} payload 字段类型或取值不合法。")
    if event_type == "TaskCreatedV1" and not _oid_matches_object_format(payload):
        _raise("EVENT_PAYLOAD_INVALID", f"{event_type} payload 字段类型或取值不合法。")


def _expected_action_digest(
    task_id: str,
    created: Mapping[str, object],
    preparation: Mapping[str, object],
) -> str:
    material = {
        "task_id": task_id,
        "git_common_dir_identity": created["git_common_dir_realpath"],
        "baseline_commit": created["baseline_commit"],
        "workspace_relative_path": preparation["workspace_relative_path"],
        "ownership_nonce": preparation["ownership_nonce"],
        "mode": "DETACHED",
        "bootstrap_policy_id": BOOTSTRAP_POLICY_ID,
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _validate_payload_bindings(events: Sequence[Mapping[str, object]]) -> None:
    by_type: dict[str, Mapping[str, object]] = {}
    for event in events:
        by_type.setdefault(_event_text(event, "event_type"), event)
    created_event = by_type.get("TaskCreatedV1")
    preparation_event = by_type.get("TaskPreparationStartedV1")
    if created_event is None or preparation_event is None:
        return
    created = _event_payload(created_event)
    preparation = _event_payload(preparation_event)
    task_id = _event_text(created_event, "task_id")
    expected_digest = _expected_action_digest(task_id, created, preparation)
    if preparation["proposed_action_digest"] != expected_digest:
        _raise("EVENT_PAYLOAD_INVALID", "workspace 提议的 action_digest 无法由权威事实重算。")
    authorization_event = by_type.get("WorkspaceProvisioningAuthorizedV1")
    if authorization_event is None:
        return
    authorization = _event_payload(authorization_event)
    _validate_authorization_bindings(created, preparation, authorization, expected_digest)
    for event in events:
        if _event_text(event, "event_type") in {
            "TaskWorkspacePreparedV1",
            "TaskWorkspaceProvisioningFailedV1",
        }:
            _validate_terminal_binding(event, authorization)
    failure_event = by_type.get("TaskWorkspaceProvisioningFailedV1")
    attention_event = by_type.get("TaskAttentionRequiredV1")
    if failure_event is not None and attention_event is not None:
        _validate_attention_binding(failure_event, attention_event)


def _validate_authorization_bindings(
    created: Mapping[str, object],
    preparation: Mapping[str, object],
    authorization: Mapping[str, object],
    expected_digest: str,
) -> None:
    expected_pairs = (
        (authorization["action_digest"], expected_digest),
        (authorization["action_digest"], preparation["proposed_action_digest"]),
        (authorization["ownership_nonce"], preparation["ownership_nonce"]),
        (authorization["workspace_relative_path"], preparation["workspace_relative_path"]),
        (authorization["baseline_commit"], created["baseline_commit"]),
    )
    if any(actual != expected for actual, expected in expected_pairs):
        _raise("EVENT_PAYLOAD_INVALID", "workspace 授权没有逐字节绑定提议与 Task 事实。")


def _validate_terminal_binding(
    event: Mapping[str, object],
    authorization: Mapping[str, object],
) -> None:
    event_type = _event_text(event, "event_type")
    payload = _event_payload(event)
    if payload["action_digest"] != authorization["action_digest"]:
        _raise("EVENT_PAYLOAD_INVALID", "workspace 终态没有绑定获准 action_digest。")
    if event_type == "TaskWorkspacePreparedV1":
        prepared_pairs = (
            (payload["ownership_nonce"], authorization["ownership_nonce"]),
            (payload["workspace_relative_path"], authorization["workspace_relative_path"]),
            (payload["mode"], authorization["mode"]),
            (payload["head_oid"], authorization["baseline_commit"]),
        )
        if any(actual != expected for actual, expected in prepared_pairs):
            _raise("EVENT_PAYLOAD_INVALID", "Prepared 事实没有绑定授权或 baseline。")


def _validate_attention_binding(
    failure_event: Mapping[str, object],
    attention_event: Mapping[str, object],
) -> None:
    failure = _event_payload(failure_event)
    attention = _event_payload(attention_event)
    expected_reason = (
        "WORKSPACE_PROVISIONING_FAILED"
        if failure["resource_state"] == "NOT_CREATED"
        else "WORKSPACE_PROVISIONING_UNCERTAIN"
    )
    if attention["reason"] != expected_reason:
        _raise("EVENT_PAYLOAD_INVALID", "Attention 原因与 workspace 资源状态不一致。")


def _validate_payloads(events: Sequence[Mapping[str, object]]) -> None:
    for event in events:
        _validate_payload_shape(event)


def _validate_causation(events: Sequence[Mapping[str, object]]) -> None:
    if events[0]["causation_id"] is not None:
        _raise("EVENT_CAUSATION_INVALID", "首事件 causation_id 必须为 null。")
    previous_id = _event_text(events[0], "event_id")
    for event in events[1:]:
        if event["causation_id"] != previous_id:
            _raise("EVENT_CAUSATION_INVALID", "事件没有因果指向直接前序事实。")
        previous_id = _event_text(event, "event_id")


def _validate_transitions(events: Sequence[Mapping[str, object]]) -> None:
    previous_type: str | None = None
    for event in events:
        event_type = _event_text(event, "event_type")
        if event_type not in _ALLOWED_NEXT_EVENT[previous_type]:
            _raise("EVENT_TRANSITION_INVALID", "事件类型不符合 T01 状态转换协议。")
        previous_type = event_type


def _validate_durable_boundary(events: Sequence[Mapping[str, object]]) -> None:
    terminal_type = _event_text(events[-1], "event_type")
    if terminal_type in _DURABLE_TAIL_EVENTS:
        return
    if terminal_type == "TaskWorkspaceProvisioningFailedV1":
        _raise(
            "EVENT_TRANSITION_INVALID",
            "失败事实必须与注意状态在同一耐久事务完成。",
            reason=DURABLE_BOUNDARY_INCOMPLETE_REASON,
        )
    _raise(
        "EVENT_TRANSITION_INVALID",
        "初始授权事实必须在同一耐久事务完整提交。",
        reason=DURABLE_BOUNDARY_INCOMPLETE_REASON,
    )


def _initial_projection(
    event: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    payload = _event_payload(event)
    workspace: dict[str, object] = {
        "kind": "git_linked_worktree",
        "mode": "DETACHED",
        "relative_path": None,
        "head_oid": None,
        "availability": "NOT_CREATED",
        "ownership_nonce": None,
        "action_digest": None,
        "git_pointer_digest": None,
    }
    preparation: dict[str, object] = {
        "workspace": "NOT_STARTED",
        "event_store": "READY",
        "sandbox": "NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS",
        "agent_run": "NOT_STARTED",
    }
    projection: dict[str, object] = {
        "projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "task_id": event["task_id"],
        "objective": payload["objective"],
        "lifecycle_state": "CREATED",
        "health": "HEALTHY",
        "baseline": {
            "repository_realpath": payload["repository_realpath"],
            "git_common_dir_realpath": payload["git_common_dir_realpath"],
            "object_format": payload["object_format"],
            "commit_oid": payload["baseline_commit"],
            "source_dirty": payload["source_dirty"],
            "dirty_content_included": payload["dirty_content_included"],
        },
        "workspace": workspace,
        "preparation": preparation,
        "failure": None,
        "event_position": {
            "sequence": event["sequence"],
            "event_hash": event["event_hash"],
        },
        "runtime": {
            "process_restored": False,
            "terminal_restored": False,
            "memory_restored": False,
            "network_transaction_restored": False,
        },
    }
    return projection, workspace, preparation


def _apply_event(
    projection: dict[str, object],
    workspace: dict[str, object],
    preparation: dict[str, object],
    event: Mapping[str, object],
) -> None:
    event_type = _event_text(event, "event_type")
    payload = _event_payload(event)
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
        _apply_failure(projection, payload, workspace, preparation)
    else:
        projection["lifecycle_state"] = "NEEDS_ATTENTION"
        projection["health"] = "NEEDS_ATTENTION"
        failure = cast(dict[str, object], projection["failure"])
        failure["reason"] = payload["reason"]
    projection["event_position"] = {
        "sequence": event["sequence"],
        "event_hash": event["event_hash"],
    }


def _apply_failure(
    projection: dict[str, object],
    payload: Mapping[str, object],
    workspace: dict[str, object],
    preparation: dict[str, object],
) -> None:
    resource_state = _event_text(payload, "resource_state")
    projection["health"] = "NEEDS_ATTENTION"
    workspace["availability"] = resource_state
    workspace["head_oid"] = None
    preparation["workspace"] = "FAILED" if resource_state == "NOT_CREATED" else "RECOVERY_REQUIRED"
    projection["failure"] = {
        "stage": payload["failure_stage"],
        "error_code": payload["error_code"],
        "diagnostic": payload["diagnostic"],
        "reason": None,
    }


def _reduce_events(events: Sequence[Mapping[str, object]]) -> dict[str, object]:
    projection, workspace, preparation = _initial_projection(events[0])
    for event in events[1:]:
        _apply_event(projection, workspace, preparation, event)
    return projection


def _checkpoint_for(
    task_id: str,
    events: Sequence[Mapping[str, object]],
    projection: Mapping[str, object],
) -> dict[str, object]:
    checkpoint: dict[str, object] = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "task_id": task_id,
        "through_sequence": _event_int(events[-1], "sequence"),
        "through_event_hash": events[-1]["event_hash"],
        "projection_schema_version": PROJECTION_SCHEMA_VERSION,
        "projection": deepcopy(dict(projection)),
    }
    checkpoint["checkpoint_hash"] = calculate_checkpoint_hash(checkpoint)
    return checkpoint


def _checkpoint_prefix(
    checkpoint: object,
    events: Sequence[Mapping[str, object]],
    task_id: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], int] | None:
    if not isinstance(checkpoint, Mapping):
        return None
    try:
        return _validated_checkpoint_prefix(checkpoint, events, task_id)
    except (KeyError, TypeError, ValueError, UnicodeError):
        return None


def _validated_checkpoint_prefix(
    checkpoint: Mapping[object, object],
    events: Sequence[Mapping[str, object]],
    task_id: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], int] | None:
    required = {
        "checkpoint_version",
        "task_id",
        "through_sequence",
        "through_event_hash",
        "projection_schema_version",
        "projection",
        "checkpoint_hash",
    }
    if not required.issubset(checkpoint) or any(not isinstance(key, str) for key in checkpoint):
        return None
    typed = {key: value for key, value in checkpoint.items() if isinstance(key, str)}
    stored_projection = typed["projection"]
    if not isinstance(stored_projection, Mapping):
        return None
    if any(not isinstance(key, str) for key in stored_projection):
        return None
    if not _checkpoint_header_is_valid(typed, task_id):
        return None
    through = _checkpoint_position(typed, events)
    if through is None:
        return None
    projection = deepcopy(cast(dict[str, object], _normalize_mapping(stored_projection)))
    workspace = projection.get("workspace")
    preparation = projection.get("preparation")
    if not isinstance(workspace, dict) or not isinstance(preparation, dict):
        return None
    expected_projection = _reduce_events(events[:through])
    if canonical_json_bytes(projection) != canonical_json_bytes(expected_projection):
        return None
    return projection, workspace, preparation, through


def _checkpoint_header_is_valid(checkpoint: Mapping[str, object], task_id: str) -> bool:
    if checkpoint["checkpoint_version"] != CHECKPOINT_VERSION:
        return False
    if checkpoint["projection_schema_version"] != PROJECTION_SCHEMA_VERSION:
        return False
    if checkpoint["task_id"] != task_id or not _is_digest(checkpoint["checkpoint_hash"]):
        return False
    return calculate_checkpoint_hash(checkpoint) == checkpoint["checkpoint_hash"]


def _checkpoint_position(
    checkpoint: Mapping[str, object],
    events: Sequence[Mapping[str, object]],
) -> int | None:
    through = checkpoint["through_sequence"]
    if type(through) is not int or not 1 <= through <= len(events):
        return None
    if checkpoint["through_event_hash"] != events[through - 1]["event_hash"]:
        return None
    return through


def _projection_from_checkpoint(
    checkpoint: object,
    events: Sequence[Mapping[str, object]],
    task_id: str,
) -> tuple[dict[str, object], str]:
    restored = _checkpoint_prefix(checkpoint, events, task_id)
    if restored is None:
        return _reduce_events(events), "FULL_REPLAY"
    projection, workspace, preparation, through = restored
    for event in events[through:]:
        _apply_event(projection, workspace, preparation, event)
    return projection, "CHECKPOINT"


def restore_task_projection(
    events: Sequence[Mapping[str, object]],
    *,
    checkpoint: object | None = None,
) -> ProjectionRestoreResult:
    """完整验证权威事件，再从可信 checkpoint 或 sequence 1 重建。"""

    if not events:
        _raise("EVENT_SEQUENCE_GAP", "事件流为空，缺少 sequence 1。")
    validation_order = sorted(events, key=_prevalidation_order_key)
    for event in validation_order:
        if not isinstance(event, Mapping):
            _raise("EVENT_ENVELOPE_INVALID", "事件流成员必须是对象。")
        _validate_envelope_shape(event)
        _validate_envelope_schema_support(event)
    _validate_task_identity(validation_order)
    _validate_identifiers(validation_order)
    ordered = _order_by_sequence(validation_order)
    _validate_previous_hashes(ordered)
    _validate_event_hashes(ordered)
    _validate_payloads(ordered)
    _validate_payload_bindings(ordered)
    _validate_causation(ordered)
    _validate_transitions(ordered)
    _validate_durable_boundary(ordered)
    normalized_ordered = [_normalized_event_copy(event) for event in ordered]
    task_id = _event_text(normalized_ordered[0], "task_id")
    projection, load_mode = _projection_from_checkpoint(
        checkpoint,
        normalized_ordered,
        task_id,
    )
    rebuilt_checkpoint = _checkpoint_for(task_id, normalized_ordered, projection)
    return ProjectionRestoreResult(
        projection=projection,
        through_sequence=_event_int(normalized_ordered[-1], "sequence"),
        through_event_hash=_event_text(normalized_ordered[-1], "event_hash"),
        load_mode=load_mode,
        checkpoint=rebuilt_checkpoint,
    )


__all__ = [
    "BOOTSTRAP_POLICY_ID",
    "CHECKPOINT_VERSION",
    "DURABLE_BOUNDARY_INCOMPLETE_REASON",
    "DomainValidationError",
    "PROJECTION_SCHEMA_VERSION",
    "ProjectionRestoreResult",
    "ZERO_HASH",
    "calculate_checkpoint_hash",
    "calculate_event_hash",
    "canonical_json_bytes",
    "restore_task_projection",
]
