"""CLI v1 的稳定外壳、退出码与 data root 解析。"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, Literal, TextIO

from sigmacoder.errors import EXIT_CODES, SigmaCoderError

type CommandName = Literal["task.start", "task.list", "task.status"]
type JsonObject = dict[str, Any]

SCHEMA_VERSION: Final = 1
PARTIAL_DATA_COMMANDS: Final[dict[str, frozenset[CommandName]]] = {
    "PARTIAL_INTEGRITY_FAILURE": frozenset({"task.list"}),
    "WORKSPACE_UNAVAILABLE": frozenset({"task.start", "task.status"}),
    "WORKSPACE_BASELINE_MISMATCH": frozenset({"task.start", "task.status"}),
    "TASK_PREPARATION_FAILED": frozenset({"task.start", "task.status"}),
    "CREATION_RECOVERY_REQUIRED": frozenset({"task.start", "task.status"}),
}


def resolve_data_root(
    explicit: str | None,
    *,
    environment: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """按显式参数、环境变量、平台默认值的顺序解析 data root。"""

    selected_environment = os.environ if environment is None else environment
    selected_platform = sys.platform if platform is None else platform
    selected_home = Path.home() if home is None else home

    if explicit is not None:
        raw = explicit
    elif "SIGMACODER_DATA_ROOT" in selected_environment:
        raw = selected_environment["SIGMACODER_DATA_ROOT"]
    elif selected_platform == "win32":
        local_app_data = selected_environment.get("LOCALAPPDATA", "")
        base = (
            Path(local_app_data) if local_app_data.strip() else selected_home / "AppData" / "Local"
        )
        return (base / "SigmaCoder").expanduser().resolve(strict=False)
    elif selected_platform == "darwin":
        return (
            (selected_home / "Library" / "Application Support" / "SigmaCoder")
            .expanduser()
            .resolve(strict=False)
        )
    else:
        xdg_state_home = selected_environment.get("XDG_STATE_HOME", "")
        base = (
            Path(xdg_state_home) if xdg_state_home.strip() else selected_home / ".local" / "state"
        )
        return (base / "sigmacoder").expanduser().resolve(strict=False)

    if not raw.strip():
        raise SigmaCoderError("INVALID_ARGUMENT", "data root 不能为空。")
    try:
        return Path(raw).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as error:
        raise SigmaCoderError("INVALID_ARGUMENT", "data root 路径无效。") from error


def success_envelope(command: CommandName, data: Mapping[str, object]) -> JsonObject:
    """构造与命令绑定的成功外壳。"""

    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "ok": True,
        "data": dict(data),
        "error": None,
    }


def failure_response(
    command: CommandName,
    *,
    code: str,
    message: str,
    details: Mapping[str, object] | None = None,
    data: Mapping[str, object] | None = None,
) -> tuple[int, JsonObject]:
    """构造条件联合失败外壳；无法证明部分数据时退化为内部错误。"""

    public_code = code if code in EXIT_CODES else "INTERNAL_ERROR"
    permitted_commands = PARTIAL_DATA_COMMANDS.get(public_code)
    if permitted_commands is not None and (command not in permitted_commands or data is None):
        public_code = "INTERNAL_ERROR"
        message = "无法构造符合 CLI v1 契约的可信错误响应。"
        details = {}
        data = None
    elif permitted_commands is None:
        data = None

    payload: JsonObject = {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "ok": False,
        "data": dict(data) if data is not None else None,
        "error": {
            "code": public_code,
            "message": message or "命令失败。",
            "details": sanitize_details(details),
        },
    }
    return EXIT_CODES[public_code], payload


def sanitize_details(details: Mapping[str, object] | None) -> JsonObject:
    """只允许有限 JSON 值进入公开错误详情。"""

    if details is None:
        return {}
    return {str(key): _json_value(value, depth=0) for key, value in details.items()}


def _json_value(value: object, *, depth: int) -> object:
    if depth >= 8:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else "[NON_FINITE]"
    if isinstance(value, Mapping):
        return {str(key): _json_value(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item, depth=depth + 1) for item in value]
    return f"[{type(value).__name__}]"


def write_json_document(payload: Mapping[str, object], *, stream: TextIO) -> None:
    """向 stdout 写入且只写入一个无 BOM 的 UTF-8 JSON 文档。"""

    serialized = json.dumps(
        dict(payload),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    stream.write(serialized)
    stream.write("\n")
    stream.flush()
