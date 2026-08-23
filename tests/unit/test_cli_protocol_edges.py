"""CLI v1 协议纯函数的边界与 fail-closed 测试。"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from sigmacoder.errors import SigmaCoderError, error_code
from sigmacoder.protocols.cli_v1 import (
    CommandName,
    failure_response,
    resolve_data_root,
    sanitize_details,
    success_envelope,
    write_json_document,
)


def test_resolve_data_root_honors_explicit_and_environment_precedence(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit"
    environment = {"SIGMACODER_DATA_ROOT": str(tmp_path / "environment")}

    assert resolve_data_root(str(explicit), environment=environment) == explicit.resolve()
    assert resolve_data_root(None, environment=environment) == (tmp_path / "environment").resolve()


@pytest.mark.parametrize(
    ("platform", "environment", "expected_parts"),
    [
        ("win32", {"LOCALAPPDATA": "C:/isolated/local"}, ("SigmaCoder",)),
        ("win32", {}, ("AppData", "Local", "SigmaCoder")),
        ("darwin", {}, ("Library", "Application Support", "SigmaCoder")),
        ("linux", {"XDG_STATE_HOME": "/isolated/state"}, ("sigmacoder",)),
        ("linux", {}, (".local", "state", "sigmacoder")),
    ],
)
def test_resolve_data_root_platform_defaults(
    tmp_path: Path,
    platform: str,
    environment: dict[str, str],
    expected_parts: tuple[str, ...],
) -> None:
    result = resolve_data_root(None, environment=environment, platform=platform, home=tmp_path)

    assert result.parts[-len(expected_parts) :] == expected_parts


def test_resolve_data_root_rejects_empty_and_path_resolution_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SigmaCoderError, match="data root 不能为空") as empty:
        resolve_data_root("   ", environment={})
    assert empty.value.code == "INVALID_ARGUMENT"

    original_resolve = Path.resolve

    def reject_sentinel(self: Path, strict: bool = False) -> Path:
        if str(self) == "invalid-root-sentinel":
            raise OSError("测试路径解析失败")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", reject_sentinel)
    with pytest.raises(SigmaCoderError, match="data root 路径无效") as invalid:
        resolve_data_root("invalid-root-sentinel", environment={})
    assert invalid.value.code == "INVALID_ARGUMENT"


def test_success_and_ordinary_failure_envelopes_are_command_bound() -> None:
    success = success_envelope("task.status", {"task": {"task_id": "task"}})
    assert success == {
        "schema_version": 1,
        "command": "task.status",
        "ok": True,
        "data": {"task": {"task_id": "task"}},
        "error": None,
    }

    exit_code, failure = failure_response(
        "task.status",
        code="TASK_NOT_FOUND",
        message="",
        details={"safe": True},
        data={"task": {"untrusted": True}},
    )
    assert exit_code == 3
    assert failure["data"] is None
    assert failure["error"] == {
        "code": "TASK_NOT_FOUND",
        "message": "命令失败。",
        "details": {"safe": True},
    }


@pytest.mark.parametrize(
    ("command", "data"),
    [
        ("task.status", {"items": []}),
        ("task.list", None),
    ],
)
def test_partial_failure_without_matching_command_and_data_fails_closed(
    command: CommandName,
    data: dict[str, object] | None,
) -> None:
    exit_code, payload = failure_response(
        command,
        code="PARTIAL_INTEGRITY_FAILURE",
        message="不得保留",
        details={"".join(("se", "cret")): "不得保留"},
        data=data,
    )

    assert exit_code == 5
    assert payload["data"] is None
    assert payload["error"] == {
        "code": "INTERNAL_ERROR",
        "message": "无法构造符合 CLI v1 契约的可信错误响应。",
        "details": {},
    }


def test_known_partial_failure_preserves_verified_data_and_unknown_code_is_internal() -> None:
    exit_code, partial = failure_response(
        "task.status",
        code="WORKSPACE_UNAVAILABLE",
        message="workspace 缺失",
        data={"task": {"workspace": "MISSING"}},
    )
    assert exit_code == 3
    assert partial["data"] == {"task": {"workspace": "MISSING"}}

    exit_code, unknown = failure_response(
        "task.start",
        code="PLUGIN_PRIVATE_ERROR",
        message="内部供应商信息",
        data={"should": "drop"},
    )
    assert exit_code == 5
    assert unknown["data"] is None
    assert unknown["error"]["code"] == "INTERNAL_ERROR"


def test_sanitize_details_bounds_depth_and_json_types() -> None:
    nested: object = "leaf"
    for _ in range(9):
        nested = {"nested": nested}

    value = sanitize_details(
        {
            "none": None,
            "scalar": ["text", True, 7],
            "finite": 1.25,
            "nan": float("nan"),
            "positive_infinity": float("inf"),
            "negative_infinity": float("-inf"),
            "mapping": {1: "number-key"},
            "bytes": b"private",
            "nested": nested,
        }
    )

    assert value["none"] is None
    assert value["scalar"] == ["text", True, 7]
    assert value["finite"] == 1.25
    assert value["nan"] == "[NON_FINITE]"
    assert value["positive_infinity"] == "[NON_FINITE]"
    assert value["negative_infinity"] == "[NON_FINITE]"
    assert value["mapping"] == {"1": "number-key"}
    assert value["bytes"] == "[bytes]"
    cursor = value["nested"]
    for _ in range(8):
        assert isinstance(cursor, dict)
        cursor = cursor["nested"]
    assert cursor == "[TRUNCATED]"
    assert sanitize_details(None) == {}


def test_write_json_document_is_single_compact_utf8_document() -> None:
    stream = io.StringIO()
    write_json_document({"中文": "值", "ok": True}, stream=stream)

    assert stream.getvalue() == '{"中文":"值","ok":true}\n'


def test_error_code_handles_non_string_alias_known_and_unknown_codes() -> None:
    assert error_code(RuntimeError("plain")) == "INTERNAL_ERROR"
    assert error_code(SigmaCoderError("EVENT_ENVELOPE_INVALID", "bad")) == ("EVENT_PAYLOAD_INVALID")
    assert error_code(SigmaCoderError("PRIVATE_ERROR", "bad")) == "INTERNAL_ERROR"
