"""CLI 编排层的稳定错误与最后兜底路径测试。"""

from __future__ import annotations

import argparse
import io
import runpy
import sys
from pathlib import Path
from typing import Any

import pytest

import sigmacoder.cli as cli
from sigmacoder.application.task_service import TaskListOutcome, TaskOutcome


class _ServiceStub:
    """记录 CLI 委派参数的确定性应用服务替身。"""

    def __init__(self) -> None:
        self.start_arguments: dict[str, object] | None = None
        self.status_task_id: str | None = None

    def __enter__(self) -> _ServiceStub:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def start_task(self, **arguments: object) -> TaskOutcome:
        self.start_arguments = arguments
        return TaskOutcome({"task_id": "start-result"})

    def status(self, task_id: str) -> TaskOutcome:
        self.status_task_id = task_id
        return TaskOutcome({"task_id": task_id})

    def list_tasks(self) -> TaskListOutcome:
        return TaskListOutcome(items=[{"task_id": "z"}, {"task_id": "a"}], invalid_items=[])


class _ReconfigurableStream(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.configuration: tuple[str, str] | None = None

    def reconfigure(self, *, encoding: str, errors: str) -> None:
        self.configuration = (encoding, errors)


@pytest.mark.parametrize("value", ["not-a-uuid", "123e4567-e89b-12d3-a456-426614174000"])
def test_task_id_rejects_malformed_and_non_v4_values(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError, match="UUIDv4"):
        cli._task_id(value)


def test_task_id_rejects_noncanonical_case_and_accepts_canonical_v4() -> None:
    canonical = "123e4567-e89b-42d3-a456-426614174000"
    with pytest.raises(argparse.ArgumentTypeError, match="规范小写"):
        cli._task_id(canonical.upper())
    assert cli._task_id(canonical) == canonical


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], "task.list"),
        (["repository", "status"], "task.list"),
        (["task", "unknown"], "task.list"),
        (["task", "start"], "task.start"),
    ],
)
def test_infer_command_is_fail_closed(arguments: list[str], expected: str) -> None:
    assert cli._infer_command(arguments) == expected


def test_task_and_list_responses_cover_success_degradation_and_sorting() -> None:
    exit_code, success = cli._task_response(
        "task.status",
        TaskOutcome({"task_id": "task"}),
    )
    assert exit_code == 0
    assert success["ok"] is True

    exit_code, degraded = cli._task_response(
        "task.status",
        TaskOutcome({"task_id": "task"}, error_code="PRIVATE_ERROR"),
    )
    assert exit_code == 5
    assert degraded["error"]["message"] == "Task 当前不可用。"

    exit_code, listed = cli._list_response(
        TaskListOutcome(
            items=[{"task_id": "z"}, {"task_id": "a"}],
            invalid_items=[{"task_id": "y"}, {"task_id": "b"}],
        )
    )
    assert exit_code == 4
    assert [item["task_id"] for item in listed["data"]["items"]] == ["a", "z"]
    assert [item["task_id"] for item in listed["data"]["invalid_items"]] == ["b", "y"]


@pytest.mark.parametrize("command", ["task.start", "task.status", "task.list"])
def test_execute_delegates_each_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
) -> None:
    service = _ServiceStub()
    monkeypatch.setattr(cli, "TaskService", lambda _root: service)
    values: dict[str, Any] = {"command": command, "data_root": str(tmp_path)}
    if command == "task.start":
        values.update(
            repo="repo",
            baseline="baseline",
            objective="objective",
            acknowledge_excluded_changes=True,
        )
    elif command == "task.status":
        values["task_id"] = "123e4567-e89b-42d3-a456-426614174000"

    exit_code, payload = cli._execute(argparse.Namespace(**values))

    assert exit_code == 0
    assert payload["command"] == command
    if command == "task.start":
        assert service.start_arguments == {
            "repository": "repo",
            "baseline": "baseline",
            "objective": "objective",
            "acknowledge_excluded_changes": True,
        }
    elif command == "task.status":
        assert service.status_task_id == values["task_id"]


def test_configure_streams_tolerates_stream_without_reconfigure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = _ReconfigurableStream()
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    cli._configure_utf8_streams()

    assert stdout.configuration == ("utf-8", "replace")


def test_emit_failure_diagnostic_ignores_non_error_and_uses_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    cli._emit_failure_diagnostic({"error": None})
    assert stream.getvalue() == ""

    cli._emit_failure_diagnostic({"error": {}})
    assert stream.getvalue() == "SigmaCoder INTERNAL_ERROR: 命令失败。\n"


def test_main_uses_sys_argv_and_maps_unexpected_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "argv", ["sigma", "task", "list"])
    monkeypatch.setattr(cli, "_execute", lambda _namespace: (_ for _ in ()).throw(RuntimeError()))

    assert cli.main() == 5
    assert '"code":"INTERNAL_ERROR"' in stdout.getvalue()
    assert "SigmaCoder INTERNAL_ERROR" in stderr.getvalue()


def test_main_recovers_when_first_json_serialization_attempt_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents: list[dict[str, Any]] = []

    def flaky_writer(payload: dict[str, Any], *, stream: object) -> None:
        del stream
        documents.append(payload)
        if len(documents) == 1:
            raise ValueError("模拟不可序列化响应")

    monkeypatch.setattr(cli, "write_json_document", flaky_writer)
    monkeypatch.setattr(cli, "_execute", lambda _namespace: (0, {"bad": object()}))
    monkeypatch.setattr(cli, "_configure_utf8_streams", lambda: None)

    assert cli.main(["task", "list"]) == 5
    assert len(documents) == 2
    assert documents[1]["error"]["message"] == "无法序列化 CLI 响应。"


def test_module_main_guard_exits_with_command_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["sigma", "task", "list", "--data-root", str(tmp_path / "data"), "--json"],
    )
    with pytest.warns(RuntimeWarning), pytest.raises(SystemExit) as raised:
        runpy.run_module("sigmacoder.cli", run_name="__main__")
    assert raised.value.code == 0
