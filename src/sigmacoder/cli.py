"""SigmaCoder T01 的公共命令行入口。"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import NoReturn, cast
from uuid import UUID

from sigmacoder.application.task_service import TaskListOutcome, TaskOutcome, TaskService
from sigmacoder.errors import SigmaCoderError, error_code
from sigmacoder.protocols.cli_v1 import (
    CommandName,
    JsonObject,
    failure_response,
    resolve_data_root,
    success_envelope,
    write_json_document,
)

_ERROR_MESSAGES: dict[str, str] = {
    "PARTIAL_INTEGRITY_FAILURE": "部分 Task 的事件完整性校验失败。",
    "WORKSPACE_UNAVAILABLE": "Task Workspace 当前不可用。",
    "WORKSPACE_BASELINE_MISMATCH": "Task Workspace 的 HEAD 与冻结基准不一致。",
    "TASK_PREPARATION_FAILED": "Task Workspace 准备失败。",
    "CREATION_RECOVERY_REQUIRED": "Task 创建状态需要人工恢复。",
}


class _ArgumentParser(argparse.ArgumentParser):
    """把 argparse 的进程退出改为稳定产品错误。"""

    def error(self, message: str) -> NoReturn:
        del message
        raise SigmaCoderError("INVALID_ARGUMENT", "命令参数无效。")


def _task_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Task ID 必须是 UUIDv4。") from error
    if parsed.version != 4 or str(parsed) != value:
        raise argparse.ArgumentTypeError("Task ID 必须是规范小写 UUIDv4。")
    return value


def _build_parser() -> _ArgumentParser:
    parser = _ArgumentParser(prog="sigma", description="SigmaCoder 本地 Coding Task")
    scopes = parser.add_subparsers(dest="scope", required=True)
    task = scopes.add_parser("task", help="管理持久 Coding Task")
    commands = task.add_subparsers(dest="action", required=True)

    start = commands.add_parser("start", help="创建持久 Coding Task")
    start.add_argument("--repo", required=True, help="现有 Git worktree")
    start.add_argument("--baseline", required=True, help="冻结的 commitish")
    start.add_argument("--objective", required=True, help="任务目标")
    start.add_argument(
        "--acknowledge-excluded-changes",
        action="store_true",
        help="确认源工作区未提交变化不会进入 Task Workspace",
    )
    start.add_argument("--data-root", help="SigmaCoder data root")
    start.add_argument("--json", action="store_true", help="输出 CLI v1 JSON")
    start.set_defaults(command="task.start")

    task_list = commands.add_parser("list", help="列出持久 Coding Task")
    task_list.add_argument("--data-root", help="SigmaCoder data root")
    task_list.add_argument("--json", action="store_true", help="输出 CLI v1 JSON")
    task_list.set_defaults(command="task.list")

    status = commands.add_parser("status", help="读取持久 Coding Task")
    status.add_argument("task_id", type=_task_id, help="规范小写 UUIDv4")
    status.add_argument("--data-root", help="SigmaCoder data root")
    status.add_argument("--json", action="store_true", help="输出 CLI v1 JSON")
    status.set_defaults(command="task.status")
    return parser


def _infer_command(arguments: Sequence[str]) -> CommandName:
    if len(arguments) >= 2 and arguments[0] == "task":
        candidate = f"task.{arguments[1]}"
        if candidate in {"task.start", "task.list", "task.status"}:
            return cast(CommandName, candidate)
    return "task.list"


def _task_response(command: CommandName, outcome: TaskOutcome) -> tuple[int, JsonObject]:
    data = {"task": outcome.task}
    if outcome.error_code is None:
        return 0, success_envelope(command, data)
    code = outcome.error_code
    return failure_response(
        command,
        code=code,
        message=_ERROR_MESSAGES.get(code, "Task 当前不可用。"),
        data=data,
    )


def _list_response(outcome: TaskListOutcome) -> tuple[int, JsonObject]:
    items = sorted(outcome.items, key=lambda item: str(item["task_id"]))
    invalid_items = sorted(
        outcome.invalid_items,
        key=lambda item: str(item["task_id"]),
    )
    data = {"items": items, "invalid_items": invalid_items}
    if not invalid_items:
        return 0, success_envelope("task.list", data)
    return failure_response(
        "task.list",
        code="PARTIAL_INTEGRITY_FAILURE",
        message=_ERROR_MESSAGES["PARTIAL_INTEGRITY_FAILURE"],
        details={"invalid_count": len(invalid_items)},
        data=data,
    )


def _execute(namespace: argparse.Namespace) -> tuple[int, JsonObject]:
    command = cast(CommandName, namespace.command)
    data_root = resolve_data_root(cast(str | None, namespace.data_root))
    with TaskService(data_root) as service:
        if command == "task.start":
            outcome = service.start_task(
                repository=cast(str, namespace.repo),
                baseline=cast(str, namespace.baseline),
                objective=cast(str, namespace.objective),
                acknowledge_excluded_changes=cast(
                    bool,
                    namespace.acknowledge_excluded_changes,
                ),
            )
            return _task_response(command, outcome)
        if command == "task.status":
            return _task_response(command, service.status(cast(str, namespace.task_id)))
        return _list_response(service.list_tasks())


def _configure_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def _emit_failure_diagnostic(payload: JsonObject) -> None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    code = error.get("code", "INTERNAL_ERROR")
    message = error.get("message", "命令失败。")
    sys.stderr.write(f"SigmaCoder {code}: {message}\n")
    sys.stderr.flush()


def main(argv: Sequence[str] | None = None) -> int:
    """执行一个 CLI 命令，并始终为业务结果输出单一 JSON 文档。"""

    _configure_utf8_streams()
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = _infer_command(arguments)
    try:
        namespace = _build_parser().parse_args(arguments)
        command = cast(CommandName, namespace.command)
        exit_code, payload = _execute(namespace)
    except SigmaCoderError as error:
        public_code = error_code(error)
        exit_code, payload = failure_response(
            command,
            code=public_code,
            message=error.message,
            details=error.details,
            data=error.data,
        )
    except Exception:
        exit_code, payload = failure_response(
            command,
            code="INTERNAL_ERROR",
            message="发生未预期的内部错误。",
        )

    try:
        write_json_document(payload, stream=sys.stdout)
    except Exception:
        exit_code, payload = failure_response(
            command,
            code="INTERNAL_ERROR",
            message="无法序列化 CLI 响应。",
        )
        write_json_document(payload, stream=sys.stdout)
    if exit_code != 0:
        _emit_failure_diagnostic(payload)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
