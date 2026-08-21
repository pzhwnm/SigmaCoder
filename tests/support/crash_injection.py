"""仅供 E2E 子进程使用的确定性崩溃注入器。

本模块不会被产品导入。测试通过临时 ``sitecustomize.py`` 显式调用
``install``，从而让安装后的 ``sigma`` 进程在真实事务边界硬退出。
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

CRASH_ENV = "SIGMACODER_TEST_CRASH_POINT"
CRASH_EXIT_CODES = {
    "before_authorization_commit": 81,
    "after_authorization_commit": 82,
    "during_git_worktree_add": 83,
    "after_workspace_created": 84,
    "before_prepared_commit": 85,
    "after_prepared_commit": 86,
    "after_recovery_adoption": 87,
}


def _hard_exit(point: str) -> NoReturn:
    os._exit(CRASH_EXIT_CODES[point])


def _is_prepared_batch(events: object) -> bool:
    if not isinstance(events, Sequence) or isinstance(events, str | bytes):
        return False
    return any(
        isinstance(event, Mapping) and event.get("event_type") == "TaskWorkspacePreparedV1"
        for event in events
    )


def _install_store_boundary(point: str) -> None:
    from sigmacoder.adapters.sqlite_event_store import SQLiteEventStore

    if point in {"before_authorization_commit", "after_authorization_commit"}:
        original_create = SQLiteEventStore.create_task

        def injected_create(self: SQLiteEventStore, *args: Any, **kwargs: Any) -> None:
            if point == "before_authorization_commit":
                _hard_exit(point)
            original_create(self, *args, **kwargs)
            _hard_exit(point)

        SQLiteEventStore.create_task = injected_create
        return

    original_append = SQLiteEventStore.append_events

    def injected_append(
        self: SQLiteEventStore,
        task_id: str,
        events: object,
        projection: object,
        checkpoint: object,
    ) -> None:
        if not _is_prepared_batch(events):
            original_append(self, task_id, events, projection, checkpoint)  # type: ignore[arg-type]
            return
        if point == "before_prepared_commit":
            _hard_exit(point)
        original_append(self, task_id, events, projection, checkpoint)  # type: ignore[arg-type]
        _hard_exit(point)

    SQLiteEventStore.append_events = injected_append  # type: ignore[method-assign]


def _install_workspace_boundary(point: str) -> None:
    from sigmacoder.adapters.git_workspace import GitWorkspaceAdapter

    original_create = GitWorkspaceAdapter.create_detached_worktree

    def injected_workspace(self: GitWorkspaceAdapter, *args: Any, **kwargs: Any) -> Path:
        original_create(self, *args, **kwargs)
        _hard_exit(point)

    GitWorkspaceAdapter.create_detached_worktree = injected_workspace  # type: ignore[method-assign]


def _install_git_child_boundary() -> None:
    original_run = subprocess.run

    def injected_run(command: Any, *args: Any, **kwargs: Any) -> Any:
        values = [os.fspath(value) for value in command] if isinstance(command, Sequence) else []
        if "worktree" not in values or "add" not in values:
            return original_run(command, *args, **kwargs)
        separator = values.index("--", values.index("add") + 1)
        workspace = Path(values[separator + 1])
        child = subprocess.Popen(
            values,
            cwd=kwargs.get("cwd"),
            stdin=kwargs.get("stdin"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            env=kwargs.get("env"),
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if workspace.exists() or child.poll() is not None:
                _hard_exit("during_git_worktree_add")
            time.sleep(0.001)
        _hard_exit("during_git_worktree_add")

    subprocess.run = injected_run  # type: ignore[assignment]


def _install_recovery_boundary() -> None:
    from sigmacoder.application.task_service import TaskService

    original = TaskService._record_prepared

    def injected_record(self: TaskService, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("recovered") is True:
            _hard_exit("after_recovery_adoption")
        return original(self, *args, **kwargs)

    TaskService._record_prepared = injected_record  # type: ignore[method-assign]


def install() -> None:
    """按单一显式环境变量安装一个故障点；未知值立即退出。"""

    point = os.environ.get(CRASH_ENV)
    if point not in CRASH_EXIT_CODES:
        raise RuntimeError("未知或缺失的 SigmaCoder 测试崩溃点。")
    if point in {
        "before_authorization_commit",
        "after_authorization_commit",
        "before_prepared_commit",
        "after_prepared_commit",
    }:
        _install_store_boundary(point)
    elif point == "after_workspace_created":
        _install_workspace_boundary(point)
    elif point == "during_git_worktree_add":
        _install_git_child_boundary()
    else:
        _install_recovery_boundary()
