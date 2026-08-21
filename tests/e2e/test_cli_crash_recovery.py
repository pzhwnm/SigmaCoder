"""S11：真实进程硬退出后的先行授权、严格采纳与终态幂等。"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from tests.support.crash_injection import CRASH_ENV, CRASH_EXIT_CODES
from tests.support.git_repo_factory import (
    PROJECT_ROOT,
    GitRepository,
    cli_arguments,
    create_git_repository,
    isolated_cli_environment,
    run_cli,
    source_business_snapshot,
    worktree_inventory,
)


def _sigma_executable() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    candidate = Path(sys.executable).with_name(f"sigma{suffix}")
    assert candidate.is_file(), f"未找到安装后的 sigma 入口：{candidate}"
    return candidate


def _injected_environment(
    tmp_path: Path,
    point: str,
    base: Mapping[str, str],
) -> dict[str, str]:
    injection_root = tmp_path / f"site-{point}"
    injection_root.mkdir()
    (injection_root / "sitecustomize.py").write_text(
        "from tests.support.crash_injection import install\ninstall()\n",
        encoding="utf-8",
    )
    environment = isolated_cli_environment(base)
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(injection_root), str(PROJECT_ROOT), str(PROJECT_ROOT / "src"))
    )
    environment[CRASH_ENV] = point
    return environment


def _run_crashing_sigma(
    tmp_path: Path,
    point: str,
    arguments: Sequence[str],
    base: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [_sigma_executable(), *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        env=_injected_environment(tmp_path, point, base),
        timeout=60,
    )
    assert result.returncode == CRASH_EXIT_CODES[point], (
        f"故障点 {point} 未按约定硬退出：{result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert result.stdout == ""
    return result


def _database(data_root: Path) -> Path:
    return data_root / "sigmacoder.sqlite3"


def _task_rows(data_root: Path) -> list[tuple[str, str]]:
    database = _database(data_root)
    if not database.exists():
        return []
    with sqlite3.connect(database) as connection:
        return [
            (str(task_id), str(relative))
            for task_id, relative in connection.execute(
                "SELECT task_id, workspace_relative_path FROM task_registry ORDER BY task_id"
            )
        ]


def _event_types(data_root: Path, task_id: str) -> list[str]:
    with sqlite3.connect(_database(data_root)) as connection:
        return [
            str(row[0])
            for row in connection.execute(
                "SELECT event_type FROM events WHERE task_id = ? ORDER BY sequence",
                (task_id,),
            )
        ]


def _prepared_payload(data_root: Path, task_id: str) -> dict[str, object]:
    with sqlite3.connect(_database(data_root)) as connection:
        row = connection.execute(
            "SELECT payload FROM events WHERE task_id = ? AND event_type = ?",
            (task_id, "TaskWorkspacePreparedV1"),
        ).fetchone()
    assert row is not None
    value = json.loads(str(row[0]))
    assert isinstance(value, dict)
    return value


def _wait_for_worktree(workspace: Path) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if workspace.is_dir() and (workspace / ".git").is_file():
            result = subprocess.run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if result.returncode == 0:
                return
        time.sleep(0.02)
    pytest.fail("Git 子进程退出父进程后未形成可观测 worktree。", pytrace=False)


def _start_arguments(repository: GitRepository, data_root: Path) -> list[str]:
    return cli_arguments(
        repository,
        data_root,
        baseline=repository.latest_commit,
        objective="验证真实进程崩溃恢复",
    )


def test_s11_exit_before_authorization_commit_leaves_no_task_or_worktree(
    tmp_path: Path,
) -> None:
    repository = create_git_repository(tmp_path / "fixture", seed=1101)
    data_root = tmp_path / "data-before-authorization"
    source_before = source_business_snapshot(repository)
    worktrees_before = worktree_inventory(repository)

    _run_crashing_sigma(
        tmp_path,
        "before_authorization_commit",
        _start_arguments(repository, data_root),
        repository.environment,
    )

    assert _task_rows(data_root) == []
    assert source_business_snapshot(repository) == source_before
    assert worktree_inventory(repository) == worktrees_before


def test_s11_exit_after_authorization_without_workspace_becomes_visible_failure(
    tmp_path: Path,
) -> None:
    repository = create_git_repository(tmp_path / "fixture", seed=1102)
    data_root = tmp_path / "data-after-authorization"

    _run_crashing_sigma(
        tmp_path,
        "after_authorization_commit",
        _start_arguments(repository, data_root),
        repository.environment,
    )

    [(task_id, relative)] = _task_rows(data_root)
    assert _event_types(data_root, task_id) == [
        "TaskCreatedV1",
        "TaskPreparationStartedV1",
        "WorkspaceProvisioningAuthorizedV1",
    ]
    assert not (data_root / relative).exists()
    recovered = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exits=5,
        environment=repository.environment,
    )
    assert recovered.payload["error"]["code"] == "CREATION_RECOVERY_REQUIRED"
    assert _event_types(data_root, task_id)[-2:] == [
        "TaskWorkspaceProvisioningFailedV1",
        "TaskAttentionRequiredV1",
    ]


@pytest.mark.parametrize(
    "point",
    ("during_git_worktree_add", "after_workspace_created", "before_prepared_commit"),
)
def test_s11_workspace_without_terminal_is_strictly_adopted_after_restart(
    tmp_path: Path,
    point: str,
) -> None:
    repository = create_git_repository(tmp_path / "fixture", seed=1110 + len(point))
    data_root = tmp_path / f"data-{point}"
    source_before = source_business_snapshot(repository)

    _run_crashing_sigma(
        tmp_path,
        point,
        _start_arguments(repository, data_root),
        repository.environment,
    )

    [(task_id, relative)] = _task_rows(data_root)
    workspace = data_root / relative
    if point == "during_git_worktree_add":
        _wait_for_worktree(workspace)
    assert _event_types(data_root, task_id) == [
        "TaskCreatedV1",
        "TaskPreparationStartedV1",
        "WorkspaceProvisioningAuthorizedV1",
    ]
    recovered = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exits=0,
        environment=repository.environment,
    )
    assert recovered.payload["data"]["task"]["workspace"]["availability"] == "AVAILABLE"
    assert _prepared_payload(data_root, task_id)["recovered_after_interruption"] is True
    assert source_business_snapshot(repository) == source_before


def test_s11_exit_after_prepared_commit_reopens_without_duplicate_terminal(
    tmp_path: Path,
) -> None:
    repository = create_git_repository(tmp_path / "fixture", seed=1106)
    data_root = tmp_path / "data-after-prepared"

    _run_crashing_sigma(
        tmp_path,
        "after_prepared_commit",
        _start_arguments(repository, data_root),
        repository.environment,
    )

    [(task_id, _)] = _task_rows(data_root)
    assert len(_event_types(data_root, task_id)) == 4
    reopened = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exits=0,
        environment=repository.environment,
    )
    assert reopened.payload["data"]["task"]["runtime"] == {
        "process_restored": False,
        "terminal_restored": False,
        "memory_restored": False,
        "network_transaction_restored": False,
    }
    assert len(_event_types(data_root, task_id)) == 4


def test_s11_second_exit_after_recovery_adoption_remains_retryable(tmp_path: Path) -> None:
    repository = create_git_repository(tmp_path / "fixture", seed=1107)
    data_root = tmp_path / "data-recovery-retry"
    start_arguments = _start_arguments(repository, data_root)
    _run_crashing_sigma(
        tmp_path,
        "after_workspace_created",
        start_arguments,
        repository.environment,
    )
    [(task_id, _)] = _task_rows(data_root)
    status_arguments = ["task", "status", task_id, "--data-root", str(data_root), "--json"]

    _run_crashing_sigma(
        tmp_path,
        "after_recovery_adoption",
        status_arguments,
        repository.environment,
    )

    assert len(_event_types(data_root, task_id)) == 3
    run_cli(status_arguments, expected_exits=0, environment=repository.environment)
    assert len(_event_types(data_root, task_id)) == 4
    assert _prepared_payload(data_root, task_id)["recovered_after_interruption"] is True
