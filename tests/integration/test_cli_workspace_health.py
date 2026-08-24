"""S03/S14/S16/S17 的持久事件与真实 workspace 条件联合验收。"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from tests.support.git_repo_factory import (
    GitRepository,
    cli_arguments,
    create_git_repository,
    run_cli,
    source_business_snapshot,
)

from sigmacoder.adapters.git_workspace import GitWorkspaceAdapter
from sigmacoder.application.task_service import TaskService


def _database(data_root: Path) -> Path:
    """定位当前测试 data root 的 SQLite 权威库。"""

    for candidate in sorted(path for path in data_root.rglob("*") if path.is_file()):
        try:
            with sqlite3.connect(candidate) as connection:
                found = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
                ).fetchone()
        except sqlite3.DatabaseError:
            continue
        if found is not None:
            return candidate
    raise AssertionError("data root 中没有事件权威库。")


def _start(repository: GitRepository, data_root: Path, baseline: str) -> dict[str, object]:
    result = run_cli(
        cli_arguments(
            repository,
            data_root,
            baseline=baseline,
            objective=f"workspace 健康验收 {data_root.name}",
        ),
        expected_exits=0,
        environment=repository.environment,
    )
    task = result.payload["data"]["task"]
    assert isinstance(task, dict)
    return task


def _corrupt_first_event_payload(database: Path, task_id: str) -> None:
    """在临时 fixture 内绕过不可变触发器，模拟单 Task 权威事件损坏。"""

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            DROP TRIGGER events_reject_update;
            """
        )
        row = connection.execute(
            "SELECT payload FROM events WHERE task_id = ? AND sequence = 1",
            (task_id,),
        ).fetchone()
        assert row is not None
        raw = row[0].decode("utf-8") if isinstance(row[0], bytes) else str(row[0])
        payload = json.loads(raw)
        assert isinstance(payload, dict)
        payload["objective"] = "单 Task 故意损坏"
        connection.execute(
            "UPDATE events SET payload = ? WHERE task_id = ? AND sequence = 1",
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":")), task_id),
        )
        connection.executescript(
            """
            CREATE TRIGGER events_reject_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
            END;
            """
        )
        connection.commit()


class _AdvanceMainAfterFreeze(GitWorkspaceAdapter):
    """确定性 S03 故障点：冻结 C1 后、收集其余事实前把 main 前移到 C2。"""

    def __init__(
        self,
        hooks_dir: Path,
        repository: GitRepository,
        advanced_target: str,
    ) -> None:
        super().__init__(hooks_dir)
        self._fixture_repository = repository
        self._advanced_target = advanced_target

    def _freeze_commit(self, repository: Path, baseline: str, object_format: str) -> str:
        frozen = super()._freeze_commit(repository, baseline, object_format)
        self._fixture_repository.git(
            "update-ref",
            "refs/heads/main",
            self._advanced_target,
            frozen,
        )
        return frozen


def test_s03_symbolic_baseline_is_frozen_before_ref_moves(tmp_path: Path) -> None:
    """故障点主动移动 main；Task、workspace 与权威事件仍全部绑定 C1。"""

    repository = create_git_repository(tmp_path, seed=303, commit_count=2)
    repository.git("tag", "keep-c2", repository.latest_commit)
    repository.git("checkout", "--detach", repository.first_commit)
    repository.git("update-ref", "refs/heads/main", repository.first_commit)
    assert repository.git("status", "--porcelain").stdout == ""
    data_root = tmp_path / "toctou-data"
    hooks = tmp_path / "empty-hooks"
    hooks.mkdir()
    service = TaskService(data_root)
    service._git = _AdvanceMainAfterFreeze(
        hooks,
        repository,
        repository.latest_commit,
    )
    try:
        outcome = service.start_task(
            repository=repository.path,
            baseline="main",
            objective="冻结解析时的 main",
            acknowledge_excluded_changes=False,
        )
    finally:
        service.close()

    task = outcome.task
    workspace = Path(str(task["workspace"]["path"]))
    assert repository.git("rev-parse", "refs/heads/main").stdout.strip() == (
        repository.latest_commit
    )
    assert task["baseline"]["commit_oid"] == repository.first_commit
    assert task["workspace"]["head_oid"] == repository.first_commit
    assert repository.git("-C", str(workspace), "rev-parse", "HEAD").stdout.strip() == (
        repository.first_commit
    )
    with sqlite3.connect(_database(data_root)) as connection:
        raw_payload = connection.execute(
            "SELECT payload FROM events WHERE task_id = ? AND sequence = 1",
            (task["task_id"],),
        ).fetchone()
    assert raw_payload is not None
    payload = json.loads(str(raw_payload[0]))
    assert payload["baseline_commit"] == repository.first_commit


def test_s16_corrupt_task_does_not_hide_or_taint_healthy_task(tmp_path: Path) -> None:
    """status 逐 Task 隔离；list 只返回可信 B 与 A 的最小损坏定位。"""

    repository = create_git_repository(tmp_path, seed=1600, commit_count=1)
    data_root = tmp_path / "partial-list-data"
    bad_task = _start(repository, data_root, repository.first_commit)
    healthy_task = _start(repository, data_root, repository.first_commit)
    bad_id = str(bad_task["task_id"])
    healthy_id = str(healthy_task["task_id"])
    _corrupt_first_event_payload(_database(data_root), bad_id)

    bad_status = run_cli(
        ["task", "status", bad_id, "--data-root", str(data_root), "--json"],
        expected_exits=4,
        environment=repository.environment,
    )
    healthy_status = run_cli(
        ["task", "status", healthy_id, "--data-root", str(data_root), "--json"],
        expected_exits=0,
        environment=repository.environment,
    )
    partial = run_cli(
        ["task", "list", "--data-root", str(data_root), "--json"],
        expected_exits=4,
        environment=repository.environment,
    )

    assert bad_status.payload["data"] is None
    assert bad_status.payload["error"]["code"] == "EVENT_HASH_MISMATCH"
    assert healthy_status.payload["data"]["task"]["task_id"] == healthy_id
    assert partial.payload["ok"] is False
    assert partial.payload["error"]["code"] == "PARTIAL_INTEGRITY_FAILURE"
    assert [item["task_id"] for item in partial.payload["data"]["items"]] == [healthy_id]
    assert partial.payload["data"]["invalid_items"] == [
        {
            "task_id": bad_id,
            "error_code": "EVENT_HASH_MISMATCH",
            "first_invalid_sequence": 1,
        }
    ]


def test_s17_missing_workspace_returns_only_verified_event_facts(tmp_path: Path) -> None:
    """缺失时返回获准 partial data，但不静默重建或移走现有资源。"""

    repository = create_git_repository(tmp_path, seed=1701, commit_count=1)
    data_root = tmp_path / "missing-data"
    task = _start(repository, data_root, repository.first_commit)
    task_id = str(task["task_id"])
    workspace = Path(str(task["workspace"]["path"]))
    quarantined = workspace.with_name(f"{workspace.name}-quarantined")
    source_before = source_business_snapshot(repository)
    workspace.rename(quarantined)

    status = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exits=3,
        environment=repository.environment,
    )

    returned = status.payload["data"]["task"]
    assert status.payload["ok"] is False
    assert status.payload["error"]["code"] == "WORKSPACE_UNAVAILABLE"
    assert returned["task_id"] == task_id
    assert returned["baseline"] == task["baseline"]
    assert returned["event_position"] == task["event_position"]
    assert returned["health"] == "NEEDS_ATTENTION"
    assert returned["workspace"]["availability"] == "MISSING"
    assert returned["workspace"]["head_oid"] is None
    assert returned["preparation"]["workspace"] == "READY"
    assert not workspace.exists()
    assert quarantined.exists()
    assert source_business_snapshot(repository) == source_before


def test_s17_workspace_head_drift_is_reported_without_checkout(tmp_path: Path) -> None:
    """clean detached HEAD 漂移只报告 BASELINE_MISMATCH，不自动修复。"""

    repository = create_git_repository(tmp_path, seed=1702, commit_count=2)
    data_root = tmp_path / "mismatch-data"
    task = _start(repository, data_root, repository.first_commit)
    task_id = str(task["task_id"])
    workspace = Path(str(task["workspace"]["path"]))
    source_before = source_business_snapshot(repository)
    repository.git("-C", str(workspace), "checkout", "--detach", repository.latest_commit)

    status = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exits=3,
        environment=repository.environment,
    )

    returned = status.payload["data"]["task"]
    assert status.payload["error"]["code"] == "WORKSPACE_BASELINE_MISMATCH"
    assert returned["task_id"] == task_id
    assert returned["baseline"]["commit_oid"] == repository.first_commit
    assert returned["event_position"] == task["event_position"]
    assert returned["health"] == "NEEDS_ATTENTION"
    assert returned["workspace"]["availability"] == "BASELINE_MISMATCH"
    assert returned["workspace"]["head_oid"] == repository.latest_commit
    assert returned["preparation"]["workspace"] == "READY"
    assert repository.git("-C", str(workspace), "rev-parse", "HEAD").stdout.strip() == (
        repository.latest_commit
    )
    assert source_business_snapshot(repository) == source_before
