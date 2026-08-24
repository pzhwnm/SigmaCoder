"""T01 Git 基准、dirty 排除及事件优先恢复的真实边界测试。"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.support.isolated_git import FixtureGitRuntime, create_fixture_git_runtime

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class GitFixture:
    """使用真实 Git CLI 的隔离仓库。"""

    path: Path
    git_runtime: FixtureGitRuntime
    first_commit: str

    def git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = self.git_runtime.run(self.path, arguments, timeout=20)
        if check and result.returncode != 0:
            pytest.fail(
                f"测试 Git 命令失败：git {' '.join(arguments)}\n{result.stderr}",
                pytrace=False,
            )
        return result


def create_git_fixture(tmp_path: Path) -> GitFixture:
    """创建不继承宿主 Git 配置、没有网络动作的参数化基础仓库。"""

    repo = tmp_path / "source-repo"
    repo.mkdir()
    git_runtime = create_fixture_git_runtime(
        tmp_path / "git-control",
        untrusted_boundary=tmp_path,
    )
    init = git_runtime.init(repo)
    assert init.returncode == 0, init.stderr
    fixture = GitFixture(repo, git_runtime, "")
    fixture.git("config", "user.name", "SigmaCoder Test")
    fixture.git("config", "user.email", "sigmacoder-test@example.invalid")
    (repo / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("来自 C1\n", encoding="utf-8")
    fixture.git("add", ".gitignore", "tracked.txt")
    fixture.git("commit", "-m", "fixture C1")
    first_commit = fixture.git("rev-parse", "HEAD").stdout.strip()
    return GitFixture(repo, git_runtime, first_commit)


def source_fingerprint(repo: GitFixture) -> dict[str, object]:
    """排除获准的 common-dir worktree 管理元数据，锁定用户业务状态。"""

    status = repo.git(
        "status",
        "--porcelain=v2",
        "--untracked-files=all",
        "--ignored=matching",
    ).stdout
    files: dict[str, bytes] = {}
    for path in sorted(repo.path.rglob("*")):
        relative = path.relative_to(repo.path)
        if ".git" in relative.parts or not path.is_file() or path.is_symlink():
            continue
        files[relative.as_posix()] = path.read_bytes()
    index = repo.path / ".git" / "index"
    return {
        "files": files,
        "index": index.read_bytes(),
        "head": repo.git("rev-parse", "HEAD").stdout.strip(),
        "symbolic_head": repo.git("symbolic-ref", "HEAD").stdout.strip(),
        "refs": repo.git("show-ref").stdout,
        "status": status,
    }


def run_sigma_json(
    arguments: Sequence[str],
    *,
    expected_exit: int,
) -> dict[str, Any]:
    """运行安装后的真实 CLI；缺实现时以运行期断言形成 RED。"""

    env = dict(os.environ)
    source_path = str(PROJECT_ROOT / "src")
    env["PYTHONPATH"] = source_path + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "sigmacoder.cli", *arguments, "--json"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        env=env,
        timeout=30,
    )
    assert result.returncode == expected_exit, (
        f"CLI 退出码应为 {expected_exit}，实际为 {result.returncode}。\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        pytest.fail(f"CLI stdout 不是单一 JSON 文档：{error}\n{result.stdout!r}", pytrace=False)
    assert isinstance(payload, dict)
    return payload


def start_task(
    repo: GitFixture,
    data_root: Path,
    baseline: str,
    *,
    acknowledge_dirty: bool = False,
    expected_exit: int = 0,
) -> dict[str, Any]:
    arguments = [
        "task",
        "start",
        "--repo",
        str(repo.path),
        "--baseline",
        baseline,
        "--objective",
        "验证明确基准与持久恢复",
        "--data-root",
        str(data_root),
    ]
    if acknowledge_dirty:
        arguments.append("--acknowledge-excluded-changes")
    return run_sigma_json(arguments, expected_exit=expected_exit)


def event_database(data_root: Path) -> Path:
    """从隔离 data root 中定位包含规范 events 表的 SQLite 文件。"""

    for candidate in sorted(path for path in data_root.rglob("*") if path.is_file()):
        try:
            with sqlite3.connect(candidate) as connection:
                row = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
                ).fetchone()
        except sqlite3.DatabaseError:
            continue
        if row is not None:
            return candidate
    pytest.fail("RED：data root 中没有包含 events 表的 SQLite 权威库。", pytrace=False)


def drop_event_immutability_triggers(connection: sqlite3.Connection) -> None:
    """仅在临时 fixture 中解除触发器，以模拟进程崩溃时的存储快照。"""

    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'"
    ).fetchall()
    for (name,) in rows:
        escaped = str(name).replace('"', '""')
        connection.execute(f'DROP TRIGGER "{escaped}"')


def remove_prepared_terminal_event(database: Path, task_id: str) -> None:
    """把成功样本转成“授权已耐久、Prepared 未提交”的崩溃快照。"""

    with sqlite3.connect(database) as connection:
        drop_event_immutability_triggers(connection)
        deleted = connection.execute(
            "DELETE FROM events WHERE task_id = ? AND sequence = 4",
            (task_id,),
        ).rowcount
        assert deleted == 1
        connection.commit()


def corrupt_authoritative_payload(database: Path, task_id: str) -> None:
    """修改 payload 而不重算哈希，模拟权威事件损坏。"""

    with sqlite3.connect(database) as connection:
        drop_event_immutability_triggers(connection)
        row = connection.execute(
            "SELECT payload FROM events WHERE task_id = ? AND sequence = 1",
            (task_id,),
        ).fetchone()
        assert row is not None
        raw_payload = row[0]
        if isinstance(raw_payload, bytes):
            raw_payload = raw_payload.decode("utf-8")
        payload = json.loads(str(raw_payload))
        payload["objective"] = "已损坏但未重算哈希"
        connection.execute(
            "UPDATE events SET payload = ? WHERE task_id = ? AND sequence = 1",
            (json.dumps(payload, ensure_ascii=False, separators=(",", ":")), task_id),
        )
        connection.commit()


def test_explicit_commit_baseline_is_used_even_when_source_branch_is_newer(
    tmp_path: Path,
) -> None:
    repo = create_git_fixture(tmp_path)
    (repo.path / "tracked.txt").write_text("来自 C2\n", encoding="utf-8")
    repo.git("add", "tracked.txt")
    repo.git("commit", "-m", "fixture C2")
    source_before = source_fingerprint(repo)
    data_root = tmp_path / "data-explicit-baseline"

    payload = start_task(repo, data_root, repo.first_commit)

    task = payload["data"]["task"]
    workspace = Path(task["workspace"]["path"])
    assert task["baseline"]["commit_oid"] == repo.first_commit
    assert repo.git("rev-parse", "HEAD").stdout.strip() != repo.first_commit
    assert (
        repo.git_runtime.run(workspace, ("rev-parse", "HEAD"), timeout=20).stdout.strip()
        == repo.first_commit
    )
    assert (workspace / "tracked.txt").read_text(encoding="utf-8") == "来自 C1\n"
    assert source_fingerprint(repo) == source_before


def test_dirty_source_requires_ack_and_never_enters_task_workspace(tmp_path: Path) -> None:
    repo = create_git_fixture(tmp_path)
    (repo.path / "tracked.txt").write_text("未暂存变化\n", encoding="utf-8")
    (repo.path / "staged.txt").write_text("已暂存变化\n", encoding="utf-8")
    (repo.path / "untracked.txt").write_text("未跟踪变化\n", encoding="utf-8")
    (repo.path / "cache.ignored").write_text("忽略变化\n", encoding="utf-8")
    repo.git("add", "staged.txt")
    source_before = source_fingerprint(repo)
    data_root = tmp_path / "data-dirty"

    rejected = start_task(repo, data_root, repo.first_commit, expected_exit=2)

    assert rejected["ok"] is False
    assert rejected["error"]["code"] == "DIRTY_SOURCE_REQUIRES_ACK"
    accepted = start_task(
        repo,
        data_root,
        repo.first_commit,
        acknowledge_dirty=True,
    )
    workspace = Path(accepted["data"]["task"]["workspace"]["path"])
    assert accepted["data"]["task"]["baseline"]["source_dirty"] is True
    assert accepted["data"]["task"]["baseline"]["dirty_content_included"] is False
    assert (workspace / "tracked.txt").read_text(encoding="utf-8") == "来自 C1\n"
    assert not (workspace / "staged.txt").exists()
    assert not (workspace / "untracked.txt").exists()
    assert not (workspace / "cache.ignored").exists()
    assert source_fingerprint(repo) == source_before


def test_unterminated_authorization_adopts_only_an_unchanged_workspace(tmp_path: Path) -> None:
    repo = create_git_fixture(tmp_path)
    data_root = tmp_path / "data-adopt"
    created = start_task(repo, data_root, repo.first_commit)
    task = created["data"]["task"]
    task_id = task["task_id"]
    database = event_database(data_root)
    remove_prepared_terminal_event(database, task_id)

    reopened = run_sigma_json(
        ["task", "status", task_id, "--data-root", str(data_root)],
        expected_exit=0,
    )

    assert reopened["data"]["task"]["workspace"]["availability"] == "AVAILABLE"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT payload FROM events WHERE task_id = ? AND sequence = 4",
            (task_id,),
        ).fetchone()
    assert row is not None
    payload = json.loads(row[0] if isinstance(row[0], str) else row[0].decode("utf-8"))
    assert payload["recovered_after_interruption"] is True


def test_unterminated_authorization_with_extra_file_never_deletes_or_repairs(
    tmp_path: Path,
) -> None:
    repo = create_git_fixture(tmp_path)
    data_root = tmp_path / "data-unverified"
    created = start_task(repo, data_root, repo.first_commit)
    task = created["data"]["task"]
    task_id = task["task_id"]
    workspace = Path(task["workspace"]["path"])
    database = event_database(data_root)
    remove_prepared_terminal_event(database, task_id)
    sentinel = workspace / "human-file-after-crash.txt"
    sentinel.write_text("不得删除\n", encoding="utf-8")

    reopened = run_sigma_json(
        ["task", "status", task_id, "--data-root", str(data_root)],
        expected_exit=5,
    )

    assert reopened["error"]["code"] == "CREATION_RECOVERY_REQUIRED"
    assert reopened["data"]["task"]["workspace"]["availability"] == "UNVERIFIED"
    assert sentinel.read_text(encoding="utf-8") == "不得删除\n"
    assert workspace.exists()


def test_corrupt_event_chain_is_rejected_before_workspace_recovery(tmp_path: Path) -> None:
    repo = create_git_fixture(tmp_path)
    data_root = tmp_path / "data-corrupt-first"
    created = start_task(repo, data_root, repo.first_commit)
    task = created["data"]["task"]
    task_id = task["task_id"]
    workspace = Path(task["workspace"]["path"])
    database = event_database(data_root)
    corrupt_authoritative_payload(database, task_id)
    moved_workspace = workspace.with_name(f"{workspace.name}-moved")
    workspace.rename(moved_workspace)

    reopened = run_sigma_json(
        ["task", "status", task_id, "--data-root", str(data_root)],
        expected_exit=4,
    )

    assert reopened["error"]["code"] == "EVENT_HASH_MISMATCH"
    assert moved_workspace.exists()
    with sqlite3.connect(database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM events WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    assert count == (4,)
