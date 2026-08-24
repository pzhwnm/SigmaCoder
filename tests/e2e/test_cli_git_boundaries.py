"""S04/S12/S13 的真实 Git 与真实 CLI 对抗验收。"""

from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path
from uuid import UUID

import pytest
from tests.support.git_repo_factory import (
    GitRepository,
    cli_arguments,
    create_git_repository,
    directory_snapshot,
    finish_cli,
    launch_cli,
    run_cli,
    shell_quote_path,
    source_business_snapshot,
    worktree_inventory,
    write_executable_shell_script,
)


def _replace_baseline_with_equals(arguments: list[str], value: str) -> list[str]:
    """确保前导连字符到达产品边界，而非被 argparse 当作另一个选项。"""

    index = arguments.index("--baseline")
    return [*arguments[:index], f"--baseline={value}", *arguments[index + 2 :]]


@pytest.mark.parametrize(
    ("case", "expected_code"),
    [
        ("non-git", "INVALID_GIT_REPOSITORY"),
        ("unborn", "UNBORN_REPOSITORY"),
        ("missing-ref", "INVALID_BASELINE"),
        ("tree-oid", "INVALID_BASELINE"),
        ("blob-oid", "INVALID_BASELINE"),
        ("leading-hyphen", "INVALID_BASELINE"),
    ],
)
def test_s04_invalid_git_inputs_fail_without_persistent_side_effects(
    tmp_path: Path,
    case: str,
    expected_code: str,
) -> None:
    """每类敌对输入都返回稳定输入错误，且不创建 data root 或 worktree。"""

    fixture_root = tmp_path / case
    data_root = fixture_root / "data-root"
    if case == "non-git":
        repository_path = fixture_root / "ordinary-directory"
        repository_path.mkdir(parents=True)
        (repository_path / "do-not-touch.txt").write_text("保持原样\n", encoding="utf-8")
        before = directory_snapshot(repository_path)
        result = run_cli(
            [
                "task",
                "start",
                "--repo",
                str(repository_path),
                "--baseline",
                "HEAD",
                "--objective",
                "拒绝非 Git 输入",
                "--data-root",
                str(data_root),
                "--json",
            ],
            expected_exits=2,
        )
        assert directory_snapshot(repository_path) == before
    else:
        repository = create_git_repository(
            fixture_root,
            seed=sum(ord(character) for character in case),
            commit_count=0 if case == "unborn" else 1,
            file_count=2,
        )
        before = source_business_snapshot(repository)
        worktrees_before = worktree_inventory(repository)
        baseline = "HEAD"
        if case == "missing-ref":
            baseline = "refs/heads/definitely-missing"
        elif case == "tree-oid":
            baseline = repository.git(
                "rev-parse", f"{repository.first_commit}^{{tree}}"
            ).stdout.strip()
        elif case == "blob-oid":
            baseline = repository.git(
                "rev-parse", f"{repository.first_commit}:tracked.txt"
            ).stdout.strip()
        elif case == "leading-hyphen":
            baseline = "-malicious-option"
        arguments = cli_arguments(
            repository,
            data_root,
            baseline=baseline,
            objective=f"拒绝无效 Git 输入 {case}",
        )
        if case == "leading-hyphen":
            arguments = _replace_baseline_with_equals(arguments, baseline)
        result = run_cli(
            arguments,
            expected_exits=2,
            environment=repository.environment,
        )
        assert source_business_snapshot(repository) == before
        assert worktree_inventory(repository) == worktrees_before

    assert result.payload["ok"] is False
    assert result.payload["data"] is None
    assert result.payload["error"]["code"] == expected_code
    assert not data_root.exists()


def _raw_control_worktree(repository: GitRepository, path: Path) -> None:
    """故意不用安全覆盖创建 worktree，证明 sentinel fixture 确实可触发。"""

    repository.git(
        "worktree",
        "add",
        "--detach",
        "--",
        str(path),
        repository.latest_commit,
    )
    repository.git("worktree", "remove", "--force", "--", str(path))


def test_s13_cli_never_executes_repository_post_checkout_hook(tmp_path: Path) -> None:
    """受控 raw Git 会执行 hook，而 SigmaCoder 的同一仓库创建不会。"""

    repository = create_git_repository(tmp_path, seed=1301, commit_count=1)
    sentinel = tmp_path / "post-checkout-ran"
    hooks = tmp_path / "hostile-hooks"
    hook = hooks / "post-checkout"
    write_executable_shell_script(
        hook,
        f"printf '%s' 'post-checkout' > {shell_quote_path(sentinel)}",
    )
    repository.git("config", "core.hooksPath", str(hooks))
    _raw_control_worktree(repository, tmp_path / "unsafe-hook-control")
    assert sentinel.read_text(encoding="utf-8") == "post-checkout"
    sentinel.unlink()
    before = source_business_snapshot(repository)

    created = run_cli(
        cli_arguments(
            repository,
            tmp_path / "safe-data",
            baseline=repository.latest_commit,
            objective="禁止执行仓库 hook",
        ),
        expected_exits=0,
        environment=repository.environment,
    )

    assert created.payload["data"]["task"]["workspace"]["availability"] == "AVAILABLE"
    assert not sentinel.exists()
    assert source_business_snapshot(repository) == before


def test_s13_external_checkout_filter_is_rejected_before_execution(tmp_path: Path) -> None:
    """raw Git 证明 filter 可执行；CLI 必须在任何持久副作用前拒绝。"""

    repository = create_git_repository(
        tmp_path,
        seed=1302,
        commit_count=1,
        initial_files={".gitattributes": "tracked.txt filter=untrusted\n"},
    )
    sentinel = tmp_path / "smudge-filter-ran"
    smudge = tmp_path / "hostile-smudge.sh"
    write_executable_shell_script(
        smudge,
        f"printf '%s' 'smudge' > {shell_quote_path(sentinel)}\ncat",
    )
    repository.git("config", "filter.untrusted.smudge", shell_quote_path(smudge))
    _raw_control_worktree(repository, tmp_path / "unsafe-filter-control")
    assert sentinel.read_text(encoding="utf-8") == "smudge"
    sentinel.unlink()
    before = source_business_snapshot(repository)
    worktrees_before = worktree_inventory(repository)
    data_root = tmp_path / "rejected-data"

    rejected = run_cli(
        cli_arguments(
            repository,
            data_root,
            baseline=repository.latest_commit,
            objective="拒绝外部 checkout filter",
        ),
        expected_exits=2,
        environment=repository.environment,
    )

    assert rejected.payload["error"]["code"] == "UNSAFE_GIT_CHECKOUT_CONFIG"
    assert rejected.payload["data"] is None
    assert not sentinel.exists()
    assert not data_root.exists()
    assert source_business_snapshot(repository) == before
    assert worktree_inventory(repository) == worktrees_before


def test_s13_cli_disables_repository_fsmonitor_command(tmp_path: Path) -> None:
    """raw status 会执行 fsmonitor sentinel；CLI 内所有 Git 调用必须覆盖为 false。"""

    repository = create_git_repository(tmp_path, seed=1303, commit_count=1)
    sentinel = tmp_path / "fsmonitor-ran"
    monitor = repository.path / ".git" / "hooks" / "fsmonitor-watchmanv2"
    write_executable_shell_script(
        monitor,
        (
            f"printf '%s' 'fsmonitor' > {shell_quote_path(sentinel)}\n"
            "printf '%s\\0' 'fixture-token' '/'"
        ),
    )
    repository.git("config", "core.fsmonitor", ".git/hooks/fsmonitor-watchmanv2")
    repository.git("config", "core.fsmonitorHookVersion", "2")
    control_environment = dict(repository.environment)
    control_environment.pop("GIT_OPTIONAL_LOCKS", None)
    control = subprocess.run(
        [
            str(repository.git_runtime.executable),
            "-C",
            str(repository.path),
            "status",
            "--porcelain=v2",
        ],
        cwd=repository.git_runtime.executable.parent,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=control_environment,
        stdin=subprocess.DEVNULL,
        shell=False,
        timeout=30,
    )
    assert control.returncode == 0, control.stderr
    assert sentinel.read_text(encoding="utf-8") == "fsmonitor"
    sentinel.unlink()

    created = run_cli(
        cli_arguments(
            repository,
            tmp_path / "safe-fsmonitor-data",
            baseline=repository.latest_commit,
            objective="禁止执行 fsmonitor",
        ),
        expected_exits=0,
        environment=repository.environment,
    )

    assert created.payload["data"]["task"]["workspace"]["availability"] == "AVAILABLE"
    assert not sentinel.exists()


def _event_database(data_root: Path) -> Path:
    candidates = [path for path in data_root.rglob("*") if path.is_file()]
    for candidate in sorted(candidates):
        try:
            with sqlite3.connect(candidate) as connection:
                found = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
                ).fetchone()
        except sqlite3.DatabaseError:
            continue
        if found is not None:
            return candidate
    pytest.fail("data root 中没有事件权威库。", pytrace=False)


def test_s12_concurrent_cli_starts_have_unique_isolated_event_streams(
    tmp_path: Path,
) -> None:
    """小型日常并发门；Gauntlet 以环境变量把轮数提升到 20。"""

    repository = create_git_repository(tmp_path, seed=1200, commit_count=1, file_count=5)
    data_root = tmp_path / "shared-data"
    repeats = int(os.environ.get("SIGMACODER_CONCURRENCY_REPEATS", "2"))
    assert 1 <= repeats <= 20
    process_count = 4
    results = []
    for repeat in range(repeats):
        processes = [
            launch_cli(
                cli_arguments(
                    repository,
                    data_root,
                    baseline=repository.latest_commit,
                    objective=f"并发轮次 {repeat} 请求 {index}",
                ),
                environment=repository.environment,
            )
            for index in range(process_count)
        ]
        results.extend(
            finish_cli(process, expected_exits={0, 6}, timeout=90) for process in processes
        )

    successes = [result for result in results if result.exit_code == 0]
    busy = [result for result in results if result.exit_code == 6]
    assert successes, "至少一个并发创建必须成功。"
    assert all(result.payload["error"]["code"] == "STORE_BUSY" for result in busy)
    task_ids = [str(result.payload["data"]["task"]["task_id"]) for result in successes]
    workspace_paths = [
        str(result.payload["data"]["task"]["workspace"]["path"]) for result in successes
    ]
    assert len(task_ids) == len(set(task_ids))
    assert len(workspace_paths) == len(set(workspace_paths))
    assert all(UUID(task_id).version == 4 for task_id in task_ids)
    assert all(Path(path).is_dir() for path in workspace_paths)

    database = _event_database(data_root)
    with sqlite3.connect(database) as connection:
        registry_ids = [
            str(row[0])
            for row in connection.execute(
                "SELECT task_id FROM task_registry ORDER BY task_id"
            ).fetchall()
        ]
        event_rows = connection.execute(
            "SELECT task_id, sequence, event_id FROM events ORDER BY task_id, sequence"
        ).fetchall()
    assert registry_ids == sorted(task_ids)
    assert len({str(row[2]) for row in event_rows}) == len(event_rows)
    for task_id in task_ids:
        assert [int(row[1]) for row in event_rows if str(row[0]) == task_id] == [1, 2, 3, 4]

    listed = run_cli(
        ["task", "list", "--data-root", str(data_root), "--json"],
        expected_exits=0,
        environment=repository.environment,
    )
    assert [item["task_id"] for item in listed.payload["data"]["items"]] == sorted(task_ids)
    assert listed.payload["data"]["invalid_items"] == []
