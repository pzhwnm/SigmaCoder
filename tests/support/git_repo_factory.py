"""为真实 Git/CLI 验收生成参数化、隔离且可审计的临时仓库。"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from tests.support.isolated_git import FixtureGitRuntime, create_fixture_git_runtime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "schemas" / "cli" / "v1"
SCHEMA_NAMES = (
    "error.schema.json",
    "task-view.schema.json",
    "task-list.schema.json",
    "envelope.schema.json",
)


@dataclass(frozen=True, slots=True)
class GitRepository:
    """一个不继承宿主 Git 配置的真实临时仓库。"""

    path: Path
    git_runtime: FixtureGitRuntime
    environment: Mapping[str, str]
    commits: tuple[str, ...]

    @property
    def first_commit(self) -> str:
        if not self.commits:
            raise AssertionError("unborn fixture 没有 first_commit。")
        return self.commits[0]

    @property
    def latest_commit(self) -> str:
        if not self.commits:
            raise AssertionError("unborn fixture 没有 latest_commit。")
        return self.commits[-1]

    def git(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        """执行 argv 形式的真实 Git；测试中禁止 shell 拼接。"""

        result = subprocess.run(
            [
                str(self.git_runtime.executable),
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.autocrlf=false",
                "-C",
                str(self.path),
                *arguments,
            ],
            cwd=self.git_runtime.executable.parent,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(self.environment),
            stdin=subprocess.DEVNULL,
            shell=False,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            pytest.fail(
                f"测试 Git 命令失败：git {' '.join(arguments)}\n{result.stderr}",
                pytrace=False,
            )
        return result


@dataclass(frozen=True, slots=True)
class CliResult:
    """已通过退出码、单 JSON 文档和 CLI v1 Schema 校验的结果。"""

    exit_code: int
    payload: dict[str, Any]
    stderr: str


def create_git_repository(
    root: Path,
    *,
    seed: int,
    commit_count: int = 1,
    file_count: int = 3,
    initial_files: Mapping[str, str] | None = None,
) -> GitRepository:
    """按 seed 生成不同路径/内容的仓库，避免所有场景共享单一硬编码 fixture。"""

    if commit_count < 0 or file_count < 1:
        raise ValueError("commit_count 必须非负，file_count 必须为正。")
    root.mkdir(parents=True, exist_ok=True)
    repository_path = root / f"source-{seed:08x}"
    git_runtime = create_fixture_git_runtime(
        root / f"git-control-{seed:08x}",
        untrusted_boundary=root,
    )
    environment = dict(git_runtime.environment)
    initialized = git_runtime.init(repository_path)
    assert initialized.returncode == 0, initialized.stderr
    repository = GitRepository(repository_path, git_runtime, environment, ())
    repository.git("config", "user.name", f"SigmaCoder Fixture {seed}")
    repository.git("config", "user.email", f"fixture-{seed}@example.invalid")

    files = {
        ".gitignore": "*.ignored\n",
        "tracked.txt": f"seed={seed};revision=1\n",
    }
    for index in range(max(0, file_count - 2)):
        files[f"fixtures/{seed:08x}/unit-{index:02d}.txt"] = (
            f"seed={seed};file={index};revision=1\n"
        )
    files.update(initial_files or {})
    for relative, content in files.items():
        target = repository_path / Path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    commits: list[str] = []
    for revision in range(1, commit_count + 1):
        if revision > 1:
            (repository_path / "tracked.txt").write_text(
                f"seed={seed};revision={revision}\n",
                encoding="utf-8",
            )
            revision_file = repository_path / "fixtures" / f"revision-{revision:02d}.txt"
            revision_file.parent.mkdir(parents=True, exist_ok=True)
            revision_file.write_text(
                f"seed={seed};revision={revision}\n",
                encoding="utf-8",
            )
        repository.git("add", "--all")
        repository.git("commit", "-m", f"fixture seed {seed} revision {revision}")
        commits.append(repository.git("rev-parse", "HEAD").stdout.strip().lower())
    return GitRepository(repository_path, git_runtime, environment, tuple(commits))


def source_business_snapshot(repository: GitRepository) -> dict[str, object]:
    """排除获准 linked-worktree 管理元数据，锁定源 worktree 业务状态。"""

    files: dict[str, bytes] = {}
    for path in sorted(repository.path.rglob("*")):
        relative = path.relative_to(repository.path)
        if ".git" in relative.parts or not path.is_file() or path.is_symlink():
            continue
        files[relative.as_posix()] = path.read_bytes()
    index = repository.path / ".git" / "index"
    head = repository.git("rev-parse", "--verify", "HEAD", check=False)
    symbolic = repository.git("symbolic-ref", "-q", "HEAD", check=False)
    return {
        "files": files,
        "index": index.read_bytes() if index.exists() else None,
        "head_returncode": head.returncode,
        "head": head.stdout.strip(),
        "symbolic_returncode": symbolic.returncode,
        "symbolic_head": symbolic.stdout.strip(),
        "refs": repository.git("show-ref", check=False).stdout,
        "status": repository.git(
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignored=matching",
        ).stdout,
    }


def worktree_inventory(repository: GitRepository) -> str:
    """返回可逐字节比较的 linked-worktree 清单。"""

    return repository.git("worktree", "list", "--porcelain").stdout


def directory_snapshot(path: Path) -> dict[str, bytes]:
    """记录非 Git 输入目录的全部普通文件。"""

    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in sorted(path.rglob("*"))
        if item.is_file() and not item.is_symlink()
    }


def isolated_cli_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """让 CLI 子进程只加载当前 checkout，并强制 UTF-8。"""

    environment = dict(os.environ if base is None else base)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


@lru_cache(maxsize=1)
def schema_validator() -> Draft202012Validator:
    """从仓库发布 Artifact 构造 CLI v1 validator。"""

    schemas: list[dict[str, Any]] = []
    for filename in SCHEMA_NAMES:
        value = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
        assert isinstance(value, dict)
        schemas.append(value)
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in schemas
    )
    envelope = next(
        schema for schema in schemas if str(schema["$id"]).endswith("envelope.schema.json")
    )
    return Draft202012Validator(envelope, registry=registry)


def cli_arguments(
    repository: GitRepository,
    data_root: Path,
    *,
    baseline: str,
    objective: str,
) -> list[str]:
    """构造真实 task start argv。"""

    return [
        "task",
        "start",
        "--repo",
        str(repository.path),
        "--baseline",
        baseline,
        "--objective",
        objective,
        "--data-root",
        str(data_root),
        "--json",
    ]


def launch_cli(
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
) -> subprocess.Popen[str]:
    """启动真实 OS 进程；调用者可先全部启动再统一回收形成并发。"""

    return subprocess.Popen(
        [sys.executable, "-m", "sigmacoder.cli", *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        env=isolated_cli_environment(environment),
    )


def finish_cli(
    process: subprocess.Popen[str],
    *,
    expected_exits: int | Collection[int],
    timeout: float = 60,
) -> CliResult:
    """回收子进程并验证稳定机器接口。"""

    stdout, stderr = process.communicate(timeout=timeout)
    allowed = {expected_exits} if isinstance(expected_exits, int) else set(expected_exits)
    assert process.returncode in allowed, (
        f"CLI 退出码应属于 {sorted(allowed)}，实际为 {process.returncode}。\n"
        f"stdout={stdout!r}\nstderr={stderr!r}"
    )
    assert not stdout.startswith("\ufeff")
    assert "Traceback (most recent call last)" not in stdout
    decoder = json.JSONDecoder()
    try:
        payload, end = decoder.raw_decode(stdout)
    except json.JSONDecodeError as error:
        pytest.fail(f"CLI stdout 不是 JSON 文档：{error}\n{stdout!r}", pytrace=False)
    assert stdout[end:].strip() == "", "stdout 含第二份 JSON 或其他尾随内容。"
    assert isinstance(payload, dict)
    schema_errors = list(schema_validator().iter_errors(payload))
    assert not schema_errors, "\n".join(error.message for error in schema_errors)
    return CliResult(int(process.returncode), payload, stderr)


def run_cli(
    arguments: Sequence[str],
    *,
    expected_exits: int | Collection[int],
    environment: Mapping[str, str] | None = None,
    timeout: float = 60,
) -> CliResult:
    """同步执行并验证真实 CLI。"""

    return finish_cli(
        launch_cli(arguments, environment=environment),
        expected_exits=expected_exits,
        timeout=timeout,
    )


def write_executable_shell_script(path: Path, body: str) -> None:
    """创建 Git for Windows 与 POSIX Git 都可执行的测试 sentinel 脚本。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def shell_quote_path(path: Path) -> str:
    """把测试临时路径编码为 POSIX shell 单引号参数。"""

    return "'" + path.resolve(strict=False).as_posix().replace("'", "'\"'\"'") + "'"
