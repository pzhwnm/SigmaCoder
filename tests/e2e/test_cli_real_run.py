"""通过真实 OS 子进程锁定 CLI v1 的机器接口。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from tests.support.isolated_git import (
    FixtureGitRuntime,
    create_fixture_git_runtime,
    isolated_coverage_subprocess_environment,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "schemas" / "cli" / "v1"
SCHEMA_NAMES = (
    "error.schema.json",
    "task-view.schema.json",
    "task-list.schema.json",
    "envelope.schema.json",
)
NOT_FOUND_TASK_ID = "123e4567-e89b-42d3-a456-426614174999"


@dataclass(frozen=True)
class GitRepository:
    """不继承宿主 Git 配置的临时源仓库。"""

    path: Path
    git_runtime: FixtureGitRuntime
    environment: Mapping[str, str]
    baseline_oid: str

    def git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = self.git_runtime.run(self.path, arguments, timeout=20)
        if check and result.returncode != 0:
            pytest.fail(
                f"测试 Git 命令失败：git {' '.join(arguments)}\n{result.stderr}",
                pytrace=False,
            )
        return result


@dataclass(frozen=True)
class CliResult:
    """已证明 stdout 只有一个 JSON 文档的 CLI 结果。"""

    exit_code: int
    payload: dict[str, Any]
    stderr: str


def schema_validator() -> Draft202012Validator:
    """使用仓库内发布 Artifact 校验真实子进程输出。"""

    schemas: list[dict[str, Any]] = []
    for filename in SCHEMA_NAMES:
        value = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
        assert isinstance(value, dict)
        schemas.append(value)
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in schemas
    )
    envelope_schema = next(
        schema for schema in schemas if str(schema["$id"]).endswith("envelope.schema.json")
    )
    return Draft202012Validator(envelope_schema, registry=registry)


def create_repository(tmp_path: Path) -> GitRepository:
    """创建 S01 所需的 clean commit，不联网、不读取宿主凭据。"""

    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = tmp_path / "source-repository"
    git_runtime = create_fixture_git_runtime(
        tmp_path / "git-control",
        untrusted_boundary=tmp_path,
    )
    environment = dict(git_runtime.environment)
    initialized = git_runtime.init(repo)
    assert initialized.returncode == 0, initialized.stderr
    repository = GitRepository(repo, git_runtime, environment, "")
    repository.git("config", "user.name", "SigmaCoder Contract")
    repository.git("config", "user.email", "contract@example.invalid")
    (repo / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("固定基准内容\n", encoding="utf-8")
    repository.git("add", ".gitignore", "tracked.txt")
    repository.git("commit", "-m", "contract baseline")
    baseline = repository.git("rev-parse", "HEAD").stdout.strip()
    return GitRepository(repo, git_runtime, environment, baseline)


def source_fingerprint(repository: GitRepository) -> dict[str, object]:
    """排除获准 linked-worktree 元数据后，记录原 source 的业务状态。"""

    files: dict[str, bytes] = {}
    for path in sorted(repository.path.rglob("*")):
        relative = path.relative_to(repository.path)
        if ".git" in relative.parts or not path.is_file() or path.is_symlink():
            continue
        files[relative.as_posix()] = path.read_bytes()
    index = repository.path / ".git" / "index"
    return {
        "files": files,
        "index": index.read_bytes(),
        "head": repository.git("rev-parse", "HEAD").stdout.strip(),
        "symbolic_head": repository.git("symbolic-ref", "HEAD").stdout.strip(),
        "refs": repository.git("show-ref").stdout,
        "status": repository.git(
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignored=matching",
        ).stdout,
    }


def isolated_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """让真实 CLI 仅从当前 checkout 加载产品，并强制 UTF-8。"""

    environment = isolated_coverage_subprocess_environment(os.environ if base is None else base)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def decode_single_json_document(stdout: str) -> dict[str, Any]:
    """拒绝 BOM、前置日志、尾随第二个 JSON 或任意非空垃圾。"""

    assert not stdout.startswith("\ufeff"), "stdout 不得包含 UTF-8 BOM。"
    assert "Traceback (most recent call last)" not in stdout
    decoder = json.JSONDecoder()
    try:
        payload, end = decoder.raw_decode(stdout)
    except json.JSONDecodeError as error:
        pytest.fail(f"CLI stdout 不是 JSON 文档：{error}\n{stdout!r}", pytrace=False)
    assert stdout[end:].strip() == "", "stdout 包含第二份文档、日志或其他尾随内容。"
    assert isinstance(payload, dict)
    return payload


def run_cli(
    arguments: Sequence[str],
    *,
    expected_exit: int,
    environment: Mapping[str, str] | None = None,
) -> CliResult:
    """在全新 OS 进程执行 CLI，并同时验证退出码与公开 Schema。"""

    result = subprocess.run(
        [sys.executable, "-m", "sigmacoder", *arguments],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=PROJECT_ROOT,
        env=isolated_environment(environment),
        timeout=30,
    )
    assert result.returncode == expected_exit, (
        f"CLI 退出码应为 {expected_exit}，实际为 {result.returncode}。\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    payload = decode_single_json_document(result.stdout)
    errors = list(schema_validator().iter_errors(payload))
    assert not errors, "\n".join(error.message for error in errors)
    return CliResult(result.returncode, payload, result.stderr)


def start_arguments(repository: GitRepository, data_root: Path) -> list[str]:
    """返回显式冻结 commit 的 S01 命令。"""

    return [
        "task",
        "start",
        "--repo",
        str(repository.path),
        "--baseline",
        repository.baseline_oid,
        "--objective",
        "验证 CLI 持久 Task",
        "--data-root",
        str(data_root),
        "--json",
    ]


def test_s01_s05_start_list_and_status_reopen_without_touching_source(tmp_path: Path) -> None:
    """S01/S05：三个命令跨真实进程重开，且原 source 业务状态不变。"""

    repository = create_repository(tmp_path)
    source_before = source_fingerprint(repository)
    data_root = tmp_path / "data-root"

    started = run_cli(
        start_arguments(repository, data_root),
        expected_exit=0,
        environment=repository.environment,
    )
    task = started.payload["data"]["task"]
    task_id = task["task_id"]
    workspace = Path(task["workspace"]["path"])

    assert started.payload["command"] == "task.start"
    assert task["lifecycle_state"] == "PREPARING"
    assert task["health"] == "HEALTHY"
    assert task["baseline"]["commit_oid"] == repository.baseline_oid
    assert task["workspace"]["head_oid"] == repository.baseline_oid
    assert task["workspace"]["availability"] == "AVAILABLE"
    assert task["preparation"]["sandbox"] == "NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS"
    assert task["event_position"]["sequence"] == 4
    assert repository.git("-C", str(workspace), "rev-parse", "HEAD").stdout.strip() == (
        repository.baseline_oid
    )
    assert (
        repository.git("-C", str(workspace), "symbolic-ref", "-q", "HEAD", check=False).returncode
        != 0
    )

    listed = run_cli(
        ["task", "list", "--data-root", str(data_root), "--json"],
        expected_exit=0,
        environment=repository.environment,
    )
    listed_tasks = listed.payload["data"]["items"]
    assert [item["task_id"] for item in listed_tasks] == sorted(
        item["task_id"] for item in listed_tasks
    )
    assert [item["task_id"] for item in listed_tasks] == [task_id]

    reopened = run_cli(
        ["task", "status", task_id, "--data-root", str(data_root), "--json"],
        expected_exit=0,
        environment=repository.environment,
    )
    reopened_task = reopened.payload["data"]["task"]
    assert reopened.payload["command"] == "task.status"
    assert reopened_task["task_id"] == task_id
    assert reopened_task["runtime"] == {
        "process_restored": False,
        "terminal_restored": False,
        "memory_restored": False,
        "network_transaction_restored": False,
    }
    assert source_fingerprint(repository) == source_before


def test_s14_empty_list_not_found_invalid_baseline_and_invalid_arguments(
    tmp_path: Path,
) -> None:
    """S14：成功、输入失败与不存在分别使用固定退出码及 null data。"""

    data_root = tmp_path / "empty-data-root"
    empty = run_cli(
        ["task", "list", "--data-root", str(data_root), "--json"],
        expected_exit=0,
    )
    assert empty.payload == {
        "schema_version": 1,
        "command": "task.list",
        "ok": True,
        "data": {"items": [], "invalid_items": []},
        "error": None,
    }

    missing = run_cli(
        [
            "task",
            "status",
            NOT_FOUND_TASK_ID,
            "--data-root",
            str(data_root),
            "--json",
        ],
        expected_exit=3,
    )
    assert missing.payload["data"] is None
    assert missing.payload["error"]["code"] == "TASK_NOT_FOUND"

    repository = create_repository(tmp_path / "invalid-baseline-fixture")
    invalid_baseline = run_cli(
        [
            "task",
            "start",
            "--repo",
            str(repository.path),
            "--baseline",
            "refs/heads/does-not-exist",
            "--objective",
            "拒绝不存在的基准",
            "--data-root",
            str(data_root),
            "--json",
        ],
        expected_exit=2,
        environment=repository.environment,
    )
    assert invalid_baseline.payload["data"] is None
    assert invalid_baseline.payload["error"]["code"] == "INVALID_BASELINE"

    invalid_arguments = run_cli(
        ["task", "start", "--data-root", str(data_root), "--json"],
        expected_exit=2,
    )
    assert invalid_arguments.payload["data"] is None
    assert invalid_arguments.payload["error"]["code"] == "INVALID_ARGUMENT"
