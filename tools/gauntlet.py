"""T01 Tier 3 的固定、fail-closed Gauntlet 总入口。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

if __package__:
    from tools.check_junit import CORE_PROPERTY_NODEIDS
    from tools.repo_lease import (
        REPOSITORY_LEASE_FILE,
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        acquire_repository_lease,
    )
else:  # pragma: no cover - 由真实脚本入口覆盖
    from check_junit import CORE_PROPERTY_NODEIDS  # type: ignore[no-redef]
    from repo_lease import (  # type: ignore[no-redef]
        REPOSITORY_LEASE_FILE,
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        acquire_repository_lease,
    )

SPEC_VERSION = "r4"
PROFILE_UBUNTU = "ubuntu-tier3"
PROFILE_WINDOWS = "windows-compat"
GAUNTLET_LOCK_FILE = REPOSITORY_LEASE_FILE


class GauntletError(RuntimeError):
    """Gauntlet 配置、执行或完成审计失败。"""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
StateGuard = Callable[[str], None]


class _Digest(Protocol):
    def update(self, value: bytes) -> object: ...


@dataclass(frozen=True)
class Layer:
    name: str
    commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 900
    cleanup_after: tuple[str, ...] = ()


@dataclass(frozen=True)
class LayerResult:
    name: str
    commands: int
    duration_seconds: float
    output_sha256: str
    structured_evidence: tuple[object, ...] = ()


@dataclass(frozen=True)
class RepositoryBinding:
    git_head: str
    git_status_sha256: str
    input_tree_sha256: str
    input_file_count: int
    uv_lock_sha256: str
    profile_manifest_sha256: str
    mutation_profiles_sha256: str
    protected_state_sha256: str


@dataclass(frozen=True)
class GauntletRunResult:
    profile: str
    binding: RepositoryBinding
    layers: tuple[LayerResult, ...]


COMMON_LAYER_NAMES = (
    "toolchain",
    "gauntlet-meta-tests",
    "tests",
    "types",
    "lint",
    "format",
    "coverage",
    "properties",
    "random-order-1",
    "random-order-2",
    "random-order-3",
    "stability",
    "real-execution",
    "secret-scan",
    "supply-chain",
    "licenses",
)

EXPECTED_LAYER_NAMES = {
    PROFILE_UBUNTU: (
        *COMMON_LAYER_NAMES,
        "mutation-events",
        "mutation-task-service",
        "mutation-semantic",
        "source-state",
    ),
    PROFILE_WINDOWS: (*COMMON_LAYER_NAMES, "source-state"),
}

STALE_PATHS = (
    ".coverage",
    "coverage.xml",
    "coverage.json",
    "licenses.json",
    "build/licenses.json",
    "build/audit-requirements.txt",
    "build/test-results",
    "mutants",
    "mutation-reports/events.json",
    "mutation-reports/task-service.json",
    "mutation-reports/semantic.json",
    ".pytest_cache",
)
STALE_GLOBS = (".coverage.*",)


def _layer(
    name: str, *commands: Sequence[str], timeout: int = 900, cleanup: Sequence[str] = ()
) -> Layer:
    return Layer(
        name=name,
        commands=tuple(tuple(command) for command in commands),
        timeout_seconds=timeout,
        cleanup_after=tuple(cleanup),
    )


def _pytest_commands(
    report_name: str,
    *arguments: str,
    hypothesis_contract: bool = False,
) -> tuple[tuple[str, ...], ...]:
    report = f"build/test-results/{report_name}.xml"
    return (
        (
            "uv",
            "run",
            "--frozen",
            "pytest",
            *arguments,
            f"--junitxml={report}",
        ),
        (
            "uv",
            "run",
            "--frozen",
            "python",
            "-m",
            "tools.check_junit",
            *(("--hypothesis-contract=t01-core-v1",) if hypothesis_contract else ()),
            report,
        ),
    )


def build_manifest(profile: str) -> tuple[Layer, ...]:
    if profile not in EXPECTED_LAYER_NAMES:
        raise GauntletError(f"未知 Gauntlet profile：{profile}")
    layers = [
        _layer("toolchain", ("uv", "run", "--frozen", "python", "tools/check_toolchain.py")),
        _layer(
            "gauntlet-meta-tests",
            *_pytest_commands(
                "gauntlet-meta",
                "-q",
                "tests/unit/test_gauntlet_check_coverage.py",
                "tests/unit/test_gauntlet_check_licenses.py",
                "tests/unit/test_gauntlet_checkers.py",
                "tests/unit/test_gauntlet_negative_controls.py",
                "tests/unit/test_gauntlet_runner.py",
                "tests/unit/test_junit_checker.py",
                "tests/unit/test_mutation_profile.py",
                "tests/unit/test_semantic_mutants.py",
                "tests/unit/test_semantic_report.py",
                "tests/unit/test_source_state.py",
                "tests/unit/test_stability_runner.py",
                "tests/unit/test_workflow_contract.py",
            ),
        ),
        _layer("tests", *_pytest_commands("all-tests", "-q")),
        _layer("types", ("uv", "run", "--frozen", "mypy", "--strict", "src/sigmacoder")),
        _layer("lint", ("uv", "run", "--frozen", "ruff", "check", ".")),
        _layer("format", ("uv", "run", "--frozen", "ruff", "format", "--check", ".")),
        _layer(
            "coverage",
            *_pytest_commands(
                "coverage-tests",
                "-q",
                "--cov=src/sigmacoder",
                "--cov-branch",
                "--cov-report=xml:coverage.xml",
                "--cov-report=json:coverage.json",
            ),
            (
                "uv",
                "run",
                "--frozen",
                "python",
                "tools/check_coverage.py",
                "--input",
                "coverage.json",
                "--total-branch-min",
                "95",
                "--module-branch",
                "src/sigmacoder/domain/events.py=100",
                "--module-branch",
                "src/sigmacoder/application/task_service.py=100",
            ),
            (
                "uv",
                "run",
                "--frozen",
                "diff-cover",
                "coverage.xml",
                "--compare-branch",
                "main",
                "--fail-under=100",
            ),
            timeout=1200,
        ),
        _layer(
            "properties",
            *_pytest_commands(
                "properties",
                "-q",
                "--hypothesis-profile=default",
                "--hypothesis-seed=20260823",
                "--hypothesis-show-statistics",
                "tests/property",
                hypothesis_contract=True,
            ),
        ),
        _layer(
            "random-order-1",
            *_pytest_commands("random-order-1", "-q", "--randomly-seed=20260821"),
        ),
        _layer(
            "random-order-2",
            *_pytest_commands("random-order-2", "-q", "--randomly-seed=20260822"),
        ),
        _layer(
            "random-order-3",
            *_pytest_commands("random-order-3", "-q", "--randomly-seed=20260823"),
        ),
        _layer(
            "stability",
            ("uv", "run", "--frozen", "python", "tools/run_stability.py"),
            timeout=1200,
        ),
        _layer(
            "real-execution",
            *_pytest_commands("real-execution", "-q", "tests/e2e"),
        ),
        _layer(
            "secret-scan",
            ("uv", "run", "--frozen", "python", "tools/check_secrets.py", "--repo", "."),
        ),
        _layer(
            "supply-chain",
            ("uv", "lock", "--check"),
            ("uv", "sync", "--frozen"),
            (
                "uv",
                "export",
                "--format",
                "requirements.txt",
                "--all-groups",
                "--no-emit-project",
                "--frozen",
                "--output-file",
                "build/audit-requirements.txt",
            ),
            (
                "uv",
                "run",
                "--frozen",
                "pip-audit",
                "--requirement",
                "build/audit-requirements.txt",
                "--strict",
            ),
            timeout=1200,
        ),
        _layer(
            "licenses",
            (
                "uv",
                "run",
                "--frozen",
                "pip-licenses",
                "--format=json",
                "--with-system",
                "--with-authors",
                "--ignore-packages",
                "sigmacoder",
                "--output-file",
                "build/licenses.json",
            ),
            (
                "uv",
                "run",
                "--frozen",
                "python",
                "tools/check_licenses.py",
                "build/licenses.json",
            ),
            cleanup=("build/licenses.json",),
        ),
    ]
    if profile == PROFILE_UBUNTU:
        layers.extend(
            [
                _layer(
                    "mutation-events",
                    ("uv", "run", "--frozen", "python", "tools/run_mutation_profile.py", "events"),
                    timeout=7200,
                ),
                _layer(
                    "mutation-task-service",
                    (
                        "uv",
                        "run",
                        "--frozen",
                        "python",
                        "tools/run_mutation_profile.py",
                        "task-service",
                    ),
                    timeout=7200,
                ),
                _layer(
                    "mutation-semantic",
                    (
                        "uv",
                        "run",
                        "--frozen",
                        "python",
                        "tools/semantic_mutants.py",
                    ),
                    (
                        "uv",
                        "run",
                        "--frozen",
                        "python",
                        "-m",
                        "tools.check_semantic_report",
                    ),
                    timeout=7200,
                ),
            ]
        )
    source_state_commands: list[tuple[str, ...]] = [
        ("uv", "run", "--frozen", "python", "tools/source_state.py", "--repo", ".")
    ]
    if profile == PROFILE_UBUNTU:
        source_state_commands.append(
            ("uv", "run", "--frozen", "python", "-m", "tools.check_mutation_reports")
        )
        source_state_commands.append(
            ("uv", "run", "--frozen", "python", "-m", "tools.check_semantic_report")
        )
    layers.append(_layer("source-state", *source_state_commands))
    manifest = tuple(layers)
    validate_manifest(profile, manifest)
    return manifest


def validate_manifest(profile: str, layers: Sequence[Layer]) -> None:
    expected = EXPECTED_LAYER_NAMES.get(profile)
    if expected is None:
        raise GauntletError(f"未知 Gauntlet profile：{profile}")
    actual = tuple(layer.name for layer in layers)
    if actual != expected:
        raise GauntletError(f"层清单不完整或顺序错误：期望 {expected}，实际 {actual}。")
    if len(set(actual)) != len(actual):
        raise GauntletError("层清单包含重复名称。")
    for layer in layers:
        if not layer.commands or any(not command for command in layer.commands):
            raise GauntletError(f"层 {layer.name} 没有可执行命令。")


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        attributes = 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(is_junction()) or bool(attributes & reparse_flag)


def _git_head(repo: Path) -> str:
    raw = _git_output(
        repo,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        "Git HEAD",
    )
    try:
        head = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise GauntletError(f"Git HEAD 不是 ASCII：{exc}") from exc
    if len(head) not in {40, 64} or any(character not in "0123456789abcdef" for character in head):
        raise GauntletError("无法读取有效 Git HEAD。")
    return head


def _git_output(repo: Path, arguments: Sequence[str], label: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GauntletError(f"无法读取 {label}：{exc}") from exc
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise GauntletError(f"无法读取 {label}：{error}")
    return result.stdout


def _protected_file_bytes(path: Path, label: str) -> bytes:
    if _is_link_or_junction(path) or path.resolve(strict=False) != path or not path.is_file():
        raise GauntletError(f"受保护的 {label} 必须是仓库内普通文件且不得是链接。")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise GauntletError(f"无法读取受保护的 {label}：{exc}") from exc


def _update_digest(digest: _Digest, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _validated_input_file(repo: Path, relative_text: str) -> Path:
    relative_path = Path(relative_text)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise GauntletError(f"Git 输入路径逃逸仓库：{relative_text}")
    ancestor = repo
    for part in relative_path.parts:
        ancestor /= part
        if _is_link_or_junction(ancestor):
            raise GauntletError(
                f"Gauntlet 非忽略输入路径不得经过链接或 reparse point：{relative_text}"
            )
    path = repo / relative_path
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(repo)
    except (OSError, ValueError) as exc:
        raise GauntletError(f"Git 输入无法解析为仓库内文件：{relative_text}") from exc
    if _is_link_or_junction(path) or not path.is_file():
        raise GauntletError(f"Gauntlet 非忽略输入必须是仓库内普通文件：{relative_text}")
    return path


def _read_input_bytes(path: Path, relative_text: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise GauntletError(f"无法读取 Git 输入 {relative_text}：{exc}") from exc


def _input_tree_digest(repo: Path) -> tuple[str, int]:
    raw_paths = _git_output(
        repo,
        ("ls-files", "-z", "--cached", "--others", "--exclude-standard"),
        "Git 非忽略输入清单",
    )
    try:
        relative_paths = sorted(item.decode("utf-8") for item in raw_paths.split(b"\0") if item)
    except UnicodeError as exc:
        raise GauntletError(f"Git 输入路径不是 UTF-8：{exc}") from exc
    if not relative_paths or len(relative_paths) != len(set(relative_paths)):
        raise GauntletError("Git 非忽略输入清单为空或包含重复路径。")
    digest = hashlib.sha256()
    for relative_text in relative_paths:
        path = _validated_input_file(repo, relative_text)
        relative = relative_text.encode("utf-8")
        _update_digest(digest, relative)
        _update_digest(digest, b"file")
        _update_digest(digest, _read_input_bytes(path, relative_text))
    return digest.hexdigest(), len(relative_paths)


def _manifest_digest(profile: str, layers: Sequence[Layer]) -> str:
    payload = {
        "profile": profile,
        "layers": [asdict(layer) for layer in layers],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _capture_repository_binding(
    repo: Path,
    profile: str,
    layers: Sequence[Layer],
) -> RepositoryBinding:
    git_head = _git_head(repo)
    git_status_sha256 = hashlib.sha256(
        _git_output(
            repo,
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
            "Git status",
        )
    ).hexdigest()
    input_tree_sha256, input_file_count = _input_tree_digest(repo)
    uv_lock_sha256 = hashlib.sha256(_protected_file_bytes(repo / "uv.lock", "uv.lock")).hexdigest()
    mutation_profiles_sha256 = hashlib.sha256(
        _protected_file_bytes(
            repo / "tools/mutation_profiles.json",
            "tools/mutation_profiles.json",
        )
    ).hexdigest()
    profile_manifest_sha256 = _manifest_digest(profile, layers)
    components = {
        "git_head": git_head,
        "git_status_sha256": git_status_sha256,
        "input_file_count": input_file_count,
        "input_tree_sha256": input_tree_sha256,
        "mutation_profiles_sha256": mutation_profiles_sha256,
        "profile_manifest_sha256": profile_manifest_sha256,
        "uv_lock_sha256": uv_lock_sha256,
    }
    protected_state_sha256 = hashlib.sha256(
        json.dumps(
            components,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return RepositoryBinding(
        git_head=git_head,
        git_status_sha256=git_status_sha256,
        input_tree_sha256=input_tree_sha256,
        input_file_count=input_file_count,
        uv_lock_sha256=uv_lock_sha256,
        profile_manifest_sha256=profile_manifest_sha256,
        mutation_profiles_sha256=mutation_profiles_sha256,
        protected_state_sha256=protected_state_sha256,
    )


def _verify_repository_binding(
    repo: Path,
    profile: str,
    layers: Sequence[Layer],
    expected: RepositoryBinding,
    phase: str,
) -> None:
    actual = _capture_repository_binding(repo, profile, layers)
    if actual == expected:
        return
    changed = [
        field for field in asdict(expected) if getattr(actual, field) != getattr(expected, field)
    ]
    raise GauntletError(f"{phase}受保护仓库状态发生变化：{', '.join(changed)}。")


def _os_release_id(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise GauntletError(f"无法读取 Ubuntu 身份文件 {path}：{exc}") from exc
    values: list[str] = []
    for line in lines:
        key, separator, raw_value = line.partition("=")
        if separator and key.strip() == "ID":
            value = raw_value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            values.append(value)
    if len(values) != 1 or not values[0]:
        raise GauntletError(f"Ubuntu 身份文件 {path} 必须且只能包含一个非空 ID。")
    return values[0]


def validate_platform(
    profile: str,
    system_name: str | None = None,
    *,
    os_release_path: Path | None = None,
) -> None:
    actual = system_name or platform.system()
    if profile == PROFILE_UBUNTU and actual != "Linux":
        raise GauntletError(f"{PROFILE_UBUNTU} 只能在 Linux/Ubuntu 执行，当前为 {actual}。")
    if profile == PROFILE_UBUNTU:
        release_path = os_release_path or Path("/etc/os-release")
        distribution_id = _os_release_id(release_path)
        if distribution_id != "ubuntu":
            raise GauntletError(
                f"{PROFILE_UBUNTU} 只能在 Ubuntu 执行，当前发行版 ID={distribution_id!r}。"
            )
    if profile == PROFILE_WINDOWS and actual != "Windows":
        raise GauntletError(f"{PROFILE_WINDOWS} 只能在 Windows 执行，当前为 {actual}。")


def _safe_repo_path(repo: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise GauntletError(f"清理路径逃逸仓库：{relative}")
    resolved_repo = repo.resolve()
    candidate = resolved_repo / relative_path
    if candidate == resolved_repo:
        raise GauntletError("拒绝把仓库根目录作为清理目标。")
    try:
        candidate.relative_to(resolved_repo)
    except ValueError as exc:
        raise GauntletError(f"清理路径逃逸仓库：{relative}") from exc
    is_junction = getattr(candidate, "is_junction", lambda: False)
    if candidate.is_symlink() or is_junction() or candidate.resolve(strict=False) != candidate:
        raise GauntletError(f"清理路径不得经过链接或 junction：{relative}")
    return candidate


def cleanup_paths(repo: Path, paths: Sequence[str]) -> None:
    for relative in paths:
        candidate = _safe_repo_path(repo, relative)
        if candidate.is_dir():
            shutil.rmtree(candidate)
        elif candidate.exists():
            candidate.unlink()


def cleanup_globs(repo: Path, patterns: Sequence[str]) -> None:
    """清除仓库根内固定模式命中的陈旧并行报告。"""

    resolved_repo = repo.resolve()
    for pattern in patterns:
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise GauntletError(f"清理模式逃逸仓库：{pattern}")
        for candidate in resolved_repo.glob(pattern):
            safe_candidate = _safe_repo_path(
                resolved_repo, candidate.relative_to(resolved_repo).as_posix()
            )
            if safe_candidate.is_symlink() or safe_candidate.is_file():
                safe_candidate.unlink()
            elif safe_candidate.is_dir():
                shutil.rmtree(safe_candidate)


def _execute(
    command: Sequence[str],
    *,
    repo: Path,
    timeout: int,
    runner: CommandRunner,
    repository_lease_token: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment.pop(REPOSITORY_LEASE_TOKEN_ENV, None)
    if repository_lease_token is not None and _is_repository_lease_child(command):
        environment[REPOSITORY_LEASE_TOKEN_ENV] = repository_lease_token
    try:
        return runner(
            list(command),
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=environment,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GauntletError(f"命令超时：{' '.join(command)}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise GauntletError(f"命令无法执行：{' '.join(command)}：{exc}") from exc


def _is_mutation_report_checker(command: Sequence[str]) -> bool:
    return any(
        item == "-m"
        and index + 1 < len(command)
        and command[index + 1] == "tools.check_mutation_reports"
        for index, item in enumerate(command)
    )


def _is_semantic_report_checker(command: Sequence[str]) -> bool:
    return any(
        item == "-m"
        and index + 1 < len(command)
        and command[index + 1] == "tools.check_semantic_report"
        for index, item in enumerate(command)
    )


def _is_mutation_profile_runner(command: Sequence[str]) -> bool:
    return "tools/run_mutation_profile.py" in command or any(
        item == "-m"
        and index + 1 < len(command)
        and command[index + 1] == "tools.run_mutation_profile"
        for index, item in enumerate(command)
    )


def _is_semantic_mutation_runner(command: Sequence[str]) -> bool:
    return "tools/semantic_mutants.py" in command or any(
        item == "-m" and index + 1 < len(command) and command[index + 1] == "tools.semantic_mutants"
        for index, item in enumerate(command)
    )


def _is_repository_lease_child(command: Sequence[str]) -> bool:
    return _is_mutation_profile_runner(command) or _is_semantic_mutation_runner(command)


def _is_junit_checker(command: Sequence[str]) -> bool:
    return any(
        item == "-m" and index + 1 < len(command) and command[index + 1] == "tools.check_junit"
        for index, item in enumerate(command)
    )


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_hypothesis_evidence(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "contract_version",
        "minimum_examples",
        "profile",
        "properties",
        "seed",
        "shrink",
    }:
        raise GauntletError("Hypothesis 结构化证据字段无效。")
    properties = value.get("properties")
    if (
        value.get("contract_version") != "t01-core-v1"
        or value.get("minimum_examples") != 200
        or isinstance(value.get("minimum_examples"), bool)
        or value.get("profile") != "default"
        or value.get("seed") != 20260823
        or isinstance(value.get("seed"), bool)
        or value.get("shrink") != "NOT_APPLICABLE"
        or not isinstance(properties, list)
        or len(properties) != len(CORE_PROPERTY_NODEIDS)
    ):
        raise GauntletError("Hypothesis 证据未绑定固定 contract/profile/seed/9 个属性。")
    nodeids: set[str] = set()
    for property_evidence in properties:
        if not isinstance(property_evidence, dict) or set(property_evidence) != {
            "nodeid",
            "passing",
            "failing",
            "invalid",
            "max_examples",
            "shrink",
            "stats_sha256",
        }:
            raise GauntletError("Hypothesis 单属性证据字段无效。")
        nodeid = property_evidence.get("nodeid")
        integers = {
            name: property_evidence.get(name)
            for name in ("passing", "failing", "invalid", "max_examples")
        }
        if (
            not isinstance(nodeid, str)
            or not nodeid
            or nodeid in nodeids
            or any(
                isinstance(number, bool) or not isinstance(number, int)
                for number in integers.values()
            )
            or integers["passing"] < 200
            or integers["failing"] != 0
            or integers["invalid"] < 0
            or integers["max_examples"] < 200
            or property_evidence.get("shrink") != "NOT_APPLICABLE"
            or not _is_lower_sha256(property_evidence.get("stats_sha256"))
        ):
            raise GauntletError("Hypothesis 单属性证据未证明 ≥200 passing、零 failing。")
        nodeids.add(nodeid)
    if nodeids != set(CORE_PROPERTY_NODEIDS):
        raise GauntletError("Hypothesis 证据未绑定版本化核心属性 nodeid 集合。")


def _validate_junit_checker_output(payload: object, *, require_hypothesis: bool) -> None:
    expected_top = {"ok", "reports", *(("hypothesis",) if require_hypothesis else ())}
    if not isinstance(payload, dict) or set(payload) != expected_top:
        raise GauntletError("JUnit checker JSON 顶层契约无效。")
    reports = payload.get("reports")
    if payload.get("ok") is not True or not isinstance(reports, list) or len(reports) != 1:
        raise GauntletError("JUnit checker JSON 未证明唯一报告。")
    report = reports[0]
    expected_fields = {"path", "sha256", "tests", "failures", "errors", "skipped"}
    if not isinstance(report, dict) or set(report) != expected_fields:
        raise GauntletError("JUnit checker JSON 报告字段无效。")
    numeric = {name: report.get(name) for name in ("tests", "failures", "errors", "skipped")}
    if (
        not isinstance(report.get("path"), str)
        or not report["path"]
        or not _is_lower_sha256(report.get("sha256"))
        or any(isinstance(value, bool) or not isinstance(value, int) for value in numeric.values())
        or numeric["tests"] <= 0
        or any(numeric[name] != 0 for name in ("failures", "errors", "skipped"))
    ):
        raise GauntletError("JUnit checker JSON 未证明 tests>0 且零失败、错误、跳过。")
    if require_hypothesis:
        _validate_hypothesis_evidence(payload.get("hypothesis"))


def _validate_json_command_output(command: Sequence[str], stdout: str) -> object | None:
    if not (
        _is_mutation_report_checker(command)
        or _is_semantic_report_checker(command)
        or _is_junit_checker(command)
    ):
        return None
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise GauntletError("结构化 checker 未输出有效 JSON。") from exc
    if _is_junit_checker(command):
        _validate_junit_checker_output(
            payload,
            require_hypothesis="--hypothesis-contract=t01-core-v1" in command,
        )
        return payload
    if _is_semantic_report_checker(command):
        if (
            not isinstance(payload, dict)
            or set(payload) != {"ok", "report_sha256", "git_head", "mutants"}
            or payload.get("ok") is not True
            or not _is_lower_sha256(payload.get("report_sha256"))
            or not isinstance(payload.get("git_head"), str)
            or len(payload["git_head"]) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in payload["git_head"])
            or payload.get("mutants") != 8
            or isinstance(payload.get("mutants"), bool)
        ):
            raise GauntletError("semantic mutation checker JSON 未证明八类有效报告。")
        return payload
    if not isinstance(payload, dict) or set(payload) != {"ok", "reports"}:
        raise GauntletError("mutation 双报告 checker JSON 顶层契约无效。")
    reports = payload.get("reports")
    if (
        payload.get("ok") is not True
        or not isinstance(reports, dict)
        or set(reports) != {"events", "task-service"}
        or not all(_is_lower_sha256(value) for value in reports.values())
    ):
        raise GauntletError("mutation 双报告 checker JSON 未证明两份有效报告。")
    return payload


def _frame_layer_evidence(digest: _Digest, label: str, value: bytes) -> None:
    _update_digest(digest, label.encode("ascii"))
    _update_digest(digest, value)


def _execute_with_state_guard(
    command: Sequence[str],
    *,
    repo: Path,
    timeout: int,
    runner: CommandRunner,
    repository_lease_token: str | None,
    state_guard: StateGuard | None,
    command_index: int,
) -> subprocess.CompletedProcess[str]:
    if state_guard is not None:
        state_guard(f"命令 {command_index} 执行前")
    result = _execute(
        command,
        repo=repo,
        timeout=timeout,
        runner=runner,
        repository_lease_token=repository_lease_token,
    )
    if state_guard is not None:
        state_guard(f"命令 {command_index} 执行后")
    return result


def run_layer(
    layer: Layer,
    repo: Path,
    *,
    runner: CommandRunner = subprocess.run,
    repository_lease_token: str | None = None,
    state_guard: StateGuard | None = None,
) -> LayerResult:
    started = time.monotonic()
    digest = hashlib.sha256()
    saw_output = False
    structured_evidence: list[object] = []
    for command_index, command in enumerate(layer.commands, start=1):
        result = _execute_with_state_guard(
            command,
            repo=repo,
            timeout=layer.timeout_seconds,
            runner=runner,
            repository_lease_token=repository_lease_token,
            state_guard=state_guard,
            command_index=command_index,
        )
        _frame_layer_evidence(
            digest,
            "command",
            json.dumps(
                list(command),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        _frame_layer_evidence(digest, "returncode", str(result.returncode).encode("ascii"))
        _frame_layer_evidence(digest, "stdout", result.stdout.encode("utf-8"))
        _frame_layer_evidence(digest, "stderr", result.stderr.encode("utf-8"))
        saw_output = saw_output or bool(result.stdout.strip() or result.stderr.strip())
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
        if result.returncode != 0:
            raise GauntletError(
                f"层 {layer.name} 命令退出码为 {result.returncode}：{' '.join(command)}"
            )
        evidence = _validate_json_command_output(command, result.stdout)
        if evidence is not None:
            structured_evidence.append(evidence)
    if not saw_output:
        raise GauntletError(f"层 {layer.name} 的命令全部以 0 退出但未产生任何输出。")
    cleanup_paths(repo, layer.cleanup_after)
    return LayerResult(
        name=layer.name,
        commands=len(layer.commands),
        duration_seconds=round(time.monotonic() - started, 3),
        output_sha256=digest.hexdigest(),
        structured_evidence=tuple(structured_evidence),
    )


def audit_completion(profile: str, results: Sequence[LayerResult]) -> None:
    expected = EXPECTED_LAYER_NAMES[profile]
    actual = tuple(result.name for result in results)
    if actual != expected:
        raise GauntletError(f"完成审计失败：期望 {expected}，实际 {actual}。")
    if any(result.commands <= 0 or len(result.output_sha256) != 64 for result in results):
        raise GauntletError("完成审计发现空命令或无效输出摘要。")


def run_gauntlet(
    repo: Path,
    profile: str,
    *,
    runner: CommandRunner = subprocess.run,
    enforce_platform: bool = True,
) -> GauntletRunResult:
    repo = repo.resolve()
    if enforce_platform:
        validate_platform(profile)
    layers = build_manifest(profile)
    try:
        with acquire_repository_lease(repo, f"gauntlet:{profile}") as lease:
            binding = _capture_repository_binding(repo, profile, layers)
            cleanup_paths(repo, STALE_PATHS)
            cleanup_globs(repo, STALE_GLOBS)
            results: list[LayerResult] = []
            for layer in layers:
                _verify_repository_binding(
                    repo,
                    profile,
                    layers,
                    binding,
                    f"层 {layer.name} 执行前，",
                )
                print(f"\n=== Gauntlet 层：{layer.name} ===")
                results.append(
                    run_layer(
                        layer,
                        repo,
                        runner=runner,
                        repository_lease_token=lease.token,
                        state_guard=lambda command_phase, layer_name=layer.name: (
                            _verify_repository_binding(
                                repo,
                                profile,
                                layers,
                                binding,
                                f"层 {layer_name} {command_phase}，",
                            )
                        ),
                    )
                )
                _verify_repository_binding(
                    repo,
                    profile,
                    layers,
                    binding,
                    f"层 {layer.name} 执行后，",
                )
            audit_completion(profile, results)
            _verify_repository_binding(
                repo,
                profile,
                layers,
                binding,
                "最终完成审计时，",
            )
            return GauntletRunResult(
                profile=profile,
                binding=binding,
                layers=tuple(results),
            )
    except RepositoryLeaseError as exc:
        raise GauntletError(str(exc)) from exc


def default_profile() -> str:
    system_name = platform.system()
    if system_name == "Windows":
        return PROFILE_WINDOWS
    if system_name == "Linux":
        return PROFILE_UBUNTU
    raise GauntletError(f"不支持的平台：{system_name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行 T01 Tier 3 Gauntlet。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument("--profile", choices=(PROFILE_UBUNTU, PROFILE_WINDOWS))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = args.profile or default_profile()
        result = run_gauntlet(args.repo, profile)
    except GauntletError as exc:
        print(f"Gauntlet 失败：{exc}", file=sys.stderr)
        return 1
    payload = {
        "ok": True,
        "spec_version": SPEC_VERSION,
        "profile": result.profile,
        "binding": asdict(result.binding),
        "layers": [asdict(layer) for layer in result.layers],
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
