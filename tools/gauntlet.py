"""T01 Tier 3 的固定、fail-closed Gauntlet 总入口。"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

SPEC_VERSION = "r4"
PROFILE_UBUNTU = "ubuntu-tier3"
PROFILE_WINDOWS = "windows-compat"


class GauntletError(RuntimeError):
    """Gauntlet 配置、执行或完成审计失败。"""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


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
        "source-state",
    ),
    PROFILE_WINDOWS: (*COMMON_LAYER_NAMES, "source-state"),
}

STALE_PATHS = (
    ".coverage",
    "coverage.xml",
    "coverage.json",
    "licenses.json",
    "build/audit-requirements.txt",
    "mutants",
    ".pytest_cache",
)


def _layer(
    name: str, *commands: Sequence[str], timeout: int = 900, cleanup: Sequence[str] = ()
) -> Layer:
    return Layer(
        name=name,
        commands=tuple(tuple(command) for command in commands),
        timeout_seconds=timeout,
        cleanup_after=tuple(cleanup),
    )


def build_manifest(profile: str) -> tuple[Layer, ...]:
    if profile not in EXPECTED_LAYER_NAMES:
        raise GauntletError(f"未知 Gauntlet profile：{profile}")
    layers = [
        _layer("toolchain", ("uv", "run", "--frozen", "python", "tools/check_toolchain.py")),
        _layer("gauntlet-meta-tests", ("uv", "run", "--frozen", "pytest", "-q", "tests/gauntlet")),
        _layer("tests", ("uv", "run", "--frozen", "pytest", "-q")),
        _layer("types", ("uv", "run", "--frozen", "mypy", "--strict", "src/sigmacoder")),
        _layer("lint", ("uv", "run", "--frozen", "ruff", "check", ".")),
        _layer("format", ("uv", "run", "--frozen", "ruff", "format", "--check", ".")),
        _layer(
            "coverage",
            (
                "uv",
                "run",
                "--frozen",
                "pytest",
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
        _layer("properties", ("uv", "run", "--frozen", "pytest", "-q", "tests/property")),
        _layer(
            "random-order-1",
            ("uv", "run", "--frozen", "pytest", "-q", "--randomly-seed=20260821"),
        ),
        _layer(
            "random-order-2",
            ("uv", "run", "--frozen", "pytest", "-q", "--randomly-seed=20260822"),
        ),
        _layer(
            "random-order-3",
            ("uv", "run", "--frozen", "pytest", "-q", "--randomly-seed=20260823"),
        ),
        _layer("real-execution", ("uv", "run", "--frozen", "pytest", "-q", "tests/e2e")),
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
                "licenses.json",
            ),
            ("uv", "run", "--frozen", "python", "tools/check_licenses.py", "licenses.json"),
            cleanup=("licenses.json",),
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
            ]
        )
    layers.append(
        _layer(
            "source-state",
            ("uv", "run", "--frozen", "python", "tools/source_state.py", "--repo", "."),
        )
    )
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


def validate_platform(profile: str, system_name: str | None = None) -> None:
    actual = system_name or platform.system()
    if profile == PROFILE_UBUNTU and actual != "Linux":
        raise GauntletError(f"{PROFILE_UBUNTU} 只能在 Linux/Ubuntu 执行，当前为 {actual}。")
    if profile == PROFILE_WINDOWS and actual != "Windows":
        raise GauntletError(f"{PROFILE_WINDOWS} 只能在 Windows 执行，当前为 {actual}。")


def _safe_repo_path(repo: Path, relative: str) -> Path:
    candidate = (repo / relative).resolve()
    try:
        candidate.relative_to(repo.resolve())
    except ValueError as exc:
        raise GauntletError(f"清理路径逃逸仓库：{relative}") from exc
    return candidate


def cleanup_paths(repo: Path, paths: Sequence[str]) -> None:
    for relative in paths:
        candidate = _safe_repo_path(repo, relative)
        if candidate.is_dir():
            shutil.rmtree(candidate)
        elif candidate.exists():
            candidate.unlink()


def _execute(
    command: Sequence[str],
    *,
    repo: Path,
    timeout: int,
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(command),
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GauntletError(f"命令超时：{' '.join(command)}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise GauntletError(f"命令无法执行：{' '.join(command)}：{exc}") from exc


def run_layer(
    layer: Layer,
    repo: Path,
    *,
    runner: CommandRunner = subprocess.run,
) -> LayerResult:
    started = time.monotonic()
    digest = hashlib.sha256()
    for command in layer.commands:
        result = _execute(command, repo=repo, timeout=layer.timeout_seconds, runner=runner)
        digest.update(result.stdout.encode("utf-8"))
        digest.update(result.stderr.encode("utf-8"))
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
        if result.returncode != 0:
            raise GauntletError(
                f"层 {layer.name} 命令退出码为 {result.returncode}：{' '.join(command)}"
            )
    cleanup_paths(repo, layer.cleanup_after)
    return LayerResult(
        name=layer.name,
        commands=len(layer.commands),
        duration_seconds=round(time.monotonic() - started, 3),
        output_sha256=digest.hexdigest(),
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
) -> list[LayerResult]:
    repo = repo.resolve()
    if enforce_platform:
        validate_platform(profile)
    layers = build_manifest(profile)
    cleanup_paths(repo, STALE_PATHS)
    results: list[LayerResult] = []
    for layer in layers:
        print(f"\n=== Gauntlet 层：{layer.name} ===")
        results.append(run_layer(layer, repo, runner=runner))
    audit_completion(profile, results)
    return results


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
        results = run_gauntlet(args.repo, profile)
    except GauntletError as exc:
        print(f"Gauntlet 失败：{exc}", file=sys.stderr)
        return 1
    payload = {
        "ok": True,
        "spec_version": SPEC_VERSION,
        "profile": profile,
        "layers": [result.__dict__ for result in results],
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
