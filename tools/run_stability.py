"""重复并发与真实崩溃矩阵，任何一次波动都阻断完成。"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

MINIMUM_REPEATS = 20


class StabilityGateError(RuntimeError):
    """稳定性矩阵配置错误或任一重复失败。"""


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _execute(
    command: Sequence[str],
    *,
    repo: Path,
    environment: Mapping[str, str],
    runner: Runner,
    label: str,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(command),
            cwd=repo,
            env=dict(environment),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=1200,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise StabilityGateError(f"{label} 无法执行：{error}") from error
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(
            result.stderr,
            file=sys.stderr,
            end="" if result.stderr.endswith("\n") else "\n",
        )
    if result.returncode != 0:
        raise StabilityGateError(f"{label} 退出码为 {result.returncode}。")
    return result


def _junit_commands(
    root: Path,
    report_name: str,
    pytest_arguments: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    report_root = root / "build/test-results"
    report = report_root / f"{report_name}.xml"
    if report_root.is_symlink() or report.is_symlink():
        raise StabilityGateError("稳定性 JUnit 路径不得是链接。")
    report_root.mkdir(parents=True, exist_ok=True)
    if report.exists():
        raise StabilityGateError(f"稳定性 JUnit 报告已存在，拒绝复用陈旧证据：{report}")
    relative = report.relative_to(root).as_posix()
    pytest_command = (
        sys.executable,
        "-m",
        "pytest",
        *pytest_arguments,
        f"--junitxml={relative}",
    )
    checker_command = (sys.executable, "-m", "tools.check_junit", relative)
    return pytest_command, checker_command


def _execute_pytest_with_junit(
    *,
    root: Path,
    report_name: str,
    pytest_arguments: Sequence[str],
    environment: Mapping[str, str],
    runner: Runner,
    label: str,
) -> None:
    pytest_command, checker_command = _junit_commands(root, report_name, pytest_arguments)
    _execute(
        pytest_command,
        repo=root,
        environment=environment,
        runner=runner,
        label=label,
    )
    checker_result = _execute(
        checker_command,
        repo=root,
        environment=environment,
        runner=runner,
        label=f"{label} JUnit 审计",
    )
    try:
        payload = json.loads(checker_result.stdout)
    except json.JSONDecodeError as exc:
        raise StabilityGateError(f"{label} JUnit checker 未输出有效 JSON。") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"ok", "reports"}
        or payload.get("ok") is not True
        or not isinstance(payload.get("reports"), list)
        or len(payload["reports"]) != 1
    ):
        raise StabilityGateError(f"{label} JUnit checker JSON 契约无效。")


def run_stability(
    repo: Path,
    *,
    repeats: int = MINIMUM_REPEATS,
    runner: Runner = subprocess.run,
) -> None:
    """并发矩阵内部重复 N 次，崩溃矩阵以独立 pytest 进程重复 N 次。"""

    if repeats < MINIMUM_REPEATS:
        raise StabilityGateError(f"稳定性重复次数必须至少为 {MINIMUM_REPEATS}。")
    root = repo.resolve()
    base_environment = dict(os.environ)
    concurrency_environment = dict(base_environment)
    concurrency_environment["SIGMACODER_CONCURRENCY_REPEATS"] = str(repeats)
    _execute_pytest_with_junit(
        root=root,
        report_name="stability-concurrency",
        pytest_arguments=(
            "-q",
            "tests/e2e/test_cli_git_boundaries.py::"
            "test_s12_concurrent_cli_starts_have_unique_isolated_event_streams",
        ),
        environment=concurrency_environment,
        runner=runner,
        label="并发稳定性矩阵",
    )
    for iteration in range(1, repeats + 1):
        crash_environment = dict(base_environment)
        crash_environment["SIGMACODER_STABILITY_ITERATION"] = str(iteration)
        _execute_pytest_with_junit(
            root=root,
            report_name=f"stability-crash-{iteration:02d}",
            pytest_arguments=("-q", "tests/e2e/test_cli_crash_recovery.py"),
            environment=crash_environment,
            runner=runner,
            label=f"第 {iteration} 次崩溃矩阵",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行 T01 并发与崩溃稳定性矩阵。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument("--repeats", type=int, default=MINIMUM_REPEATS, help="重复次数。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run_stability(args.repo, repeats=args.repeats)
    except StabilityGateError as error:
        print(f"稳定性门禁失败：{error}", file=sys.stderr)
        return 1
    print(f"稳定性门禁通过：并发与崩溃矩阵各完成 {args.repeats} 次。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
