"""重复并发与真实崩溃矩阵，任何一次波动都阻断完成。"""

from __future__ import annotations

import argparse
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
) -> None:
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
    _execute(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/e2e/test_cli_git_boundaries.py::"
            "test_s12_concurrent_cli_starts_have_unique_isolated_event_streams",
        ),
        repo=root,
        environment=concurrency_environment,
        runner=runner,
        label="并发稳定性矩阵",
    )
    for iteration in range(1, repeats + 1):
        crash_environment = dict(base_environment)
        crash_environment["SIGMACODER_STABILITY_ITERATION"] = str(iteration)
        _execute(
            (
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/e2e/test_cli_crash_recovery.py",
            ),
            repo=root,
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
