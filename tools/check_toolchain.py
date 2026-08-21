"""核验 T01 SPEC r4 锁定的 Python 与 uv 工具链。"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

EXPECTED_PYTHON = "3.12.14"
EXPECTED_UV = "0.12.5"


class ToolchainError(RuntimeError):
    """工具链不满足规范。"""


def validate_versions(python_version: str, uv_output: str) -> None:
    """对精确版本执行 fail-closed 校验。"""
    if python_version != EXPECTED_PYTHON:
        raise ToolchainError(
            f"Python 版本错误：需要 {EXPECTED_PYTHON}，实际为 {python_version or '空值'}。"
        )
    first_line = uv_output.strip().splitlines()
    if len(first_line) != 1:
        raise ToolchainError("uv 版本输出必须且只能包含一行。")
    fields = first_line[0].split()
    if len(fields) < 2 or fields[0] != "uv" or fields[1] != EXPECTED_UV:
        raise ToolchainError(f"uv 版本错误：需要 {EXPECTED_UV}，实际输出为 {first_line[0]!r}。")


def validate_metadata(repo: Path) -> None:
    """核验版本元数据，避免运行时版本与仓库声明漂移。"""
    python_file = repo / ".python-version"
    pyproject_file = repo / "pyproject.toml"
    try:
        pinned_python = python_file.read_text(encoding="utf-8").strip()
        pyproject = tomllib.loads(pyproject_file.read_text(encoding="utf-8"))
        required_uv = pyproject["tool"]["uv"]["required-version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise ToolchainError(f"无法读取工具链元数据：{exc}") from exc
    if pinned_python != EXPECTED_PYTHON:
        raise ToolchainError(
            f".python-version 必须为 {EXPECTED_PYTHON}，实际为 {pinned_python!r}。"
        )
    if required_uv != f"=={EXPECTED_UV}":
        raise ToolchainError(
            f"tool.uv.required-version 必须为 =={EXPECTED_UV}，实际为 {required_uv!r}。"
        )


def check_toolchain(
    repo: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    python_version: str | None = None,
) -> None:
    """检查当前进程、uv 可执行文件和仓库元数据。"""
    validate_metadata(repo)
    try:
        result = runner(
            ["uv", "--version"],
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ToolchainError(f"无法执行 uv --version：{exc}") from exc
    if result.returncode != 0:
        raise ToolchainError(f"uv --version 退出码为 {result.returncode}：{result.stderr.strip()}")
    validate_versions(python_version or platform.python_version(), result.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="核验 T01 锁定工具链。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        check_toolchain(args.repo.resolve())
    except ToolchainError as exc:
        print(f"工具链门禁失败：{exc}", file=sys.stderr)
        return 1
    print(f"工具链门禁通过：Python {EXPECTED_PYTHON}，uv {EXPECTED_UV}。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
