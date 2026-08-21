"""确认最终候选 Git 源状态没有未记录改动。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path


class SourceStateError(RuntimeError):
    """Git 源状态不可读或不干净。"""


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _git_paths(repo: Path, arguments: Sequence[str], runner: Runner) -> set[str]:
    command = ["git", "-C", str(repo), *arguments, "-z"]
    try:
        result = runner(command, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceStateError(f"无法执行 {' '.join(command[:-1])}：{exc}") from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise SourceStateError(f"Git 命令退出码 {result.returncode}：{stderr}")
    try:
        return {
            item.decode("utf-8", errors="strict") for item in result.stdout.split(b"\0") if item
        }
    except UnicodeDecodeError as exc:
        raise SourceStateError(f"Git 路径不是有效 UTF-8：{exc}") from exc


def inspect_source_state(
    repo: Path,
    *,
    runner: Runner = subprocess.run,
) -> dict[str, list[str]]:
    repo = repo.resolve()
    staged = _git_paths(repo, ["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"], runner)
    unstaged = _git_paths(repo, ["diff", "--name-only", "--diff-filter=ACMRTUXB"], runner)
    deleted = _git_paths(repo, ["diff", "--name-only", "--diff-filter=D"], runner)
    deleted |= _git_paths(repo, ["diff", "--cached", "--name-only", "--diff-filter=D"], runner)
    untracked = _git_paths(repo, ["ls-files", "--others", "--exclude-standard"], runner)
    return {
        "staged": sorted(staged),
        "unstaged": sorted(unstaged),
        "deleted": sorted(deleted),
        "untracked": sorted(untracked),
    }


def assert_clean(state: dict[str, list[str]]) -> None:
    dirty = {name: paths for name, paths in state.items() if paths}
    if dirty:
        details = "; ".join(f"{name}={','.join(paths)}" for name, paths in dirty.items())
        raise SourceStateError(f"存在未记录源状态：{details}")


def head_sha(repo: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceStateError(f"无法读取 HEAD：{exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise SourceStateError(f"HEAD 不可用：{result.stderr.strip()}")
    return result.stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="核验最终候选 Git 源状态。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Git 仓库根目录。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = args.repo.resolve()
    try:
        state = inspect_source_state(repo)
        assert_clean(state)
        commit = head_sha(repo)
    except SourceStateError as exc:
        print(f"源状态门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "commit": commit, "state": state}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
