"""确认最终候选 Git 源状态没有未记录改动。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

if __package__:
    from tools.trusted_tools import TrustedGit, TrustedToolError
else:  # pragma: no cover - 由真实脚本入口覆盖
    from trusted_tools import (  # type: ignore[import-not-found,no-redef]
        TrustedGit,
        TrustedToolError,
    )


class SourceStateError(RuntimeError):
    """Git 源状态不可读或不干净。"""


Runner = Callable[..., subprocess.CompletedProcess[bytes]]


def _open_git(repo: Path, runner: Runner = subprocess.run) -> TrustedGit:
    try:
        return TrustedGit.open(repo, runner=runner)
    except TrustedToolError as exc:
        raise SourceStateError(f"Git 命令退出码或权威核验失败：{exc}") from exc


def _git_paths(git: TrustedGit, arguments: Sequence[str]) -> set[str]:
    try:
        raw = git.read((*arguments, "-z"), label="Git 源状态")
        return {item.decode("utf-8", errors="strict") for item in raw.split(b"\0") if item}
    except TrustedToolError as exc:
        raise SourceStateError(str(exc)) from exc
    except UnicodeDecodeError as exc:
        raise SourceStateError(f"Git 路径不是有效 UTF-8：{exc}") from exc


def inspect_source_state(
    repo: Path,
    *,
    runner: Runner = subprocess.run,
) -> dict[str, list[str]]:
    repo = repo.resolve()
    git = _open_git(repo, runner)
    staged = _git_paths(git, ["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"])
    unstaged = _git_paths(git, ["diff", "--name-only", "--diff-filter=ACMRTUXB"])
    deleted = _git_paths(git, ["diff", "--name-only", "--diff-filter=D"])
    deleted |= _git_paths(git, ["diff", "--cached", "--name-only", "--diff-filter=D"])
    untracked = _git_paths(git, ["ls-files", "--others", "--exclude-standard"])
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
        return TrustedGit.open(repo).head_commit()
    except TrustedToolError as exc:
        raise SourceStateError(f"HEAD 不可用：{exc}") from exc


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
