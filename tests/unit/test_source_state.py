"""最终 source state 计算器的单元测试。"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest
from tests.support.isolated_git import (
    create_fixture_git_runtime,
    sibling_control_root,
)
from tools.source_state import SourceStateError, assert_clean, inspect_source_state


def git(repo: Path, *arguments: str) -> None:
    runtime = create_fixture_git_runtime(
        sibling_control_root(repo),
        untrusted_boundary=repo,
    )
    result = runtime.init(repo) if arguments == ("init",) else runtime.run(repo, arguments)
    assert result.returncode == 0, result.stderr


def clean_repo(tmp_path: Path) -> Path:
    git(tmp_path, "init")
    git(tmp_path, "config", "user.name", "Gauntlet Test")
    git(tmp_path, "config", "user.email", "gauntlet@example.invalid")
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")
    git(tmp_path, "add", "tracked.txt")
    git(tmp_path, "commit", "-m", "baseline")
    return tmp_path


def test_干净源状态通过(tmp_path: Path) -> None:
    repo = clean_repo(tmp_path)
    state = inspect_source_state(repo)
    assert_clean(state)
    assert state == {"staged": [], "unstaged": [], "deleted": [], "untracked": []}


@pytest.mark.parametrize("kind", ["staged", "unstaged", "deleted", "untracked"])
def test_四类源状态负控分别失败(tmp_path: Path, kind: str) -> None:
    repo = clean_repo(tmp_path)
    tracked = repo / "tracked.txt"
    if kind == "staged":
        tracked.write_text("staged\n", encoding="utf-8")
        git(repo, "add", "tracked.txt")
    elif kind == "unstaged":
        tracked.write_text("unstaged\n", encoding="utf-8")
    elif kind == "deleted":
        tracked.unlink()
    else:
        (repo / "new.txt").write_text("untracked\n", encoding="utf-8")
    state = inspect_source_state(repo)
    assert state[kind]
    with pytest.raises(SourceStateError, match=kind):
        assert_clean(state)


def test_非_git_目录不能误报干净(tmp_path: Path) -> None:
    with pytest.raises(SourceStateError, match="Git 命令退出码"):
        inspect_source_state(tmp_path)


def test_仓库内_git_影子不能伪造干净源状态(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = clean_repo(tmp_path)
    shadow_name = "git.exe" if os.name == "nt" else "git"
    shadow = repo / shadow_name
    shutil.copy2(sys.executable, shadow)
    shadow.chmod(0o755)
    exclude = repo / ".git/info/exclude"
    exclude.parent.mkdir(parents=True, exist_ok=True)
    exclude.write_text(f"{shadow_name}\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(repo) + os.pathsep + os.environ.get("PATH", ""))

    state = inspect_source_state(repo)

    assert_clean(state)
    assert all(not paths for paths in state.values())
