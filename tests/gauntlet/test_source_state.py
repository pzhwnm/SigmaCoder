from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from tools.source_state import SourceStateError, assert_clean, inspect_source_state


def git(repo: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


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
