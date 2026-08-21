"""T01 Git/worktree 适配器的真实边界测试。"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from sigmacoder.adapters.git_workspace import (
    GitWorkspaceAdapter,
    GitWorkspaceError,
    WorkspaceAvailability,
    workspace_slot_name,
)


@dataclass(frozen=True)
class RepositoryFixture:
    """不继承宿主 Git 配置的双提交仓库。"""

    path: Path
    first_commit: str
    second_commit: str
    env: dict[str, str]

    def git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.path), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self.env,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()


def _repository(tmp_path: Path) -> RepositoryFixture:
    path = tmp_path / "source"
    path.mkdir()
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    fixture = RepositoryFixture(path, "", "", env)
    fixture.git("init", "--initial-branch=main")
    fixture.git("config", "user.name", "SigmaCoder Test")
    fixture.git("config", "user.email", "test@example.invalid")
    (path / ".gitignore").write_text("*.ignored\n", encoding="utf-8")
    (path / "tracked.txt").write_text("C1\n", encoding="utf-8")
    fixture.git("add", ".gitignore", "tracked.txt")
    fixture.git("commit", "-m", "C1")
    first = fixture.git("rev-parse", "HEAD")
    (path / "tracked.txt").write_text("C2\n", encoding="utf-8")
    fixture.git("add", "tracked.txt")
    fixture.git("commit", "-m", "C2")
    second = fixture.git("rev-parse", "HEAD")
    return RepositoryFixture(path, first, second, env)


def test_workspace_slot_uses_all_128_nonce_bits(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    adapter = GitWorkspaceAdapter(tmp_path / "control" / "hooks")
    inspection = adapter.inspect_repository(repo.path, repo.first_commit)
    first_nonce = "0123456789abcdef0000000000000000"
    second_nonce = "0123456789abcdefffffffffffffffff"

    assert workspace_slot_name(first_nonce) == f"workspace-{first_nonce}"
    assert workspace_slot_name(second_nonce) == f"workspace-{second_nonce}"
    assert workspace_slot_name(first_nonce) != workspace_slot_name(second_nonce)

    with pytest.raises(GitWorkspaceError) as captured:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "data",
            workspace_relative_path=f"tasks/task/{workspace_slot_name(first_nonce)}",
            ownership_nonce=second_nonce,
            expected_action_digest="a" * 64,
            recomputed_action_digest="a" * 64,
        )
    assert captured.value.code == "INVALID_WORKSPACE_PATH"

    authorized_relative = f"tasks/task/{workspace_slot_name(first_nonce)}"
    with pytest.raises(GitWorkspaceError) as digest_error:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "data",
            workspace_relative_path=authorized_relative,
            ownership_nonce=first_nonce,
            expected_action_digest="a" * 64,
            recomputed_action_digest="b" * 64,
        )
    assert digest_error.value.code == "WORKSPACE_AUTHORIZATION_MISMATCH"
    assert not (tmp_path / "data").exists()

    noncanonical = f"tasks//task/./{workspace_slot_name(first_nonce)}"
    with pytest.raises(GitWorkspaceError) as noncanonical_error:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "data",
            workspace_relative_path=noncanonical,
            ownership_nonce=first_nonce,
            expected_action_digest="a" * 64,
            recomputed_action_digest="a" * 64,
        )
    assert noncanonical_error.value.code == "INVALID_WORKSPACE_PATH"
    assert not (tmp_path / "data" / "tasks" / "task" / workspace_slot_name(first_nonce)).exists()

    occupied_relative = f"tasks/task/{workspace_slot_name(first_nonce)}"
    occupied = tmp_path / "data" / Path(occupied_relative)
    occupied.parent.mkdir(parents=True)
    occupied.write_text("不是 workspace\n", encoding="utf-8")
    status = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=occupied_relative,
        ownership_nonce=first_nonce,
        expected_action_digest="a" * 64,
        recomputed_action_digest="a" * 64,
        expected_git_pointer_digest="b" * 64,
    )
    assert status.availability is WorkspaceAvailability.UNVERIFIED
    assert status.error_code == "CREATION_RECOVERY_REQUIRED"


def test_real_worktree_observation_is_fail_closed(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    adapter = GitWorkspaceAdapter(tmp_path / "control" / "hooks")
    inspection = adapter.inspect_repository(repo.path, repo.first_commit)
    nonce = "".join(("01234567", "89abcdef")) * 2
    relative = f"tasks/task/{workspace_slot_name(nonce)}"
    digest = "a" * 64
    workspace = adapter.create_detached_worktree(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
    )
    observation = adapter.observe_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
    )
    pointer_digest = observation.git_pointer_digest
    assert pointer_digest is not None

    available = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert available.availability is WorkspaceAvailability.AVAILABLE
    assert available.observation.as_adoption_mapping() == {
        "workspace_realpath": str(workspace),
        "within_data_root": True,
        "git_admin_points_to_workspace": True,
        "workspace_git_points_to_admin": True,
        "head_detached": True,
        "head_oid": repo.first_commit,
        "index_and_tracked_clean": True,
        "no_extra_files": True,
        "ownership_nonce": nonce,
        "action_digest": digest,
    }

    wrong_pointer = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest="f" * 64,
    )
    assert wrong_pointer.availability is WorkspaceAvailability.UNVERIFIED

    repo.git("-C", str(workspace), "update-index", "--skip-worktree", "tracked.txt")
    (workspace / "tracked.txt").unlink()
    hidden_missing = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert hidden_missing.availability is WorkspaceAvailability.UNVERIFIED
    assert hidden_missing.observation.index_and_tracked_clean is False
    repo.git("-C", str(workspace), "update-index", "--no-skip-worktree", "tracked.txt")
    (workspace / "tracked.txt").write_text("C1\n", encoding="utf-8")

    repo.git("-C", str(workspace), "update-index", "--assume-unchanged", "tracked.txt")
    (workspace / "tracked.txt").write_text("被 assume-unchanged 隐藏\n", encoding="utf-8")
    assumed = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert assumed.availability is WorkspaceAvailability.UNVERIFIED
    assert "WORKSPACE_UNSAFE_INDEX_FLAGS" in assumed.observation.problems
    repo.git("-C", str(workspace), "update-index", "--no-assume-unchanged", "tracked.txt")
    (workspace / "tracked.txt").write_text("C1\n", encoding="utf-8")

    extra = workspace / "untrusted.ignored"
    extra.write_text("不得被忽略\n", encoding="utf-8")
    unverified = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert unverified.availability is WorkspaceAvailability.UNVERIFIED
    assert unverified.observation.no_extra_files is False
    extra.unlink()

    repo.git("-C", str(workspace), "checkout", "--detach", repo.second_commit)
    extra.write_text("复合故障不得降级\n", encoding="utf-8")
    compound = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert compound.availability is WorkspaceAvailability.UNVERIFIED
    assert compound.head_oid is None
    extra.unlink()
    drifted = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=nonce,
        expected_action_digest=digest,
        recomputed_action_digest=digest,
        expected_git_pointer_digest=pointer_digest,
    )
    assert drifted.availability is WorkspaceAvailability.BASELINE_MISMATCH
    assert drifted.head_oid == repo.second_commit


def test_external_checkout_filter_is_rejected_without_execution(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    sentinel = tmp_path / "filter-ran"
    repo.git("config", "filter.untrusted.smudge", f'echo unsafe > "{sentinel}"')
    adapter = GitWorkspaceAdapter(tmp_path / "control" / "hooks")

    with pytest.raises(GitWorkspaceError) as captured:
        adapter.inspect_repository(repo.path, "HEAD")

    assert captured.value.code == "UNSAFE_GIT_CHECKOUT_CONFIG"
    assert not sentinel.exists()
