"""Git/worktree 适配器的参数、路径、进程与指针防御分支。"""

from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import pytest
from tests.support.git_repo_factory import create_git_repository

import sigmacoder.adapters.git_workspace as git_module
from sigmacoder.adapters.git_workspace import GitWorkspaceAdapter, GitWorkspaceError
from sigmacoder.ports.workspace import RepositoryInspection

NONCE = "".join(("01234567", "89abcdef")) * 2
DIGEST = "a" * 64


def _assert_code(captured: pytest.ExceptionInfo[GitWorkspaceError], code: str) -> None:
    assert captured.value.code == code


def _adapter(tmp_path: Path) -> GitWorkspaceAdapter:
    return GitWorkspaceAdapter(tmp_path / "control" / "hooks")


def _inspection(
    tmp_path: Path, *, seed: int = 9001
) -> tuple[GitWorkspaceAdapter, RepositoryInspection]:
    repository = create_git_repository(tmp_path / "fixture", seed=seed, commit_count=1)
    adapter = _adapter(tmp_path)
    return adapter, adapter.inspect_repository(repository.path, "HEAD")


def test_nonce_plain_text_and_json_normalization_boundaries() -> None:
    with pytest.raises(GitWorkspaceError) as nonce:
        git_module.workspace_slot_name("A" * 32)
    _assert_code(nonce, "INVALID_OWNERSHIP_NONCE")

    for value in ("nul\x00value", "line\nvalue", "return\rvalue"):
        with pytest.raises(GitWorkspaceError) as text:
            git_module._validate_plain_text(value, field="fixture")
        _assert_code(text, "INVALID_GIT_ARGUMENT")

    assert git_module._normalize_json(None) is None
    assert git_module._normalize_json(True) is True
    assert git_module._normalize_json(7) == 7
    assert git_module._normalize_json("e\u0301") == "é"
    assert git_module._normalize_json(("e\u0301", [1])) == ["é", [1]]
    assert git_module._normalize_json({"e\u0301": "e\u0301"}) == {"é": "é"}
    with pytest.raises(TypeError, match="无法规范化"):
        git_module._normalize_json(object())


def test_path_and_diagnostic_helpers_cover_both_outcomes(tmp_path: Path) -> None:
    assert git_module._is_within(tmp_path / "child", tmp_path) is True
    assert git_module._is_within(tmp_path.parent, tmp_path) is False
    assert git_module._same_path(tmp_path / ".", tmp_path)
    assert git_module._sanitized_diagnostic(" short\x00 ") == "short�"
    long_value = "prefix" + "x" * 2_100
    assert git_module._sanitized_diagnostic(long_value) == long_value[-2_000:]

    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("ok", encoding="utf-8")
    assert git_module._is_reparse(ordinary) is False


def test_reparse_detection_short_circuits_on_junction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ordinary"
    path.write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(git_module, "_is_junction", lambda candidate: candidate == path)
    assert git_module._is_reparse(path) is True


def test_reparse_detection_reads_optional_windows_attributes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "ordinary"
    path.write_text("fixture", encoding="utf-8")
    marker = 0x400
    monkeypatch.setattr(Path, "is_symlink", lambda _path: False)
    monkeypatch.setattr(git_module, "_is_junction", lambda _path: False)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _path: SimpleNamespace(st_file_attributes=marker),
    )
    monkeypatch.setattr(
        git_module.stat,
        "FILE_ATTRIBUTE_REPARSE_POINT",
        marker,
        raising=False,
    )

    assert git_module._is_reparse(path) is True


class _ChangingFile:
    def __init__(self) -> None:
        self.calls = 0

    def stat(self, *, follow_symlinks: bool) -> SimpleNamespace:
        assert follow_symlinks is False
        self.calls += 1
        return SimpleNamespace(st_size=self.calls, st_mtime_ns=self.calls, st_mode=stat.S_IFREG)

    @staticmethod
    def read_bytes() -> bytes:
        return b"unstable"

    def __str__(self) -> str:
        return "changing-fixture"


def test_stable_read_and_unreadable_link_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(GitWorkspaceError) as unstable:
        git_module._read_stable_file(_ChangingFile())  # type: ignore[arg-type]
    _assert_code(unstable, "SOURCE_WORKTREE_UNSTABLE")

    monkeypatch.setattr(os, "readlink", lambda _path: (_ for _ in ()).throw(OSError("denied")))
    assert git_module._link_target_bytes(Path("missing")) == b"<unreadable-reparse-target>"


def test_entry_and_business_tree_digest_regular_directory_and_reparse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    file_path = nested / "value.txt"
    file_path.write_text("内容", encoding="utf-8")

    regular = git_module._entry_digest(root, file_path)
    directory = git_module._entry_digest(root, nested)
    assert regular.kind == "file"
    assert directory.kind == "directory"
    assert git_module._business_entries(root) == (regular,)

    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path == file_path)
    monkeypatch.setattr(git_module, "_link_target_bytes", lambda _path: b"target")
    reparse = git_module._entry_digest(root, file_path)
    assert reparse.kind == "reparse"


def test_business_tree_unreadable_is_stable_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        os,
        "scandir",
        lambda _path: (_ for _ in ()).throw(PermissionError("denied")),
    )
    with pytest.raises(GitWorkspaceError) as captured:
        git_module._business_entries(tmp_path)
    _assert_code(captured, "SOURCE_WORKTREE_UNREADABLE")


def test_existing_path_reparse_walk_stops_on_missing_or_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    assert git_module._existing_path_has_reparse(root, PurePosixPath("a/missing")) is False

    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path.name == "a")
    assert git_module._existing_path_has_reparse(root, PurePosixPath("a/child")) is True


@pytest.mark.parametrize(
    "raw",
    [
        "tasks\\workspace",
        "é/e\u0301",
        "/absolute",
        "tasks//collapsed",
        "tasks/../escaped",
        "tasks/name.",
        "tasks/NUL.txt",
        "tasks/has space",
    ],
)
def test_portable_workspace_path_rejects_noncanonical_components(raw: str) -> None:
    with pytest.raises(GitWorkspaceError) as captured:
        git_module._validate_portable_relative_path(raw)
    _assert_code(captured, "INVALID_WORKSPACE_PATH")


def test_adapter_constructor_rejects_timeout_and_missing_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="超时"):
        GitWorkspaceAdapter(tmp_path / "hooks", timeout_seconds=0)

    monkeypatch.setattr(git_module.shutil, "which", lambda _candidate: None)
    with pytest.raises(GitWorkspaceError) as missing:
        GitWorkspaceAdapter(tmp_path / "hooks")
    _assert_code(missing, "GIT_UNAVAILABLE")


def test_hooks_directory_creation_and_safety_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_mkdir = Path.mkdir

    def denied(path: Path, *args: object, **kwargs: object) -> None:
        if path.name == "denied-hooks":
            raise PermissionError("denied")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", denied)
    with pytest.raises(GitWorkspaceError) as unavailable:
        GitWorkspaceAdapter(tmp_path / "denied-hooks")
    _assert_code(unavailable, "CONTROLLED_HOOKS_PATH_UNAVAILABLE")
    monkeypatch.setattr(Path, "mkdir", original_mkdir)

    adapter = _adapter(tmp_path / "safe")
    adapter._hooks_dir.rmdir()
    adapter._hooks_dir.write_text("不是目录", encoding="utf-8")
    with pytest.raises(GitWorkspaceError) as unsafe_file:
        adapter._assert_hooks_dir_safe()
    _assert_code(unsafe_file, "CONTROLLED_HOOKS_PATH_UNSAFE")

    adapter._hooks_dir.unlink()
    adapter._hooks_dir.mkdir()
    (adapter._hooks_dir / "hostile-hook").write_text("unsafe", encoding="utf-8")
    with pytest.raises(GitWorkspaceError) as nonempty:
        adapter._assert_hooks_dir_safe()
    _assert_code(nonempty, "CONTROLLED_HOOKS_PATH_UNSAFE")


def test_hooks_directory_iteration_error_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    original_iterdir = Path.iterdir

    def denied(path: Path) -> Any:
        if path == adapter._hooks_dir:
            raise PermissionError("denied")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied)
    with pytest.raises(GitWorkspaceError) as captured:
        adapter._assert_hooks_dir_safe()
    _assert_code(captured, "CONTROLLED_HOOKS_PATH_UNSAFE")


def test_run_maps_invalid_argv_timeout_os_error_and_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    with pytest.raises(GitWorkspaceError) as invalid:
        adapter._run(tmp_path, ("status\n--hostile",))
    _assert_code(invalid, "INVALID_GIT_ARGUMENT")

    monkeypatch.setattr(
        git_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("git", 1)),
    )
    with pytest.raises(GitWorkspaceError) as timeout:
        adapter._run(tmp_path, ("status",))
    _assert_code(timeout, "GIT_COMMAND_TIMEOUT")

    monkeypatch.setattr(
        git_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )
    with pytest.raises(GitWorkspaceError) as unavailable:
        adapter._run(tmp_path, ("status",))
    _assert_code(unavailable, "GIT_COMMAND_UNAVAILABLE")

    monkeypatch.setattr(
        git_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 7, "", "fatal\x00"),
    )
    with pytest.raises(GitWorkspaceError) as failed:
        adapter._run(tmp_path, ("status",))
    _assert_code(failed, "GIT_COMMAND_FAILED")
    assert failed.value.details["diagnostic"] == "fatal�"


def test_repository_and_git_metadata_validation_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("not repository", encoding="utf-8")
    with pytest.raises(GitWorkspaceError) as non_directory:
        adapter.inspect_repository(ordinary, "HEAD")
    _assert_code(non_directory, "INVALID_REPOSITORY")

    monkeypatch.setattr(
        adapter, "_run", lambda *_args, **_kwargs: git_module._GitResult("false", "", 0)
    )
    with pytest.raises(GitWorkspaceError) as outside:
        adapter.inspect_repository(tmp_path, "HEAD")
    _assert_code(outside, "INVALID_REPOSITORY")

    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: git_module._GitResult("", "", 0))
    with pytest.raises(GitWorkspaceError) as empty:
        adapter._absolute_git_path(tmp_path, "--show-toplevel")
    _assert_code(empty, "INVALID_REPOSITORY")

    monkeypatch.setattr(
        adapter, "_run", lambda *_args, **_kwargs: git_module._GitResult("sha512", "", 0)
    )
    with pytest.raises(GitWorkspaceError) as object_format:
        adapter._object_format(tmp_path)
    _assert_code(object_format, "UNSUPPORTED_GIT_OBJECT_FORMAT")


def test_unborn_repository_and_relative_git_paths_are_handled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unborn = create_git_repository(tmp_path / "unborn", seed=9100, commit_count=0)
    adapter = _adapter(tmp_path)
    with pytest.raises(GitWorkspaceError) as captured:
        adapter.inspect_repository(unborn.path, "HEAD")
    _assert_code(captured, "REPOSITORY_UNBORN")

    relative_directory = tmp_path / "relative-directory"
    relative_directory.mkdir()
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: git_module._GitResult(relative_directory.name, "", 0),
    )
    assert adapter._absolute_git_path(tmp_path, "--show-toplevel") == relative_directory

    relative_file = tmp_path / "relative-index"
    relative_file.write_bytes(b"index")
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: git_module._GitResult(relative_file.name, "", 0),
    )
    assert adapter._git_path(tmp_path, "index") == relative_file


def test_freeze_commit_validates_baseline_oid_and_object_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    for baseline in ("", "-option"):
        with pytest.raises(GitWorkspaceError) as invalid:
            adapter._freeze_commit(tmp_path, baseline, "sha1")
        _assert_code(invalid, "INVALID_BASELINE")

    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: git_module._GitResult("", "", 1))
    with pytest.raises(GitWorkspaceError) as missing:
        adapter._freeze_commit(tmp_path, "missing", "sha1")
    _assert_code(missing, "BASELINE_NOT_COMMIT")

    monkeypatch.setattr(
        adapter, "_run", lambda *_args, **_kwargs: git_module._GitResult("bad", "", 0)
    )
    with pytest.raises(GitWorkspaceError) as invalid_oid:
        adapter._freeze_commit(tmp_path, "HEAD", "sha1")
    _assert_code(invalid_oid, "BASELINE_NOT_COMMIT")

    calls = iter((git_module._GitResult("a" * 40, "", 0), git_module._GitResult("tree", "", 0)))
    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: next(calls))
    with pytest.raises(GitWorkspaceError) as not_commit:
        adapter._freeze_commit(tmp_path, "HEAD", "sha1")
    _assert_code(not_commit, "BASELINE_NOT_COMMIT")

    with pytest.raises(GitWorkspaceError):
        adapter._validate_oid("g" * 64, "sha256", error_code="BAD_OID")


def test_filter_source_change_and_data_root_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    changed = replace(inspection.source_fingerprint, porcelain_v2="? changed")
    with pytest.raises(GitWorkspaceError) as source:
        adapter.assert_source_unchanged(inspection.source_fingerprint, changed)
    _assert_code(source, "SOURCE_WORKTREE_CHANGED")

    for forbidden in (
        inspection.repository_realpath / "nested",
        inspection.git_common_dir_realpath / "nested",
        tmp_path / "existing" / "nested",
    ):
        existing = (tmp_path / "existing",) if "existing" in forbidden.parts else ()
        with pytest.raises(GitWorkspaceError) as data_root:
            adapter.validate_data_root(forbidden, inspection, existing_workspaces=existing)
        _assert_code(data_root, "INVALID_DATA_ROOT")

    result = git_module._GitResult("filter.z.clean\x00filter.a.process\x00", "", 0)
    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: result)
    with pytest.raises(GitWorkspaceError) as filters:
        adapter._reject_external_filters(tmp_path)
    _assert_code(filters, "UNSAFE_GIT_CHECKOUT_CONFIG")
    assert filters.value.details["filter_keys"] == ("filter.a.process", "filter.z.clean")

    allowed = adapter.validate_data_root(tmp_path / "isolated-data", inspection)
    assert allowed == (tmp_path / "isolated-data").resolve()


def test_workspace_authorization_path_and_digest_guards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    for expected, actual in (("bad", DIGEST), (DIGEST, "bad")):
        with pytest.raises(GitWorkspaceError) as digest:
            adapter._validate_action_digests(expected, actual)
        _assert_code(digest, "INVALID_ACTION_DIGEST")

    relative = f"tasks/t/workspace-{NONCE}"
    root = tmp_path / "data"
    wrong = relative.replace(NONCE, "f" * 32)
    with pytest.raises(GitWorkspaceError) as nonce:
        adapter._authorized_workspace_path(root, wrong, NONCE, require_exists=False)
    _assert_code(nonce, "INVALID_WORKSPACE_PATH")

    (root / "tasks").mkdir(parents=True)
    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path.name == "tasks")
    with pytest.raises(GitWorkspaceError) as reparse:
        adapter._authorized_workspace_path(root, relative, NONCE, require_exists=False)
    _assert_code(reparse, "INVALID_WORKSPACE_PATH")

    assert adapter._relative_matches(root, root.parent / "outside", relative) is False


def test_worktree_creation_wraps_git_failure_without_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    original_run = adapter._run

    def fail_worktree(
        repository: Path,
        arguments: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
    ) -> git_module._GitResult:
        if arguments[:2] == ("worktree", "add"):
            raise GitWorkspaceError("GIT_COMMAND_FAILED", "fixture")
        return original_run(repository, arguments, allowed_codes=allowed_codes)

    monkeypatch.setattr(adapter, "_run", fail_worktree)
    relative = f"tasks/t/workspace-{NONCE}"
    with pytest.raises(GitWorkspaceError) as captured:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "data",
            workspace_relative_path=relative,
            ownership_nonce=NONCE,
            expected_action_digest=DIGEST,
            recomputed_action_digest=DIGEST,
        )
    _assert_code(captured, "WORKSPACE_PROVISIONING_FAILED")
    assert captured.value.details["cause_code"] == "GIT_COMMAND_FAILED"


def test_worktree_creation_rejects_collision_and_reparse_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    relative = f"tasks/t/workspace-{NONCE}"
    occupied = tmp_path / "collision-data" / Path(relative)
    occupied.parent.mkdir(parents=True)
    occupied.write_text("occupied", encoding="utf-8")
    with pytest.raises(GitWorkspaceError) as collision:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "collision-data",
            workspace_relative_path=relative,
            ownership_nonce=NONCE,
            expected_action_digest=DIGEST,
            recomputed_action_digest=DIGEST,
        )
    _assert_code(collision, "WORKSPACE_PATH_COLLISION")

    original_reparse = git_module._is_reparse
    target_parent = tmp_path / "reparse-data" / "tasks" / "t"
    monkeypatch.setattr(
        git_module,
        "_is_reparse",
        lambda path: path == target_parent or original_reparse(path),
    )
    with pytest.raises(GitWorkspaceError) as parent:
        adapter.create_detached_worktree(
            inspection,
            data_root=tmp_path / "reparse-data",
            workspace_relative_path=relative,
            ownership_nonce=NONCE,
            expected_action_digest=DIGEST,
            recomputed_action_digest=DIGEST,
        )
    _assert_code(parent, "INVALID_WORKSPACE_PATH")


def test_authorized_workspace_rejects_post_resolution_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    root = tmp_path / "data"
    outside = tmp_path / "outside"
    original_resolve = git_module._resolve_path

    def escaped(path: str | Path, *, strict: bool, field: str) -> Path:
        if field == "workspace":
            return outside
        return original_resolve(path, strict=strict, field=field)

    monkeypatch.setattr(git_module, "_resolve_path", escaped)
    with pytest.raises(GitWorkspaceError) as captured:
        adapter._authorized_workspace_path(
            root,
            f"tasks/t/workspace-{NONCE}",
            NONCE,
            require_exists=False,
        )
    _assert_code(captured, "INVALID_WORKSPACE_PATH")


def test_observe_workspace_missing_file_invalid_path_and_unreadable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    relative = f"tasks/t/workspace-{NONCE}"
    missing = adapter.observe_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
    )
    assert missing.problems == ("WORKSPACE_MISSING",)

    invalid = adapter.observe_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path="../escape",
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
    )
    assert invalid.problems == ("INVALID_WORKSPACE_PATH",)

    workspace = tmp_path / "occupied"
    workspace.write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(adapter, "_authorized_workspace_path", lambda *_args, **_kwargs: workspace)
    occupied = adapter.observe_workspace(
        inspection,
        data_root=tmp_path,
        workspace_relative_path=relative,
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
    )
    assert occupied.problems == ("WORKSPACE_NOT_DIRECTORY",)

    original_lstat = Path.lstat

    def denied(path: Path) -> os.stat_result:
        if path == workspace:
            raise PermissionError("denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", denied)
    unreadable = adapter.observe_workspace(
        inspection,
        data_root=tmp_path,
        workspace_relative_path=relative,
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
    )
    assert unreadable.problems == ("WORKSPACE_UNREADABLE",)


def test_observation_returns_unverified_when_git_pointer_is_not_trusted(tmp_path: Path) -> None:
    adapter, inspection = _inspection(tmp_path)
    relative = f"tasks/t/workspace-{NONCE}"
    workspace = tmp_path / "data" / Path(relative)
    workspace.mkdir(parents=True)

    observation = adapter.observe_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=relative,
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
    )

    assert observation.workspace_exists is True
    assert observation.git_admin_points_to_workspace is False
    assert observation.problems == ("WORKSPACE_GIT_POINTER_INVALID",)


def test_authorization_observation_reports_each_identity_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "root"
    workspace = root / "wrong-name"
    nonce, relative, problems = GitWorkspaceAdapter._authorization_observation(
        root,
        workspace,
        "different/path",
        NONCE,
        DIGEST,
        "b" * 64,
    )
    assert nonce is None
    assert relative is False
    assert problems == (
        "OWNERSHIP_NONCE_MISMATCH",
        "ACTION_DIGEST_MISMATCH",
        "WORKSPACE_RELATIVE_PATH_MISMATCH",
    )


@pytest.mark.parametrize(
    ("kind", "content"),
    [
        ("directory", None),
        ("missing", None),
        ("bad-prefix", "not-a-pointer"),
        ("newline", "gitdir: one\ntwo"),
        ("missing-target", "gitdir: missing-admin"),
    ],
)
def test_gitdir_pointer_rejects_untrusted_shapes(
    tmp_path: Path,
    kind: str,
    content: str | None,
) -> None:
    path = tmp_path / "git-pointer"
    if kind == "directory":
        path.mkdir()
    elif kind != "missing":
        path.write_text(content or "", encoding="utf-8")
    problems: list[str] = []
    assert GitWorkspaceAdapter._read_gitdir_pointer(path, problems, "BAD_POINTER") is None
    assert problems == ["BAD_POINTER"]


@pytest.mark.parametrize(
    ("kind", "content"),
    [
        ("directory", None),
        ("missing", None),
        ("empty", ""),
        ("newline", "one\ntwo"),
        ("missing-target", "missing-target"),
    ],
)
def test_plain_reverse_pointer_rejects_untrusted_shapes(
    tmp_path: Path,
    kind: str,
    content: str | None,
) -> None:
    path = tmp_path / "reverse"
    if kind == "directory":
        path.mkdir()
    elif kind != "missing":
        path.write_text(content or "", encoding="utf-8")
    problems: list[str] = []
    assert GitWorkspaceAdapter._read_plain_path(path, problems, "BAD_REVERSE") is None
    assert problems == ["BAD_REVERSE"]


def test_pointer_readers_reject_reparse_pointer_and_reparse_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    git_pointer = tmp_path / "git-pointer"
    git_admin = tmp_path / "git-admin"
    git_admin.mkdir()
    git_pointer.write_text(f"gitdir: {git_admin}", encoding="utf-8")

    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path == git_pointer)
    problems: list[str] = []
    assert GitWorkspaceAdapter._read_gitdir_pointer(git_pointer, problems, "BAD") is None
    assert problems == ["BAD"]

    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path == git_admin)
    problems = []
    assert GitWorkspaceAdapter._read_gitdir_pointer(git_pointer, problems, "BAD") is None
    assert problems == ["BAD"]

    reverse = tmp_path / "reverse"
    target = tmp_path / "target"
    target.write_text("target", encoding="utf-8")
    reverse.write_text(str(target), encoding="utf-8")
    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path == reverse)
    problems = []
    assert GitWorkspaceAdapter._read_plain_path(reverse, problems, "BAD") is None
    assert problems == ["BAD"]

    monkeypatch.setattr(git_module, "_is_reparse", lambda path: path == target)
    problems = []
    assert GitWorkspaceAdapter._read_plain_path(reverse, problems, "BAD") is None
    assert problems == ["BAD"]


def test_pointer_observation_reports_outside_reverse_and_git_metadata_mismatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)

    outside_workspace = tmp_path / "outside-workspace"
    outside_workspace.mkdir()
    outside_admin = tmp_path / "outside-admin"
    outside_admin.mkdir()
    outside_git_file = outside_workspace / ".git"
    outside_git_file.write_text(f"gitdir: {outside_admin}", encoding="utf-8")
    (outside_admin / "gitdir").write_text(str(outside_git_file), encoding="utf-8")
    outside = adapter._observe_pointers(inspection, outside_workspace)
    assert "GIT_ADMIN_OUTSIDE_COMMON_DIR" in outside.problems
    assert outside.admin_points_to_workspace is False

    admin_root = inspection.git_common_dir_realpath / "worktrees"
    admin_root.mkdir(exist_ok=True)
    reverse_workspace = tmp_path / "reverse-workspace"
    reverse_workspace.mkdir()
    reverse_admin = admin_root / "edge-reverse"
    reverse_admin.mkdir()
    reverse_git_file = reverse_workspace / ".git"
    reverse_git_file.write_text(f"gitdir: {reverse_admin}", encoding="utf-8")
    (reverse_admin / "gitdir").write_text(str(tmp_path / "wrong-git-file"), encoding="utf-8")
    reverse = adapter._observe_pointers(inspection, reverse_workspace)
    assert "GIT_ADMIN_REVERSE_MISMATCH" in reverse.problems

    trusted_workspace = tmp_path / "trusted-workspace"
    trusted_workspace.mkdir()
    trusted_admin = admin_root / "edge-trusted"
    trusted_admin.mkdir()
    trusted_git_file = trusted_workspace / ".git"
    trusted_git_file.write_text(f"gitdir: {trusted_admin}", encoding="utf-8")
    (trusted_admin / "gitdir").write_text(str(trusted_git_file), encoding="utf-8")
    monkeypatch.setattr(adapter, "_safe_absolute_git_dir", lambda *_args: tmp_path / "wrong-admin")
    monkeypatch.setattr(adapter, "_safe_common_dir", lambda *_args: tmp_path / "wrong-common")
    metadata = adapter._observe_pointers(inspection, trusted_workspace)
    assert "WORKSPACE_GIT_POINTER_MISMATCH" in metadata.problems
    assert "GIT_COMMON_DIR_MISMATCH" in metadata.problems
    assert metadata.pointer_digest is None


def test_safe_git_paths_head_and_cleanliness_translate_observation_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    problems: list[str] = []
    monkeypatch.setattr(
        adapter,
        "_absolute_git_path",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            GitWorkspaceError("INVALID_REPOSITORY", "fixture")
        ),
    )
    assert adapter._safe_absolute_git_dir(tmp_path, problems).name == ".invalid-git-admin"
    assert adapter._safe_common_dir(tmp_path, problems) is None
    assert problems == ["WORKSPACE_GIT_DIR_UNREADABLE", "WORKSPACE_COMMON_DIR_UNREADABLE"]

    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            GitWorkspaceError("GIT_COMMAND_FAILED", "fixture")
        ),
    )
    assert adapter._observe_head(inspection, tmp_path, problems) == (False, None)
    assert adapter._observe_cleanliness(tmp_path, problems) == (False, False)
    assert "WORKSPACE_HEAD_INVALID" in problems
    assert "WORKSPACE_CLEANLINESS_UNVERIFIED" in problems


def test_head_and_cleanliness_report_attached_mismatch_and_tree_problems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    results = iter(
        (
            git_module._GitResult("refs/heads/main", "", 0),
            git_module._GitResult("b" * 40, "", 0),
        )
    )
    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: next(results))
    problems: list[str] = []
    detached, head = adapter._observe_head(inspection, tmp_path, problems)
    assert detached is False and head == "b" * 40
    assert problems == ["WORKSPACE_HEAD_NOT_DETACHED", "WORKSPACE_BASELINE_MISMATCH"]

    monkeypatch.setattr(adapter, "_status", lambda _workspace: "dirty")
    monkeypatch.setattr(
        adapter,
        "_workspace_tree_diff",
        lambda _workspace: git_module._WorkspaceTreeDiff(
            extra=("extra",), missing=("missing",), hidden_index_entries=("hidden",)
        ),
    )
    problems = []
    assert adapter._observe_cleanliness(tmp_path, problems) == (False, False)
    assert problems == [
        "WORKSPACE_NOT_CLEAN",
        "WORKSPACE_HAS_EXTRA_FILES",
        "WORKSPACE_MISSING_TRACKED_FILES",
        "WORKSPACE_UNSAFE_INDEX_FLAGS",
    ]


def test_index_parsers_reject_malformed_conflict_and_sparse_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _adapter(tmp_path)
    with pytest.raises(GitWorkspaceError) as malformed:
        adapter._parse_staged_entries("broken\x00")
    _assert_code(malformed, "WORKSPACE_INDEX_UNREADABLE")

    for record in (
        "100644 " + "a" * 40 + " 1\tconflict.txt\x00",
        "040000 " + "a" * 40 + " 0\tsparse-dir\x00",
    ):
        with pytest.raises(GitWorkspaceError) as unsafe:
            adapter._parse_staged_entries(record)
        _assert_code(unsafe, "WORKSPACE_UNSAFE_INDEX_FLAGS")

    monkeypatch.setattr(adapter, "_config_bool", lambda *_args: True)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: git_module._GitResult("H visible\x00s hidden\x00", "", 0),
    )
    assert adapter._hidden_index_entries(tmp_path) == ("<core.sparseCheckout>", "hidden")

    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: git_module._GitResult("malformed\x00", "", 0),
    )
    with pytest.raises(GitWorkspaceError) as unreadable:
        adapter._hidden_index_entries(tmp_path)
    _assert_code(unreadable, "WORKSPACE_INDEX_UNREADABLE")


def test_expected_pointer_digest_shape_is_validated(tmp_path: Path) -> None:
    adapter, inspection = _inspection(tmp_path)
    with pytest.raises(GitWorkspaceError) as captured:
        adapter.inspect_prepared_workspace(
            inspection,
            data_root=tmp_path / "data",
            workspace_relative_path=f"tasks/t/workspace-{NONCE}",
            ownership_nonce=NONCE,
            expected_action_digest=DIGEST,
            recomputed_action_digest=DIGEST,
            expected_git_pointer_digest="BAD",
        )
    _assert_code(captured, "INVALID_GIT_POINTER_DIGEST")


def test_prepared_workspace_distinguishes_verified_missing_from_invalid_missing(
    tmp_path: Path,
) -> None:
    adapter, inspection = _inspection(tmp_path)
    missing = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path=f"tasks/t/workspace-{NONCE}",
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
        expected_git_pointer_digest="b" * 64,
    )
    assert missing.availability.value == "MISSING"
    assert missing.error_code == "WORKSPACE_UNAVAILABLE"

    invalid = adapter.inspect_prepared_workspace(
        inspection,
        data_root=tmp_path / "data",
        workspace_relative_path="../escape",
        ownership_nonce=NONCE,
        expected_action_digest=DIGEST,
        recomputed_action_digest=DIGEST,
        expected_git_pointer_digest="b" * 64,
    )
    assert invalid.availability.value == "UNVERIFIED"
    assert invalid.error_code == "CREATION_RECOVERY_REQUIRED"
