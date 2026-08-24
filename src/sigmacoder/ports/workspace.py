"""持久 Task workspace 的应用端口与稳定值对象。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class WorkspaceError(RuntimeError):
    """带稳定错误码、可由应用边界映射的 workspace 失败。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


class WorkspaceAvailability(StrEnum):
    """持久 Task workspace 的当前物理可用性。"""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    BASELINE_MISMATCH = "BASELINE_MISMATCH"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True, slots=True)
class WorktreeEntryDigest:
    """源 worktree 中一个业务条目的稳定摘要。"""

    relative_path: str
    kind: str
    mode: int
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class SourceWorktreeFingerprint:
    """排除获准 common-dir worktree 元数据后的源仓库指纹。"""

    entries: tuple[WorktreeEntryDigest, ...]
    index_size: int
    index_sha256: str
    head_oid: str
    symbolic_head: str | None
    refs: str
    porcelain_v2: str


@dataclass(frozen=True, slots=True)
class RepositoryInspection:
    """创建 Task 前冻结的仓库事实。"""

    repository_realpath: Path
    git_dir_realpath: Path
    git_common_dir_realpath: Path
    object_format: str
    baseline_commit: str
    source_dirty: bool
    source_fingerprint: SourceWorktreeFingerprint


@dataclass(frozen=True, slots=True)
class WorkspaceObservation:
    """半创建恢复使用的只读物理观测。"""

    workspace_realpath: str | None
    workspace_exists: bool
    within_data_root: bool
    relative_path_matches: bool
    git_admin_realpath: str | None
    git_admin_points_to_workspace: bool
    workspace_git_points_to_admin: bool
    common_dir_matches: bool
    head_detached: bool
    head_oid: str | None
    index_and_tracked_clean: bool
    no_extra_files: bool
    ownership_nonce: str | None
    action_digest: str | None
    git_pointer_digest: str | None
    problems: tuple[str, ...]

    def as_adoption_mapping(self) -> dict[str, object]:
        """转换为领域层七证据判定器所需的稳定字段。"""

        return {
            "workspace_realpath": self.workspace_realpath,
            "within_data_root": self.within_data_root and self.relative_path_matches,
            "git_admin_points_to_workspace": (
                self.git_admin_points_to_workspace and self.common_dir_matches
            ),
            "workspace_git_points_to_admin": self.workspace_git_points_to_admin,
            "head_detached": self.head_detached,
            "head_oid": self.head_oid,
            "index_and_tracked_clean": self.index_and_tracked_clean,
            "no_extra_files": self.no_extra_files,
            "ownership_nonce": self.ownership_nonce,
            "action_digest": self.action_digest,
        }


@dataclass(frozen=True, slots=True)
class PreparedWorkspaceStatus:
    """已 Prepared workspace 的当前退化状态。"""

    availability: WorkspaceAvailability
    head_oid: str | None
    observation: WorkspaceObservation
    error_code: str | None


class WorkspacePort(Protocol):
    """应用服务所需的最小可信 workspace 能力。"""

    def inspect_repository(
        self,
        repository: str | Path,
        baseline: str,
    ) -> RepositoryInspection: ...

    def validate_data_root(
        self,
        data_root: str | Path,
        repository: RepositoryInspection,
        *,
        existing_workspaces: tuple[str | Path, ...] = (),
    ) -> Path: ...

    def create_detached_worktree(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> Path: ...

    def observe_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> WorkspaceObservation: ...

    def inspect_prepared_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
        expected_git_pointer_digest: str,
    ) -> PreparedWorkspaceStatus: ...


__all__ = [
    "PreparedWorkspaceStatus",
    "RepositoryInspection",
    "SourceWorktreeFingerprint",
    "WorkspaceAvailability",
    "WorkspaceError",
    "WorkspaceObservation",
    "WorkspacePort",
    "WorktreeEntryDigest",
]
