"""SigmaCoder 外部系统适配器。"""

from sigmacoder.adapters.git_workspace import (
    GitWorkspaceAdapter,
    GitWorkspaceError,
    workspace_slot_name,
)
from sigmacoder.ports.workspace import (
    PreparedWorkspaceStatus,
    RepositoryInspection,
    SourceWorktreeFingerprint,
    WorkspaceAvailability,
    WorkspaceObservation,
)

__all__ = [
    "GitWorkspaceAdapter",
    "GitWorkspaceError",
    "PreparedWorkspaceStatus",
    "RepositoryInspection",
    "SourceWorktreeFingerprint",
    "WorkspaceAvailability",
    "WorkspaceObservation",
    "workspace_slot_name",
]
