"""T01 Task 创建恢复的纯领域判定。"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Final

_LOWER_HEX_32 = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_40_OR_64 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_WINDOWS_DRIVE = re.compile(r"[A-Za-z]:[/\\]")

_AUTHORIZATION_FIELDS: Final = frozenset(
    {
        "data_root",
        "workspace_realpath",
        "workspace_relative_path",
        "git_admin_realpath",
        "baseline_commit",
        "ownership_nonce",
        "action_digest",
    }
)
_OBSERVATION_FIELDS: Final = frozenset(
    {
        "workspace_realpath",
        "within_data_root",
        "git_admin_points_to_workspace",
        "workspace_git_points_to_admin",
        "head_detached",
        "head_oid",
        "index_and_tracked_clean",
        "no_extra_files",
        "ownership_nonce",
        "action_digest",
    }
)


@dataclass(frozen=True)
class WorkspaceAdoptionDecision:
    """七证据判定结果；判定函数本身永不授权物理修改。"""

    adopted: bool
    availability: str
    may_mutate_workspace: bool
    error_code: str | None
    failed_evidence: tuple[str, ...]


def _path_flavour(path: str) -> type[PurePath]:
    if _WINDOWS_DRIVE.match(path) or "\\" in path:
        return PureWindowsPath
    return PurePosixPath


def _pure_path(path: object, *, flavour_hint: str | None = None) -> PurePath | None:
    if not isinstance(path, str) or not path:
        return None
    flavour = _path_flavour(flavour_hint if flavour_hint is not None else path)
    return flavour(path)


def _same_path(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    if _path_flavour(left) is not _path_flavour(right):
        return False
    return _pure_path(left) == _pure_path(right)


def _authorization_paths_are_consistent(authorization: Mapping[str, object]) -> bool:
    data_root_value = authorization["data_root"]
    workspace_value = authorization["workspace_realpath"]
    relative_value = authorization["workspace_relative_path"]
    if not isinstance(data_root_value, str) or not isinstance(relative_value, str):
        return False
    data_root = _pure_path(data_root_value)
    relative = _pure_path(relative_value, flavour_hint=data_root_value)
    workspace = _pure_path(workspace_value, flavour_hint=data_root_value)
    if data_root is None or relative is None or workspace is None:
        return False
    if not data_root.is_absolute() or relative.is_absolute() or ".." in relative.parts:
        return False
    return workspace == data_root / relative


def _authorization_shape_is_valid(authorization: Mapping[str, object]) -> bool:
    if not _AUTHORIZATION_FIELDS.issubset(authorization):
        return False
    text_fields = (
        "data_root",
        "workspace_realpath",
        "workspace_relative_path",
        "git_admin_realpath",
    )
    if any(
        not isinstance(authorization[name], str) or not authorization[name] for name in text_fields
    ):
        return False
    baseline = authorization["baseline_commit"]
    nonce = authorization["ownership_nonce"]
    digest = authorization["action_digest"]
    return (
        isinstance(baseline, str)
        and _LOWER_HEX_40_OR_64.fullmatch(baseline) is not None
        and isinstance(nonce, str)
        and _LOWER_HEX_32.fullmatch(nonce) is not None
        and isinstance(digest, str)
        and _LOWER_HEX_64.fullmatch(digest) is not None
        and _authorization_paths_are_consistent(authorization)
    )


def _observation_shape_is_valid(observation: Mapping[str, object]) -> bool:
    return _OBSERVATION_FIELDS.issubset(observation)


def _path_evidence(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> bool:
    return observation["within_data_root"] is True and _same_path(
        observation["workspace_realpath"], authorization["workspace_realpath"]
    )


def _git_pointer_evidence(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> bool:
    if observation["git_admin_points_to_workspace"] is not True:
        return False
    if observation["workspace_git_points_to_admin"] is not True:
        return False
    observed_admin = observation.get("git_admin_realpath")
    if observed_admin is not None:
        return _same_path(observed_admin, authorization["git_admin_realpath"])
    return True


def _head_evidence(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> bool:
    return (
        observation["head_detached"] is True
        and observation["head_oid"] == authorization["baseline_commit"]
    )


def _identity_evidence(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> bool:
    return (
        observation["ownership_nonce"] == authorization["ownership_nonce"]
        and observation["action_digest"] == authorization["action_digest"]
    )


def _failed_evidence(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> tuple[str, ...]:
    checks = (
        ("PATH_AND_ROOT", _path_evidence(authorization, observation)),
        ("GIT_BIDIRECTIONAL_POINTERS", _git_pointer_evidence(authorization, observation)),
        ("DETACHED_BASELINE_HEAD", _head_evidence(authorization, observation)),
        ("INDEX_AND_TRACKED_CLEAN", observation["index_and_tracked_clean"] is True),
        ("NO_EXTRA_FILES", observation["no_extra_files"] is True),
        (
            "OWNERSHIP_NONCE",
            observation["ownership_nonce"] == authorization["ownership_nonce"],
        ),
        ("ACTION_DIGEST", observation["action_digest"] == authorization["action_digest"]),
    )
    return tuple(name for name, passed in checks if not passed)


def _rejected(*failed: str) -> WorkspaceAdoptionDecision:
    return WorkspaceAdoptionDecision(
        adopted=False,
        availability="UNVERIFIED",
        may_mutate_workspace=False,
        error_code="CREATION_RECOVERY_REQUIRED",
        failed_evidence=tuple(failed),
    )


def evaluate_workspace_adoption(
    authorization: Mapping[str, object],
    observation: Mapping[str, object],
) -> WorkspaceAdoptionDecision:
    """只有七项只读证据全部匹配时才采纳既有 workspace。"""

    if not _authorization_shape_is_valid(authorization):
        return _rejected("AUTHORIZATION_INVALID")
    if not _observation_shape_is_valid(observation):
        return _rejected("OBSERVATION_INCOMPLETE")
    failed = _failed_evidence(authorization, observation)
    if failed or not _identity_evidence(authorization, observation):
        return _rejected(*failed)
    return WorkspaceAdoptionDecision(
        adopted=True,
        availability="AVAILABLE",
        may_mutate_workspace=False,
        error_code=None,
        failed_evidence=(),
    )


__all__ = ["WorkspaceAdoptionDecision", "evaluate_workspace_adoption"]
