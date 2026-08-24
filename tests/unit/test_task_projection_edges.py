"""Task workspace 采纳判定的形状、路径与身份边界。"""

from __future__ import annotations

from copy import deepcopy

import pytest

import sigmacoder.domain.tasks as task_module
from sigmacoder.domain.tasks import evaluate_workspace_adoption


def _authorization() -> dict[str, object]:
    nonce = "".join(("01234567", "89abcdef")) * 2
    return {
        "data_root": "C:/data",
        "workspace_realpath": f"C:/data/tasks/t/workspace-{nonce}",
        "workspace_relative_path": f"tasks/t/workspace-{nonce}",
        "git_admin_realpath": "C:/repo/.git/worktrees/w",
        "baseline_commit": "a" * 40,
        "ownership_nonce": "0" * 32,
        "action_digest": "b" * 64,
    }


def _observation() -> dict[str, object]:
    authorization = _authorization()
    return {
        "workspace_realpath": authorization["workspace_realpath"],
        "within_data_root": True,
        "git_admin_points_to_workspace": True,
        "workspace_git_points_to_admin": True,
        "head_detached": True,
        "head_oid": authorization["baseline_commit"],
        "index_and_tracked_clean": True,
        "no_extra_files": True,
        "ownership_nonce": authorization["ownership_nonce"],
        "action_digest": authorization["action_digest"],
    }


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("data_root", object()),
        ("workspace_realpath", ""),
        ("workspace_relative_path", ""),
        ("git_admin_realpath", ""),
        ("baseline_commit", None),
        ("baseline_commit", "A" * 40),
        ("ownership_nonce", None),
        ("ownership_nonce", "0" * 31),
        ("action_digest", None),
        ("action_digest", "b" * 63),
        ("data_root", "relative/root"),
        ("workspace_relative_path", "C:/absolute"),
        ("workspace_relative_path", "tasks/../escaped"),
        ("workspace_realpath", object()),
    ],
)
def test_invalid_authorization_shapes_fail_closed(field: str, invalid: object) -> None:
    authorization = _authorization()
    authorization[field] = invalid

    decision = evaluate_workspace_adoption(authorization, _observation())

    assert decision.adopted is False
    assert decision.failed_evidence == ("AUTHORIZATION_INVALID",)


def test_missing_authorization_and_observation_fields_are_distinguished() -> None:
    authorization = _authorization()
    del authorization["action_digest"]
    missing_authorization = evaluate_workspace_adoption(authorization, _observation())

    observation = _observation()
    del observation["head_oid"]
    missing_observation = evaluate_workspace_adoption(_authorization(), observation)

    assert missing_authorization.failed_evidence == ("AUTHORIZATION_INVALID",)
    assert missing_observation.failed_evidence == ("OBSERVATION_INCOMPLETE",)


def test_posix_paths_are_accepted_and_cross_flavour_or_non_text_evidence_is_rejected() -> None:
    authorization = _authorization()
    authorization.update(
        data_root="/srv/data",
        workspace_realpath="/srv/data/tasks/t/workspace-nonce",
        workspace_relative_path="tasks/t/workspace-nonce",
        git_admin_realpath="/srv/repo/.git/worktrees/w",
    )
    observation = _observation()
    observation["workspace_realpath"] = authorization["workspace_realpath"]

    accepted = evaluate_workspace_adoption(authorization, observation)
    assert accepted.adopted is True

    for invalid_path in (object(), "C:/srv/data/tasks/t/workspace-nonce"):
        invalid = deepcopy(observation)
        invalid["workspace_realpath"] = invalid_path
        rejected = evaluate_workspace_adoption(authorization, invalid)
        assert rejected.failed_evidence == ("PATH_AND_ROOT",)


def test_git_pointer_evidence_requires_both_directions_and_optional_admin_match() -> None:
    authorization = _authorization()
    cases = (
        {"git_admin_points_to_workspace": False},
        {"workspace_git_points_to_admin": False},
        {"git_admin_realpath": "C:/repo/.git/worktrees/attacker"},
    )
    for changes in cases:
        observation = _observation()
        observation.update(changes)
        decision = evaluate_workspace_adoption(authorization, observation)
        assert "GIT_BIDIRECTIONAL_POINTERS" in decision.failed_evidence

    matching = _observation()
    matching["git_admin_realpath"] = authorization["git_admin_realpath"]
    assert evaluate_workspace_adoption(authorization, matching).adopted is True


def test_internal_path_parser_fails_closed_before_public_shape_validation() -> None:
    assert task_module._pure_path(object()) is None
    assert task_module._pure_path("") is None

    authorization = _authorization()
    authorization["data_root"] = object()
    assert task_module._authorization_paths_are_consistent(authorization) is False

    authorization = _authorization()
    authorization["workspace_realpath"] = object()
    assert task_module._authorization_paths_are_consistent(authorization) is False
