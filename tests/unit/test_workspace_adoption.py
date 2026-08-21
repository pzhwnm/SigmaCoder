"""T01 半创建 workspace 七证据采纳判定的 RED 合同。"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from copy import deepcopy
from enum import Enum
from typing import Any, cast

import pytest
from tests.support.event_contract import BASELINE_OID, OWNERSHIP_NONCE, action_digest, field


def adoption_evaluator() -> Callable[[Mapping[str, object], Mapping[str, object]], Any]:
    """在执行期加载纯判定接口，缺失时产生行为 RED 而非 collection error。"""

    try:
        module = importlib.import_module("sigmacoder.domain.tasks")
    except ModuleNotFoundError:
        pytest.fail("RED：sigmacoder.domain.tasks 尚未实现。", pytrace=False)
    evaluator = getattr(module, "evaluate_workspace_adoption", None)
    if not callable(evaluator):
        pytest.fail(
            "RED：sigmacoder.domain.tasks.evaluate_workspace_adoption 尚未实现。",
            pytrace=False,
        )
    return cast(Callable[[Mapping[str, object], Mapping[str, object]], Any], evaluator)


def enum_text(value: object) -> str:
    """允许判定结果使用字符串或字符串 Enum。"""

    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def expected_authorization() -> dict[str, object]:
    return {
        "data_root": "C:/sigmacoder-data",
        "workspace_realpath": ("C:/sigmacoder-data/tasks/11111111/workspace-0123456789abcdef"),
        "workspace_relative_path": ("tasks/11111111/workspace-0123456789abcdef"),
        "git_admin_realpath": ("C:/fixture/repository/.git/worktrees/workspace-0123456789abcdef"),
        "baseline_commit": BASELINE_OID,
        "ownership_nonce": OWNERSHIP_NONCE,
        "action_digest": action_digest(),
    }


def valid_observation() -> dict[str, object]:
    authorization = expected_authorization()
    return {
        "workspace_realpath": authorization["workspace_realpath"],
        "within_data_root": True,
        "git_admin_points_to_workspace": True,
        "workspace_git_points_to_admin": True,
        "head_detached": True,
        "head_oid": BASELINE_OID,
        "index_and_tracked_clean": True,
        "no_extra_files": True,
        "ownership_nonce": OWNERSHIP_NONCE,
        "action_digest": action_digest(),
    }


def test_all_seven_evidence_items_are_required_for_adoption() -> None:
    result = adoption_evaluator()(expected_authorization(), valid_observation())

    assert field(result, "adopted") is True
    assert enum_text(field(result, "availability")) == "AVAILABLE"
    assert field(result, "may_mutate_workspace") is False


@pytest.mark.parametrize(
    ("case_id", "mutate"),
    [
        (
            "规范路径或根目录不匹配",
            lambda value: value.update(within_data_root=False),
        ),
        (
            "Git 管理双向指针不匹配",
            lambda value: value.update(git_admin_points_to_workspace=False),
        ),
        (
            "HEAD 非 detached",
            lambda value: value.update(head_detached=False),
        ),
        (
            "HEAD 偏离 baseline",
            lambda value: value.update(head_oid="2" * 40),
        ),
        (
            "index 或 tracked tree 不干净",
            lambda value: value.update(index_and_tracked_clean=False),
        ),
        (
            "存在 baseline 之外文件",
            lambda value: value.update(no_extra_files=False),
        ),
        (
            "ownership nonce 不匹配",
            lambda value: value.update(ownership_nonce="f" * 32),
        ),
        (
            "action digest 不匹配",
            lambda value: value.update(action_digest="e" * 64),
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_any_missing_adoption_evidence_fails_closed_without_cleanup(
    case_id: str,
    mutate: Callable[[dict[str, object]], None],
) -> None:
    del case_id
    observation = deepcopy(valid_observation())
    mutate(observation)

    result = adoption_evaluator()(expected_authorization(), observation)

    assert field(result, "adopted") is False
    assert field(result, "error_code") == "CREATION_RECOVERY_REQUIRED"
    assert enum_text(field(result, "availability")) == "UNVERIFIED"
    assert field(result, "may_mutate_workspace") is False
