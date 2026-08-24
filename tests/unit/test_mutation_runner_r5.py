"""T01 r5 mutation runner 的原始状态与集合策略契约。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

import pytest
import tools.run_mutation_profile as mutation


def _evaluate(
    profile_name: str,
    results: Mapping[str, str],
    *,
    expected_names: Sequence[str],
    approved_names: Sequence[str],
) -> Mapping[str, object]:
    return mutation.evaluate_mutation_results(
        profile_name,
        results,
        expected_names=tuple(expected_names),
        approved_names=tuple(approved_names),
    )


def test_parser_完整保留原始_killed_与_survived() -> None:
    assert mutation.parse_mutmut_results("a: killed\nb: survived\n") == {
        "a": "killed",
        "b": "survived",
    }


@pytest.mark.parametrize(
    "status",
    (
        "timeout",
        "no tests",
        "skipped",
        "not checked",
        "suspicious",
        "segfault",
        "caught by type check",
        "check was interrupted by user",
    ),
)
def test_events_policy_拒绝所有非_survived_的非_killed_状态(status: str) -> None:
    with pytest.raises(mutation.MutationGateError):
        _evaluate(
            "events",
            {"a": "killed", "b": status},
            expected_names=("a", "b"),
            approved_names=("b",),
        )


def test_events_policy_只接受精确获批_survivor_集合且不改写状态() -> None:
    evaluation = _evaluate(
        "events",
        {"a": "killed", "b": "survived", "c": "killed"},
        expected_names=("a", "b", "c"),
        approved_names=("b",),
    )

    assert evaluation == {
        "raw": {"total": 3, "killed": 2, "survived": 1},
        "approved_equivalents": {
            "count": 1,
            "names": ["b"],
            "names_sha256": mutation._mutant_names_digest(("b",)),
        },
        "unexpected_non_killed": {"count": 0, "names": [], "statuses": {}},
        "gate_passed": True,
    }


@pytest.mark.parametrize(
    ("results", "expected_names", "approved_names", "message"),
    (
        (
            {"a": "killed", "b": "survived", "c": "survived"},
            ("a", "b", "c"),
            ("b",),
            "清单外",
        ),
        (
            {"a": "killed", "b": "killed", "c": "killed"},
            ("a", "b", "c"),
            ("b",),
            "已被杀死",
        ),
        (
            {"a": "killed", "c": "killed"},
            ("a", "b", "c"),
            ("b",),
            "缺失",
        ),
        (
            {"a": "killed", "b": "survived", "x": "killed"},
            ("a", "b", "c"),
            ("b",),
            "全集",
        ),
    ),
)
def test_events_policy_拒绝任何集合偏差(
    results: Mapping[str, str],
    expected_names: Sequence[str],
    approved_names: Sequence[str],
    message: str,
) -> None:
    with pytest.raises(mutation.MutationGateError, match=message):
        _evaluate(
            "events",
            results,
            expected_names=expected_names,
            approved_names=approved_names,
        )


@pytest.mark.parametrize("status", tuple(sorted(mutation.KNOWN_STATUSES - {"killed"})))
def test_task_service_继续要求全部_killed(status: str) -> None:
    with pytest.raises(mutation.MutationGateError):
        _evaluate(
            "task-service",
            {"a": status},
            expected_names=("a",),
            approved_names=(),
        )


def test_parser_仍拒绝未知状态且不是策略层静默处理() -> None:
    with pytest.raises(mutation.MutationGateError, match="未知状态"):
        mutation.parse_mutmut_results("a: future status\n")


def test_policy_拒绝_bool_或其他非字符串状态() -> None:
    malformed = cast(dict[str, Any], {"a": True})
    with pytest.raises(mutation.MutationGateError):
        _evaluate(
            "events",
            malformed,
            expected_names=("a",),
            approved_names=(),
        )
