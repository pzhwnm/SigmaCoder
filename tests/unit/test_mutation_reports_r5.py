"""r5 mutation 原始报告与独立等价项 checker 的 RED 契约测试。"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

APPROVED = "sigmacoder.domain.events.x__approved__mutmut_1"
KILLED = "sigmacoder.domain.events.x__killed__mutmut_2"
PROFILE: dict[str, object] = {"name": "events", "repeat": 2}
EXPECTED_RUNS = (("full", 1), ("full", 2), ("property-only", 1))
BASE_BINDINGS = {
    "git_head": "a" * 40,
    "spec_version": "r5",
    "mutmut_version": "3.7.0",
    "uv_lock_sha256": "b" * 64,
    "profile_sha256": "c" * 64,
    "source_fingerprint": "d" * 64,
    "source_sha256": "e" * 64,
    "runner_sha256": "1" * 64,
    "checker_sha256": "2" * 64,
}


def _names_sha256(names: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()


def _statuses_sha256(results: Sequence[Mapping[str, str]]) -> str:
    encoded = json.dumps(
        list(results),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest() -> dict[str, object]:
    names = tuple(sorted((APPROVED, KILLED), key=lambda name: name.encode("utf-8")))
    return {
        "schema_version": 1,
        "manifest_id": "T01-events-equivalent-mutants-test-v1",
        "approved_spec": {
            "path": "docs/specs/T01-persistent-coding-task.md",
            "revision": "r5",
        },
        "generator": {
            "distribution": "mutmut",
            "version": "3.7.0",
            "uv_lock_sha256": BASE_BINDINGS["uv_lock_sha256"],
        },
        "profile": {
            "name": "events",
            "profile_sha256": BASE_BINDINGS["profile_sha256"],
            "expected_mutant_count": 2,
            "expected_mutant_names_sha256": _names_sha256(names),
            "expected_equivalent_count": 1,
            "expected_equivalent_names_sha256": _names_sha256((APPROVED,)),
        },
        "category_counts": {
            "TYPE_ONLY_CAST": 1,
            "OBSERVATIONALLY_EQUIVALENT_RUNTIME": 0,
            "GUARD_DOMINATED_EQUIVALENCE": 0,
            "NON_CONTRACT_DIAGNOSTIC": 0,
            "UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK": 0,
        },
        "equivalents": [
            {
                "name": APPROVED,
                "category": "TYPE_ONLY_CAST",
                "reason_code": "CAST_RUNTIME_IDENTITY",
                "reason": "测试替身中的 cast 变异只影响静态类型参数。",
                "source": {
                    "path": "src/sigmacoder/domain/events.py",
                    "function": "_approved",
                    "sha256": BASE_BINDINGS["source_sha256"],
                },
            }
        ],
    }


def _expected_bindings() -> dict[str, str]:
    return {**BASE_BINDINGS, "manifest_sha256": _canonical_sha256(_manifest())}


def _result_items(statuses: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"name": name, "status": status}
        for name, status in sorted(statuses.items(), key=lambda item: item[0].encode("utf-8"))
    ]


def _run(kind: str, number: int, statuses: Mapping[str, str]) -> dict[str, object]:
    results = _result_items(statuses)
    names = [item["name"] for item in results]
    return {
        "kind": kind,
        "run": number,
        "source_fingerprint": _expected_bindings()["source_fingerprint"],
        "result_count": len(results),
        "result_names_sha256": _names_sha256(names),
        "result_statuses_sha256": _statuses_sha256(results),
        "results": results,
    }


def _report(statuses: Mapping[str, str]) -> dict[str, object]:
    names = sorted(statuses, key=lambda name: name.encode("utf-8"))
    approved_names = [APPROVED]
    return {
        "schema_version": 2,
        "profile": copy.deepcopy(PROFILE),
        "bindings": _expected_bindings(),
        "runs": [_run(kind, number, statuses) for kind, number in EXPECTED_RUNS],
        "raw": {
            "total": len(statuses),
            "killed": sum(status == "killed" for status in statuses.values()),
            "survived": sum(status == "survived" for status in statuses.values()),
            "mutant_names_sha256": _names_sha256(names),
        },
        "approved_equivalents": {
            "count": len(approved_names),
            "names": approved_names,
            "digest": _names_sha256(approved_names),
        },
        "unexpected_non_killed": {
            "count": 0,
            "names": [],
            "statuses": {},
        },
        "gate_passed": True,
    }


def _checker_api() -> tuple[Callable[..., Mapping[str, object]], type[Exception]]:
    """动态加载拟定接口，使缺少实现表现为测试 RED，而非 collection error。"""

    module = importlib.import_module("tools.check_mutation_equivalents")
    audit = module.audit_profile_report
    error = module.MutationEquivalentError
    return audit, error


def _audit(payload: object) -> Mapping[str, object]:
    audit, _ = _checker_api()
    return audit(
        payload,
        manifest_payload=_manifest(),
        expected_profile=PROFILE,
        expected_bindings=_expected_bindings(),
        expected_runs=EXPECTED_RUNS,
    )


def _assert_rejected(payload: object, message: str) -> None:
    _, error = _checker_api()
    with pytest.raises(error, match=message):
        _audit(payload)


def test_r5_透明保留原始_survived_并精确批准名称集合() -> None:
    report = _report({APPROVED: "survived", KILLED: "killed"})
    original = copy.deepcopy(report)

    audit = _audit(report)

    assert report == original, "checker 不得把原始 survived 改写成 killed。"
    assert audit["raw"] == {"total": 2, "killed": 1, "survived": 1}
    assert audit["approved_equivalents"] == {
        "count": 1,
        "names": [APPROVED],
    }
    assert audit["unexpected_non_killed"] == {
        "count": 0,
        "names": [],
        "statuses": {},
    }
    assert audit["gate_passed"] is True


def test_r5_清单项已被杀死必须作为陈旧批准拒绝() -> None:
    report = _report({APPROVED: "killed", KILLED: "killed"})

    _assert_rejected(report, "陈旧|listed-but-killed|已.*killed")


def test_r5_清单外_survivor_必须拒绝() -> None:
    report = _report({APPROVED: "survived", KILLED: "survived"})

    _assert_rejected(report, "清单外|unexpected")


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
        "unknown-status",
    ),
)
def test_r5_任何非_killed_survived_状态都不能被批准(status: str) -> None:
    report = _report({APPROVED: status, KILLED: "killed"})

    _assert_rejected(report, "状态|只允许.*killed.*survived|非.*killed")


def test_r5_survivor_计数不变但名称交换仍必须拒绝() -> None:
    report = _report({APPROVED: "killed", KILLED: "survived"})
    assert report["raw"] == {
        "total": 2,
        "killed": 1,
        "survived": 1,
        "mutant_names_sha256": _names_sha256(sorted((APPROVED, KILLED))),
    }

    _assert_rejected(report, "清单外|陈旧|集合")


def test_r5_schema_v1_报告必须拒绝() -> None:
    report = _report({APPROVED: "survived", KILLED: "killed"})
    report["schema_version"] = 1

    _assert_rejected(report, "schema.*2|版本")


def test_r5_报告未知字段必须拒绝() -> None:
    report = _report({APPROVED: "survived", KILLED: "killed"})
    report["silent_exclusions"] = ["*"]

    _assert_rejected(report, "字段|未知")


def test_r5_布尔值不得冒充数值计数() -> None:
    report = _report({APPROVED: "survived", KILLED: "killed"})
    raw = report["raw"]
    assert isinstance(raw, dict)
    raw["total"] = True

    _assert_rejected(report, "布尔|整数")


def test_r5_绑定指纹被篡改必须拒绝() -> None:
    report = _report({APPROVED: "survived", KILLED: "killed"})
    bindings = report["bindings"]
    assert isinstance(bindings, dict)
    bindings["source_sha256"] = "0" * 64

    _assert_rejected(report, "绑定|source|指纹")


def test_r5_独立_checker_不得导入_runner_实现() -> None:
    module = importlib.import_module("tools.check_mutation_equivalents")
    module_path = Path(str(module.__file__))
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "tools.run_mutation_profile" not in imported_modules
    assert "tools.run_mutation_profile" not in imported_names


def test_r5_audit_接口不要求_runner_私有类型() -> None:
    audit, error = _checker_api()

    assert callable(audit)
    assert issubclass(error, Exception)
    assert "tools.run_mutation_profile" not in str(getattr(audit, "__annotations__", {}))
