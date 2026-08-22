"""校验 pytest JUnit XML，拒绝空运行、失败、错误、跳过与 xfail。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as element_tree
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path


class JUnitGateError(RuntimeError):
    """JUnit 报告缺失、畸形或未证明测试真实执行。"""


@dataclass(frozen=True)
class JUnitSummary:
    path: str
    sha256: str
    tests: int
    failures: int
    errors: int
    skipped: int


@dataclass(frozen=True)
class HypothesisPropertyEvidence:
    nodeid: str
    passing: int
    failing: int
    invalid: int
    max_examples: int
    shrink: str
    stats_sha256: str


HYPOTHESIS_CONTRACT_VERSION = "t01-core-v1"
HYPOTHESIS_PROFILE = "default"
HYPOTHESIS_SEED = 20260823
MINIMUM_PASSING_EXAMPLES = 200
CORE_PROPERTY_NODEIDS = (
    "tests/property/test_event_generated_properties.py::"
    "test_canonicalization_is_independent_of_mapping_insertion_order",
    "tests/property/test_event_generated_properties.py::"
    "test_generated_cross_field_and_path_violations_fail_closed",
    "tests/property/test_event_generated_properties.py::"
    "test_incomplete_transaction_boundaries_are_never_recoverable",
    "tests/property/test_event_generated_properties.py::"
    "test_canonicalization_matches_independent_spec_oracle",
    "tests/property/test_event_generated_properties.py::"
    "test_same_authoritative_event_bytes_have_exact_projection_and_round_trip",
    "tests/property/test_event_generated_properties.py::"
    "test_checkpoint_replay_is_idempotent_for_generated_legal_prefixes",
    "tests/property/test_event_generated_properties.py::"
    "test_generated_damage_fails_closed_and_physical_order_is_irrelevant",
    "tests/property/test_event_generated_properties.py::"
    "test_nfd_and_nfc_event_twins_restore_to_identical_python_objects",
    "tests/property/test_event_store_properties.py::"
    "test_generated_sqlite_append_round_trip_and_cross_task_isolation",
)
STATISTICS_PATTERN = re.compile(
    r"during generate phase .*?\n(?:.*\n)*?\s*- "
    r"(?P<passing>\d+) passing, (?P<failing>\d+) failing, and "
    r"(?P<invalid>\d+) invalid test cases",
)
MAX_EXAMPLES_PATTERN = re.compile(r"Stopped because settings\.max_examples=(\d+)")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _count(element: element_tree.Element, name: str, label: str) -> int:
    value = element.attrib.get(name)
    if value is None or not value.isascii() or not value.isdecimal():
        raise JUnitGateError(f"{label} 的 {name} 必须是非负十进制整数。")
    return int(value)


def _read_xml(path: Path) -> tuple[bytes, element_tree.Element]:
    if path.is_symlink() or not path.is_file():
        raise JUnitGateError(f"JUnit 报告必须是普通文件且不得是链接：{path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise JUnitGateError(f"无法读取 JUnit 报告 {path}：{exc}") from exc
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise JUnitGateError("JUnit 报告不得包含 DTD 或实体声明。")
    try:
        root = element_tree.fromstring(raw)
    except element_tree.ParseError as exc:
        raise JUnitGateError(f"JUnit XML 无法解析：{exc}") from exc
    return raw, root


def _test_suites(root: element_tree.Element) -> list[element_tree.Element]:
    root_name = _local_name(root.tag)
    if root_name == "testsuite":
        suites = [root]
    elif root_name == "testsuites":
        suites = [child for child in root if _local_name(child.tag) == "testsuite"]
    else:
        raise JUnitGateError(f"JUnit 根元素不受支持：{root_name}")
    if not suites:
        raise JUnitGateError("JUnit 报告没有 testsuite。")
    return suites


def _totals(suites: list[element_tree.Element]) -> dict[str, int]:
    totals = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    for index, suite in enumerate(suites, start=1):
        for name in totals:
            totals[name] += _count(suite, name, f"testsuite[{index}]")
    return totals


def _actual_outcome_nodes(suites: list[element_tree.Element]) -> dict[str, int]:
    names = ("failure", "error", "skipped")
    return {
        name: sum(
            1
            for suite in suites
            for descendant in suite.iter()
            if _local_name(descendant.tag) == name
        )
        for name in names
    }


def check_junit(path: Path) -> JUnitSummary:
    raw, root = _read_xml(path)
    suites = _test_suites(root)
    totals = _totals(suites)
    testcases = sum(
        1
        for suite in suites
        for descendant in suite.iter()
        if _local_name(descendant.tag) == "testcase"
    )
    if totals["tests"] <= 0 or testcases != totals["tests"]:
        raise JUnitGateError(
            f"JUnit 必须证明 tests>0 且 testcase 数量一致：tests={totals['tests']}，"
            f"testcase={testcases}。"
        )
    actual_outcomes = _actual_outcome_nodes(suites)
    declared_outcomes = {
        "failure": totals["failures"],
        "error": totals["errors"],
        "skipped": totals["skipped"],
    }
    if actual_outcomes != declared_outcomes:
        raise JUnitGateError(
            "JUnit 汇总计数与实际节点不一致："
            f"declared={declared_outcomes}，actual={actual_outcomes}。"
        )
    blocked = {name: totals[name] for name in ("failures", "errors", "skipped")}
    if any(blocked.values()):
        raise JUnitGateError(
            "JUnit 不允许失败、错误、跳过或 xfail："
            + "，".join(f"{name}={value}" for name, value in blocked.items())
        )
    return JUnitSummary(
        path=path.as_posix(),
        sha256=hashlib.sha256(raw).hexdigest(),
        **totals,
    )


def _hypothesis_properties(root: element_tree.Element) -> dict[str, str]:
    prefix = "hypothesis-statistics-"
    found: dict[str, str] = {}
    for element in root.iter():
        if _local_name(element.tag) != "property":
            continue
        name = element.attrib.get("name", "")
        if not name.startswith(prefix):
            continue
        nodeid = name.removeprefix(prefix)
        value = element.attrib.get("value")
        if not nodeid or value is None or nodeid in found:
            raise JUnitGateError("Hypothesis statistics 属性名称为空、重复或缺少 value。")
        found[nodeid] = value
    return found


def _parse_hypothesis_property(nodeid: str, encoded: str) -> HypothesisPropertyEvidence:
    try:
        raw = base64.b64decode(encoded, validate=True)
        statistics = raw.decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise JUnitGateError(f"{nodeid} 的 Hypothesis statistics 不是严格 base64/UTF-8。") from exc
    if not statistics.startswith(f"{nodeid}:\n\n"):
        raise JUnitGateError(f"{nodeid} 的 Hypothesis statistics 未绑定自身 nodeid。")
    matches = list(STATISTICS_PATTERN.finditer(statistics))
    max_examples = [int(value) for value in MAX_EXAMPLES_PATTERN.findall(statistics)]
    if len(matches) != 1 or len(max_examples) != 1:
        raise JUnitGateError(f"{nodeid} 缺少唯一 generate/max_examples 统计块。")
    counts = {name: int(matches[0].group(name)) for name in ("passing", "failing", "invalid")}
    if (
        counts["passing"] < MINIMUM_PASSING_EXAMPLES
        or counts["failing"] != 0
        or max_examples[0] < MINIMUM_PASSING_EXAMPLES
    ):
        raise JUnitGateError(
            f"{nodeid} 未证明 passing>={MINIMUM_PASSING_EXAMPLES}、failing=0：{counts}。"
        )
    if "during shrink phase" in statistics:
        raise JUnitGateError(f"{nodeid} 出现非预期 shrink phase，拒绝成功证据。")
    return HypothesisPropertyEvidence(
        nodeid=nodeid,
        max_examples=max_examples[0],
        shrink="NOT_APPLICABLE",
        stats_sha256=hashlib.sha256(raw).hexdigest(),
        **counts,
    )


def check_hypothesis_statistics(path: Path) -> tuple[HypothesisPropertyEvidence, ...]:
    _, root = _read_xml(path)
    properties = _hypothesis_properties(root)
    if set(properties) != set(CORE_PROPERTY_NODEIDS):
        missing = sorted(set(CORE_PROPERTY_NODEIDS) - set(properties))
        extra = sorted(set(properties) - set(CORE_PROPERTY_NODEIDS))
        raise JUnitGateError(f"Hypothesis 核心属性集合不匹配：missing={missing}，extra={extra}。")
    return tuple(
        _parse_hypothesis_property(nodeid, properties[nodeid]) for nodeid in CORE_PROPERTY_NODEIDS
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="校验 pytest JUnit XML 的非空零跳过契约。")
    parser.add_argument("reports", nargs="+", type=Path, help="待校验的 JUnit XML。")
    parser.add_argument(
        "--hypothesis-contract",
        choices=(HYPOTHESIS_CONTRACT_VERSION,),
        help="对单个报告同时验证版本化核心属性统计契约。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summaries = [check_junit(path) for path in args.reports]
        hypothesis = None
        if args.hypothesis_contract:
            if len(args.reports) != 1:
                raise JUnitGateError("Hypothesis 统计模式必须且只能校验一个 JUnit 报告。")
            properties = check_hypothesis_statistics(args.reports[0])
            hypothesis = {
                "contract_version": HYPOTHESIS_CONTRACT_VERSION,
                "minimum_examples": MINIMUM_PASSING_EXAMPLES,
                "profile": HYPOTHESIS_PROFILE,
                "properties": [asdict(property_evidence) for property_evidence in properties],
                "seed": HYPOTHESIS_SEED,
                "shrink": "NOT_APPLICABLE",
            }
    except JUnitGateError as exc:
        print(f"JUnit 报告审计失败：{exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "reports": [asdict(summary) for summary in summaries],
                **({"hypothesis": hypothesis} if hypothesis is not None else {}),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
