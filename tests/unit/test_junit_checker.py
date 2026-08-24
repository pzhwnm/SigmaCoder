"""JUnit 结构化测试证据门的负控。"""

from __future__ import annotations

import base64
import json
import tomllib
from pathlib import Path

import pytest
from tools.check_junit import (
    CORE_PROPERTY_NODEIDS,
    HYPOTHESIS_CONTRACT_VERSION,
    JUnitGateError,
    check_hypothesis_statistics,
    check_junit,
    main,
)


def write_report(
    path: Path,
    *,
    tests: int,
    failures: int = 0,
    errors: int = 0,
    skipped: int = 0,
    testcase_body: str = "",
) -> None:
    testcases = "".join(
        f'<testcase classname="suite" name="case-{index}">{testcase_body}</testcase>'
        for index in range(tests)
    )
    path.write_text(
        (
            f'<testsuites tests="{tests}" failures="{failures}" errors="{errors}" '
            f'skipped="{skipped}"><testsuite name="pytest" tests="{tests}" '
            f'failures="{failures}" errors="{errors}" skipped="{skipped}">'
            f"{testcases}</testsuite></testsuites>"
        ),
        encoding="utf-8",
    )


def write_hypothesis_report(
    path: Path,
    *,
    missing_last: bool = False,
    first_passing: int = 200,
    first_failing: int = 0,
    malformed_first: bool = False,
) -> None:
    nodeids = CORE_PROPERTY_NODEIDS[:-1] if missing_last else CORE_PROPERTY_NODEIDS
    properties: list[str] = []
    for index, nodeid in enumerate(nodeids):
        passing = first_passing if index == 0 else 200
        failing = first_failing if index == 0 else 0
        statistics = (
            f"{nodeid}:\n\n"
            "  - during generate phase (0.10 seconds):\n"
            f"    - {passing} passing, {failing} failing, and 3 invalid test cases\n\n"
            "  - Stopped because settings.max_examples=200"
        )
        encoded = base64.b64encode(statistics.encode()).decode()
        if index == 0 and malformed_first:
            encoded = "%%%not-base64%%%"
        properties.append(f'<property name="hypothesis-statistics-{nodeid}" value="{encoded}" />')
    testcases = "".join(
        f'<testcase classname="property" name="case-{index}" />' for index in range(len(nodeids))
    )
    path.write_text(
        (
            f'<testsuites><testsuite name="pytest" tests="{len(nodeids)}" failures="0" '
            f'errors="0" skipped="0"><properties>{"".join(properties)}</properties>'
            f"{testcases}</testsuite></testsuites>"
        ),
        encoding="utf-8",
    )


def test_junit_checker_接受非空且零失败错误跳过的报告(tmp_path: Path) -> None:
    report = tmp_path / "valid.xml"
    write_report(report, tests=2)

    summary = check_junit(report)

    assert summary.tests == 2
    assert summary.failures == summary.errors == summary.skipped == 0
    assert len(summary.sha256) == 64


@pytest.mark.parametrize(
    ("name", "tests", "skipped", "body", "message"),
    [
        ("empty", 0, 0, "", "tests>0"),
        ("skipped", 1, 1, "<skipped />", "跳过或 xfail"),
        (
            "xfail",
            1,
            1,
            '<skipped type="pytest.xfail" message="预期失败" />',
            "跳过或 xfail",
        ),
    ],
)
def test_junit_checker_拒绝空运行_skipped_与_xfail(
    tmp_path: Path,
    name: str,
    tests: int,
    skipped: int,
    body: str,
    message: str,
) -> None:
    report = tmp_path / f"{name}.xml"
    write_report(report, tests=tests, skipped=skipped, testcase_body=body)

    with pytest.raises(JUnitGateError, match=message):
        check_junit(report)


@pytest.mark.parametrize(
    ("failures", "errors"),
    [(1, 0), (0, 1)],
)
def test_junit_checker_拒绝_failure_与_error(
    tmp_path: Path,
    failures: int,
    errors: int,
) -> None:
    report = tmp_path / "failed.xml"
    body = "<failure />" if failures else "<error />"
    write_report(report, tests=1, failures=failures, errors=errors, testcase_body=body)

    with pytest.raises(JUnitGateError, match="失败、错误"):
        check_junit(report)


@pytest.mark.parametrize("body", ["<failure />", "<error />", "<skipped />"])
def test_junit_checker_拒绝属性伪造为零但实际存在阻断节点(
    tmp_path: Path,
    body: str,
) -> None:
    report = tmp_path / "forged.xml"
    write_report(report, tests=1, testcase_body=body)

    with pytest.raises(JUnitGateError, match="汇总计数与实际节点不一致"):
        check_junit(report)


def test_junit_checker_cli_输出结构化_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "valid.xml"
    write_report(report, tests=1)

    assert main([str(report)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["reports"][0]["tests"] == 1


def test_hypothesis_statistics_接受九个核心属性各_200_例(tmp_path: Path) -> None:
    report = tmp_path / "properties.xml"
    write_hypothesis_report(report)

    evidence = check_hypothesis_statistics(report)

    assert len(evidence) == 9
    assert all(item.passing == item.max_examples == 200 for item in evidence)
    assert all(item.failing == 0 and item.shrink == "NOT_APPLICABLE" for item in evidence)


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"missing_last": True}, "核心属性集合不匹配"),
        ({"first_passing": 199}, "passing>=200"),
        ({"first_failing": 1}, "failing=0"),
        ({"malformed_first": True}, "严格 base64/UTF-8"),
    ],
)
def test_hypothesis_statistics_拒绝缺块少例失败与畸形(
    tmp_path: Path,
    options: dict[str, object],
    message: str,
) -> None:
    report = tmp_path / "properties.xml"
    write_hypothesis_report(report, **options)  # type: ignore[arg-type]

    with pytest.raises(JUnitGateError, match=message):
        check_hypothesis_statistics(report)


def test_hypothesis_cli_json_持久化_profile_seed_shrink_与逐项_hash(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = tmp_path / "properties.xml"
    write_hypothesis_report(report)

    assert main([f"--hypothesis-contract={HYPOTHESIS_CONTRACT_VERSION}", str(report)]) == 0
    payload = json.loads(capsys.readouterr().out)
    hypothesis = payload["hypothesis"]
    assert hypothesis["profile"] == "default"
    assert hypothesis["seed"] == 20260823
    assert hypothesis["shrink"] == "NOT_APPLICABLE"
    assert len(hypothesis["properties"]) == 9
    assert all(len(item["stats_sha256"]) == 64 for item in hypothesis["properties"])


def test_pytest_全局启用_strict_xfail_使_xpass_非零退出() -> None:
    project = Path(__file__).resolve().parents[2]
    configuration = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))

    assert configuration["tool"]["pytest"]["ini_options"]["xfail_strict"] is True
