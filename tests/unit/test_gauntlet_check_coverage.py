"""changed-line coverage 检查器的 fail-closed 单元测试。"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from tools.check_coverage import BranchRequirement, CoverageGateError, check_report


def coverage_report(
    *, total_covered: int = 19, event_covered: int = 4, service_covered: int = 2
) -> dict[str, Any]:
    return {
        "meta": {"branch_coverage": True},
        "totals": {"num_branches": 20, "covered_branches": total_covered},
        "files": {
            "src/sigmacoder/domain/events.py": {
                "summary": {"num_branches": 4, "covered_branches": event_covered}
            },
            "src/sigmacoder/application/task_service.py": {
                "summary": {"num_branches": 2, "covered_branches": service_covered}
            },
        },
    }


def requirements() -> list[BranchRequirement]:
    return [
        BranchRequirement("src/sigmacoder/domain/events.py", Decimal("100")),
        BranchRequirement("src/sigmacoder/application/task_service.py", Decimal("100")),
    ]


def test_覆盖率门在全部阈值满足时通过() -> None:
    result = check_report(coverage_report(), Decimal("95"), requirements())
    assert result["total"] == "95.00%"
    assert result["src/sigmacoder/domain/events.py"] == "100.00%"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"total_covered": 18}, "全产品分支覆盖率"),
        ({"event_covered": 3}, "events.py"),
        ({"service_covered": 1}, "task_service.py"),
    ],
)
def test_覆盖率三个硬门分别能失败(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(CoverageGateError, match=message):
        check_report(coverage_report(**kwargs), Decimal("95"), requirements())


def test_缺少分支模式时拒绝() -> None:
    report = coverage_report()
    report["meta"]["branch_coverage"] = False
    with pytest.raises(CoverageGateError, match="未启用"):
        check_report(report, Decimal("95"), requirements())


def test_模块没有分支数据时拒绝而非按百分百处理() -> None:
    report = coverage_report()
    report["files"]["src/sigmacoder/domain/events.py"]["summary"] = {
        "num_branches": 0,
        "covered_branches": 0,
    }
    with pytest.raises(CoverageGateError, match="没有分支数据"):
        check_report(report, Decimal("95"), requirements())
