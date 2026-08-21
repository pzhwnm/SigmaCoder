"""以 coverage.py JSON 报告实施分支覆盖率硬门。"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any


class CoverageGateError(RuntimeError):
    """覆盖率报告缺失、损坏或低于阈值。"""


@dataclass(frozen=True)
class BranchRequirement:
    path: str
    minimum: Decimal


def _number(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CoverageGateError(f"{label} 必须是非负整数。")
    return value


def _branch_counts(summary: Mapping[str, object], label: str) -> tuple[int, int]:
    total = _number(summary.get("num_branches"), f"{label}.num_branches")
    covered = _number(summary.get("covered_branches"), f"{label}.covered_branches")
    if total == 0:
        raise CoverageGateError(f"{label} 没有分支数据，不能通过分支覆盖率门禁。")
    if covered > total:
        raise CoverageGateError(f"{label} 的已覆盖分支数大于总分支数。")
    return covered, total


def _passes(covered: int, total: int, minimum: Decimal) -> bool:
    return Decimal(covered * 100) >= minimum * Decimal(total)


def _percent(covered: int, total: int) -> Decimal:
    return (Decimal(covered * 100) / Decimal(total)).quantize(Decimal("0.01"))


def _normalize_path(value: str) -> str:
    return str(PurePosixPath(value.replace("\\", "/")))


def load_report(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageGateError(f"无法读取 coverage JSON：{exc}") from exc
    if not isinstance(payload, dict):
        raise CoverageGateError("coverage JSON 顶层必须是对象。")
    return payload


def check_report(
    report: Mapping[str, Any],
    total_minimum: Decimal,
    module_requirements: Sequence[BranchRequirement],
) -> dict[str, str]:
    meta = report.get("meta")
    totals = report.get("totals")
    files = report.get("files")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        raise CoverageGateError("报告未启用 branch coverage。")
    if not isinstance(totals, dict) or not isinstance(files, dict):
        raise CoverageGateError("报告缺少 totals 或 files 对象。")

    total_covered, total_count = _branch_counts(totals, "totals")
    if not _passes(total_covered, total_count, total_minimum):
        raise CoverageGateError(
            f"全产品分支覆盖率 {_percent(total_covered, total_count)}% 低于 {total_minimum}%。"
        )

    normalized_files = {_normalize_path(str(key)): value for key, value in files.items()}
    results = {"total": f"{_percent(total_covered, total_count)}%"}
    for requirement in module_requirements:
        normalized = _normalize_path(requirement.path)
        file_data = normalized_files.get(normalized)
        if not isinstance(file_data, dict) or not isinstance(file_data.get("summary"), dict):
            raise CoverageGateError(f"报告缺少模块 {normalized} 的 summary。")
        covered, count = _branch_counts(file_data["summary"], normalized)
        if not _passes(covered, count, requirement.minimum):
            raise CoverageGateError(
                f"模块 {normalized} 分支覆盖率 {_percent(covered, count)}% "
                f"低于 {requirement.minimum}%。"
            )
        results[normalized] = f"{_percent(covered, count)}%"
    return results


def _decimal(value: str, label: str) -> Decimal:
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"{label} 不是有效数字：{value}") from exc
    if result < 0 or result > 100:
        raise argparse.ArgumentTypeError(f"{label} 必须位于 0 到 100。")
    return result


def _module_requirement(value: str) -> BranchRequirement:
    path, separator, threshold = value.rpartition("=")
    if not separator or not path:
        raise argparse.ArgumentTypeError("--module-branch 必须使用 PATH=PERCENT。")
    return BranchRequirement(path=path, minimum=_decimal(threshold, "模块阈值"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="校验分支覆盖率硬门。")
    parser.add_argument("--input", type=Path, required=True, help="coverage JSON 路径。")
    parser.add_argument(
        "--total-branch-min",
        type=lambda value: _decimal(value, "总阈值"),
        required=True,
    )
    parser.add_argument(
        "--module-branch",
        type=_module_requirement,
        action="append",
        default=[],
        help="模块阈值，格式 PATH=PERCENT。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = check_report(load_report(args.input), args.total_branch_min, args.module_branch)
    except CoverageGateError as exc:
        print(f"覆盖率门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "branch_coverage": result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
