"""独立审计 r5 等价 mutant 清单与透明 mutation 报告。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from tools.mutation_equivalents import (
    MANIFEST_RELATIVE_PATH,
    EquivalentManifestError,
    load_equivalent_manifest,
)

_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "profile",
        "bindings",
        "runs",
        "raw",
        "approved_equivalents",
        "unexpected_non_killed",
        "gate_passed",
    }
)
_RUN_FIELDS = frozenset(
    {
        "kind",
        "run",
        "source_fingerprint",
        "result_count",
        "result_names_sha256",
        "result_statuses_sha256",
        "results",
    }
)
_RESULT_FIELDS = frozenset({"name", "status"})
_RAW_FIELDS = frozenset({"total", "killed", "survived", "mutant_names_sha256"})
_APPROVED_FIELDS = frozenset({"count", "names", "digest"})
_UNEXPECTED_FIELDS = frozenset({"count", "names", "statuses"})
_ALLOWED_RESULT_STATUSES = frozenset({"killed", "survived"})


class MutationEquivalentError(RuntimeError):
    """mutation 报告不满足 r5 精确等价集合策略。"""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MutationEquivalentError(f"{label} 必须是 JSON 对象。")
    return cast(Mapping[str, object], value)


def _closed_mapping(
    value: object,
    label: str,
    fields: frozenset[str],
) -> Mapping[str, object]:
    result = _mapping(value, label)
    if set(result) != fields:
        raise MutationEquivalentError(f"{label} 包含未知、缺失或额外字段。")
    return result


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MutationEquivalentError(f"{label} 必须是整数且不得用布尔值冒充。")
    if value < 0:
        raise MutationEquivalentError(f"{label} 不得为负数。")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MutationEquivalentError(f"{label} 必须是非空字符串。")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _names_sha256(names: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()


def _statuses_sha256(results: Sequence[Mapping[str, str]]) -> str:
    return _canonical_sha256(list(results))


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise MutationEquivalentError(f"{label} 必须是字符串数组。")
    return cast(list[str], value)


def _manifest_approved_names(manifest: Mapping[str, object]) -> list[str]:
    raw_entries = manifest.get("equivalents")
    if not isinstance(raw_entries, list):
        raise MutationEquivalentError("manifest.equivalents 必须是数组。")
    names: list[str] = []
    for index, raw_entry in enumerate(raw_entries):
        entry = _mapping(raw_entry, f"manifest.equivalents[{index}]")
        names.append(_string(entry.get("name"), f"manifest.equivalents[{index}].name"))
    if names != sorted(names, key=lambda item: item.encode("utf-8")):
        raise MutationEquivalentError("manifest 等价名称必须按 UTF-8 字节序排序。")
    if len(names) != len(set(names)):
        raise MutationEquivalentError("manifest 等价名称不得重复。")
    return names


def _validate_bindings(
    report: Mapping[str, object],
    manifest: Mapping[str, object],
    expected_bindings: Mapping[str, str],
) -> Mapping[str, object]:
    bindings = _mapping(report["bindings"], "report.bindings")
    if set(bindings) != set(expected_bindings):
        raise MutationEquivalentError("report 绑定字段不符合当前契约。")
    for key, expected in expected_bindings.items():
        actual = _string(bindings.get(key), f"bindings.{key}")
        if actual != expected:
            raise MutationEquivalentError(f"report 绑定 {key} 或指纹已被篡改。")
    canonical_manifest = _canonical_sha256(manifest)
    if bindings.get("manifest_sha256") != canonical_manifest:
        raise MutationEquivalentError("report 绑定的 manifest 指纹与实际清单不一致。")
    return bindings


def _parse_results(value: object, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise MutationEquivalentError(f"{label} 必须是非空结果数组。")
    parsed: list[dict[str, str]] = []
    for index, raw_item in enumerate(value):
        item = _closed_mapping(raw_item, f"{label}[{index}]", _RESULT_FIELDS)
        name = _string(item["name"], f"{label}[{index}].name")
        status = _string(item["status"], f"{label}[{index}].status")
        if status not in _ALLOWED_RESULT_STATUSES:
            raise MutationEquivalentError(
                f"{name} 的状态 {status} 非法；报告只允许 killed 与 survived。"
            )
        parsed.append({"name": name, "status": status})
    names = [item["name"] for item in parsed]
    if names != sorted(names, key=lambda item: item.encode("utf-8")):
        raise MutationEquivalentError(f"{label} 未按 UTF-8 字节序排序。")
    if len(names) != len(set(names)):
        raise MutationEquivalentError(f"{label} 包含重复 mutant 名称。")
    return parsed


def _validate_run(
    raw_run: object,
    expected_kind: str,
    expected_number: int,
    expected_source_fingerprint: str,
) -> list[dict[str, str]]:
    run = _closed_mapping(raw_run, "report.run", _RUN_FIELDS)
    if run["kind"] != expected_kind or _integer(run["run"], "run.run") != expected_number:
        raise MutationEquivalentError("report run 的 kind 或序号不符合固定契约。")
    if run["source_fingerprint"] != expected_source_fingerprint:
        raise MutationEquivalentError("report run 的 source 指纹不一致。")
    results = _parse_results(run["results"], "run.results")
    names = [item["name"] for item in results]
    if _integer(run["result_count"], "run.result_count") != len(results):
        raise MutationEquivalentError("run.result_count 与原始结果不一致。")
    if run["result_names_sha256"] != _names_sha256(names):
        raise MutationEquivalentError("run mutant 名称摘要与原始结果不一致。")
    if run["result_statuses_sha256"] != _statuses_sha256(results):
        raise MutationEquivalentError("run mutant 状态摘要与原始结果不一致。")
    return results


def _validate_runs(
    report: Mapping[str, object],
    expected_runs: Sequence[tuple[str, int]],
    source_fingerprint: str,
) -> list[dict[str, str]]:
    raw_runs = report["runs"]
    if not isinstance(raw_runs, list) or len(raw_runs) != len(expected_runs):
        raise MutationEquivalentError("report runs 次数不符合固定 profile 契约。")
    baseline: list[dict[str, str]] | None = None
    for raw_run, (kind, number) in zip(raw_runs, expected_runs, strict=True):
        results = _validate_run(raw_run, kind, number, source_fingerprint)
        if baseline is None:
            baseline = results
        elif results != baseline:
            raise MutationEquivalentError("full 与 property-only 的完整状态集合不一致。")
    if baseline is None:
        raise MutationEquivalentError("report 未包含任何 mutation 运行。")
    return baseline


def _validate_manifest_baseline(
    manifest: Mapping[str, object],
    results: Sequence[Mapping[str, str]],
) -> None:
    profile = _mapping(manifest.get("profile"), "manifest.profile")
    names = [item["name"] for item in results]
    expected_count = _integer(profile.get("expected_mutant_count"), "expected_mutant_count")
    expected_digest = _string(
        profile.get("expected_mutant_names_sha256"),
        "expected_mutant_names_sha256",
    )
    if len(names) != expected_count or _names_sha256(names) != expected_digest:
        raise MutationEquivalentError("mutation 全集数量或名称摘要与 manifest 基线不一致。")


def _audit_policy(
    results: Sequence[Mapping[str, str]],
    approved_names: Sequence[str],
) -> tuple[list[str], list[str], dict[str, str]]:
    statuses = {item["name"]: item["status"] for item in results}
    missing = sorted(set(approved_names) - set(statuses))
    if missing:
        raise MutationEquivalentError("manifest 清单项在实际 mutant 全集中缺失。")
    listed_but_killed = sorted(name for name in approved_names if statuses.get(name) == "killed")
    if listed_but_killed:
        raise MutationEquivalentError("等价清单已陈旧：listed-but-killed 项必须重新审批删除。")
    survivors = sorted(name for name, status in statuses.items() if status == "survived")
    unexpected = sorted(set(survivors) - set(approved_names))
    if unexpected:
        raise MutationEquivalentError("存在清单外 unexpected survivor。")
    if survivors != list(approved_names):
        raise MutationEquivalentError("实际 survivor 集合与获批等价集合不一致。")
    return survivors, [], {}


def _validate_raw(
    report: Mapping[str, object],
    results: Sequence[Mapping[str, str]],
) -> dict[str, int]:
    raw = _closed_mapping(report["raw"], "report.raw", _RAW_FIELDS)
    names = [item["name"] for item in results]
    expected = {
        "total": len(results),
        "killed": sum(item["status"] == "killed" for item in results),
        "survived": sum(item["status"] == "survived" for item in results),
    }
    for field, value in expected.items():
        if _integer(raw[field], f"raw.{field}") != value:
            raise MutationEquivalentError(f"raw.{field} 与完整原始结果不一致。")
    if raw["mutant_names_sha256"] != _names_sha256(names):
        raise MutationEquivalentError("raw mutant 名称摘要与完整原始结果不一致。")
    return expected


def _validate_reported_policy(
    report: Mapping[str, object],
    approved_names: Sequence[str],
) -> None:
    approved = _closed_mapping(
        report["approved_equivalents"],
        "approved_equivalents",
        _APPROVED_FIELDS,
    )
    reported_names = _string_list(approved["names"], "approved_equivalents.names")
    if (
        _integer(approved["count"], "approved_equivalents.count") != len(approved_names)
        or reported_names != list(approved_names)
        or approved["digest"] != _names_sha256(approved_names)
    ):
        raise MutationEquivalentError("reported approved equivalent 集合或摘要不一致。")
    unexpected = _closed_mapping(
        report["unexpected_non_killed"],
        "unexpected_non_killed",
        _UNEXPECTED_FIELDS,
    )
    statuses = _mapping(unexpected["statuses"], "unexpected_non_killed.statuses")
    if (
        _integer(unexpected["count"], "unexpected_non_killed.count") != 0
        or _string_list(unexpected["names"], "unexpected_non_killed.names")
        or statuses
    ):
        raise MutationEquivalentError("unexpected_non_killed 必须精确为空。")
    if report["gate_passed"] is not True:
        raise MutationEquivalentError("gate_passed 必须是布尔真且由独立审计证明。")


def audit_profile_report(
    payload: object,
    *,
    manifest_payload: Mapping[str, object],
    expected_profile: Mapping[str, object],
    expected_bindings: Mapping[str, str],
    expected_runs: Sequence[tuple[str, int]],
) -> Mapping[str, object]:
    """不依赖 runner 实现，独立重算单个 profile 的 r5 集合策略。"""

    report = _closed_mapping(payload, "report", _REPORT_FIELDS)
    if _integer(report["schema_version"], "schema_version") != 2:
        raise MutationEquivalentError("mutation report schema 版本必须为 2。")
    if _canonical_sha256(report["profile"]) != _canonical_sha256(expected_profile):
        raise MutationEquivalentError("report profile 与固定契约不一致。")
    bindings = _validate_bindings(report, manifest_payload, expected_bindings)
    source_fingerprint = _string(bindings["source_fingerprint"], "source_fingerprint")
    results = _validate_runs(report, expected_runs, source_fingerprint)
    _validate_manifest_baseline(manifest_payload, results)
    approved_names = _manifest_approved_names(manifest_payload)
    survivors, unexpected_names, unexpected_statuses = _audit_policy(
        results,
        approved_names,
    )
    raw = _validate_raw(report, results)
    _validate_reported_policy(report, approved_names)
    return {
        "raw": raw,
        "approved_equivalents": {"count": len(survivors), "names": survivors},
        "unexpected_non_killed": {
            "count": len(unexpected_names),
            "names": unexpected_names,
            "statuses": unexpected_statuses,
        },
        "gate_passed": True,
    }


def check_manifest(repo: Path, manifest_path: Path) -> Mapping[str, object]:
    """独立读取并输出清单的透明摘要。"""

    manifest = load_equivalent_manifest(repo, manifest_path)
    approved = _manifest_approved_names(manifest)
    return {
        "schema_version": 1,
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": _canonical_sha256(manifest),
        "approved_equivalents": len(approved),
        "approved_names_sha256": _names_sha256(approved),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="独立校验 T01 r5 等价 mutant 清单。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(MANIFEST_RELATIVE_PATH),
        help="固定等价清单路径。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = args.repo.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = repo / manifest_path
    try:
        result = check_manifest(repo, manifest_path)
    except (EquivalentManifestError, MutationEquivalentError) as exc:
        print(f"等价 mutant 门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
