"""审计 T01 两个持久 mutation profile 的最终证据报告。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path

from tools.run_mutation_profile import (
    HYPOTHESIS_PROFILE,
    HYPOTHESIS_SEED,
    MutationGateError,
    MutationProfile,
    _file_digest,
    _git_head,
    _managed_report_path,
    _mutant_names_digest,
    _profile_digest,
    _repository_fingerprint,
    load_profile,
    validate_inputs,
)

EXPECTED_RUNS = {
    "events": (("full", 1), ("full", 2), ("property-only", 1)),
    "task-service": (("full", 1), ("full", 2)),
}


class MutationReportError(RuntimeError):
    """最终 mutation 报告不完整、不新鲜或与当前仓库不一致。"""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise MutationReportError(f"{label} 必须是对象。")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MutationReportError(f"{label} 必须是非空字符串。")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MutationReportError(f"{label} 必须是整数且不得是布尔值。")
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _expected_profile(profile: MutationProfile) -> object:
    return json.loads(json.dumps(asdict(profile), ensure_ascii=False, sort_keys=True))


def _validate_header(
    report: Mapping[str, object],
    profile: MutationProfile,
    *,
    source_fingerprint: str,
    git_head: str,
    uv_lock_sha256: str,
) -> None:
    if set(report) != {"schema_version", "profile", "evidence", "runs", "mutants", "survivors"}:
        raise MutationReportError(f"{profile.name} report 顶层字段不符合固定契约。")
    schema_version = _integer(report["schema_version"], f"{profile.name}.schema_version")
    if schema_version != 1 or _canonical_json(report["profile"]) != _canonical_json(
        _expected_profile(profile)
    ):
        raise MutationReportError(f"{profile.name} report schema 或 profile 契约不匹配。")
    survivors = _integer(report["survivors"], f"{profile.name}.survivors")
    if survivors != 0:
        raise MutationReportError(f"{profile.name} report 必须证明 survivors=0。")

    evidence = _mapping(report["evidence"], f"{profile.name}.evidence")
    expected_evidence = {
        "git_head": git_head,
        "hypothesis_profile": HYPOTHESIS_PROFILE,
        "hypothesis_seed": HYPOTHESIS_SEED,
        "profile_sha256": _profile_digest(profile),
        "source_fingerprint": source_fingerprint,
        "uv_lock_sha256": uv_lock_sha256,
    }
    if _canonical_json(evidence) != _canonical_json(expected_evidence):
        raise MutationReportError(f"{profile.name} report 未绑定当前提交、锁文件或源码状态。")


def _validate_mutants(report: Mapping[str, object], profile_name: str) -> tuple[int, str]:
    mutants = _mapping(report["mutants"], f"{profile_name}.mutants")
    if set(mutants) != {"count", "names", "names_sha256"}:
        raise MutationReportError(f"{profile_name}.mutants 字段不符合固定契约。")
    raw_names = mutants["names"]
    if not isinstance(raw_names, list) or not raw_names:
        raise MutationReportError(f"{profile_name} report 不得是空 mutation 运行。")
    if not all(isinstance(name, str) and name for name in raw_names):
        raise MutationReportError(f"{profile_name} mutant 名称必须是非空字符串。")
    names = tuple(raw_names)
    if names != tuple(sorted(set(names))):
        raise MutationReportError(f"{profile_name} mutant 名称必须有序且唯一。")
    names_digest = _mutant_names_digest(names)
    count = _integer(mutants["count"], f"{profile_name}.mutants.count")
    if count != len(names) or mutants["names_sha256"] != names_digest:
        raise MutationReportError(f"{profile_name} mutant 数量或摘要不自洽。")
    return len(names), names_digest


def _validate_runs(
    report: Mapping[str, object],
    profile_name: str,
    *,
    mutant_count: int,
    mutant_names_digest: str,
    source_fingerprint: str,
) -> None:
    runs = report["runs"]
    if not isinstance(runs, list) or len(runs) != len(EXPECTED_RUNS[profile_name]):
        raise MutationReportError(f"{profile_name} report 运行次数不符合固定契约。")
    for run, (expected_kind, expected_number) in zip(
        runs,
        EXPECTED_RUNS[profile_name],
        strict=True,
    ):
        run_evidence = _mapping(run, f"{profile_name}.runs")
        expected_run = {
            "kind": expected_kind,
            "run": expected_number,
            "mutants": mutant_count,
            "mutant_names_sha256": mutant_names_digest,
            "source_fingerprint": source_fingerprint,
        }
        _integer(run_evidence.get("run"), f"{profile_name}.runs.run")
        _integer(run_evidence.get("mutants"), f"{profile_name}.runs.mutants")
        if _canonical_json(run_evidence) != _canonical_json(expected_run):
            raise MutationReportError(f"{profile_name} report 的逐轮证据不一致。")


def validate_report_payload(
    payload: object,
    profile: MutationProfile,
    *,
    source_fingerprint: str,
    git_head: str,
    uv_lock_sha256: str,
) -> None:
    report = _mapping(payload, f"{profile.name} report")
    _validate_header(
        report,
        profile,
        source_fingerprint=source_fingerprint,
        git_head=git_head,
        uv_lock_sha256=uv_lock_sha256,
    )
    mutant_count, names_digest = _validate_mutants(report, profile.name)
    _validate_runs(
        report,
        profile.name,
        mutant_count=mutant_count,
        mutant_names_digest=names_digest,
        source_fingerprint=source_fingerprint,
    )


def _read_report(path: Path, profile_name: str) -> tuple[object, str]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationReportError(f"无法读取 {profile_name} mutation report：{exc}") from exc
    return payload, hashlib.sha256(raw).hexdigest()


def check_reports(repo: Path, config_path: Path) -> dict[str, str]:
    repo = repo.resolve()
    digests: dict[str, str] = {}
    heads: set[str] = set()
    for name in ("events", "task-service"):
        try:
            profile = load_profile(config_path, name)
            validate_inputs(repo, profile)
            source_fingerprint = _repository_fingerprint(repo, profile)
            git_head = _git_head(repo).decode("ascii")
            uv_lock_sha256 = _file_digest(repo / "uv.lock", "uv.lock")
            report_path = _managed_report_path(repo, profile)
        except MutationGateError as exc:
            raise MutationReportError(str(exc)) from exc
        payload, report_digest = _read_report(report_path, name)
        validate_report_payload(
            payload,
            profile,
            source_fingerprint=source_fingerprint,
            git_head=git_head,
            uv_lock_sha256=uv_lock_sha256,
        )
        heads.add(git_head)
        digests[name] = report_digest
    if len(heads) != 1:
        raise MutationReportError("两份 mutation report 未绑定同一个 Git HEAD。")
    return digests


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="审计 T01 mutation 证据报告。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("mutation_profiles.json"),
        help="profile 配置文件。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        digests = check_reports(args.repo, args.config.resolve())
    except MutationReportError as exc:
        print(f"Mutation 报告审计失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "reports": digests}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
