"""独立审计 T01 两个持久 mutation profile 的 schema v2 证据。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, cast

from tools.check_mutation_equivalents import (
    MutationEquivalentError,
    audit_profile_report,
)
from tools.mutation_equivalents import (
    MANIFEST_RELATIVE_PATH,
    MUTMUT_VERSION,
    SPEC_RELATIVE_PATH,
    EquivalentManifestError,
    load_equivalent_manifest,
)
from tools.trusted_tools import TrustedGit, TrustedToolError

MUTATION_REPORT_ROOT = "mutation-reports"
MUTATION_MANIFEST_MODULE = "tools/mutation_equivalents.py"
MUTATION_EQUIVALENCE_CHECKER = "tools/check_mutation_equivalents.py"
MUTATION_REPORT_CHECKER = "tools/check_mutation_reports.py"
MUTATION_RUNNER = "tools/run_mutation_profile.py"
MUTATION_PROFILE_FILE = "tools/mutation_profiles.json"

EXPECTED_RUNS: dict[str, tuple[tuple[str, int], ...]] = {
    "events": (("full", 1), ("full", 2), ("property-only", 1)),
    "task-service": (("full", 1), ("full", 2)),
}

_EXPECTED_PROFILES: dict[str, dict[str, object]] = {
    "events": {
        "name": "events",
        "source_paths": ["src/sigmacoder"],
        "only_mutate": ["src/sigmacoder/domain/events.py"],
        "test_selection": [
            "tests/unit/test_event_chain.py",
            "tests/unit/test_event_semantics.py",
            "tests/unit/test_projection_checkpoint.py",
            "tests/adversarial/test_corrupt_event_chain.py",
            "tests/property/test_event_chain_properties.py",
            "tests/property/test_event_generated_properties.py",
        ],
        "property_test_selection": [
            "tests/property/test_event_chain_properties.py",
            "tests/property/test_event_generated_properties.py",
        ],
        "timeout_seconds": 1800,
        "timeout_multiplier": 15.0,
        "timeout_constant": 1.0,
        "max_children": 4,
        "repeat": 2,
        "cache_dir": "mutants",
        "report_path": "mutation-reports/events.json",
    },
    "task-service": {
        "name": "task-service",
        "source_paths": ["src/sigmacoder"],
        "only_mutate": ["src/sigmacoder/application/task_service.py"],
        "test_selection": [
            "tests/unit/test_task_service_branches.py",
            "tests/integration",
            "tests/e2e",
        ],
        "property_test_selection": [],
        "timeout_seconds": 1800,
        "timeout_multiplier": 15.0,
        "timeout_constant": 1.0,
        "max_children": 4,
        "repeat": 2,
        "cache_dir": "mutants",
        "report_path": "mutation-reports/task-service.json",
    },
}


class MutationReportError(RuntimeError):
    """最终 mutation 报告不完整、不新鲜或与当前仓库不一致。"""


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise MutationReportError(f"{label} 必须是对象。")
    return cast(Mapping[str, object], value)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MutationReportError(f"{label} 必须是整数且不得是布尔值。")
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


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _ordinary_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise MutationReportError(f"无法读取{label}：{exc}") from exc
    if _is_link_or_junction(path) or not stat.S_ISREG(metadata.st_mode):
        raise MutationReportError(f"{label}必须是普通文件且不得是链接或 junction。")


def _file_digest(path: Path, label: str) -> str:
    _ordinary_file(path, label)
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MutationReportError(f"无法读取{label}摘要：{exc}") from exc


def _profile_payload(profile: object) -> dict[str, object]:
    if isinstance(profile, Mapping):
        payload = dict(profile)
    elif is_dataclass(profile) and not isinstance(profile, type):
        payload = asdict(cast(Any, profile))
    else:
        raise MutationReportError("profile 必须是 dataclass 或映射。")
    normalized = json.loads(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if not isinstance(normalized, dict):
        raise MutationReportError("profile 无法规范化为 JSON 对象。")
    return cast(dict[str, object], normalized)


def _pairs_without_duplicates(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MutationReportError(f"JSON 包含重复字段：{key}")
        result[key] = value
    return result


def _read_json_file(path: Path, label: str) -> tuple[object, str]:
    _ordinary_file(path, label)
    try:
        raw = path.read_bytes()
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationReportError(f"无法读取{label}：{exc}") from exc
    return payload, hashlib.sha256(raw).hexdigest()


def _synthetic_zero_manifest(report: Mapping[str, object]) -> dict[str, object]:
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise MutationReportError("mutation report 运行次数不符合固定契约。")
    first_run = _mapping(runs[0], "runs[0]")
    results = first_run.get("results")
    if not isinstance(results, list) or not results:
        raise MutationReportError("mutation report 不得是空运行。")
    names: list[str] = []
    for raw_item in results:
        item = _mapping(raw_item, "run.results")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise MutationReportError("mutant 名称必须是非空字符串。")
        names.append(name)
    return {
        "profile": {
            "expected_mutant_count": len(names),
            "expected_mutant_names_sha256": _names_sha256(names),
        },
        "equivalents": [],
    }


def _string_bindings(bindings: Mapping[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in bindings.items():
        if not isinstance(value, str):
            raise MutationReportError("mutation report 绑定必须全部是字符串。")
        result[key] = value
    return result


def validate_report_payload(
    payload: object,
    profile: object,
    *,
    source_fingerprint: str,
    git_head: str,
    uv_lock_sha256: str,
    expected_bindings: Mapping[str, str] | None = None,
) -> None:
    """验证无等价项 profile；供 task-service 和隔离单元 fixture 使用。"""

    report = _mapping(payload, "mutation report")
    bindings = _mapping(report.get("bindings"), "mutation report.bindings")
    if bindings.get("source_fingerprint") != source_fingerprint:
        raise MutationReportError("mutation report 未绑定当前源码状态。")
    if bindings.get("git_head") != git_head or bindings.get("uv_lock_sha256") != uv_lock_sha256:
        raise MutationReportError("mutation report 未绑定当前提交或锁文件。")
    if bindings.get("manifest_sha256") != "0" * 64:
        raise MutationReportError("无等价项 profile 不得绑定 manifest 豁免。")
    if expected_bindings is not None and dict(bindings) != dict(expected_bindings):
        raise MutationReportError("mutation report 的完整绑定指纹与当前仓库不一致。")
    synthetic = _synthetic_zero_manifest(report)
    patched = copy.deepcopy(dict(report))
    patched_bindings = dict(bindings)
    patched_bindings["manifest_sha256"] = _canonical_sha256(synthetic)
    patched["bindings"] = patched_bindings
    expected = _string_bindings(bindings)
    expected["manifest_sha256"] = _canonical_sha256(synthetic)
    profile_payload = _profile_payload(profile)
    name = profile_payload.get("name")
    if not isinstance(name, str) or name not in EXPECTED_RUNS:
        raise MutationReportError("mutation report schema 或 profile 契约不匹配。")
    try:
        audit_profile_report(
            patched,
            manifest_payload=synthetic,
            expected_profile=profile_payload,
            expected_bindings=expected,
            expected_runs=EXPECTED_RUNS[name],
        )
    except MutationEquivalentError as exc:
        raise MutationReportError(str(exc)) from exc


def _load_profiles(config_path: Path) -> dict[str, dict[str, object]]:
    payload, _digest = _read_json_file(config_path, "mutation profile")
    root = _mapping(payload, "mutation profile")
    if set(root) != {"schema_version", "profiles"}:
        raise MutationReportError("mutation profile 顶层字段不符合固定契约。")
    if _integer(root["schema_version"], "profile.schema_version") != 1:
        raise MutationReportError("mutation profile schema_version 必须为 1。")
    raw_profiles = _mapping(root["profiles"], "profiles")
    if set(raw_profiles) != set(_EXPECTED_PROFILES):
        raise MutationReportError("mutation profile 名称集合不符合固定契约。")
    profiles: dict[str, dict[str, object]] = {}
    for name, expected in _EXPECTED_PROFILES.items():
        raw = _mapping(raw_profiles[name], name)
        candidate = {"name": name, **raw}
        if _canonical_sha256(candidate) != _canonical_sha256(expected):
            raise MutationReportError(f"{name} profile 与固定契约不一致。")
        profiles[name] = dict(candidate)
    return profiles


def _open_git(repo: Path) -> TrustedGit:
    try:
        return TrustedGit.open(repo)
    except TrustedToolError as exc:
        raise MutationReportError(str(exc)) from exc


def _git_head(repo: Path) -> bytes:
    try:
        return _open_git(repo).head_commit().encode("ascii")
    except TrustedToolError as exc:
        raise MutationReportError(str(exc)) from exc


def _git_status(repo: Path) -> bytes:
    try:
        return _open_git(repo).read(
            ("status", "--porcelain=v2", "-z", "--untracked-files=all"),
            label="mutation checker Git 状态",
        )
    except TrustedToolError as exc:
        raise MutationReportError(str(exc)) from exc


def _protected_paths(profile: Mapping[str, object]) -> tuple[str, ...]:
    arrays: list[str] = []
    for field in (
        "source_paths",
        "only_mutate",
        "test_selection",
        "property_test_selection",
    ):
        value = profile.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise MutationReportError(f"profile.{field} 必须是路径数组。")
        arrays.extend(cast(list[str], value))
    return (
        *arrays,
        "pyproject.toml",
        "uv.lock",
        SPEC_RELATIVE_PATH,
        MUTATION_PROFILE_FILE,
        MANIFEST_RELATIVE_PATH,
        MUTATION_MANIFEST_MODULE,
        MUTATION_RUNNER,
        MUTATION_EQUIVALENCE_CHECKER,
        MUTATION_REPORT_CHECKER,
    )


def _git_protected_files(repo: Path, protected: Sequence[str]) -> tuple[Path, ...]:
    try:
        output = _open_git(repo).read(
            (
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                *protected,
            ),
            label="mutation checker 受保护文件枚举",
        )
    except TrustedToolError as exc:
        raise MutationReportError(str(exc)) from exc
    return tuple(Path(os.fsdecode(raw)) for raw in output.split(b"\0") if raw)


def _repository_fingerprint(repo: Path, profile: Mapping[str, object]) -> str:
    digest = hashlib.sha256(b"sigmacoder-mutation-source-v2\0")
    protected = tuple(sorted(set(_protected_paths(profile))))
    try:
        for relative in _git_protected_files(repo, protected):
            entry = repo / relative
            digest.update(relative.as_posix().encode("utf-8"))
            digest.update(b"\0")
            if not entry.exists() and not entry.is_symlink():
                digest.update(b"MISSING\0")
                continue
            metadata = entry.lstat()
            digest.update(str(metadata.st_mode).encode("ascii"))
            digest.update(b"\0")
            if entry.is_symlink():
                digest.update(b"LINK\0")
                digest.update(os.readlink(entry).encode("utf-8"))
            elif entry.is_file():
                digest.update(b"FILE\0")
                digest.update(hashlib.sha256(entry.read_bytes()).digest())
            else:
                digest.update(b"NON_FILE\0")
    except OSError as exc:
        raise MutationReportError(f"无法计算 mutation 源码指纹：{exc}") from exc
    digest.update(b"PROFILE\0")
    digest.update(json.dumps(profile, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    digest.update(b"HEAD\0")
    digest.update(_git_head(repo))
    digest.update(b"GIT\0")
    digest.update(_git_status(repo))
    return digest.hexdigest()


def _managed_report_path(repo: Path, name: str) -> Path:
    report_root = repo / MUTATION_REPORT_ROOT
    report = report_root / f"{name}.json"
    if _is_link_or_junction(report_root) or report_root.resolve(strict=False) != report_root:
        raise MutationReportError("mutation report 根目录不得是链接或 junction。")
    _ordinary_file(report, f"{name} mutation report")
    return report


def _expected_bindings(
    repo: Path,
    profile: Mapping[str, object],
    *,
    source_fingerprint: str,
    manifest_sha256: str,
) -> dict[str, str]:
    only_mutate = profile["only_mutate"]
    if not isinstance(only_mutate, list) or len(only_mutate) != 1:
        raise MutationReportError("only_mutate 必须精确包含一个源文件。")
    source = repo / cast(str, only_mutate[0])
    return {
        "git_head": _git_head(repo).decode("ascii"),
        "spec_version": "r5",
        "spec_sha256": _file_digest(repo / SPEC_RELATIVE_PATH, "T01 SPEC"),
        "mutmut_version": MUTMUT_VERSION,
        "uv_lock_sha256": _file_digest(repo / "uv.lock", "uv.lock"),
        "profile_sha256": _file_digest(repo / MUTATION_PROFILE_FILE, "mutation profile"),
        "source_fingerprint": source_fingerprint,
        "source_sha256": _file_digest(source, "mutation 源文件"),
        "manifest_sha256": manifest_sha256,
        "runner_sha256": _file_digest(repo / MUTATION_RUNNER, "mutation runner"),
        "checker_sha256": _file_digest(
            repo / MUTATION_EQUIVALENCE_CHECKER,
            "等价 checker",
        ),
        "report_checker_sha256": _file_digest(
            repo / MUTATION_REPORT_CHECKER,
            "报告 checker",
        ),
    }


def _audit_events(
    payload: object,
    profile: Mapping[str, object],
    bindings: Mapping[str, str],
    manifest: Mapping[str, object],
) -> Mapping[str, object]:
    try:
        return audit_profile_report(
            payload,
            manifest_payload=manifest,
            expected_profile=profile,
            expected_bindings=bindings,
            expected_runs=EXPECTED_RUNS["events"],
        )
    except MutationEquivalentError as exc:
        raise MutationReportError(str(exc)) from exc


def _audit_task_service(
    payload: object,
    profile: Mapping[str, object],
    bindings: Mapping[str, str],
) -> Mapping[str, object]:
    validate_report_payload(
        payload,
        profile,
        source_fingerprint=bindings["source_fingerprint"],
        git_head=bindings["git_head"],
        uv_lock_sha256=bindings["uv_lock_sha256"],
        expected_bindings=bindings,
    )
    report = _mapping(payload, "task-service report")
    return {
        "raw": report["raw"],
        "approved_equivalents": {"count": 0, "names": []},
        "unexpected_non_killed": {"count": 0, "names": [], "statuses": {}},
        "gate_passed": True,
    }


def check_reports(repo: Path, config_path: Path) -> dict[str, object]:
    repo = repo.resolve()
    profiles = _load_profiles(config_path)
    try:
        manifest = load_equivalent_manifest(repo, repo / MANIFEST_RELATIVE_PATH)
    except EquivalentManifestError as exc:
        raise MutationReportError(str(exc)) from exc
    manifest_sha256 = _canonical_sha256(manifest)
    audits: dict[str, Mapping[str, object]] = {}
    report_digests: dict[str, str] = {}
    heads: set[str] = set()
    fingerprints_before = {
        name: _repository_fingerprint(repo, profile) for name, profile in profiles.items()
    }
    for name in ("events", "task-service"):
        profile = profiles[name]
        payload, report_digest = _read_json_file(
            _managed_report_path(repo, name),
            f"{name} mutation report",
        )
        policy_sha = manifest_sha256 if name == "events" else "0" * 64
        bindings = _expected_bindings(
            repo,
            profile,
            source_fingerprint=fingerprints_before[name],
            manifest_sha256=policy_sha,
        )
        if name == "events":
            audits[name] = _audit_events(payload, profile, bindings, manifest)
        else:
            audits[name] = _audit_task_service(payload, profile, bindings)
        report_digests[name] = report_digest
        heads.add(bindings["git_head"])
    fingerprints_after = {
        name: _repository_fingerprint(repo, profile) for name, profile in profiles.items()
    }
    if fingerprints_after != fingerprints_before:
        raise MutationReportError("报告检查期间受保护仓库状态发生漂移。")
    if len(heads) != 1:
        raise MutationReportError("两份 mutation report 未绑定同一个 Git HEAD。")

    reports: dict[str, object] = {}
    for name, audit in audits.items():
        raw = _mapping(audit["raw"], f"{name}.raw")
        approved = _mapping(audit["approved_equivalents"], f"{name}.approved")
        unexpected = _mapping(audit["unexpected_non_killed"], f"{name}.unexpected")
        reports[name] = {
            "report_sha256": report_digests[name],
            "git_head": next(iter(heads)),
            "mutants": _integer(raw["total"], f"{name}.raw.total"),
            "raw_survived": _integer(raw["survived"], f"{name}.raw.survived"),
            "approved_equivalents": _integer(
                approved["count"],
                f"{name}.approved.count",
            ),
            "unexpected_non_killed": _integer(
                unexpected["count"],
                f"{name}.unexpected.count",
            ),
        }
    return {
        "schema_version": 2,
        "spec_version": "r5",
        "manifest_sha256": manifest_sha256,
        "approved_equivalents": 49,
        "reports": reports,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="审计 T01 mutation schema v2 证据报告。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("mutation_profiles.json"),
        help="固定 profile 配置文件。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = check_reports(args.repo, args.config.resolve())
    except MutationReportError as exc:
        print(f"Mutation 报告审计失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
