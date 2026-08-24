"""运行版本化 mutmut profile，并拒绝 survivor、跳过或空运行。"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast
from uuid import uuid4

if __package__:
    from tools.mutation_equivalents import (
        EXPECTED_SOURCE_SHA256,
        MANIFEST_RELATIVE_PATH,
        MUTMUT_VERSION,
        SPEC_RELATIVE_PATH,
        EquivalentManifestError,
        load_equivalent_manifest,
    )
    from tools.repo_lease import (
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        parent_or_standalone_repository_lease,
    )
    from tools.trusted_tools import TrustedGit, TrustedToolError, resolve_trusted_uv
else:  # pragma: no cover - 由真实脚本入口覆盖
    from mutation_equivalents import (  # type: ignore[import-not-found,no-redef]
        EXPECTED_SOURCE_SHA256,
        MANIFEST_RELATIVE_PATH,
        MUTMUT_VERSION,
        SPEC_RELATIVE_PATH,
        EquivalentManifestError,
        load_equivalent_manifest,
    )
    from repo_lease import (  # type: ignore[import-not-found,no-redef]
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        parent_or_standalone_repository_lease,
    )
    from trusted_tools import (  # type: ignore[import-not-found,no-redef]
        TrustedGit,
        TrustedToolError,
        resolve_trusted_uv,
    )

KNOWN_STATUSES = frozenset(
    {
        "killed",
        "survived",
        "no tests",
        "check was interrupted by user",
        "not checked",
        "skipped",
        "suspicious",
        "timeout",
        "caught by type check",
        "segfault",
    }
)
MUTATION_CACHE_DIR = "mutants"
MUTATION_REPORT_ROOT = "mutation-reports"
MUTATION_LOCK_FILE = ".mutation-run.lock"
MUTATION_EQUIVALENCE_CHECKER = "tools/check_mutation_equivalents.py"
MUTATION_REPORT_CHECKER = "tools/check_mutation_reports.py"
MUTATION_MANIFEST_MODULE = "tools/mutation_equivalents.py"
HYPOTHESIS_PROFILE = "default"
HYPOTHESIS_SEED = 20260823
PROFILE_CONTRACTS: dict[str, dict[str, object]] = {
    "events": {
        "source_paths": ("src/sigmacoder",),
        "only_mutate": ("src/sigmacoder/domain/events.py",),
        "test_selection": (
            "tests/unit/test_event_chain.py",
            "tests/unit/test_event_semantics.py",
            "tests/unit/test_projection_checkpoint.py",
            "tests/adversarial/test_corrupt_event_chain.py",
            "tests/property/test_event_chain_properties.py",
            "tests/property/test_event_generated_properties.py",
        ),
        "property_test_selection": (
            "tests/property/test_event_chain_properties.py",
            "tests/property/test_event_generated_properties.py",
        ),
        "report_path": "mutation-reports/events.json",
        "timeout_seconds": 1800,
        "timeout_multiplier": 15.0,
        "timeout_constant": 1.0,
        "max_children": 4,
    },
    "task-service": {
        "source_paths": ("src/sigmacoder",),
        "only_mutate": ("src/sigmacoder/application/task_service.py",),
        "test_selection": (
            "tests/unit/test_task_service_branches.py",
            "tests/integration",
            "tests/e2e",
        ),
        "property_test_selection": (),
        "report_path": "mutation-reports/task-service.json",
        "timeout_seconds": 1800,
        "timeout_multiplier": 15.0,
        "timeout_constant": 1.0,
        "max_children": 4,
    },
}


class MutationGateError(RuntimeError):
    """Mutation profile 配置或执行不满足规范。"""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class _SetupConfigLease:
    path: Path
    device: int
    inode: int
    owner_marker: bytes
    payload: bytes


@dataclass(frozen=True)
class _ReportTempLease:
    path: Path
    device: int
    inode: int
    payload: bytes


@dataclass(frozen=True)
class MutationProfile:
    name: str
    source_paths: tuple[str, ...]
    only_mutate: tuple[str, ...]
    test_selection: tuple[str, ...]
    property_test_selection: tuple[str, ...]
    timeout_seconds: int
    timeout_multiplier: float
    timeout_constant: float
    max_children: int
    repeat: int
    cache_dir: str
    report_path: str


@dataclass(frozen=True)
class MutationPolicy:
    """一次 profile 运行所绑定的精确等价策略。"""

    manifest: Mapping[str, object] | None
    manifest_sha256: str
    expected_mutant_count: int | None
    expected_mutant_names_sha256: str | None
    approved_names: tuple[str, ...]


def _validate_profile_contract(profile: MutationProfile) -> None:
    expected = PROFILE_CONTRACTS.get(profile.name)
    if expected is None:
        raise MutationGateError(f"mutation profile 名称不受支持：{profile.name}")
    for field in (
        "source_paths",
        "only_mutate",
        "test_selection",
        "property_test_selection",
        "report_path",
        "timeout_seconds",
        "timeout_multiplier",
        "timeout_constant",
        "max_children",
    ):
        if getattr(profile, field) != expected[field]:
            raise MutationGateError(f"{profile.name} profile 的 {field} 不符合固定契约。")
    if profile.repeat != 2:
        raise MutationGateError(f"{profile.name} profile 的 repeat 必须精确为 2。")
    if profile.cache_dir != MUTATION_CACHE_DIR:
        raise MutationGateError(
            f"{profile.name} profile 的 cache_dir 必须精确为 {MUTATION_CACHE_DIR}。"
        )


def _string_tuple(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise MutationGateError(
            f"{label} 必须是{'可为空的' if allow_empty else '非空'}字符串数组。"
        )
    if not all(isinstance(item, str) and item for item in value):
        raise MutationGateError(f"{label} 包含无效路径。")
    return tuple(value)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MutationGateError(f"{label} 必须是正整数。")
    return value


def _positive_float(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise MutationGateError(f"{label} 必须是正数。")
    return float(value)


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MutationGateError(f"{label} 必须是相对路径。")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise MutationGateError(f"{label} 不得逃逸仓库：{value}")
    return value


def load_profile(config_path: Path, name: str) -> MutationProfile:
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationGateError(f"无法读取 mutation profile：{exc}") from exc
    schema_version = payload.get("schema_version") if isinstance(payload, dict) else None
    if isinstance(schema_version, bool) or schema_version != 1:
        raise MutationGateError("mutation profile schema_version 必须为 1。")
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or not isinstance(profiles.get(name), dict):
        raise MutationGateError(f"不存在 mutation profile：{name}")
    raw: Mapping[str, object] = profiles[name]
    profile = MutationProfile(
        name=name,
        source_paths=_string_tuple(raw.get("source_paths"), "source_paths"),
        only_mutate=_string_tuple(raw.get("only_mutate"), "only_mutate"),
        test_selection=_string_tuple(raw.get("test_selection"), "test_selection"),
        property_test_selection=_string_tuple(
            raw.get("property_test_selection"), "property_test_selection", allow_empty=True
        ),
        timeout_seconds=_positive_int(raw.get("timeout_seconds"), "timeout_seconds"),
        timeout_multiplier=_positive_float(raw.get("timeout_multiplier"), "timeout_multiplier"),
        timeout_constant=_positive_float(raw.get("timeout_constant"), "timeout_constant"),
        max_children=_positive_int(raw.get("max_children"), "max_children"),
        repeat=_positive_int(raw.get("repeat"), "repeat"),
        cache_dir=_safe_relative(raw.get("cache_dir"), "cache_dir"),
        report_path=_safe_relative(raw.get("report_path"), "report_path"),
    )
    _validate_profile_contract(profile)
    return profile


def _managed_cache_path(repo: Path, profile: MutationProfile) -> Path:
    resolved_repo = repo.resolve()
    expected = resolved_repo / MUTATION_CACHE_DIR
    candidate = resolved_repo / profile.cache_dir
    if candidate.is_symlink() or candidate.resolve(strict=False) != expected:
        raise MutationGateError("mutation cache 不是仓库内固定专用目录。")
    if candidate.exists() and not candidate.is_dir():
        raise MutationGateError("mutation cache 必须是目录且不得是链接。")
    return candidate


def _directory_identity(path: Path, label: str) -> tuple[int, int]:
    try:
        current = path.lstat()
    except OSError as exc:
        raise MutationGateError(f"无法核验{label}：{exc}") from exc
    if _is_link_or_junction(path) or not stat.S_ISDIR(current.st_mode):
        raise MutationGateError(f"{label}必须是普通目录且不得是链接或 junction。")
    return current.st_dev, current.st_ino


def _quarantine_and_remove_cache(repo: Path, cache: Path) -> None:
    if not cache.exists():
        return
    original_identity = _directory_identity(cache, "mutation cache")
    quarantine_root = _managed_report_root(repo)
    quarantine = quarantine_root / f".{MUTATION_CACHE_DIR}.quarantine-{uuid4().hex}"
    if os.path.lexists(quarantine):  # pragma: no cover - UUID 碰撞仍 fail closed
        raise MutationGateError("mutation cache 隔离路径已存在，拒绝覆盖未知路径。")
    try:
        quarantine_root.mkdir(parents=True, exist_ok=True)
        os.rename(cache, quarantine)
    except OSError as exc:
        raise MutationGateError(f"无法把 mutation cache 原子移入隔离区：{exc}") from exc
    quarantined_identity = _directory_identity(
        quarantine,
        f"已隔离 mutation cache {quarantine}（核验失败时保留现场）",
    )
    if quarantined_identity != original_identity:
        raise MutationGateError(
            f"mutation cache 隔离后身份不匹配；已保留 {quarantine}，拒绝删除未知目录。"
        )
    try:
        shutil.rmtree(quarantine)
    except OSError as exc:
        raise MutationGateError(f"无法删除已核验的 mutation cache 隔离目录：{exc}") from exc


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _managed_report_root(repo: Path) -> Path:
    resolved_repo = repo.resolve()
    report_root = resolved_repo / MUTATION_REPORT_ROOT
    if _is_link_or_junction(report_root) or report_root.resolve(strict=False) != report_root:
        raise MutationGateError("mutation report 根目录不得是链接、junction 或逃逸仓库。")
    if report_root.exists() and not report_root.is_dir():
        raise MutationGateError("mutation report 根目录必须是普通目录。")
    return report_root


def _managed_report_path(repo: Path, profile: MutationProfile) -> Path:
    resolved_repo = repo.resolve()
    expected = resolved_repo / MUTATION_REPORT_ROOT / f"{profile.name}.json"
    candidate = resolved_repo / profile.report_path
    _managed_report_root(resolved_repo)
    if _is_link_or_junction(candidate) or candidate.resolve(strict=False) != expected:
        raise MutationGateError("mutation report 路径不符合固定专用位置。")
    if candidate.exists() and not candidate.is_file():
        raise MutationGateError("mutation report 目标必须是普通文件。")
    return candidate


def _managed_setup_path(repo: Path) -> Path:
    resolved_repo = repo.resolve()
    path = resolved_repo / "setup.cfg"
    if _is_link_or_junction(path) or path.resolve(strict=False) != path:
        raise MutationGateError("setup.cfg 不得是链接、junction 或逃逸仓库。")
    if path.exists():
        raise MutationGateError("仓库已存在 setup.cfg，拒绝临时覆盖 mutmut 配置。")
    return path


def _managed_lock_path(repo: Path) -> Path:
    report_root = _managed_report_root(repo)
    path = report_root / MUTATION_LOCK_FILE
    if _is_link_or_junction(path) or path.resolve(strict=False) != path:
        raise MutationGateError("mutation 互斥锁不得是链接、junction 或逃逸仓库。")
    if path.exists() and not path.is_file():
        raise MutationGateError("mutation 互斥锁路径必须是普通文件或不存在。")
    return path


@contextmanager
def _exclusive_mutation_lock(repo: Path, profile: MutationProfile) -> Iterator[None]:
    path = _managed_lock_path(repo)
    token = uuid4().hex
    payload = json.dumps(
        {"pid": os.getpid(), "profile": profile.name, "token": token},
        ensure_ascii=False,
        sort_keys=True,
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("xb")
    except FileExistsError as exc:
        raise MutationGateError(
            f"mutation 仓库锁已被占用或为崩溃残留：{path}；拒绝并发或自动清理。"
        ) from exc
    except OSError as exc:
        raise MutationGateError(f"无法创建 mutation 仓库锁：{exc}") from exc
    try:
        handle.write(payload.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        yield
    finally:
        if not handle.closed:
            handle.close()
        try:
            if _is_link_or_junction(path) or path.read_text(encoding="utf-8") != payload:
                raise MutationGateError("mutation 仓库锁所有权已变化，拒绝删除未知锁文件。")
            path.unlink()
        except MutationGateError:
            raise
        except OSError as exc:
            raise MutationGateError(f"无法释放 mutation 仓库锁：{exc}") from exc


def validate_inputs(repo: Path, profile: MutationProfile) -> None:
    missing = [
        path for path in (*profile.source_paths, *profile.only_mutate) if not (repo / path).exists()
    ]
    missing += [path for path in profile.test_selection if not (repo / path).exists()]
    missing += [path for path in profile.property_test_selection if not (repo / path).exists()]
    missing += [path for path in ("pyproject.toml", "uv.lock") if not (repo / path).is_file()]
    if missing:
        raise MutationGateError(f"mutation profile 输入缺失：{', '.join(sorted(set(missing)))}")
    _managed_setup_path(repo)
    _managed_cache_path(repo, profile)
    _managed_report_path(repo, profile)


def _open_git(repo: Path) -> TrustedGit:
    try:
        return TrustedGit.open(repo)
    except TrustedToolError as exc:
        raise MutationGateError(str(exc)) from exc


def _git_status(repo: Path) -> bytes:
    try:
        return _open_git(repo).read(
            ("status", "--porcelain=v2", "-z", "--untracked-files=all"),
            label="mutation 前后 Git 状态",
        )
    except TrustedToolError as exc:
        raise MutationGateError(str(exc)) from exc


def _git_head(repo: Path) -> bytes:
    try:
        return _open_git(repo).head_commit().encode("ascii")
    except TrustedToolError as exc:
        raise MutationGateError(str(exc)) from exc


def _protected_paths(profile: MutationProfile) -> tuple[str, ...]:
    return (
        *profile.source_paths,
        *profile.only_mutate,
        *profile.test_selection,
        *profile.property_test_selection,
        "pyproject.toml",
        "uv.lock",
        SPEC_RELATIVE_PATH,
        "tools/mutation_profiles.json",
        MANIFEST_RELATIVE_PATH,
        MUTATION_MANIFEST_MODULE,
        "tools/run_mutation_profile.py",
        MUTATION_EQUIVALENCE_CHECKER,
        MUTATION_REPORT_CHECKER,
    )


def _git_protected_files(repo: Path, protected_paths: Sequence[str]) -> tuple[Path, ...]:
    try:
        stdout = _open_git(repo).read(
            (
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                *protected_paths,
            ),
            label="mutation 受保护文件枚举",
        )
    except TrustedToolError as exc:
        raise MutationGateError(str(exc)) from exc
    return tuple(Path(os.fsdecode(raw)) for raw in stdout.split(b"\0") if raw)


def _repository_fingerprint(repo: Path, profile: MutationProfile) -> str:
    digest = hashlib.sha256(b"sigmacoder-mutation-source-v2\0")
    resolved_repo = repo.resolve()
    protected_paths = tuple(sorted(set(_protected_paths(profile))))
    try:
        for relative in _git_protected_files(resolved_repo, protected_paths):
            entry = resolved_repo / relative
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
        raise MutationGateError(f"无法计算 mutation 源码指纹：{exc}") from exc
    digest.update(b"PROFILE\0")
    digest.update(json.dumps(asdict(profile), ensure_ascii=False, sort_keys=True).encode("utf-8"))
    digest.update(b"HEAD\0")
    digest.update(_git_head(resolved_repo))
    digest.update(b"GIT\0")
    digest.update(_git_status(resolved_repo))
    return digest.hexdigest()


def _mutant_names_digest(names: Sequence[str]) -> str:
    material = "\n".join(names).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _profile_digest(profile: MutationProfile) -> str:
    material = json.dumps(
        asdict(profile),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _profile_payload(profile: MutationProfile) -> dict[str, object]:
    payload = json.loads(json.dumps(asdict(profile), ensure_ascii=False, sort_keys=True))
    if not isinstance(payload, dict):
        raise MutationGateError("mutation profile 无法规范化为 JSON 对象。")
    return payload


def _file_digest(path: Path, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise MutationGateError(f"无法读取 {label} 摘要：{exc}") from exc


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _result_items(mutants: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"name": name, "status": mutants[name]}
        for name in sorted(mutants, key=lambda value: value.encode("utf-8"))
    ]


def _result_statuses_digest(results: Sequence[Mapping[str, str]]) -> str:
    return _canonical_sha256(list(results))


def _load_policy(repo: Path, profile: MutationProfile) -> MutationPolicy:
    if profile.name != "events":
        return MutationPolicy(
            manifest=None,
            manifest_sha256="0" * 64,
            expected_mutant_count=None,
            expected_mutant_names_sha256=None,
            approved_names=(),
        )
    try:
        manifest = load_equivalent_manifest(repo, repo / MANIFEST_RELATIVE_PATH)
    except EquivalentManifestError as exc:
        raise MutationGateError(f"等价 mutant 清单无效：{exc}") from exc
    raw_profile = manifest.get("profile")
    raw_entries = manifest.get("equivalents")
    if not isinstance(raw_profile, Mapping) or not isinstance(raw_entries, list):
        raise MutationGateError("等价 mutant 清单缺少 profile 或 equivalents。")
    expected_count = raw_profile.get("expected_mutant_count")
    expected_digest = raw_profile.get("expected_mutant_names_sha256")
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or not isinstance(expected_digest, str)
    ):
        raise MutationGateError("等价 mutant 清单的全集绑定类型无效。")
    approved_names: list[str] = []
    for entry in raw_entries:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("name"), str):
            raise MutationGateError("等价 mutant 清单包含无效条目。")
        approved_names.append(cast(str, entry["name"]))
    return MutationPolicy(
        manifest=manifest,
        manifest_sha256=_canonical_sha256(manifest),
        expected_mutant_count=expected_count,
        expected_mutant_names_sha256=expected_digest,
        approved_names=tuple(approved_names),
    )


def _verify_policy_baseline(policy: MutationPolicy, names: Sequence[str]) -> None:
    if policy.expected_mutant_count is None:
        return
    if len(names) != policy.expected_mutant_count:
        raise MutationGateError("mutation 实际总数与等价清单批准基线不一致。")
    if _mutant_names_digest(names) != policy.expected_mutant_names_sha256:
        raise MutationGateError("mutation 实际名称全集摘要与批准基线不一致。")


def _report_bindings(
    repo: Path,
    profile: MutationProfile,
    policy: MutationPolicy,
    source_fingerprint: str,
) -> dict[str, str]:
    if len(profile.only_mutate) != 1:
        raise MutationGateError("mutation profile 必须精确绑定一个 only_mutate 源文件。")
    source_path = repo / profile.only_mutate[0]
    bindings = {
        "git_head": _git_head(repo).decode("ascii"),
        "spec_version": "r5",
        "spec_sha256": _file_digest(repo / SPEC_RELATIVE_PATH, "T01 SPEC"),
        "mutmut_version": MUTMUT_VERSION,
        "uv_lock_sha256": _file_digest(repo / "uv.lock", "uv.lock"),
        "profile_sha256": _file_digest(
            repo / "tools/mutation_profiles.json",
            "mutation profile",
        ),
        "source_fingerprint": source_fingerprint,
        "source_sha256": _file_digest(source_path, "mutation 源文件"),
        "manifest_sha256": policy.manifest_sha256,
        "runner_sha256": _file_digest(
            repo / "tools/run_mutation_profile.py",
            "mutation runner",
        ),
        "checker_sha256": _file_digest(
            repo / MUTATION_EQUIVALENCE_CHECKER,
            "等价 checker",
        ),
        "report_checker_sha256": _file_digest(
            repo / MUTATION_REPORT_CHECKER,
            "报告 checker",
        ),
    }
    if profile.name == "events" and bindings["source_sha256"] != EXPECTED_SOURCE_SHA256:
        raise MutationGateError("events 源文件摘要与 r5 批准不一致。")
    return bindings


def parse_mutmut_results(output: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ": " not in line:
            raise MutationGateError(f"mutmut 返回无法解析的非空结果行：{line}")
        name, status = line.rsplit(": ", 1)
        if status not in KNOWN_STATUSES:
            raise MutationGateError(f"mutmut 返回未知状态：{status}")
        if not name or name in results:
            raise MutationGateError("mutmut 结果包含空名称或重复 mutant。")
        results[name] = status
    if not results:
        raise MutationGateError("mutmut 未返回任何 mutant，拒绝空运行。")
    return results


def _validate_mutation_result_universe(
    results: Mapping[str, str],
    expected: Sequence[str],
    approved: Sequence[str],
) -> None:
    """验证全集与状态域；不对 runner 原始结果做任何重写。"""

    if len(expected) != len(set(expected)) or len(approved) != len(set(approved)):
        raise MutationGateError("mutation 预期全集或批准清单包含重复名称。")
    if any(
        not isinstance(status, str) or status not in KNOWN_STATUSES for status in results.values()
    ):
        raise MutationGateError("mutation 结果包含非字符串或未知状态。")
    if set(approved) - set(results):
        raise MutationGateError("获批等价 mutant 在实际全集中缺失。")
    if set(results) != set(expected):
        raise MutationGateError("mutation 实际名称全集与批准基线不一致。")
    if any(status not in {"killed", "survived"} for status in results.values()):
        raise MutationGateError("mutation 存在既非 killed 也非 survived 的非法状态。")


def evaluate_mutation_results(
    profile_name: str,
    results: Mapping[str, str],
    *,
    expected_names: Sequence[str],
    approved_names: Sequence[str],
) -> dict[str, object]:
    """在不改写原始状态的前提下执行精确 mutant 集合策略。"""

    expected = tuple(expected_names)
    approved = tuple(approved_names)
    _validate_mutation_result_universe(results, expected, approved)
    listed_but_killed = sorted(name for name in approved if results[name] == "killed")
    if listed_but_killed:
        raise MutationGateError("获批等价 mutant 已被杀死，清单属于陈旧批准。")
    survived = tuple(sorted(name for name, status in results.items() if status == "survived"))
    unexpected = tuple(sorted(set(survived) - set(approved)))
    if unexpected:
        raise MutationGateError("存在清单外 survivor。")
    if survived != tuple(sorted(approved)):
        raise MutationGateError("实际 survivor 集合与精确批准清单不一致。")
    if profile_name != "events" and approved:
        raise MutationGateError(f"{profile_name} profile 不允许等价 mutant 清单。")
    killed = sum(status == "killed" for status in results.values())
    approved_list = list(survived)
    return {
        "raw": {"total": len(results), "killed": killed, "survived": len(survived)},
        "approved_equivalents": {
            "count": len(approved_list),
            "names": approved_list,
            "names_sha256": _mutant_names_digest(approved_list),
        },
        "unexpected_non_killed": {"count": 0, "names": [], "statuses": {}},
        "gate_passed": True,
    }


def _remove_owned_setup_cfg(lease: _SetupConfigLease) -> str | None:
    path = lease.path
    try:
        current = path.lstat()
    except OSError as exc:
        return f"无法核验临时 mutmut 配置归属：{exc}"
    if (
        _is_link_or_junction(path)
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (lease.device, lease.inode)
    ):
        return "临时 mutmut 配置的文件身份已变化，拒绝删除未知路径。"
    try:
        contents = path.read_bytes()
    except OSError as exc:
        return f"无法清理本次创建的临时 mutmut 配置：{exc}"
    changed = contents != lease.payload
    if changed and not contents.startswith(lease.owner_marker):
        return "临时 mutmut 配置的归属标记已变化，拒绝删除未知文件。"
    try:
        verified = path.lstat()
        if (
            _is_link_or_junction(path)
            or not stat.S_ISREG(verified.st_mode)
            or (verified.st_dev, verified.st_ino) != (lease.device, lease.inode)
        ):
            return "临时 mutmut 配置在清理核验期间被替换，拒绝删除未知路径。"
        path.unlink()
    except OSError as exc:
        return f"无法清理本次创建的临时 mutmut 配置：{exc}"
    if changed:
        return "临时 mutmut 配置内容在运行期间发生变化；已仅删除本次创建的文件。"
    return None


def _write_setup_cfg(
    repo: Path,
    profile: MutationProfile,
    tests: Sequence[str],
) -> _SetupConfigLease:
    parser = configparser.ConfigParser()
    parser["mutmut"] = {
        "source_paths": "\n".join(profile.source_paths),
        "only_mutate": "\n".join(profile.only_mutate),
        "pytest_add_cli_args": "\n".join(
            (
                "-q",
                f"--hypothesis-profile={HYPOTHESIS_PROFILE}",
                f"--hypothesis-seed={HYPOTHESIS_SEED}",
            )
        ),
        "pytest_add_cli_args_test_selection": "\n".join(tests),
        "timeout_multiplier": str(profile.timeout_multiplier),
        "timeout_constant": str(profile.timeout_constant),
        "use_git_change_detection": "false",
    }
    owner_token = uuid4().hex
    rendered = io.StringIO(newline="\n")
    parser.write(rendered)
    owner_marker = f"# sigmacoder_owner_token = {owner_token}\n".encode()
    payload = owner_marker + rendered.getvalue().encode("utf-8")
    path = _managed_setup_path(repo)
    lease: _SetupConfigLease | None = None
    try:
        with path.open("xb") as handle:
            opened = os.fstat(handle.fileno())
            lease = _SetupConfigLease(
                path=path,
                device=opened.st_dev,
                inode=opened.st_ino,
                owner_marker=owner_marker,
                payload=payload,
            )
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise MutationGateError("setup.cfg 在独占创建前出现，拒绝覆盖或跟随链接。") from exc
    except OSError as exc:
        cleanup_error = _remove_owned_setup_cfg(lease) if lease is not None else None
        suffix = f"；{cleanup_error}" if cleanup_error else ""
        raise MutationGateError(f"无法写入临时 mutmut 配置：{exc}{suffix}") from exc
    if lease is None:  # pragma: no cover - open 成功时必定构造租约
        raise MutationGateError("临时 mutmut 配置创建后缺少所有权租约。")
    return lease


def _run_command(
    command: Sequence[str],
    *,
    repo: Path,
    timeout: int,
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop(REPOSITORY_LEASE_TOKEN_ENV, None)
    try:
        return runner(
            list(command),
            cwd=repo,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MutationGateError(f"mutation 命令无法执行：{exc}") from exc


def _cleanup_and_verify_run(
    repo: Path,
    profile: MutationProfile,
    setup_lease: _SetupConfigLease | None,
    source_before: str,
) -> None:
    failures: list[str] = []
    if setup_lease is not None:
        setup_failure = _remove_owned_setup_cfg(setup_lease)
        if setup_failure:
            failures.append(setup_failure)
    try:
        source_after = _repository_fingerprint(repo, profile)
    except MutationGateError as exc:
        failures.append(str(exc))
    else:
        if source_after != source_before:
            failures.append("mutation 执行后源码或 Git 状态未恢复到运行前指纹。")
    if failures:
        raise MutationGateError("；".join(failures))


def _run_once(
    repo: Path,
    profile: MutationProfile,
    tests: Sequence[str],
    *,
    runner: CommandRunner,
) -> tuple[dict[str, str], str]:
    cache = _managed_cache_path(repo, profile)
    _quarantine_and_remove_cache(repo, cache)
    source_before = _repository_fingerprint(repo, profile)
    setup_lease: _SetupConfigLease | None = None
    try:
        try:
            uv_executable = resolve_trusted_uv(repo)
        except TrustedToolError as exc:
            raise MutationGateError(str(exc)) from exc
        setup_lease = _write_setup_cfg(repo, profile, tests)
        run_result = _run_command(
            [
                str(uv_executable),
                "run",
                "--frozen",
                "mutmut",
                "run",
                "--max-children",
                str(profile.max_children),
            ],
            repo=repo,
            timeout=profile.timeout_seconds,
            runner=runner,
        )
        if run_result.returncode != 0:
            raise MutationGateError(
                f"mutmut run 退出码为 {run_result.returncode}：{run_result.stderr.strip()}"
            )
        result = _run_command(
            [str(uv_executable), "run", "--frozen", "mutmut", "results", "--all", "true"],
            repo=repo,
            timeout=120,
            runner=runner,
        )
        if result.returncode != 0:
            raise MutationGateError(
                f"mutmut results 退出码为 {result.returncode}：{result.stderr.strip()}"
            )
        mutants = parse_mutmut_results(result.stdout)
    finally:
        _cleanup_and_verify_run(repo, profile, setup_lease, source_before)
    return mutants, source_before


def _record_mutation_run(
    repo: Path,
    profile: MutationProfile,
    tests: Sequence[str],
    *,
    kind: str,
    run_number: int,
    runner: CommandRunner,
    baseline_names: tuple[str, ...] | None,
    baseline_source_fingerprint: str | None,
    baseline_results: tuple[tuple[str, str], ...] | None,
    policy: MutationPolicy | None,
) -> tuple[
    tuple[str, ...],
    str,
    tuple[tuple[str, str], ...],
    dict[str, object],
    dict[str, object],
    MutationPolicy,
]:
    mutants, source_fingerprint = _run_once(repo, profile, tests, runner=runner)
    if policy is None:
        policy = _load_policy(repo, profile)
    names = tuple(sorted(mutants, key=lambda value: value.encode("utf-8")))
    normalized_results = tuple((name, mutants[name]) for name in names)
    _verify_policy_baseline(policy, names)
    if baseline_names is not None and names != baseline_names:
        raise MutationGateError("mutation 各次运行枚举出的 mutant 集合不一致。")
    if (
        baseline_source_fingerprint is not None
        and source_fingerprint != baseline_source_fingerprint
    ):
        raise MutationGateError("mutation 各次运行前的源码或 Git 状态指纹不一致。")
    if baseline_results is not None and normalized_results != baseline_results:
        raise MutationGateError("mutation 各次运行的完整 mutant 状态集合不一致。")
    evaluation = evaluate_mutation_results(
        profile.name,
        mutants,
        expected_names=names,
        approved_names=policy.approved_names,
    )
    results = _result_items(mutants)
    evidence = {
        "kind": kind,
        "run": run_number,
        "source_fingerprint": source_fingerprint,
        "result_count": len(names),
        "result_names_sha256": _mutant_names_digest(names),
        "result_statuses_sha256": _result_statuses_digest(results),
        "results": results,
    }
    return names, source_fingerprint, normalized_results, evidence, evaluation, policy


def _report_temp_problem(lease: _ReportTempLease) -> str | None:
    try:
        current = lease.path.lstat()
    except OSError as exc:
        return f"无法核验 mutation report 临时文件归属：{exc}"
    if (
        _is_link_or_junction(lease.path)
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (lease.device, lease.inode)
    ):
        return "mutation report 临时文件身份已变化，拒绝操作未知路径。"
    try:
        if lease.path.read_bytes() != lease.payload:
            return "mutation report 临时文件内容已变化，拒绝操作未知文件。"
        verified = lease.path.lstat()
    except OSError as exc:
        return f"无法复核 mutation report 临时文件：{exc}"
    if (
        _is_link_or_junction(lease.path)
        or not stat.S_ISREG(verified.st_mode)
        or (verified.st_dev, verified.st_ino) != (lease.device, lease.inode)
    ):
        return "mutation report 临时文件在复核期间被替换，拒绝操作未知路径。"
    return None


def _remove_owned_report_temp(lease: _ReportTempLease) -> str | None:
    problem = _report_temp_problem(lease)
    if problem:
        return problem
    try:
        lease.path.unlink()
    except OSError as exc:
        return f"无法清理本次创建的 mutation report 临时文件：{exc}"
    return None


def _write_report_atomic(report_path: Path, report: Mapping[str, object]) -> None:
    temporary = report_path.with_name(f".{report_path.name}.{uuid4().hex}.tmp")
    payload = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    lease: _ReportTempLease | None = None
    published = False
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("xb") as handle:
            opened = os.fstat(handle.fileno())
            lease = _ReportTempLease(
                path=temporary,
                device=opened.st_dev,
                inode=opened.st_ino,
                payload=payload,
            )
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        problem = _report_temp_problem(lease)
        if problem:
            raise OSError(problem)
        os.replace(temporary, report_path)
        published = True
        if report_path.read_bytes() != payload:
            raise OSError("原子替换后的报告字节与待发布内容不一致")
    except OSError as exc:
        cleanup_error = (
            _remove_owned_report_temp(lease) if lease is not None and not published else None
        )
        suffix = f"；{cleanup_error}" if cleanup_error else ""
        raise MutationGateError(f"无法原子写入 mutation report：{exc}{suffix}") from exc


def _run_profile_locked(
    repo: Path,
    profile: MutationProfile,
    *,
    runner: CommandRunner,
) -> dict[str, object]:
    validate_inputs(repo, profile)
    policy: MutationPolicy | None = None
    runs: list[dict[str, object]] = []
    baseline_names: tuple[str, ...] | None = None
    baseline_source_fingerprint: str | None = None
    baseline_results: tuple[tuple[str, str], ...] | None = None
    evaluation: dict[str, object] | None = None

    report_path = _managed_report_path(repo, profile)
    try:
        report_path.unlink(missing_ok=True)
    except OSError as exc:
        raise MutationGateError(f"无法删除陈旧 mutation report：{exc}") from exc
    for run_number in range(1, profile.repeat + 1):
        (
            baseline_names,
            baseline_source_fingerprint,
            baseline_results,
            evidence,
            evaluation,
            policy,
        ) = _record_mutation_run(
            repo,
            profile,
            profile.test_selection,
            kind="full",
            run_number=run_number,
            runner=runner,
            baseline_names=baseline_names,
            baseline_source_fingerprint=baseline_source_fingerprint,
            baseline_results=baseline_results,
            policy=policy,
        )
        runs.append(evidence)
    if profile.property_test_selection:
        (
            baseline_names,
            baseline_source_fingerprint,
            baseline_results,
            evidence,
            evaluation,
            policy,
        ) = _record_mutation_run(
            repo,
            profile,
            profile.property_test_selection,
            kind="property-only",
            run_number=1,
            runner=runner,
            baseline_names=baseline_names,
            baseline_source_fingerprint=baseline_source_fingerprint,
            baseline_results=baseline_results,
            policy=policy,
        )
        runs.append(evidence)
    if (
        baseline_names is None
        or evaluation is None
        or baseline_source_fingerprint is None
        or policy is None
    ):
        raise MutationGateError("mutation profile 未执行任何有效运行。")
    raw_evaluation = cast(Mapping[str, object], evaluation["raw"])
    approved_evaluation = cast(Mapping[str, object], evaluation["approved_equivalents"])
    unexpected_evaluation = cast(
        Mapping[str, object],
        evaluation["unexpected_non_killed"],
    )
    report = {
        "schema_version": 2,
        "profile": _profile_payload(profile),
        "bindings": _report_bindings(
            repo,
            profile,
            policy,
            baseline_source_fingerprint,
        ),
        "runs": runs,
        "raw": {
            **raw_evaluation,
            "mutant_names_sha256": _mutant_names_digest(baseline_names),
        },
        "approved_equivalents": {
            "count": approved_evaluation["count"],
            "names": approved_evaluation["names"],
            "digest": approved_evaluation["names_sha256"],
        },
        "unexpected_non_killed": dict(unexpected_evaluation),
        "gate_passed": evaluation["gate_passed"],
    }
    report_path = _managed_report_path(repo, profile)
    before_publish_fingerprint = _repository_fingerprint(repo, profile)
    if before_publish_fingerprint != baseline_source_fingerprint:
        raise MutationGateError("写 mutation report 前受保护仓库状态发生漂移。")
    _write_report_atomic(report_path, report)
    after_publish_fingerprint = _repository_fingerprint(repo, profile)
    if after_publish_fingerprint != before_publish_fingerprint:
        raise MutationGateError("写 mutation report 后受保护仓库状态发生漂移。")
    return report


def run_profile(
    repo: Path,
    profile: MutationProfile,
    *,
    runner: CommandRunner = subprocess.run,
    require_posix: bool = True,
) -> dict[str, object]:
    if require_posix and os.name != "posix":
        raise MutationGateError("mutmut 3.x 不支持原生 Windows；本门禁必须在 Ubuntu 执行。")
    resolved_repo = repo.resolve()
    try:
        with parent_or_standalone_repository_lease(
            resolved_repo,
            f"mutation:{profile.name}",
        ):
            with _exclusive_mutation_lock(resolved_repo, profile):
                return _run_profile_locked(resolved_repo, profile, runner=runner)
    except RepositoryLeaseError as exc:
        raise MutationGateError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行 T01 的持久 mutmut profile。")
    parser.add_argument("profile", choices=("events", "task-service"))
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
        profile = load_profile(args.config.resolve(), args.profile)
        report = run_profile(args.repo.resolve(), profile)
    except MutationGateError as exc:
        print(f"Mutation 门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **report}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
