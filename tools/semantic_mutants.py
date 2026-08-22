"""执行 SPEC §12.4 的八类定向语义变异并保存可审计证据。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as element_tree
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Protocol, cast
from uuid import uuid4

if __package__:
    from tools.repo_lease import (
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        parent_or_standalone_repository_lease,
    )
else:  # pragma: no cover - 由真实脚本入口覆盖
    from repo_lease import (  # type: ignore[import-not-found,no-redef]
        REPOSITORY_LEASE_TOKEN_ENV,
        RepositoryLeaseError,
        parent_or_standalone_repository_lease,
    )

MANIFEST_NAME: Final = "semantic_mutants.json"
REPORT_PATH: Final = "mutation-reports/semantic.json"
SCHEMA_VERSION: Final = 1
HYPOTHESIS_PROFILE: Final = "default"
HYPOTHESIS_SEED: Final = 20260823
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SemanticMutationError(RuntimeError):
    """语义变异配置、执行或证据不满足 fail-closed 契约。"""


class CommandRunner(Protocol):
    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class RequiredMutant:
    category: str
    source: str
    selectors: tuple[str, ...]


@dataclass(frozen=True)
class MutantSpec:
    mutant_id: str
    category: str
    source: str
    expected_source_sha256: str
    expected_mutant_sha256: str
    selectors: tuple[str, ...]
    old: str
    new: str


@dataclass(frozen=True)
class Manifest:
    sha256: str
    timeout_seconds: int
    mutants: tuple[MutantSpec, ...]


@dataclass(frozen=True)
class JUnitEvidence:
    sha256: str
    tests: int
    failures: int
    errors: int
    skipped: int


@dataclass(frozen=True)
class PhaseEvidence:
    returncode: int
    stdout_sha256: str
    stderr_sha256: str
    junit: JUnitEvidence


@dataclass(frozen=True)
class SourceBinding:
    git_head: str
    manifest_sha256: str
    runner_sha256: str
    source_sha256: str
    input_sha256: str
    pyproject_sha256: str
    uv_lock_sha256: str
    sources: dict[str, str]
    selectors: dict[str, str]


@dataclass(frozen=True)
class TemporaryReportLease:
    path: Path
    device: int
    inode: int
    payload: bytes


_EVENT_PROPERTY_SELECTOR: Final = (
    "tests/property/test_event_generated_properties.py::"
    "test_generated_damage_fails_closed_and_physical_order_is_irrelevant"
)
REQUIRED_MUTANTS: Final[dict[str, RequiredMutant]] = {
    "SEM001_SEQUENCE_CONTINUITY": RequiredMutant(
        "sequence_continuity",
        "src/sigmacoder/domain/events.py",
        (_EVENT_PROPERTY_SELECTOR,),
    ),
    "SEM002_PREVIOUS_HASH": RequiredMutant(
        "previous_hash",
        "src/sigmacoder/domain/events.py",
        (_EVENT_PROPERTY_SELECTOR,),
    ),
    "SEM003_HASH_EQUALITY": RequiredMutant(
        "event_hash_equality",
        "src/sigmacoder/domain/events.py",
        (
            "tests/property/test_event_generated_properties.py::"
            "test_same_authoritative_event_bytes_have_exact_projection_and_round_trip",
        ),
    ),
    "SEM004_BAD_EVENT_CONTINUES": RequiredMutant(
        "bad_event_continuation",
        "src/sigmacoder/domain/events.py",
        (_EVENT_PROPERTY_SELECTOR,),
    ),
    "SEM005_FROZEN_BASELINE": RequiredMutant(
        "frozen_baseline",
        "src/sigmacoder/adapters/git_workspace.py",
        (
            "tests/integration/test_task_lifecycle.py::"
            "test_explicit_commit_baseline_is_used_even_when_source_branch_is_newer",
        ),
    ),
    "SEM006_SOURCE_FINGERPRINT": RequiredMutant(
        "source_fingerprint",
        "src/sigmacoder/adapters/git_workspace.py",
        ("tests/unit/test_git_workspace_edges.py::test_filter_source_change_and_data_root_guards",),
    ),
    "SEM007_INVALID_CHECKPOINT": RequiredMutant(
        "invalid_checkpoint",
        "src/sigmacoder/domain/events.py",
        (
            "tests/unit/test_projection_checkpoint.py::"
            "test_corrupt_checkpoint_hash_falls_back_to_full_replay",
        ),
    ),
    "SEM008_RUNTIME_RESTORED": RequiredMutant(
        "runtime_restoration",
        "src/sigmacoder/domain/events.py",
        (
            "tests/property/test_event_chain_properties.py::"
            "test_all_durable_terminal_paths_match_full_spec_oracle",
        ),
    ),
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_plain_file(path: Path) -> bool:
    junction = getattr(path, "is_junction", lambda: False)
    return path.is_file() and not path.is_symlink() and not junction()


def _relative_path(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticMutationError(f"{label} 必须是非空仓库相对路径。")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SemanticMutationError(f"{label} 必须是未折叠的仓库相对路径。")
    return value


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SemanticMutationError(f"{label} 必须是字符串键对象。")
    return cast(dict[str, object], value)


def _text(value: object, *, label: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise SemanticMutationError(f"{label} 必须是字符串。")
    return value


def _digest(value: object, *, label: str) -> str:
    text = _text(value, label=label)
    if _SHA256.fullmatch(text) is None:
        raise SemanticMutationError(f"{label} 必须是 64 位小写 SHA-256。")
    return text


def _selectors(value: object, *, mutant_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise SemanticMutationError(f"{mutant_id} selectors 必须是非空数组。")
    selectors = tuple(_text(item, label=f"{mutant_id} selector") for item in value)
    for selector in selectors:
        path_text = selector.split("::", 1)[0]
        path = _relative_path(path_text, label=f"{mutant_id} selector")
        if not path.startswith("tests/"):
            raise SemanticMutationError(f"{mutant_id} selector 必须位于 tests/。")
    return selectors


def _parse_mutant(value: object) -> MutantSpec:
    item = _mapping(value, label="mutant")
    expected_fields = {
        "id",
        "category",
        "source",
        "expected_source_sha256",
        "expected_mutant_sha256",
        "selectors",
        "old",
        "new",
    }
    if set(item) != expected_fields:
        raise SemanticMutationError("mutant 字段集合不符合 schema v1。")
    mutant_id = _text(item["id"], label="mutant id")
    required = REQUIRED_MUTANTS.get(mutant_id)
    if required is None:
        raise SemanticMutationError(f"未知语义 mutant：{mutant_id}")
    category = _text(item["category"], label=f"{mutant_id} category")
    source = _relative_path(item["source"], label=f"{mutant_id} source")
    selectors = _selectors(item["selectors"], mutant_id=mutant_id)
    if (category, source, selectors) != (
        required.category,
        required.source,
        required.selectors,
    ):
        raise SemanticMutationError(f"{mutant_id} 的类别、源码或 selector 偏离固定契约。")
    old = _text(item["old"], label=f"{mutant_id} old")
    new = _text(item["new"], label=f"{mutant_id} new", allow_empty=True)
    if old == new:
        raise SemanticMutationError(f"{mutant_id} old 与 new 不得相同。")
    return MutantSpec(
        mutant_id=mutant_id,
        category=category,
        source=source,
        expected_source_sha256=_digest(
            item["expected_source_sha256"], label=f"{mutant_id} expected_source_sha256"
        ),
        expected_mutant_sha256=_digest(
            item["expected_mutant_sha256"], label=f"{mutant_id} expected_mutant_sha256"
        ),
        selectors=selectors,
        old=old,
        new=new,
    )


def _manifest_values(payload: Mapping[str, object]) -> tuple[int, list[object]]:
    expected = {"schema_version", "report_path", "timeout_seconds", "mutants"}
    if set(payload) != expected:
        raise SemanticMutationError("语义变异 manifest 顶层字段不符合 schema v1。")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != SCHEMA_VERSION:
        raise SemanticMutationError("语义变异 manifest schema_version 必须为 1。")
    if payload["report_path"] != REPORT_PATH:
        raise SemanticMutationError("语义变异报告路径必须是固定专用位置。")
    timeout = payload["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise SemanticMutationError("语义变异 timeout_seconds 必须在 1..3600。")
    raw_mutants = payload["mutants"]
    if not isinstance(raw_mutants, list):
        raise SemanticMutationError("语义变异 mutants 必须是数组。")
    return timeout, raw_mutants


def load_manifest(path: Path) -> Manifest:
    """加载版本化清单，并拒绝缺类、重复类与选择器漂移。"""

    if not _is_plain_file(path):
        raise SemanticMutationError("语义变异 manifest 必须是普通文件且不得是链接。")
    raw = path.read_bytes()
    try:
        payload = _mapping(json.loads(raw), label="manifest")
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SemanticMutationError(f"语义变异 manifest 无法解析：{error}") from error
    timeout, raw_mutants = _manifest_values(payload)
    mutants = tuple(_parse_mutant(item) for item in raw_mutants)
    ids = [item.mutant_id for item in mutants]
    if len(ids) != len(set(ids)) or set(ids) != set(REQUIRED_MUTANTS):
        raise SemanticMutationError("语义变异清单必须恰好覆盖八类固定 mutant。")
    return Manifest(_sha256(raw), timeout, mutants)


def _mutated_bytes(source: bytes, mutant: MutantSpec) -> bytes:
    old = mutant.old.encode("utf-8")
    new = mutant.new.encode("utf-8")
    if source.count(old) != 1:
        raise SemanticMutationError(f"{mutant.mutant_id} old 必须在源码中唯一匹配。")
    return source.replace(old, new, 1)


def _validate_repo_inputs(repo: Path, manifest: Manifest) -> dict[str, str]:
    source_hashes: dict[str, str] = {}
    for mutant in manifest.mutants:
        source_path = repo / mutant.source
        if not _is_plain_file(source_path):
            raise SemanticMutationError(f"mutant 源码必须是普通文件：{mutant.source}")
        source = source_path.read_bytes()
        source_hash = _sha256(source)
        if source_hash != mutant.expected_source_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} 源码 SHA-256 已漂移。")
        if _sha256(_mutated_bytes(source, mutant)) != mutant.expected_mutant_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} 变异后 SHA-256 与清单不符。")
        previous = source_hashes.setdefault(mutant.source, source_hash)
        if previous != source_hash:
            raise SemanticMutationError(f"{mutant.source} 在清单验证期间发生变化。")
        for selector in mutant.selectors:
            test_path = repo / selector.split("::", 1)[0]
            if not _is_plain_file(test_path):
                raise SemanticMutationError(f"selector 测试文件缺失：{selector}")
    return source_hashes


def _selector_hashes(repo: Path, manifest: Manifest) -> dict[str, str]:
    paths = {
        selector.split("::", 1)[0] for mutant in manifest.mutants for selector in mutant.selectors
    }
    return {path: _sha256((repo / path).read_bytes()) for path in sorted(paths)}


def _required_file_hash(repo: Path, relative: str) -> str:
    path = repo / relative
    if not _is_plain_file(path):
        raise SemanticMutationError(f"语义变异绑定文件必须是普通文件：{relative}")
    return _sha256(path.read_bytes())


def _mapping_digest(label: bytes, hashes: Mapping[str, str]) -> str:
    digest = hashlib.sha256(label + b"\0")
    for path, value in sorted(hashes.items()):
        digest.update(path.encode("utf-8") + b"\0" + value.encode("ascii") + b"\0")
    return digest.hexdigest()


def _source_binding(
    repo: Path,
    manifest: Manifest,
    *,
    git_head: str,
    runner_sha256: str,
) -> SourceBinding:
    sources = _validate_repo_inputs(repo, manifest)
    selectors = _selector_hashes(repo, manifest)
    pyproject_sha256 = _required_file_hash(repo, "pyproject.toml")
    uv_lock_sha256 = _required_file_hash(repo, "uv.lock")
    all_inputs = {
        **sources,
        **selectors,
        "pyproject.toml": pyproject_sha256,
        "uv.lock": uv_lock_sha256,
    }
    return SourceBinding(
        git_head=git_head,
        manifest_sha256=manifest.sha256,
        runner_sha256=runner_sha256,
        source_sha256=_mapping_digest(b"sigmacoder-semantic-mutation-source-v1", sources),
        input_sha256=_mapping_digest(b"sigmacoder-semantic-mutation-input-v1", all_inputs),
        pyproject_sha256=pyproject_sha256,
        uv_lock_sha256=uv_lock_sha256,
        sources=dict(sorted(sources.items())),
        selectors=selectors,
    )


def _git_head(repo: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SemanticMutationError(f"无法读取语义变异对应的 Git HEAD：{error}") from error
    head = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head) is None:
        raise SemanticMutationError("语义变异对应的 Git HEAD 不可用。")
    return head


def _os_release_is_ubuntu(value: str) -> bool:
    values = {
        key: item.strip().strip('"')
        for key, item in (line.split("=", 1) for line in value.splitlines() if "=" in line)
    }
    return values.get("ID") == "ubuntu"


def _is_ubuntu() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError:
        return False
    return _os_release_is_ubuntu(release)


def _reject_links(root: Path) -> None:
    if root.is_symlink() or getattr(root, "is_junction", lambda: False)():
        raise SemanticMutationError(f"临时副本输入不得是链接或 junction：{root}")
    for entry in root.rglob("*"):
        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            raise SemanticMutationError(f"临时副本输入含链接或 junction：{entry}")


def _copy_inputs(repo: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns("__pycache__", ".pytest_cache", ".hypothesis", "*.pyc")
    for directory in ("src", "tests"):
        source = repo / directory
        if not source.is_dir():
            raise SemanticMutationError(f"语义变异输入目录缺失：{directory}")
        _reject_links(source)
        shutil.copytree(source, destination / directory, ignore=ignored)
    for relative in ("pyproject.toml", "uv.lock"):
        source = repo / relative
        if not _is_plain_file(source):
            raise SemanticMutationError(f"{relative} 缺失或不是普通文件。")
        shutil.copy2(source, destination / relative)


def _subprocess_runner(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _xml_count(element: element_tree.Element, name: str) -> int:
    value = element.attrib.get(name)
    if value is None or not value.isascii() or not value.isdecimal():
        raise SemanticMutationError(f"JUnit {name} 必须是非负十进制整数。")
    return int(value)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _junit_evidence(path: Path) -> JUnitEvidence:
    if not _is_plain_file(path):
        raise SemanticMutationError("语义变异 JUnit 必须是普通文件且不得是链接。")
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise SemanticMutationError("语义变异 JUnit 不得包含 DTD 或实体声明。")
    try:
        root = element_tree.fromstring(raw)
    except element_tree.ParseError as error:
        raise SemanticMutationError(f"语义变异 JUnit 无法解析：{error}") from error
    root_name = _local_name(root.tag)
    suites = (
        [root]
        if root_name == "testsuite"
        else [child for child in root if _local_name(child.tag) == "testsuite"]
    )
    if root_name not in {"testsuite", "testsuites"} or not suites:
        raise SemanticMutationError("语义变异 JUnit 根元素或 testsuite 不受支持。")
    totals = {
        name: sum(_xml_count(suite, name) for suite in suites)
        for name in ("tests", "failures", "errors", "skipped")
    }
    nodes = {
        plural: sum(
            1
            for suite in suites
            for descendant in suite.iter()
            if _local_name(descendant.tag) == singular
        )
        for plural, singular in (
            ("failures", "failure"),
            ("errors", "error"),
            ("skipped", "skipped"),
        )
    }
    testcases = sum(
        1
        for suite in suites
        for descendant in suite.iter()
        if _local_name(descendant.tag) == "testcase"
    )
    if totals["tests"] <= 0 or totals["tests"] != testcases:
        raise SemanticMutationError("语义变异 JUnit 必须证明非空且 testcase 数量一致。")
    if any(totals[name] != nodes[name] for name in nodes):
        raise SemanticMutationError("语义变异 JUnit 汇总计数与具体结果节点不一致。")
    return JUnitEvidence(sha256=_sha256(raw), **totals)


def _run_phase(
    root: Path,
    selectors: Sequence[str],
    phase: str,
    timeout: int,
    runner: CommandRunner,
) -> PhaseEvidence:
    phase_root = root / ".semantic-mutation" / phase
    phase_root.mkdir(parents=True)
    junit = phase_root / "junit.xml"
    environment = dict(os.environ)
    environment.pop(REPOSITORY_LEASE_TOKEN_ENV, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root)))
    environment["HYPOTHESIS_STORAGE_DIRECTORY"] = str(phase_root / "hypothesis")
    command = (
        sys.executable,
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-q",
        f"--hypothesis-profile={HYPOTHESIS_PROFILE}",
        f"--hypothesis-seed={HYPOTHESIS_SEED}",
        f"--junitxml={junit}",
        f"--basetemp={phase_root / 'pytest'}",
        *selectors,
    )
    try:
        completed = runner(command, cwd=root, env=environment, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise SemanticMutationError(f"{phase} pytest 无法执行：{error}") from error
    return PhaseEvidence(
        returncode=completed.returncode,
        stdout_sha256=_sha256(completed.stdout.encode("utf-8")),
        stderr_sha256=_sha256(completed.stderr.encode("utf-8")),
        junit=_junit_evidence(junit),
    )


def _assert_baseline(evidence: PhaseEvidence) -> None:
    junit = evidence.junit
    if evidence.returncode != 0 or any((junit.failures, junit.errors, junit.skipped)):
        raise SemanticMutationError("同 selector baseline 未证明 PASS、非空且零跳过。")


def _assert_killed(baseline: PhaseEvidence, mutant: PhaseEvidence) -> None:
    junit = mutant.junit
    if (
        mutant.returncode != 1
        or junit.tests != baseline.junit.tests
        or junit.failures <= 0
        or junit.errors != 0
        or junit.skipped != 0
    ):
        raise SemanticMutationError("mutant 未由同 selector 的真实测试断言失败杀死。")


def _run_mutant(
    repo: Path,
    mutant: MutantSpec,
    *,
    timeout: int,
    runner: CommandRunner,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=f"sigmacoder-{mutant.mutant_id.lower()}-") as raw:
        root = Path(raw)
        _copy_inputs(repo, root)
        copied_source = root / mutant.source
        before = copied_source.read_bytes()
        if _sha256(before) != mutant.expected_source_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} 临时副本源码已漂移。")
        baseline = _run_phase(root, mutant.selectors, "baseline", timeout, runner)
        _assert_baseline(baseline)
        if _sha256(copied_source.read_bytes()) != mutant.expected_source_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} baseline 修改了源码。")
        changed = _mutated_bytes(before, mutant)
        copied_source.write_bytes(changed)
        if _sha256(changed) != mutant.expected_mutant_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} 临时变异源码哈希不符。")
        mutated = _run_phase(root, mutant.selectors, "mutant", timeout, runner)
        _assert_killed(baseline, mutated)
        if _sha256(copied_source.read_bytes()) != mutant.expected_mutant_sha256:
            raise SemanticMutationError(f"{mutant.mutant_id} mutant 测试修改了源码。")
    return {
        "id": mutant.mutant_id,
        "category": mutant.category,
        "source": mutant.source,
        "source_sha256": mutant.expected_source_sha256,
        "mutant_sha256": mutant.expected_mutant_sha256,
        "selectors": list(mutant.selectors),
        "baseline": asdict(baseline),
        "mutant": asdict(mutated),
        "killed": True,
    }


def _temporary_report_problem(lease: TemporaryReportLease) -> str | None:
    try:
        current = lease.path.lstat()
    except OSError as error:
        return f"无法核验语义变异报告临时文件：{error}"
    if (
        lease.path.is_symlink()
        or getattr(lease.path, "is_junction", lambda: False)()
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (lease.device, lease.inode)
    ):
        return "语义变异报告临时文件身份已变化，拒绝操作未知路径。"
    try:
        if lease.path.read_bytes() != lease.payload:
            return "语义变异报告临时文件内容已变化，拒绝操作未知文件。"
        verified = lease.path.lstat()
    except OSError as error:
        return f"无法复核语义变异报告临时文件：{error}"
    if (verified.st_dev, verified.st_ino) != (lease.device, lease.inode):
        return "语义变异报告临时文件在复核期间被替换，拒绝操作未知路径。"
    return None


def _cleanup_owned_temporary(lease: TemporaryReportLease | None) -> str:
    if lease is None:
        return ""
    problem = _temporary_report_problem(lease)
    if problem:
        return f"；{problem}"
    try:
        lease.path.unlink()
    except OSError as error:
        return f"；无法清理已核验的语义变异报告临时文件：{error}"
    return ""


def _write_report_atomic(path: Path, report: Mapping[str, object]) -> None:
    parent = path.parent
    if parent.exists() and (
        not parent.is_dir()
        or parent.is_symlink()
        or getattr(parent, "is_junction", lambda: False)()
    ):
        raise SemanticMutationError("语义变异报告目录必须是普通目录且不得是链接。")
    parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not _is_plain_file(path):
        raise SemanticMutationError("语义变异报告目标必须是普通文件。")
    raw = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    temporary = parent / f".{path.name}.{uuid4().hex}.tmp"
    lease: TemporaryReportLease | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            opened = os.fstat(stream.fileno())
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        lease = TemporaryReportLease(
            temporary,
            opened.st_dev,
            opened.st_ino,
            raw,
        )
        problem = _temporary_report_problem(lease)
        if problem:
            raise SemanticMutationError(problem)
        os.replace(temporary, path)
        if sys.platform.startswith("linux"):
            directory = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except OSError as error:
        suffix = _cleanup_owned_temporary(lease)
        raise SemanticMutationError(f"无法原子写入语义变异报告：{error}{suffix}") from error


def _run_gate_locked(
    repo: Path,
    *,
    manifest_path: Path,
    report_path: Path,
    runner: CommandRunner,
    head_reader: Callable[[Path], str],
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    runner_path = Path(__file__).resolve()
    runner_sha256 = _sha256(runner_path.read_bytes())
    binding = _source_binding(
        repo,
        manifest,
        git_head=head_reader(repo),
        runner_sha256=runner_sha256,
    )
    evidence = [
        _run_mutant(
            repo,
            mutant,
            timeout=manifest.timeout_seconds,
            runner=runner,
        )
        for mutant in manifest.mutants
    ]
    if (
        not _is_plain_file(manifest_path)
        or _sha256(manifest_path.read_bytes()) != binding.manifest_sha256
    ):
        raise SemanticMutationError("语义变异运行期间 manifest 发生变化。")
    if not _is_plain_file(runner_path) or _sha256(runner_path.read_bytes()) != runner_sha256:
        raise SemanticMutationError("语义变异运行期间 runner 发生变化。")
    current_binding = _source_binding(
        repo,
        manifest,
        git_head=head_reader(repo),
        runner_sha256=runner_sha256,
    )
    if current_binding != binding:
        raise SemanticMutationError("语义变异运行期间源码、selector 或锁文件发生变化。")
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "gate": "sigmacoder-semantic-mutation-v1",
        "platform": "ubuntu" if _is_ubuntu() else "test-bypass",
        "execution": {
            "hypothesis_profile": HYPOTHESIS_PROFILE,
            "hypothesis_seed": HYPOTHESIS_SEED,
        },
        "binding": asdict(binding),
        "summary": {
            "expected": len(REQUIRED_MUTANTS),
            "executed": len(evidence),
            "killed": sum(item["killed"] is True for item in evidence),
        },
        "mutants": evidence,
    }
    _write_report_atomic(report_path, report)
    return report


def run_gate(
    repo: Path,
    *,
    manifest_path: Path,
    report_path: Path,
    require_ubuntu: bool = True,
    runner: CommandRunner = _subprocess_runner,
    head_reader: Callable[[Path], str] = _git_head,
) -> dict[str, object]:
    """运行八个固定 mutant；仅在全部真实杀死后发布报告。"""

    resolved_repo = repo.resolve(strict=True)
    if require_ubuntu and not _is_ubuntu():
        raise SemanticMutationError("语义变异门仅允许在 Ubuntu runner 执行。")
    expected_manifest = resolved_repo / "tools" / MANIFEST_NAME
    expected_report = resolved_repo / REPORT_PATH
    if manifest_path.resolve(strict=False) != expected_manifest:
        raise SemanticMutationError("语义变异 manifest 必须使用仓库内固定位置。")
    if report_path.resolve(strict=False) != expected_report:
        raise SemanticMutationError("语义变异报告必须使用仓库内固定位置。")
    try:
        with parent_or_standalone_repository_lease(
            resolved_repo,
            "semantic-mutation:t01",
        ):
            return _run_gate_locked(
                resolved_repo,
                manifest_path=manifest_path,
                report_path=report_path,
                runner=runner,
                head_reader=head_reader,
            )
    except RepositoryLeaseError as error:
        raise SemanticMutationError(str(error)) from error


def build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description="执行 T01 八类定向语义变异门。")


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    try:
        report = run_gate(
            repo,
            manifest_path=Path(__file__).with_name(MANIFEST_NAME),
            report_path=repo / REPORT_PATH,
        )
    except SemanticMutationError as error:
        print(f"语义变异门失败：{error}", file=sys.stderr)
        return 1
    print(json.dumps(report["summary"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
