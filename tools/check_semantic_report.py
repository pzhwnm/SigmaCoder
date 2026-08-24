"""独立审计 T01 八类定向语义变异报告。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final, cast

import tools.semantic_mutants as semantic_mutants
from tools.semantic_mutants import Manifest, MutantSpec, SemanticMutationError

REPORT_PATH: Final = Path("mutation-reports/semantic.json")
MANIFEST_PATH: Final = Path("tools/semantic_mutants.json")
RUNNER_PATH: Final = Path("tools/semantic_mutants.py")
MAX_REPORT_BYTES: Final = 2 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class SemanticReportError(RuntimeError):
    """语义变异最终报告不满足可审计契约。"""


@dataclass(frozen=True)
class ContractSnapshot:
    """一次不可变的当前仓库契约快照。"""

    manifest: Manifest
    binding: dict[str, object]


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise SemanticReportError(f"{label} 必须是字符串键对象。")
    return cast(dict[str, object], value)


def _exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise SemanticReportError(f"{label} 字段集合不符合 schema v1。")


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise SemanticReportError(f"{label} 必须是整数且不得用布尔值冒充。")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise SemanticReportError(f"{label} 必须是非空字符串。")
    return value


def _digest(value: object, label: str) -> str:
    digest = _text(value, label)
    if _SHA256.fullmatch(digest) is None:
        raise SemanticReportError(f"{label} 必须是 64 位小写 SHA-256。")
    return digest


def _head(value: object, label: str) -> str:
    head = _text(value, label)
    if _GIT_HEAD.fullmatch(head) is None:
        raise SemanticReportError(f"{label} 必须是小写 Git 对象 ID。")
    return head


def _is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _plain_file_bytes(path: Path, label: str, *, limit: int | None = None) -> bytes:
    """通过文件描述符读取普通文件，并拒绝链接、替换与超限输入。"""

    try:
        before = path.lstat()
        if _is_link(path) or not stat.S_ISREG(before.st_mode):
            raise SemanticReportError(f"{label} 必须是普通文件且不得是链接或 junction。")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise SemanticReportError(f"{label} 在打开期间被替换。")
            raw = stream.read() if limit is None else stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        current = path.lstat()
    except SemanticReportError:
        raise
    except OSError as error:
        raise SemanticReportError(f"无法读取{label}：{error}") from error
    if limit is not None and len(raw) > limit:
        raise SemanticReportError(f"{label} 超过允许的大小上限。")
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    identity_current = (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
    if _is_link(path) or not stat.S_ISREG(current.st_mode):
        raise SemanticReportError(f"{label} 在读取期间变成链接或非普通文件。")
    if identity_before != identity_after or identity_after != identity_current:
        raise SemanticReportError(f"{label} 在读取期间发生变化。")
    return raw


def _strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise SemanticReportError(f"语义变异报告含重复字段：{key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise SemanticReportError(f"语义变异报告含非标准 JSON 常量：{value}")

    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except SemanticReportError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SemanticReportError(f"语义变异报告无法严格解析：{error}") from error


def _runner_digest(repo: Path) -> str:
    return hashlib.sha256(_plain_file_bytes(repo / RUNNER_PATH, "语义变异 runner")).hexdigest()


def _snapshot(repo: Path) -> ContractSnapshot:
    try:
        manifest = semantic_mutants.load_manifest(repo / MANIFEST_PATH)
        binding = semantic_mutants._source_binding(
            repo,
            manifest,
            git_head=semantic_mutants._git_head(repo),
            runner_sha256=_runner_digest(repo),
        )
    except SemanticReportError:
        raise
    except SemanticMutationError as error:
        raise SemanticReportError(f"当前语义变异输入无效：{error}") from error
    return ContractSnapshot(manifest, cast(dict[str, object], asdict(binding)))


def _validate_binding(value: object, expected: Mapping[str, object]) -> None:
    binding = _mapping(value, "binding")
    _exact_fields(binding, set(expected), "binding")
    _head(binding["git_head"], "binding.git_head")
    for name in (
        "manifest_sha256",
        "runner_sha256",
        "source_sha256",
        "input_sha256",
        "pyproject_sha256",
        "uv_lock_sha256",
    ):
        _digest(binding[name], f"binding.{name}")
    for name in ("sources", "selectors"):
        actual_items = _mapping(binding[name], f"binding.{name}")
        expected_items = _mapping(expected[name], f"expected binding.{name}")
        _exact_fields(actual_items, set(expected_items), f"binding.{name}")
        for path, digest in actual_items.items():
            _digest(digest, f"binding.{name}.{path}")
    if binding != expected:
        raise SemanticReportError("语义变异报告绑定与当前 HEAD 或输入字节不一致。")


def _validate_junit(value: object, label: str) -> tuple[int, int, int, int]:
    junit = _mapping(value, label)
    _exact_fields(junit, {"sha256", "tests", "failures", "errors", "skipped"}, label)
    _digest(junit["sha256"], f"{label}.sha256")
    counts = tuple(
        _integer(junit[name], f"{label}.{name}")
        for name in ("tests", "failures", "errors", "skipped")
    )
    tests, failures, errors, skipped = counts
    if tests <= 0 or min(failures, errors, skipped) < 0:
        raise SemanticReportError(f"{label} 必须证明非空测试且计数不得为负。")
    if failures + errors + skipped > tests:
        raise SemanticReportError(f"{label} 的结果计数超过测试总数。")
    return tests, failures, errors, skipped


def _validate_phase(value: object, label: str) -> tuple[int, tuple[int, int, int, int]]:
    phase = _mapping(value, label)
    _exact_fields(
        phase,
        {"returncode", "stdout_sha256", "stderr_sha256", "junit"},
        label,
    )
    returncode = _integer(phase["returncode"], f"{label}.returncode")
    _digest(phase["stdout_sha256"], f"{label}.stdout_sha256")
    _digest(phase["stderr_sha256"], f"{label}.stderr_sha256")
    return returncode, _validate_junit(phase["junit"], f"{label}.junit")


def _validate_mutant_identity(item: Mapping[str, object], spec: MutantSpec, label: str) -> None:
    exact_strings = {
        "id": spec.mutant_id,
        "category": spec.category,
        "source": spec.source,
        "source_sha256": spec.expected_source_sha256,
        "mutant_sha256": spec.expected_mutant_sha256,
    }
    for name, expected in exact_strings.items():
        actual = _text(item[name], f"{label}.{name}")
        if name.endswith("sha256"):
            _digest(actual, f"{label}.{name}")
        if actual != expected:
            raise SemanticReportError(f"{label}.{name} 偏离固定清单契约。")
    selectors = item["selectors"]
    if type(selectors) is not list or any(type(value) is not str for value in selectors):
        raise SemanticReportError(f"{label}.selectors 必须是字符串数组。")
    if tuple(cast(list[str], selectors)) != spec.selectors:
        raise SemanticReportError(f"{label}.selectors 偏离固定清单契约。")


def _validate_kill_evidence(item: Mapping[str, object], label: str) -> None:
    if item["killed"] is not True:
        raise SemanticReportError(f"{label}.killed 必须严格为 true。")
    baseline_returncode, baseline_counts = _validate_phase(item["baseline"], f"{label}.baseline")
    mutant_returncode, mutant_counts = _validate_phase(item["mutant"], f"{label}.mutant")
    baseline_tests, baseline_failures, baseline_errors, baseline_skipped = baseline_counts
    mutant_tests, mutant_failures, mutant_errors, mutant_skipped = mutant_counts
    if baseline_returncode != 0 or any((baseline_failures, baseline_errors, baseline_skipped)):
        raise SemanticReportError(f"{label}.baseline 未证明干净的真实通过。")
    if (
        mutant_returncode != 1
        or mutant_tests != baseline_tests
        or mutant_failures <= 0
        or mutant_errors != 0
        or mutant_skipped != 0
    ):
        raise SemanticReportError(f"{label}.mutant 未证明被同组测试断言失败杀死。")


def _validate_mutant(value: object, spec: MutantSpec, index: int) -> None:
    label = f"mutants[{index}]"
    item = _mapping(value, label)
    _exact_fields(
        item,
        {
            "id",
            "category",
            "source",
            "source_sha256",
            "mutant_sha256",
            "selectors",
            "baseline",
            "mutant",
            "killed",
        },
        label,
    )
    _validate_mutant_identity(item, spec, label)
    _validate_kill_evidence(item, label)


def _validate_header(report: Mapping[str, object]) -> None:
    if _integer(report["schema_version"], "schema_version") != 1:
        raise SemanticReportError("schema_version 必须严格为 1。")
    if _text(report["gate"], "gate") != "sigmacoder-semantic-mutation-v1":
        raise SemanticReportError("gate 必须严格为 sigmacoder-semantic-mutation-v1。")
    if _text(report["platform"], "platform") != "ubuntu":
        raise SemanticReportError("platform 必须严格为 ubuntu。")


def _validate_execution(value: object) -> None:
    execution = _mapping(value, "execution")
    _exact_fields(execution, {"hypothesis_profile", "hypothesis_seed"}, "execution")
    if execution["hypothesis_profile"] != semantic_mutants.HYPOTHESIS_PROFILE:
        raise SemanticReportError("execution.hypothesis_profile 偏离固定契约。")
    if (
        _integer(execution["hypothesis_seed"], "execution.hypothesis_seed")
        != semantic_mutants.HYPOTHESIS_SEED
    ):
        raise SemanticReportError("execution.hypothesis_seed 偏离固定契约。")


def _validate_summary(value: object) -> None:
    summary = _mapping(value, "summary")
    _exact_fields(summary, {"expected", "executed", "killed"}, "summary")
    for name in ("expected", "executed", "killed"):
        if _integer(summary[name], f"summary.{name}") != 8:
            raise SemanticReportError("summary 必须严格证明 8/8/8。")


def validate_report_payload(
    payload: object,
    *,
    manifest: Manifest,
    expected_binding: Mapping[str, object],
) -> None:
    """验证报告 schema、八类证据与当前输入绑定。"""

    report = _mapping(payload, "report")
    _exact_fields(
        report,
        {"schema_version", "gate", "platform", "execution", "binding", "summary", "mutants"},
        "report",
    )
    _validate_header(report)
    _validate_execution(report["execution"])
    _validate_summary(report["summary"])
    _validate_binding(report["binding"], expected_binding)
    mutants = report["mutants"]
    if type(mutants) is not list or len(mutants) != 8:
        raise SemanticReportError("mutants 必须恰好包含八项。")
    evidence = cast(list[object], mutants)
    for index, (item, spec) in enumerate(zip(evidence, manifest.mutants, strict=True)):
        _validate_mutant(item, spec, index)


def check_semantic_report(repo: Path) -> dict[str, object]:
    """审计固定报告，并在审计前后确认仓库输入未漂移。"""

    try:
        resolved_repo = repo.resolve(strict=True)
    except OSError as error:
        raise SemanticReportError(f"仓库根目录不可用：{error}") from error
    report_directory = resolved_repo / REPORT_PATH.parent
    try:
        directory_state = report_directory.lstat()
    except OSError as error:
        raise SemanticReportError(f"语义变异报告目录不可用：{error}") from error
    if _is_link(report_directory) or not stat.S_ISDIR(directory_state.st_mode):
        raise SemanticReportError("语义变异报告目录必须是普通目录且不得是链接或 junction。")
    before = _snapshot(resolved_repo)
    raw = _plain_file_bytes(
        resolved_repo / REPORT_PATH,
        "语义变异报告",
        limit=MAX_REPORT_BYTES,
    )
    validate_report_payload(
        _strict_json(raw),
        manifest=before.manifest,
        expected_binding=before.binding,
    )
    after = _snapshot(resolved_repo)
    if after != before:
        raise SemanticReportError("语义变异输入或 Git HEAD 在审计期间发生变化。")
    return {
        "ok": True,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "git_head": before.binding["git_head"],
        "mutants": 8,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="审计 T01 八类定向语义变异最终报告。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = check_semantic_report(args.repo)
    except SemanticReportError as error:
        print(f"语义变异报告审计失败：{error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
