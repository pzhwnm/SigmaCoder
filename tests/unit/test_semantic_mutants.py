"""八类定向语义变异门的清单、隔离执行与负控测试。"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
import tools.semantic_mutants as semantic_module
from tools.repo_lease import (
    REPOSITORY_LEASE_FILE,
    REPOSITORY_LEASE_TOKEN_ENV,
    acquire_repository_lease,
)
from tools.semantic_mutants import (
    HYPOTHESIS_PROFILE,
    HYPOTHESIS_SEED,
    REPORT_PATH,
    REQUIRED_MUTANTS,
    JUnitEvidence,
    MutantSpec,
    SemanticMutationError,
    _junit_evidence,
    _mutated_bytes,
    _os_release_is_ubuntu,
    _validate_repo_inputs,
    _write_report_atomic,
    load_manifest,
    run_gate,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _fixture_repo(root: Path) -> Path:
    repo = root / "repo"
    fragments: dict[str, list[str]] = defaultdict(list)
    mutation_text: dict[str, tuple[str, str]] = {}
    for mutant_id, required in REQUIRED_MUTANTS.items():
        old = f"ORIGINAL_{mutant_id}"
        new = f"MUTATED_{mutant_id}"
        fragments[required.source].append(old)
        mutation_text[mutant_id] = old, new
        for selector in required.selectors:
            _write(repo / selector.split("::", 1)[0], "def test_placeholder():\n    assert True\n")
    sources: dict[str, bytes] = {}
    for source, parts in fragments.items():
        raw = ("\n".join(parts) + "\n").encode()
        (repo / source).parent.mkdir(parents=True, exist_ok=True)
        (repo / source).write_bytes(raw)
        sources[source] = raw
    _write(repo / "pyproject.toml", '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    _write(repo / "uv.lock", "version = 1\n")
    mutants: list[dict[str, object]] = []
    for mutant_id, required in REQUIRED_MUTANTS.items():
        old, new = mutation_text[mutant_id]
        source = sources[required.source]
        mutants.append(
            {
                "id": mutant_id,
                "category": required.category,
                "source": required.source,
                "expected_source_sha256": _sha256(source),
                "expected_mutant_sha256": _sha256(source.replace(old.encode(), new.encode(), 1)),
                "selectors": list(required.selectors),
                "old": old,
                "new": new,
            }
        )
    manifest = {
        "schema_version": 1,
        "report_path": REPORT_PATH,
        "timeout_seconds": 30,
        "mutants": mutants,
    }
    _write(
        repo / "tools/semantic_mutants.json",
        json.dumps(manifest, ensure_ascii=False, sort_keys=True),
    )
    return repo


def _junit(*, failures: int = 0, errors: int = 0, skipped: int = 0) -> str:
    child = ""
    if failures:
        child = '<failure message="mutant killed" />'
    elif errors:
        child = '<error message="setup failed" />'
    elif skipped:
        child = '<skipped message="not executed" />'
    return (
        f'<testsuites><testsuite tests="1" failures="{failures}" errors="{errors}" '
        f'skipped="{skipped}"><testcase name="semantic">{child}</testcase>'
        "</testsuite></testsuites>"
    )


class _FakeRunner:
    def __init__(self, mutant_mode: str = "failure", baseline_mode: str = "pass") -> None:
        self.mutant_mode = mutant_mode
        self.baseline_mode = baseline_mode
        self.calls: list[tuple[tuple[str, ...], str]] = []

    @staticmethod
    def _result(mode: str) -> tuple[int, str]:
        if mode == "pass":
            return 0, _junit()
        if mode == "failure":
            return 1, _junit(failures=1)
        if mode == "error":
            return 1, _junit(errors=1)
        if mode == "skip":
            return 0, _junit(skipped=1)
        raise AssertionError(f"未知 fake 模式：{mode}")

    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        assert REPOSITORY_LEASE_TOKEN_ENV not in env
        del cwd, timeout
        junit_argument = next(item for item in command if item.startswith("--junitxml="))
        junit = Path(junit_argument.split("=", 1)[1])
        phase = junit.parent.name
        mode = self.baseline_mode if phase == "baseline" else self.mutant_mode
        returncode, xml = self._result(mode)
        _write(junit, xml)
        self.calls.append((tuple(command), phase))
        return subprocess.CompletedProcess(command, returncode, f"{phase} stdout", "")


def _run_fixture(repo: Path, runner: _FakeRunner) -> dict[str, object]:
    return run_gate(
        repo,
        manifest_path=repo / "tools/semantic_mutants.json",
        report_path=repo / REPORT_PATH,
        require_ubuntu=False,
        runner=runner,
        head_reader=lambda _repo: "a" * 40,
    )


def test_semantic_gate_runs_eight_isolated_baselines_and_real_failures(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    sources_before = {
        required.source: (repo / required.source).read_bytes()
        for required in REQUIRED_MUTANTS.values()
    }
    runner = _FakeRunner()

    report = _run_fixture(repo, runner)

    summary = cast(dict[str, object], report["summary"])
    assert summary == {"expected": 8, "executed": 8, "killed": 8}
    mutants = cast(list[dict[str, object]], report["mutants"])
    assert {item["id"] for item in mutants} == set(REQUIRED_MUTANTS)
    assert all(item["killed"] is True for item in mutants)
    assert len(runner.calls) == 16
    for index in range(0, len(runner.calls), 2):
        baseline_command, baseline_phase = runner.calls[index]
        mutant_command, mutant_phase = runner.calls[index + 1]
        assert (baseline_phase, mutant_phase) == ("baseline", "mutant")
        assert baseline_command[-1:] == mutant_command[-1:]
        assert f"--hypothesis-profile={HYPOTHESIS_PROFILE}" in baseline_command
        assert f"--hypothesis-seed={HYPOTHESIS_SEED}" in baseline_command
    assert {source: (repo / source).read_bytes() for source in sources_before} == sources_before
    persisted = json.loads((repo / REPORT_PATH).read_text(encoding="utf-8"))
    assert persisted == report
    binding = cast(dict[str, object], report["binding"])
    assert binding["uv_lock_sha256"] == _sha256((repo / "uv.lock").read_bytes())
    assert binding["pyproject_sha256"] == _sha256((repo / "pyproject.toml").read_bytes())
    assert set(cast(dict[str, str], binding["selectors"])) == {
        selector.split("::", 1)[0]
        for required in REQUIRED_MUTANTS.values()
        for selector in required.selectors
    }
    assert not (repo / "mutation-reports" / REPOSITORY_LEASE_FILE).exists()


@pytest.mark.parametrize(
    ("baseline_mode", "mutant_mode", "message"),
    (
        ("failure", "failure", "baseline"),
        ("pass", "pass", "真实测试断言失败"),
        ("pass", "error", "真实测试断言失败"),
        ("pass", "skip", "真实测试断言失败"),
    ),
)
def test_semantic_gate_rejects_false_positive_execution_evidence(
    tmp_path: Path,
    baseline_mode: str,
    mutant_mode: str,
    message: str,
) -> None:
    repo = _fixture_repo(tmp_path)
    with pytest.raises(SemanticMutationError, match=message):
        _run_fixture(repo, _FakeRunner(mutant_mode, baseline_mode))
    assert not (repo / REPORT_PATH).exists()


def test_manifest_rejects_missing_class_selector_escape_and_source_drift(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    path = repo / "tools/semantic_mutants.json"
    original = json.loads(path.read_text(encoding="utf-8"))

    missing = deepcopy(original)
    missing["mutants"] = cast(list[object], missing["mutants"])[:-1]
    _write(path, json.dumps(missing))
    with pytest.raises(SemanticMutationError, match="恰好覆盖八类"):
        load_manifest(path)

    escaped = deepcopy(original)
    first = cast(dict[str, object], cast(list[object], escaped["mutants"])[0])
    first["selectors"] = ["../outside.py::test_counterfeit"]
    _write(path, json.dumps(escaped))
    with pytest.raises(SemanticMutationError, match="未折叠"):
        load_manifest(path)

    _write(path, json.dumps(original))
    manifest = load_manifest(path)
    source = repo / manifest.mutants[0].source
    source.write_bytes(source.read_bytes() + b"drift\n")
    with pytest.raises(SemanticMutationError, match="源码 SHA-256 已漂移"):
        _validate_repo_inputs(repo, manifest)


def test_selector_drift_during_run_prevents_report_publication(tmp_path: Path) -> None:
    repo = _fixture_repo(tmp_path)
    selector = next(iter(REQUIRED_MUTANTS.values())).selectors[0].split("::", 1)[0]

    class _DriftRunner(_FakeRunner):
        def __call__(
            self,
            command: Sequence[str],
            *,
            cwd: Path,
            env: Mapping[str, str],
            timeout: int,
        ) -> subprocess.CompletedProcess[str]:
            result = super().__call__(command, cwd=cwd, env=env, timeout=timeout)
            if len(self.calls) == 16:
                _write(repo / selector, "def test_counterfeit():\n    assert True\n")
            return result

    with pytest.raises(SemanticMutationError, match="selector"):
        _run_fixture(repo, _DriftRunner())
    assert not (repo / REPORT_PATH).exists()


def test_mutation_requires_exactly_one_old_match() -> None:
    required = REQUIRED_MUTANTS["SEM001_SEQUENCE_CONTINUITY"]
    mutant = MutantSpec(
        mutant_id="SEM001_SEQUENCE_CONTINUITY",
        category=required.category,
        source=required.source,
        expected_source_sha256="0" * 64,
        expected_mutant_sha256="1" * 64,
        selectors=required.selectors,
        old="needle",
        new="changed",
    )
    for source in (b"missing", b"needle needle"):
        with pytest.raises(SemanticMutationError, match="唯一匹配"):
            _mutated_bytes(source, mutant)


def test_junit_rejects_empty_and_counterfeit_failure_totals(tmp_path: Path) -> None:
    empty = tmp_path / "empty.xml"
    _write(
        empty,
        '<testsuite tests="0" failures="0" errors="0" skipped="0"></testsuite>',
    )
    with pytest.raises(SemanticMutationError, match="非空"):
        _junit_evidence(empty)

    counterfeit = tmp_path / "counterfeit.xml"
    _write(
        counterfeit,
        '<testsuite tests="1" failures="1" errors="0" skipped="0">'
        '<testcase name="x" /></testsuite>',
    )
    with pytest.raises(SemanticMutationError, match="具体结果节点"):
        _junit_evidence(counterfeit)


def test_repository_manifest_is_complete_and_bound_to_current_sources() -> None:
    manifest = load_manifest(PROJECT_ROOT / "tools/semantic_mutants.json")
    hashes = _validate_repo_inputs(PROJECT_ROOT, manifest)

    assert len(manifest.mutants) == 8
    assert {mutant.mutant_id for mutant in manifest.mutants} == set(REQUIRED_MUTANTS)
    assert set(hashes) == {
        "src/sigmacoder/domain/events.py",
        "src/sigmacoder/adapters/git_workspace.py",
    }
    for mutant in manifest.mutants[:4]:
        assert all(selector.startswith("tests/property/") for selector in mutant.selectors)


def test_repository_parent_lease_is_reentrant_and_unknown_lock_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _fixture_repo(tmp_path)
    lock = repo / "mutation-reports" / REPOSITORY_LEASE_FILE
    with acquire_repository_lease(repo, "gauntlet:test") as parent:
        monkeypatch.setenv(REPOSITORY_LEASE_TOKEN_ENV, parent.token)
        _run_fixture(repo, _FakeRunner())
        assert lock.read_bytes() == parent.payload
    assert not lock.exists()

    report = repo / REPORT_PATH
    report.unlink()
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("未知残留", encoding="utf-8")
    monkeypatch.delenv(REPOSITORY_LEASE_TOKEN_ENV, raising=False)
    with pytest.raises(SemanticMutationError, match="已被占用"):
        _run_fixture(repo, _FakeRunner())
    assert lock.read_text(encoding="utf-8") == "未知残留"
    assert not report.exists()


def test_atomic_report_collision_never_deletes_unknown_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "mutation-reports" / "semantic.json"
    report.parent.mkdir(parents=True)

    class _FixedUuid:
        hex = "f" * 32

    monkeypatch.setattr(semantic_module, "uuid4", _FixedUuid)
    unknown = report.parent / f".{report.name}.{'f' * 32}.tmp"
    unknown.write_bytes(b"unknown-owner")

    with pytest.raises(SemanticMutationError, match="原子写入"):
        _write_report_atomic(report, {"ok": True})

    assert unknown.read_bytes() == b"unknown-owner"
    assert not report.exists()


def test_junit_evidence_type_has_stable_fields() -> None:
    evidence = JUnitEvidence("0" * 64, 1, 0, 0, 0)
    assert evidence.tests == 1


def test_ubuntu_gate_requires_exact_distribution_id() -> None:
    assert _os_release_is_ubuntu('NAME="Ubuntu"\nID=ubuntu\n')
    assert not _os_release_is_ubuntu('ID=linuxmint\nID_LIKE="ubuntu debian"\n')
