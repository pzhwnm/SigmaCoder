"""语义变异最终报告审计器的正反契约测试。"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import cast

import pytest
import tools.check_semantic_report as checker
import tools.semantic_mutants as semantic_mutants
from tools.check_semantic_report import SemanticReportError, check_semantic_report


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def _fixture_repo(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, object]]:
    repo = root / "repo"
    source_fragments: dict[str, list[str]] = defaultdict(list)
    mutation_text: dict[str, tuple[str, str]] = {}
    for mutant_id, required in semantic_mutants.REQUIRED_MUTANTS.items():
        old = f"ORIGINAL_{mutant_id}"
        new = f"MUTATED_{mutant_id}"
        source_fragments[required.source].append(old)
        mutation_text[mutant_id] = old, new
        for selector in required.selectors:
            _write(
                repo / selector.split("::", 1)[0],
                "def test_semantic_contract():\n    assert True\n",
            )
    source_bytes: dict[str, bytes] = {}
    for relative, fragments in source_fragments.items():
        raw = ("\n".join(fragments) + "\n").encode()
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        source_bytes[relative] = raw
    _write(repo / "pyproject.toml", '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n')
    _write(repo / "uv.lock", "version = 1\n")
    _write(repo / "tools/semantic_mutants.py", "# 固定 runner 输入\n")
    mutants: list[dict[str, object]] = []
    for mutant_id, required in semantic_mutants.REQUIRED_MUTANTS.items():
        old, new = mutation_text[mutant_id]
        source = source_bytes[required.source]
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
    manifest_payload = {
        "schema_version": 1,
        "report_path": semantic_mutants.REPORT_PATH,
        "timeout_seconds": 30,
        "mutants": mutants,
    }
    _write(
        repo / "tools/semantic_mutants.json",
        json.dumps(manifest_payload, ensure_ascii=False, sort_keys=True),
    )
    head = "a" * 40
    monkeypatch.setattr(semantic_mutants, "_git_head", lambda _repo: head)
    manifest = semantic_mutants.load_manifest(repo / "tools/semantic_mutants.json")
    binding = semantic_mutants._source_binding(
        repo,
        manifest,
        git_head=head,
        runner_sha256=_sha256((repo / "tools/semantic_mutants.py").read_bytes()),
    )

    def phase(*, returncode: int, failures: int) -> dict[str, object]:
        return {
            "returncode": returncode,
            "stdout_sha256": "1" * 64,
            "stderr_sha256": "2" * 64,
            "junit": {
                "sha256": "3" * 64,
                "tests": 1,
                "failures": failures,
                "errors": 0,
                "skipped": 0,
            },
        }

    evidence = [
        {
            "id": mutant.mutant_id,
            "category": mutant.category,
            "source": mutant.source,
            "source_sha256": mutant.expected_source_sha256,
            "mutant_sha256": mutant.expected_mutant_sha256,
            "selectors": list(mutant.selectors),
            "baseline": phase(returncode=0, failures=0),
            "mutant": phase(returncode=1, failures=1),
            "killed": True,
        }
        for mutant in manifest.mutants
    ]
    report: dict[str, object] = {
        "schema_version": 1,
        "gate": "sigmacoder-semantic-mutation-v1",
        "platform": "ubuntu",
        "execution": {
            "hypothesis_profile": semantic_mutants.HYPOTHESIS_PROFILE,
            "hypothesis_seed": semantic_mutants.HYPOTHESIS_SEED,
        },
        "binding": asdict(binding),
        "summary": {"expected": 8, "executed": 8, "killed": 8},
        "mutants": evidence,
    }
    _publish(repo, report)
    return repo, report


def _publish(repo: Path, report: dict[str, object]) -> None:
    _write(
        repo / checker.REPORT_PATH,
        json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )


def _replace_nested(root: dict[str, object], path: tuple[str | int, ...], value: object) -> None:
    current: object = root
    for part in path[:-1]:
        if isinstance(part, int):
            current = cast(list[object], current)[part]
        else:
            current = cast(dict[str, object], current)[part]
    final = path[-1]
    if isinstance(final, int):
        cast(list[object], current)[final] = value
    else:
        cast(dict[str, object], current)[final] = value


def test_valid_report_emits_one_exact_json_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _ = _fixture_repo(tmp_path, monkeypatch)
    expected_digest = _sha256((repo / checker.REPORT_PATH).read_bytes())

    result = check_semantic_report(repo)
    assert result == {
        "ok": True,
        "report_sha256": expected_digest,
        "git_head": "a" * 40,
        "mutants": 8,
    }
    assert checker.main(["--repo", str(repo)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == result


def test_stale_git_head_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _ = _fixture_repo(tmp_path, monkeypatch)
    monkeypatch.setattr(semantic_mutants, "_git_head", lambda _repo: "b" * 40)
    with pytest.raises(SemanticReportError, match="绑定"):
        check_semantic_report(repo)


@pytest.mark.parametrize(
    "relative", ("uv.lock", "tests/property/test_event_generated_properties.py")
)
def test_lock_or_selector_byte_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
) -> None:
    repo, _ = _fixture_repo(tmp_path, monkeypatch)
    path = repo / relative
    path.write_bytes(path.read_bytes() + b"drift\n")
    with pytest.raises(SemanticReportError, match="绑定"):
        check_semantic_report(repo)


def test_false_killed_and_setup_error_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, report = _fixture_repo(tmp_path, monkeypatch)
    false_killed = deepcopy(report)
    first = cast(dict[str, object], cast(list[object], false_killed["mutants"])[0])
    first["killed"] = False
    _publish(repo, false_killed)
    with pytest.raises(SemanticReportError, match="严格为 true"):
        check_semantic_report(repo)

    setup_error = deepcopy(report)
    first = cast(dict[str, object], cast(list[object], setup_error["mutants"])[0])
    mutant = cast(dict[str, object], first["mutant"])
    junit = cast(dict[str, object], mutant["junit"])
    junit.update({"failures": 0, "errors": 1})
    _publish(repo, setup_error)
    with pytest.raises(SemanticReportError, match="断言失败杀死"):
        check_semantic_report(repo)


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("schema_version",), True),
        (("execution", "hypothesis_seed"), True),
        (("summary", "expected"), True),
        (("mutants", 0, "baseline", "returncode"), False),
        (("mutants", 0, "mutant", "junit", "tests"), True),
    ),
)
def test_boolean_never_impersonates_an_integer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str | int, ...],
    value: bool,
) -> None:
    repo, report = _fixture_repo(tmp_path, monkeypatch)
    changed_report = deepcopy(report)
    _replace_nested(changed_report, path, value)
    _publish(repo, changed_report)
    with pytest.raises(SemanticReportError, match="布尔值"):
        check_semantic_report(repo)


def test_extra_missing_and_wrong_mutant_contract_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, report = _fixture_repo(tmp_path, monkeypatch)
    extra = deepcopy(report)
    extra["unexpected"] = True
    _publish(repo, extra)
    with pytest.raises(SemanticReportError, match="字段集合"):
        check_semantic_report(repo)

    missing = deepcopy(report)
    del missing["execution"]
    _publish(repo, missing)
    with pytest.raises(SemanticReportError, match="字段集合"):
        check_semantic_report(repo)

    wrong_hash = deepcopy(report)
    first = cast(dict[str, object], cast(list[object], wrong_hash["mutants"])[0])
    first["mutant_sha256"] = "0" * 64
    _publish(repo, wrong_hash)
    with pytest.raises(SemanticReportError, match="固定清单"):
        check_semantic_report(repo)

    wrong_order = deepcopy(report)
    cast(list[object], wrong_order["mutants"]).reverse()
    _publish(repo, wrong_order)
    with pytest.raises(SemanticReportError, match="固定清单"):
        check_semantic_report(repo)


def test_malformed_duplicate_uppercase_and_nonregular_report_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, report = _fixture_repo(tmp_path, monkeypatch)
    report_path = repo / checker.REPORT_PATH
    report_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(SemanticReportError, match="重复字段"):
        check_semantic_report(repo)

    uppercase = deepcopy(report)
    first = cast(dict[str, object], cast(list[object], uppercase["mutants"])[0])
    baseline = cast(dict[str, object], first["baseline"])
    baseline["stdout_sha256"] = "A" * 64
    _publish(repo, uppercase)
    with pytest.raises(SemanticReportError, match="小写 SHA-256"):
        check_semantic_report(repo)

    report_path.unlink()
    report_path.mkdir()
    with pytest.raises(SemanticReportError, match="普通文件"):
        check_semantic_report(repo)


def test_report_or_parent_link_identity_is_rejected_without_platform_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _ = _fixture_repo(tmp_path, monkeypatch)
    report = repo / checker.REPORT_PATH
    real_is_junction = getattr(Path, "is_junction", lambda _path: False)

    def fake_is_junction(path: Path) -> bool:
        return path == report or real_is_junction(path)

    monkeypatch.setattr(Path, "is_junction", fake_is_junction, raising=False)
    with pytest.raises(SemanticReportError, match="链接或 junction"):
        check_semantic_report(repo)
