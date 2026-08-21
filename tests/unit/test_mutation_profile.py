"""Mutation profile 检查器的单元测试。"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest
from tools.run_mutation_profile import (
    MutationGateError,
    load_profile,
    parse_mutmut_results,
    run_profile,
    validate_inputs,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def write_profile(root: Path, *, cache_dir: str = "mutants") -> Path:
    payload = {
        "schema_version": 1,
        "profiles": {
            "events": {
                "source_paths": ["src/sigmacoder"],
                "only_mutate": ["src/sigmacoder/domain/events.py"],
                "test_selection": ["tests/domain", "tests/property"],
                "property_test_selection": ["tests/property"],
                "timeout_seconds": 30,
                "timeout_multiplier": 2.0,
                "timeout_constant": 1.0,
                "max_children": 1,
                "repeat": 2,
                "cache_dir": cache_dir,
                "report_path": "mutants/reports/events.json",
            }
        },
    }
    path = root / "profiles.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def create_inputs(root: Path) -> None:
    target = root / "src/sigmacoder/domain/events.py"
    target.parent.mkdir(parents=True)
    target.write_text("def value():\n    return 1\n", encoding="utf-8")
    (root / "tests/domain").mkdir(parents=True)
    (root / "tests/property").mkdir(parents=True)


def test_mutmut_results_只接受非空且全部_killed() -> None:
    assert parse_mutmut_results("    a__mutmut_1: killed\n") == {"a__mutmut_1": "killed"}
    with pytest.raises(MutationGateError, match="未返回任何"):
        parse_mutmut_results("")
    with pytest.raises(MutationGateError, match="未被测试杀死"):
        parse_mutmut_results("    a__mutmut_1: survived\n")
    with pytest.raises(MutationGateError, match="未知状态"):
        parse_mutmut_results("    a__mutmut_1: magical\n")


def test_profile_拒绝逃逸缓存路径(tmp_path: Path) -> None:
    config = write_profile(tmp_path, cache_dir="../outside")
    with pytest.raises(MutationGateError, match="逃逸"):
        load_profile(config, "events")


def test_profile_连续两次全量并追加_property_only(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    calls: list[list[str]] = []

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(list(command))
        if "results" in command:
            return subprocess.CompletedProcess(command, 0, "    a__mutmut_1: killed\n", "")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    report = run_profile(tmp_path, profile, runner=runner, require_posix=False)
    runs = cast(list[dict[str, object]], report["runs"])
    assert [item["kind"] for item in runs] == ["full", "full", "property-only"]
    assert len(calls) == 6
    assert [command for command in calls if "results" in command] == [
        ["uv", "run", "mutmut", "results", "--all", "true"],
        ["uv", "run", "mutmut", "results", "--all", "true"],
        ["uv", "run", "mutmut", "results", "--all", "true"],
    ]
    assert not (tmp_path / "setup.cfg").exists()
    assert (tmp_path / "mutants/reports/events.json").is_file()


def test_profile_命令失败时仍清理临时配置(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 7, "", "boom")

    with pytest.raises(MutationGateError, match="退出码为 7"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
    assert not (tmp_path / "setup.cfg").exists()


@pytest.mark.parametrize("name", ["events", "task-service"])
def test_仓库内固定_profile_只引用现存输入(name: str) -> None:
    profile = load_profile(PROJECT_ROOT / "tools/mutation_profiles.json", name)
    validate_inputs(PROJECT_ROOT, profile)
    for relative in (*profile.test_selection, *profile.property_test_selection):
        target = PROJECT_ROOT / relative
        assert target.is_file() or any(target.rglob("test*.py")), f"{relative} 没有可收集测试。"
