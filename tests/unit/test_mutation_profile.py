"""Mutation profile 检查器的单元测试。"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest
import tools.run_mutation_profile as mutation_module
from mutmut.configuration import _load_config
from tools.check_mutation_reports import (
    MutationReportError,
    check_reports,
    validate_report_payload,
)
from tools.repo_lease import (
    REPOSITORY_LEASE_FILE,
    REPOSITORY_LEASE_TOKEN_ENV,
    acquire_repository_lease,
)
from tools.run_mutation_profile import (
    KNOWN_STATUSES,
    MUTATION_LOCK_FILE,
    MutationGateError,
    load_profile,
    parse_mutmut_results,
    run_profile,
    validate_inputs,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENT_TEST_SELECTION = (
    "tests/unit/test_event_chain.py",
    "tests/unit/test_event_semantics.py",
    "tests/unit/test_projection_checkpoint.py",
    "tests/adversarial/test_corrupt_event_chain.py",
    "tests/property/test_event_generated_properties.py",
)
EVENT_PROPERTY_SELECTION = ("tests/property/test_event_generated_properties.py",)
TASK_TEST_SELECTION = (
    "tests/unit/test_task_service_branches.py",
    "tests/integration",
    "tests/e2e",
)


def write_profile(
    root: Path,
    *,
    cache_dir: str = "mutants",
    report_path: str = "mutation-reports/events.json",
    repeat: int = 2,
    test_selection: Sequence[str] = EVENT_TEST_SELECTION,
    property_test_selection: Sequence[str] = EVENT_PROPERTY_SELECTION,
) -> Path:
    payload = {
        "schema_version": 1,
        "profiles": {
            "events": {
                "source_paths": ["src/sigmacoder"],
                "only_mutate": ["src/sigmacoder/domain/events.py"],
                "test_selection": list(test_selection),
                "property_test_selection": list(property_test_selection),
                "timeout_seconds": 1800,
                "timeout_multiplier": 15.0,
                "timeout_constant": 1.0,
                "max_children": 4,
                "repeat": repeat,
                "cache_dir": cache_dir,
                "report_path": report_path,
            },
            "task-service": {
                "source_paths": ["src/sigmacoder"],
                "only_mutate": ["src/sigmacoder/application/task_service.py"],
                "test_selection": list(TASK_TEST_SELECTION),
                "property_test_selection": [],
                "timeout_seconds": 1800,
                "timeout_multiplier": 15.0,
                "timeout_constant": 1.0,
                "max_children": 4,
                "repeat": 2,
                "cache_dir": "mutants",
                "report_path": "mutation-reports/task-service.json",
            },
        },
    }
    path = root / "profiles.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def create_inputs(root: Path) -> None:
    source = root / "src/sigmacoder/domain/events.py"
    source.parent.mkdir(parents=True)
    source.write_text("def value():\n    return 1\n", encoding="utf-8")
    task_source = root / "src/sigmacoder/application/task_service.py"
    task_source.parent.mkdir(parents=True)
    task_source.write_text("def task_value():\n    return 1\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname = 'fixture'\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    for relative in EVENT_TEST_SELECTION:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# 测试占位。\n", encoding="utf-8")
    for relative in TASK_TEST_SELECTION:
        target = root / relative
        if target.suffix == ".py":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# 测试占位。\n", encoding="utf-8")
        else:
            target.mkdir(parents=True, exist_ok=True)
            (target / "test_placeholder.py").write_text("# 测试占位。\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        "mutants/\nmutation-reports/\n__pycache__/\n*.pyc\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "init", "-q"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "add", "."],
        cwd=root,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=SigmaCoder Tests",
            "-c",
            "user.email=tests@sigmacoder.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        cwd=root,
        capture_output=True,
        check=True,
    )


def is_mutmut_command(command: Sequence[str], subcommand: str) -> bool:
    return len(command) > 4 and command[3:5] == ["mutmut", subcommand]


def run_successful_events_profile(
    root: Path,
) -> tuple[object, dict[str, object], Path]:
    create_inputs(root)
    config = write_profile(root)
    profile = load_profile(config, "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = kwargs.get("env")
        assert isinstance(environment, dict)
        assert REPOSITORY_LEASE_TOKEN_ENV not in environment
        if is_mutmut_command(command, "results"):
            return subprocess.CompletedProcess(command, 0, "    a__mutmut_1: killed\n", "")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    report = run_profile(root, profile, runner=runner, require_posix=False)
    return profile, report, config


def test_mutmut_results_只接受非空且全部_killed() -> None:
    assert parse_mutmut_results("    a__mutmut_1: killed\n") == {"a__mutmut_1": "killed"}
    with pytest.raises(MutationGateError, match="未返回任何"):
        parse_mutmut_results("")
    with pytest.raises(MutationGateError, match="未被测试杀死"):
        parse_mutmut_results("    a__mutmut_1: survived\n")
    with pytest.raises(MutationGateError, match="未知状态"):
        parse_mutmut_results("    a__mutmut_1: magical\n")


@pytest.mark.parametrize("status", sorted(KNOWN_STATUSES - {"killed"}))
def test_mutmut_results_拒绝每一种非_killed_状态(status: str) -> None:
    output = f"    killed__mutmut_1: killed\n    failed__mutmut_2: {status}\n"

    with pytest.raises(MutationGateError, match="未被测试杀死"):
        parse_mutmut_results(output)


@pytest.mark.parametrize(
    "output",
    [
        "unexpected\n    a__mutmut_1: killed\n",
        "    a__mutmut_1: killed\nmalformed",
    ],
)
def test_mutmut_results_拒绝任何非空畸形行(output: str) -> None:
    with pytest.raises(MutationGateError, match="无法解析"):
        parse_mutmut_results(output)


def test_profile_拒绝逃逸缓存路径(tmp_path: Path) -> None:
    config = write_profile(tmp_path, cache_dir="../outside")
    with pytest.raises(MutationGateError, match="逃逸"):
        load_profile(config, "events")


@pytest.mark.parametrize("cache_dir", [".", "src", "tests"])
def test_profile_拒绝把仓库或源码目录设为缓存(tmp_path: Path, cache_dir: str) -> None:
    config = write_profile(tmp_path, cache_dir=cache_dir)
    with pytest.raises(MutationGateError, match="cache_dir 必须精确"):
        load_profile(config, "events")


def test_profile_拒绝降低重复次数(tmp_path: Path) -> None:
    config = write_profile(tmp_path, repeat=1)
    with pytest.raises(MutationGateError, match="repeat 必须精确为 2"):
        load_profile(config, "events")


@pytest.mark.parametrize(
    "selection",
    [(), ("tests/property/test_event_chain_properties.py",)],
)
def test_events_profile_拒绝删除或替换纯属性入口(
    tmp_path: Path,
    selection: Sequence[str],
) -> None:
    config = write_profile(tmp_path, property_test_selection=selection)
    with pytest.raises(MutationGateError, match="property_test_selection"):
        load_profile(config, "events")


def test_profile_拒绝把持久报告放入易失缓存(tmp_path: Path) -> None:
    config = write_profile(tmp_path, report_path="mutants/reports/events.json")
    with pytest.raises(MutationGateError, match="report_path"):
        load_profile(config, "events")


def test_profile_拒绝缺少固定测试选择器(tmp_path: Path) -> None:
    config = write_profile(tmp_path, test_selection=EVENT_TEST_SELECTION[:-1])
    with pytest.raises(MutationGateError, match="test_selection"):
        load_profile(config, "events")


def test_profile_连续两次全量并追加_property_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    monkeypatch.chdir(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    calls: list[list[str]] = []
    mutation_runs = 0

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal mutation_runs
        calls.append(list(command))
        if is_mutmut_command(command, "run"):
            parsed = _load_config()
            assert parsed.pytest_add_cli_args == [
                "-q",
                "--hypothesis-profile=default",
                "--hypothesis-seed=20260823",
            ]
            expected_selection = (
                list(EVENT_PROPERTY_SELECTION) if mutation_runs == 2 else list(EVENT_TEST_SELECTION)
            )
            assert parsed.pytest_add_cli_args_test_selection == expected_selection
            marker = tmp_path / "mutants/previous-run"
            assert not marker.exists(), "每轮 mutation 前必须清空易失缓存。"
            marker.parent.mkdir()
            marker.write_text(str(mutation_runs), encoding="utf-8")
            ignored_cache = tmp_path / "src/sigmacoder/__pycache__/ignored.pyc"
            ignored_cache.parent.mkdir(exist_ok=True)
            ignored_cache.write_bytes(b"ignored")
            mutation_runs += 1
            return subprocess.CompletedProcess(command, 0, "run ok\n", "")
        return subprocess.CompletedProcess(command, 0, "    a__mutmut_1: killed\n", "")

    report = run_profile(tmp_path, profile, runner=runner, require_posix=False)
    runs = cast(list[dict[str, object]], report["runs"])
    assert [item["kind"] for item in runs] == ["full", "full", "property-only"]
    assert mutation_runs == 3
    assert len(calls) == 6
    assert [command for command in calls if is_mutmut_command(command, "results")] == [
        ["uv", "run", "--frozen", "mutmut", "results", "--all", "true"],
        ["uv", "run", "--frozen", "mutmut", "results", "--all", "true"],
        ["uv", "run", "--frozen", "mutmut", "results", "--all", "true"],
    ]
    assert not (tmp_path / "setup.cfg").exists()
    assert (tmp_path / "mutation-reports/events.json").is_file()
    assert not list((tmp_path / "mutation-reports").glob(".events.json.*.tmp"))
    mutant_evidence = cast(dict[str, object], report["mutants"])
    assert mutant_evidence["names"] == ["a__mutmut_1"]
    assert len(cast(str, mutant_evidence["names_sha256"])) == 64
    assert len({cast(str, item["source_fingerprint"]) for item in runs}) == 1
    evidence = cast(dict[str, object], report["evidence"])
    validate_report_payload(
        report,
        profile,
        source_fingerprint=cast(str, evidence["source_fingerprint"]),
        git_head=cast(str, evidence["git_head"]),
        uv_lock_sha256=cast(str, evidence["uv_lock_sha256"]),
    )
    assert not (tmp_path / "mutation-reports/.events.json.tmp").exists()


def test_profile_命令失败时仍清理临时配置(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 7, "", "boom")

    with pytest.raises(MutationGateError, match="退出码为 7"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
    assert not (tmp_path / "setup.cfg").exists()
    assert not (tmp_path / "mutation-reports" / MUTATION_LOCK_FILE).exists()
    assert not (tmp_path / "mutation-reports" / REPOSITORY_LEASE_FILE).exists()


def test_profile_拒绝_broken_setup_cfg_链接且不创建目标(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    setup_path = tmp_path / "setup.cfg"
    target = tmp_path / "setup-target"
    try:
        if os.name == "nt":
            target.mkdir()
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(setup_path), str(target)],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                pytest.skip("当前 Windows 环境无法创建 junction。")
            os.rmdir(target)
        else:
            setup_path.symlink_to(target)
        assert os.path.lexists(setup_path)

        with pytest.raises(MutationGateError, match="setup.cfg.*链接|junction"):
            run_profile(tmp_path, profile, require_posix=False)

        assert not target.exists()
    finally:
        if os.path.lexists(setup_path):
            if os.name == "nt":
                os.rmdir(setup_path)
            else:
                setup_path.unlink()


def test_profile_临时配置使用独占创建且不覆盖既有文件(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    setup_path = tmp_path / "setup.cfg"
    setup_path.write_text("必须保留\n", encoding="utf-8")

    with pytest.raises(MutationGateError, match="已存在 setup.cfg"):
        mutation_module._write_setup_cfg(tmp_path, profile, EVENT_TEST_SELECTION)

    assert setup_path.read_text(encoding="utf-8") == "必须保留\n"


def test_profile_跨_profile_共享仓库级原子互斥锁(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    config = write_profile(tmp_path)
    events_profile = load_profile(config, "events")
    task_profile = load_profile(config, "task-service")
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def first_runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_mutmut_command(command, "run") and not entered.is_set():
            entered.set()
            assert release.wait(timeout=10), "测试未及时释放第一个 mutation 运行。"
        if is_mutmut_command(command, "results"):
            return subprocess.CompletedProcess(command, 0, "    a__mutmut_1: killed\n", "")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    def execute_first() -> None:
        try:
            run_profile(tmp_path, events_profile, runner=first_runner, require_posix=False)
        except BaseException as exc:  # pragma: no cover - 失败由主线程断言呈现
            failures.append(exc)

    thread = threading.Thread(target=execute_first)
    thread.start()
    assert entered.wait(timeout=10), "第一个 mutation 运行未进入受锁区间。"
    second_runner_called = False

    def second_runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal second_runner_called
        second_runner_called = True
        return subprocess.CompletedProcess(command, 0, "不应执行\n", "")

    try:
        with pytest.raises(MutationGateError, match="仓库锁已被占用|拒绝并发"):
            run_profile(
                tmp_path,
                task_profile,
                runner=second_runner,
                require_posix=False,
            )
        assert not second_runner_called
    finally:
        release.set()
        thread.join(timeout=10)

    assert not thread.is_alive()
    assert not failures
    assert not (tmp_path / "mutation-reports" / MUTATION_LOCK_FILE).exists()


def test_profile_拒绝自动清理崩溃残留锁(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    lock_path = tmp_path / "mutation-reports" / MUTATION_LOCK_FILE
    lock_path.parent.mkdir()
    residue = '{"pid":1,"profile":"events","token":"residue"}'
    lock_path.write_text(residue, encoding="utf-8")

    with pytest.raises(MutationGateError, match="崩溃残留"):
        run_profile(tmp_path, profile, require_posix=False)

    assert lock_path.read_text(encoding="utf-8") == residue


def test_profile_精确匹配_gauntlet_父_lease_token_后获取子锁(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = kwargs.get("env")
        assert isinstance(environment, dict)
        assert REPOSITORY_LEASE_TOKEN_ENV not in environment
        if is_mutmut_command(command, "results"):
            return subprocess.CompletedProcess(command, 0, "    a__mutmut_1: killed\n", "")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    with acquire_repository_lease(tmp_path, "gauntlet:test") as parent_lease:
        monkeypatch.setenv(REPOSITORY_LEASE_TOKEN_ENV, parent_lease.token)
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
        assert parent_lease.path.is_file()
        assert not (tmp_path / "mutation-reports" / MUTATION_LOCK_FILE).exists()

    assert not (tmp_path / "mutation-reports" / REPOSITORY_LEASE_FILE).exists()


def test_profile_拒绝伪造或不匹配的_gauntlet_父_lease_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    runner_called = False

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal runner_called
        runner_called = True
        return subprocess.CompletedProcess(command, 0, "不应执行\n", "")

    with acquire_repository_lease(tmp_path, "gauntlet:test") as parent_lease:
        original_payload = parent_lease.path.read_bytes()
        monkeypatch.setenv(REPOSITORY_LEASE_TOKEN_ENV, "0" * 32)
        with pytest.raises(MutationGateError, match="不精确匹配"):
            run_profile(tmp_path, profile, runner=runner, require_posix=False)
        assert parent_lease.path.read_bytes() == original_payload

    assert not runner_called


def test_profile_临时配置创建失败时不删除无法证明归属的文件(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def broken_write(repo: Path, profile: object, tests: Sequence[str]) -> Path:
        path = repo / "setup.cfg"
        path.write_text("[mutmut]\npartial", encoding="utf-8")
        raise MutationGateError("预期的半写失败")

    monkeypatch.setattr(mutation_module, "_write_setup_cfg", broken_write)
    with pytest.raises(MutationGateError, match="源码或 Git 状态未恢复"):
        run_profile(tmp_path, profile, require_posix=False)
    assert (tmp_path / "setup.cfg").read_text(encoding="utf-8") == "[mutmut]\npartial"


def test_profile_运行中替换临时配置时拒绝删除未知文件(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    setup_path = tmp_path / "setup.cfg"

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_mutmut_command(command, "run"):
            setup_path.unlink()
            setup_path.write_text("外部替换文件\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 7, "", "boom")
        return subprocess.CompletedProcess(command, 0, "不应执行\n", "")

    with pytest.raises(MutationGateError, match="拒绝删除未知"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)

    assert setup_path.read_text(encoding="utf-8") == "外部替换文件\n"


def test_profile_results_命令失败时仍清理临时配置(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_mutmut_command(command, "results"):
            return subprocess.CompletedProcess(command, 2, "", "bad option")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    with pytest.raises(MutationGateError, match="mutmut results 退出码为 2"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
    assert not (tmp_path / "setup.cfg").exists()


def test_profile_拒绝运行器污染源码且优先报告指纹错误(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    source = tmp_path / "src/sigmacoder/domain/events.py"

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_mutmut_command(command, "run"):
            source.write_text("def value():\n    return 2\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 9, "", "mutation failed")
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(MutationGateError, match="源码或 Git 状态未恢复"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
    assert not (tmp_path / "setup.cfg").exists()


def test_profile_拒绝运行器新增未忽略文件(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_mutmut_command(command, "run"):
            (tmp_path / "unexpected.txt").write_text("污染", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "run ok\n", "")
        return subprocess.CompletedProcess(command, 0, "    a: killed\n", "")

    with pytest.raises(MutationGateError, match="源码或 Git 状态未恢复"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)


def test_profile_拒绝各轮枚举出不同_mutant_集合(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    result_calls = 0

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal result_calls
        if is_mutmut_command(command, "results"):
            result_calls += 1
            name = "a" if result_calls == 1 else "b"
            return subprocess.CompletedProcess(command, 0, f"    {name}: killed\n", "")
        return subprocess.CompletedProcess(command, 0, "run ok\n", "")

    with pytest.raises(MutationGateError, match="mutant 集合不一致"):
        run_profile(tmp_path, profile, runner=runner, require_posix=False)
    assert not (tmp_path / "mutation-reports/events.json").exists()


def test_profile_拒绝各轮源码基线指纹变化(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    calls = 0

    def fake_run_once(
        repo: Path,
        loaded_profile: object,
        tests: Sequence[str],
        *,
        runner: object,
    ) -> tuple[dict[str, str], str]:
        nonlocal calls
        calls += 1
        return {"a": "killed"}, f"fingerprint-{calls}"

    monkeypatch.setattr(mutation_module, "_run_once", fake_run_once)
    with pytest.raises(MutationGateError, match="运行前的源码或 Git 状态指纹不一致"):
        run_profile(tmp_path, profile, runner=lambda *args, **kwargs: None, require_posix=False)


def test_profile_拒绝把普通文件当作缓存目录(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    (tmp_path / "mutants").write_text("不是目录", encoding="utf-8")
    profile = load_profile(write_profile(tmp_path), "events")

    with pytest.raises(MutationGateError, match="cache 必须是目录"):
        run_profile(tmp_path, profile, require_posix=False)


def test_profile_拒绝缓存目录链接且不伤害目标(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    target = tmp_path / "sentinel"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("必须保留", encoding="utf-8")
    link = tmp_path / "mutants"
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                pytest.skip("当前 Windows 环境无法创建 junction。")
        else:
            link.symlink_to(target, target_is_directory=True)
        profile = load_profile(write_profile(tmp_path), "events")
        with pytest.raises(MutationGateError, match="固定专用目录"):
            run_profile(tmp_path, profile, require_posix=False)
        assert sentinel.read_text(encoding="utf-8") == "必须保留"
    finally:
        if link.is_symlink():
            link.unlink()
        elif link.exists():
            os.rmdir(link)


def test_profile_cache_隔离后身份变化时保留外部_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_inputs(tmp_path)
    cache = tmp_path / "mutants"
    cache.mkdir()
    (cache / "owned.txt").write_text("原缓存", encoding="utf-8")
    profile = load_profile(write_profile(tmp_path), "events")
    original_backup = tmp_path / "original-cache-backup"
    real_rename = os.rename
    quarantines: list[Path] = []

    def raced_rename(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        if source_path == cache:
            real_rename(source_path, original_backup)
            source_path.mkdir()
            (source_path / "external-sentinel.txt").write_text(
                "外部文件必须保留",
                encoding="utf-8",
            )
            real_rename(source_path, destination_path)
            quarantines.append(destination_path)
            return
        real_rename(source_path, destination_path)

    monkeypatch.setattr(mutation_module.os, "rename", raced_rename)
    with pytest.raises(MutationGateError, match="隔离后身份不匹配"):
        run_profile(tmp_path, profile, require_posix=False)

    assert len(quarantines) == 1
    assert quarantines[0].parent == tmp_path / "mutation-reports"
    assert (quarantines[0] / "external-sentinel.txt").read_text(
        encoding="utf-8"
    ) == "外部文件必须保留"
    assert (original_backup / "owned.txt").read_text(encoding="utf-8") == "原缓存"


def test_profile_report_临时文件被替换时保留外部_sentinel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "mutation-reports/events.json"
    report_path.parent.mkdir()
    owned_backup = tmp_path / "owned-report-temp"
    real_replace = os.replace
    replaced_paths: list[Path] = []

    def raced_replace(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        source_path = Path(source)
        real_replace(source_path, owned_backup)
        source_path.write_text("外部临时报告必须保留", encoding="utf-8")
        replaced_paths.append(source_path)
        raise OSError("注入报告发布竞态")

    monkeypatch.setattr(mutation_module.os, "replace", raced_replace)
    with pytest.raises(MutationGateError, match="临时文件身份已变化"):
        mutation_module._write_report_atomic(report_path, {"ok": True})

    assert len(replaced_paths) == 1
    temporary = replaced_paths[0]
    assert temporary.name.startswith(".events.json.")
    assert temporary.name.endswith(".tmp")
    assert temporary.name != ".events.json.tmp"
    assert temporary.read_text(encoding="utf-8") == "外部临时报告必须保留"
    assert owned_backup.is_file()
    assert not report_path.exists()


def test_profile_报告目标是链接时不删除外部_sentinel(tmp_path: Path) -> None:
    create_inputs(tmp_path)
    profile = load_profile(write_profile(tmp_path), "events")
    report_root = tmp_path / "mutation-reports"
    report_root.mkdir()
    report_path = report_root / "events.json"
    target = tmp_path / "external-report-target"
    try:
        if os.name == "nt":
            target.mkdir()
            (target / "sentinel.txt").write_text("必须保留", encoding="utf-8")
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(report_path), str(target)],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                pytest.skip("当前 Windows 环境无法创建 junction。")
        else:
            target.write_text("必须保留", encoding="utf-8")
            report_path.symlink_to(target)

        with pytest.raises(MutationGateError, match="report 路径"):
            run_profile(tmp_path, profile, require_posix=False)

        sentinel = target / "sentinel.txt" if target.is_dir() else target
        assert sentinel.read_text(encoding="utf-8") == "必须保留"
    finally:
        if report_path.is_symlink():
            report_path.unlink()
        elif report_path.exists():
            os.rmdir(report_path)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("survivor", "survivors=0"),
        ("empty", "不得是空"),
        ("digest", "数量或摘要"),
        ("runs", "运行次数"),
        ("source", "未绑定当前提交"),
    ],
)
def test_mutation_report_拒绝不完整或不新鲜证据(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    profile_object, report, _ = run_successful_events_profile(tmp_path)
    profile = cast(mutation_module.MutationProfile, profile_object)
    evidence = cast(dict[str, object], report["evidence"])
    broken = copy.deepcopy(report)
    if case == "survivor":
        broken["survivors"] = 1
    elif case == "empty":
        cast(dict[str, object], broken["mutants"])["names"] = []
    elif case == "digest":
        cast(dict[str, object], broken["mutants"])["names_sha256"] = "0" * 64
    elif case == "runs":
        cast(list[object], broken["runs"]).pop()
    else:
        cast(dict[str, object], broken["evidence"])["source_fingerprint"] = "0" * 64

    with pytest.raises(MutationReportError, match=message):
        validate_report_payload(
            broken,
            profile,
            source_fingerprint=cast(str, evidence["source_fingerprint"]),
            git_head=cast(str, evidence["git_head"]),
            uv_lock_sha256=cast(str, evidence["uv_lock_sha256"]),
        )


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("schema", "不得是布尔值"),
        ("survivors", "不得是布尔值"),
        ("count", "不得是布尔值"),
        ("run", "不得是布尔值"),
        ("run_mutants", "不得是布尔值"),
        ("seed", "未绑定当前提交"),
        ("profile", "schema 或 profile"),
    ],
)
def test_mutation_report_所有数值字段拒绝_bool(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    profile_object, report, _ = run_successful_events_profile(tmp_path)
    profile = cast(mutation_module.MutationProfile, profile_object)
    evidence = cast(dict[str, object], report["evidence"])
    broken = copy.deepcopy(report)
    if case == "schema":
        broken["schema_version"] = True
    elif case == "survivors":
        broken["survivors"] = False
    elif case == "count":
        cast(dict[str, object], broken["mutants"])["count"] = True
    elif case == "run":
        cast(dict[str, object], cast(list[object], broken["runs"])[0])["run"] = True
    elif case == "run_mutants":
        cast(dict[str, object], cast(list[object], broken["runs"])[0])["mutants"] = True
    elif case == "seed":
        cast(dict[str, object], broken["evidence"])["hypothesis_seed"] = True
    else:
        cast(dict[str, object], broken["profile"])["timeout_constant"] = True

    with pytest.raises(MutationReportError, match=message):
        validate_report_payload(
            broken,
            profile,
            source_fingerprint=cast(str, evidence["source_fingerprint"]),
            git_head=cast(str, evidence["git_head"]),
            uv_lock_sha256=cast(str, evidence["uv_lock_sha256"]),
        )


def test_mutation_report_最终审计要求两个_profile_同时存在(tmp_path: Path) -> None:
    _, _, config = run_successful_events_profile(tmp_path)

    with pytest.raises(MutationReportError, match="task-service"):
        check_reports(tmp_path, config)


@pytest.mark.parametrize("name", ["events", "task-service"])
def test_仓库内固定_profile_只引用现存输入(name: str) -> None:
    profile = load_profile(PROJECT_ROOT / "tools/mutation_profiles.json", name)
    validate_inputs(PROJECT_ROOT, profile)
    assert profile.repeat == 2
    assert profile.cache_dir == "mutants"
    assert profile.report_path == f"mutation-reports/{name}.json"
    if name == "events":
        assert profile.property_test_selection == EVENT_PROPERTY_SELECTION
    else:
        assert not profile.property_test_selection
    for relative in (*profile.test_selection, *profile.property_test_selection):
        target = PROJECT_ROOT / relative
        assert target.is_file() or any(target.rglob("test*.py")), f"{relative} 没有可收集测试。"
