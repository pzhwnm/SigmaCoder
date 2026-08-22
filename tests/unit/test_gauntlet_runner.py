"""Gauntlet 入口的完成绑定单元测试。"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Sequence
from pathlib import Path

import pytest
import tools.gauntlet as gauntlet_module
from tools.check_junit import CORE_PROPERTY_NODEIDS
from tools.gauntlet import (
    GAUNTLET_LOCK_FILE,
    PROFILE_UBUNTU,
    PROFILE_WINDOWS,
    GauntletError,
    GauntletRunResult,
    Layer,
    LayerResult,
    RepositoryBinding,
    audit_completion,
    build_manifest,
    cleanup_paths,
    run_gauntlet,
    run_layer,
    validate_manifest,
    validate_platform,
)


def create_gauntlet_repo(root: Path) -> None:
    source = root / "src/sigmacoder/example.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    profiles = root / "tools/mutation_profiles.json"
    profiles.parent.mkdir()
    profiles.write_text('{"schema_version":1,"profiles":{}}\n', encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        "mutation-reports/\nmutants/\n.coverage*\n.pytest_cache/\nbuild/\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True, check=True)
    subprocess.run(["git", "add", "."], cwd=root, capture_output=True, check=True)
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


def completed(
    command: Sequence[str],
    returncode: int = 0,
    stdout: str | None = None,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    if stdout is None:
        stdout = "ok\n"
        if "tools.check_junit" in command:
            payload: dict[str, object] = {
                "ok": True,
                "reports": [
                    {
                        "path": command[-1],
                        "sha256": "0" * 64,
                        "tests": 1,
                        "failures": 0,
                        "errors": 0,
                        "skipped": 0,
                    }
                ],
            }
            if "--hypothesis-contract=t01-core-v1" in command:
                payload["hypothesis"] = {
                    "contract_version": "t01-core-v1",
                    "minimum_examples": 200,
                    "profile": "default",
                    "properties": [
                        {
                            "nodeid": nodeid,
                            "passing": 200,
                            "failing": 0,
                            "invalid": 0,
                            "max_examples": 200,
                            "shrink": "NOT_APPLICABLE",
                            "stats_sha256": f"{index:x}" * 64,
                        }
                        for index, nodeid in enumerate(CORE_PROPERTY_NODEIDS)
                    ],
                    "seed": 20260823,
                    "shrink": "NOT_APPLICABLE",
                }
            stdout = json.dumps(payload)
        elif "tools.check_semantic_report" in command:
            stdout = json.dumps(
                {
                    "ok": True,
                    "report_sha256": "a" * 64,
                    "git_head": "b" * 40,
                    "mutants": 8,
                }
            )
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_固定层清单完整且_windows_不含_mutation() -> None:
    layers = build_manifest(PROFILE_WINDOWS)
    validate_manifest(PROFILE_WINDOWS, layers)
    assert all(not layer.name.startswith("mutation-") for layer in layers)


def test_ubuntu_固定运行语义变异并在最终状态审计全部报告() -> None:
    layers = build_manifest(PROFILE_UBUNTU)
    semantic = next(item for item in layers if item.name == "mutation-semantic")
    assert semantic.commands == (
        ("uv", "run", "--frozen", "python", "tools/semantic_mutants.py"),
        ("uv", "run", "--frozen", "python", "-m", "tools.check_semantic_report"),
    )
    source_state = next(item for item in layers if item.name == "source-state")
    assert source_state.commands[-2] == (
        "uv",
        "run",
        "--frozen",
        "python",
        "-m",
        "tools.check_mutation_reports",
    )
    assert source_state.commands[-1] == (
        "uv",
        "run",
        "--frozen",
        "python",
        "-m",
        "tools.check_semantic_report",
    )


def test_属性层固定并显示_hypothesis_证据() -> None:
    layer = next(item for item in build_manifest(PROFILE_WINDOWS) if item.name == "properties")
    command = layer.commands[0]
    assert "--hypothesis-profile=default" in command
    assert "--hypothesis-seed=20260823" in command
    assert "--hypothesis-show-statistics" in command


def test_每个_pytest_层紧随唯一_junit_checker() -> None:
    pytest_layers = {
        "gauntlet-meta-tests",
        "tests",
        "coverage",
        "properties",
        "random-order-1",
        "random-order-2",
        "random-order-3",
        "real-execution",
    }
    reports: list[str] = []
    for layer in build_manifest(PROFILE_WINDOWS):
        if layer.name not in pytest_layers:
            continue
        pytest_indexes = [
            index for index, command in enumerate(layer.commands) if "pytest" in command
        ]
        assert len(pytest_indexes) == 1
        pytest_index = pytest_indexes[0]
        report_arguments = [
            item
            for item in layer.commands[pytest_index]
            if item.startswith("--junitxml=build/test-results/")
        ]
        assert len(report_arguments) == 1
        report = report_arguments[0].removeprefix("--junitxml=")
        reports.append(report)
        expected_checker = [
            "uv",
            "run",
            "--frozen",
            "python",
            "-m",
            "tools.check_junit",
        ]
        if layer.name == "properties":
            expected_checker.append("--hypothesis-contract=t01-core-v1")
        expected_checker.append(report)
        assert layer.commands[pytest_index + 1] == tuple(expected_checker)
    assert len(reports) == len(pytest_layers)
    assert len(set(reports)) == len(reports)


def test_gauntlet_meta_tests_只引用仓库内现存测试() -> None:
    repo = Path(__file__).resolve().parents[2]
    layer = next(
        item for item in build_manifest(PROFILE_WINDOWS) if item.name == "gauntlet-meta-tests"
    )
    selected = [
        argument
        for command in layer.commands
        for argument in command
        if argument.startswith("tests/")
    ]
    assert selected, "Gauntlet 必须显式选择元测试。"
    for relative in selected:
        target = repo / relative
        assert target.exists()
        assert target.is_file() or any(target.rglob("test*.py")), f"{relative} 没有可收集测试。"


def test_删除一个预期层时门禁失败() -> None:
    layers = build_manifest(PROFILE_WINDOWS)
    with pytest.raises(GauntletError, match="层清单不完整"):
        validate_manifest(PROFILE_WINDOWS, layers[:-1])


def test_已知失败命令使层失败(tmp_path: Path) -> None:
    layer = Layer(name="known-failure", commands=(("fake",),))

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command, returncode=9, stderr="预期失败")

    with pytest.raises(GauntletError, match="退出码为 9"):
        run_layer(layer, tmp_path, runner=runner)


def test_整层命令_exit0_但输出全空时_fail_closed(tmp_path: Path) -> None:
    layer = Layer(name="empty-success", commands=(("silent-one",), ("silent-two",)))

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command, stdout="", stderr="")

    with pytest.raises(GauntletError, match="未产生任何输出"):
        run_layer(layer, tmp_path, runner=runner)


def test_整层允许单条命令静默但要求至少一条有输出(tmp_path: Path) -> None:
    layer = Layer(name="mixed-output", commands=(("silent",), ("visible",)))

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "完成\n" if command[0] == "visible" else ""
        return completed(command, stdout=output)

    result = run_layer(layer, tmp_path, runner=runner)
    assert result.commands == 2


def test_mutation_checker_要求可解析且精确的_json_契约(tmp_path: Path) -> None:
    command = ("uv", "run", "--frozen", "python", "-m", "tools.check_mutation_reports")
    layer = Layer(name="source-state", commands=(command,))

    def invalid_json(invoked: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(invoked, stdout="not-json\n")

    with pytest.raises(GauntletError, match="未输出有效 JSON"):
        run_layer(layer, tmp_path, runner=invalid_json)

    def non_hex_digest(
        invoked: Sequence[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        payload = {"ok": True, "reports": {"events": "x" * 64, "task-service": "0" * 64}}
        return completed(invoked, stdout=json.dumps(payload))

    with pytest.raises(GauntletError, match="未证明两份有效报告"):
        run_layer(layer, tmp_path, runner=non_hex_digest)

    def valid_json(invoked: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        payload = {"ok": True, "reports": {"events": "a" * 64, "task-service": "0" * 64}}
        return completed(invoked, stdout=json.dumps(payload))

    result = run_layer(layer, tmp_path, runner=valid_json)
    assert result.commands == 1


def test_semantic_checker_要求八类报告且拒绝_bool_冒充整数(tmp_path: Path) -> None:
    command = ("uv", "run", "--frozen", "python", "-m", "tools.check_semantic_report")
    layer = Layer(name="semantic-report", commands=(command,))

    def invalid(invoked: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        payload = {
            "ok": True,
            "report_sha256": "a" * 64,
            "git_head": "b" * 40,
            "mutants": True,
        }
        return completed(invoked, stdout=json.dumps(payload))

    with pytest.raises(GauntletError, match="八类有效报告"):
        run_layer(layer, tmp_path, runner=invalid)

    result = run_layer(layer, tmp_path, runner=lambda command, **kwargs: completed(command))
    assert result.commands == 1


def test_junit_checker_json_拒绝_skipped_证据(tmp_path: Path) -> None:
    command = (
        "uv",
        "run",
        "--frozen",
        "python",
        "-m",
        "tools.check_junit",
        "build/test-results/tests.xml",
    )
    layer = Layer(name="tests", commands=(command,))

    def runner(invoked: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        payload = {
            "ok": True,
            "reports": [
                {
                    "path": invoked[-1],
                    "sha256": "0" * 64,
                    "tests": 1,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 1,
                }
            ],
        }
        return completed(invoked, stdout=json.dumps(payload))

    with pytest.raises(GauntletError, match="零失败、错误、跳过"):
        run_layer(layer, tmp_path, runner=runner)


def test_层摘要使用命令与输出边界_framing(tmp_path: Path) -> None:
    first = Layer(name="framing-a", commands=(("one",),))
    second = Layer(name="framing-b", commands=(("two",),))

    first_result = run_layer(
        first,
        tmp_path,
        runner=lambda command, **kwargs: completed(command, stdout="ab", stderr="c"),
    )
    second_result = run_layer(
        second,
        tmp_path,
        runner=lambda command, **kwargs: completed(command, stdout="a", stderr="bc"),
    )

    assert first_result.output_sha256 != second_result.output_sha256


@pytest.mark.parametrize("layer_name", ("mutation-events", "mutation-semantic"))
def test_变异子进程精确接收父_lease_token且_checker_不继承(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    layer_name: str,
) -> None:
    mutation_layer = next(
        layer for layer in build_manifest(PROFILE_UBUNTU) if layer.name == layer_name
    )
    token = "a" * 32
    monkeypatch.setenv("SIGMACODER_REPOSITORY_LEASE_TOKEN", "ambient-must-not-leak")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = kwargs["env"]
        is_child = (
            "tools/run_mutation_profile.py" in command or "tools/semantic_mutants.py" in command
        )
        if is_child:
            assert environment["SIGMACODER_REPOSITORY_LEASE_TOKEN"] == token
        else:
            assert "SIGMACODER_REPOSITORY_LEASE_TOKEN" not in environment
        return completed(command)

    run_layer(
        mutation_layer,
        tmp_path,
        runner=runner,
        repository_lease_token=token,
    )


def test_所有外部_python_工具统一使用_utf8_环境(tmp_path: Path) -> None:
    layer = Layer(name="utf8", commands=(("fake",),))

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = kwargs.get("env")
        assert isinstance(environment, dict)
        assert environment["PYTHONUTF8"] == "1"
        assert environment["PYTHONIOENCODING"] == "utf-8"
        assert environment.get("PATH") == os.environ.get("PATH")
        return completed(command)

    run_layer(layer, tmp_path, runner=runner)


def test_命令异常和超时均_fail_closed(tmp_path: Path) -> None:
    layer = Layer(name="broken", commands=(("fake",),))

    def missing(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("missing")

    with pytest.raises(GauntletError, match="无法执行"):
        run_layer(layer, tmp_path, runner=missing)

    def timeout(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, 1)

    with pytest.raises(GauntletError, match="超时"):
        run_layer(layer, tmp_path, runner=timeout)


def test_陈旧报告在执行前被删除(tmp_path: Path) -> None:
    for relative in (
        "coverage.json",
        "coverage.xml",
        "mutants",
        "mutation-reports/events.json",
        "mutation-reports/task-service.json",
        "mutation-reports/semantic.json",
    ):
        path = tmp_path / relative
        if path.suffix:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("stale", encoding="utf-8")
        else:
            path.mkdir()
            (path / "old").write_text("stale", encoding="utf-8")
    cleanup_paths(
        tmp_path,
        (
            "coverage.json",
            "coverage.xml",
            "mutants",
            "mutation-reports/events.json",
            "mutation-reports/task-service.json",
            "mutation-reports/semantic.json",
        ),
    )
    assert not (tmp_path / "coverage.json").exists()
    assert not (tmp_path / "mutants").exists()
    assert not (tmp_path / "mutation-reports/events.json").exists()
    assert not (tmp_path / "mutation-reports/task-service.json").exists()
    assert not (tmp_path / "mutation-reports/semantic.json").exists()


def test_并行_coverage_陈旧分片在执行前被删除(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)
    stale = tmp_path / ".coverage.worker-previous-run"
    stale.write_text("stale", encoding="utf-8")

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command)

    run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)
    assert not stale.exists()


def test_清理路径不能逃逸仓库(tmp_path: Path) -> None:
    with pytest.raises(GauntletError, match="逃逸"):
        cleanup_paths(tmp_path, ("../outside",))


def test_清理路径不能指向仓库根(tmp_path: Path) -> None:
    with pytest.raises(GauntletError, match="仓库根目录"):
        cleanup_paths(tmp_path, (".",))


def test_完成审计拒绝缺层() -> None:
    with pytest.raises(GauntletError, match="完成审计失败"):
        audit_completion(PROFILE_WINDOWS, [])


def test_windows_profile_完整假执行产生全部结果(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command)

    result = run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)
    assert len(result.layers) == len(build_manifest(PROFILE_WINDOWS))
    assert len(result.binding.git_head) in {40, 64}
    assert len(result.binding.protected_state_sha256) == 64


def test_gauntlet_崩溃残留_lease_在任何清理前_fail_closed(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)
    stale = tmp_path / "mutants/sentinel.txt"
    stale.parent.mkdir()
    stale.write_text("不得清理", encoding="utf-8")
    lock_path = tmp_path / "mutation-reports" / GAUNTLET_LOCK_FILE
    lock_path.parent.mkdir()
    lock_path.write_text("stale lease", encoding="utf-8")
    runner_called = False

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal runner_called
        runner_called = True
        return completed(command)

    with pytest.raises(GauntletError, match="已被占用或为崩溃残留"):
        run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)

    assert not runner_called
    assert stale.read_text(encoding="utf-8") == "不得清理"
    assert lock_path.read_text(encoding="utf-8") == "stale lease"


def test_gauntlet_并发运行不能清理活动运行的_mutants(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def first_runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if not entered.is_set():
            entered.set()
            assert release.wait(timeout=10), "测试未及时释放第一个 Gauntlet。"
        return completed(command)

    def execute_first() -> None:
        try:
            run_gauntlet(
                tmp_path,
                PROFILE_WINDOWS,
                runner=first_runner,
                enforce_platform=False,
            )
        except BaseException as exc:  # pragma: no cover - 失败由主线程断言呈现
            failures.append(exc)

    thread = threading.Thread(target=execute_first)
    thread.start()
    assert entered.wait(timeout=10), "第一个 Gauntlet 未进入持有全局 lease 的命令层。"
    active = tmp_path / "mutants/active-sentinel.txt"
    active.parent.mkdir()
    active.write_text("活动运行证据", encoding="utf-8")
    second_runner_called = False

    def second_runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal second_runner_called
        second_runner_called = True
        return completed(command)

    try:
        with pytest.raises(GauntletError, match="lease 已被占用|拒绝并发"):
            run_gauntlet(
                tmp_path,
                PROFILE_WINDOWS,
                runner=second_runner,
                enforce_platform=False,
            )
        assert not second_runner_called
        assert active.read_text(encoding="utf-8") == "活动运行证据"
    finally:
        release.set()
        thread.join(timeout=15)

    assert not thread.is_alive()
    assert not failures
    assert not (tmp_path / "mutation-reports" / GAUNTLET_LOCK_FILE).exists()


def test_gauntlet_层内源码漂移立即_fail_closed(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)
    source = tmp_path / "src/sigmacoder/example.py"
    changed = False

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal changed
        if not changed:
            source.write_text("VALUE = 2\n", encoding="utf-8")
            changed = True
        return completed(command)

    with pytest.raises(GauntletError, match="input_tree_sha256"):
        run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)

    assert not (tmp_path / "mutation-reports" / GAUNTLET_LOCK_FILE).exists()


def test_gauntlet_层内_git_head_漂移立即_fail_closed(tmp_path: Path) -> None:
    create_gauntlet_repo(tmp_path)
    changed = False

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal changed
        if not changed:
            (tmp_path / "head-drift.txt").write_text("新提交\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "head-drift.txt"],
                cwd=tmp_path,
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
                    "head drift",
                ],
                cwd=tmp_path,
                capture_output=True,
                check=True,
            )
            changed = True
        return completed(command)

    with pytest.raises(GauntletError, match="git_head"):
        run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)

    assert not (tmp_path / "mutation-reports" / GAUNTLET_LOCK_FILE).exists()


def test_gauntlet_最终_json_包含_commit_与受保护指纹(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binding = RepositoryBinding(
        git_head="a" * 40,
        git_status_sha256="b" * 64,
        input_tree_sha256="c" * 64,
        input_file_count=10,
        uv_lock_sha256="d" * 64,
        profile_manifest_sha256="e" * 64,
        mutation_profiles_sha256="f" * 64,
        protected_state_sha256="0" * 64,
    )
    result = GauntletRunResult(
        profile=PROFILE_WINDOWS,
        binding=binding,
        layers=(LayerResult("toolchain", 1, 0.1, "0" * 64),),
    )
    monkeypatch.setattr(gauntlet_module, "run_gauntlet", lambda *args, **kwargs: result)

    assert gauntlet_module.main(["--repo", str(tmp_path), "--profile", PROFILE_WINDOWS]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["binding"]["git_head"] == "a" * 40
    assert payload["binding"]["protected_state_sha256"] == "0" * 64


def test_平台_profile_不允许互换(tmp_path: Path) -> None:
    validate_platform(PROFILE_WINDOWS, "Windows")
    with pytest.raises(GauntletError, match="只能在 Windows"):
        validate_platform(PROFILE_WINDOWS, "Linux")

    ubuntu_release = tmp_path / "ubuntu-os-release"
    ubuntu_release.write_text('NAME="Ubuntu"\nID=ubuntu\n', encoding="utf-8")
    validate_platform(
        PROFILE_UBUNTU,
        "Linux",
        os_release_path=ubuntu_release,
    )
    with pytest.raises(GauntletError, match="只能在 Linux/Ubuntu"):
        validate_platform(
            PROFILE_UBUNTU,
            "Windows",
            os_release_path=ubuntu_release,
        )


@pytest.mark.parametrize(
    "contents",
    [
        'NAME="Debian GNU/Linux"\nID=debian\n',
        'NAME="Unknown"\n',
        "ID=ubuntu\nID=ubuntu\n",
    ],
)
def test_ubuntu_profile_要求_os_release_精确声明唯一_ubuntu_id(
    tmp_path: Path,
    contents: str,
) -> None:
    os_release = tmp_path / "os-release"
    os_release.write_text(contents, encoding="utf-8")

    with pytest.raises(GauntletError, match="Ubuntu 身份文件|只能在 Ubuntu"):
        validate_platform(PROFILE_UBUNTU, "Linux", os_release_path=os_release)
