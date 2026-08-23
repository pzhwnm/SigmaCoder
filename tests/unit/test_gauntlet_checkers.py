"""Gauntlet 自制检查器的负控单元测试。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import tools.check_secrets as secrets_module
from tools.check_secrets import (
    DETECT_SECRETS_VERSION,
    DISABLED_SECRET_FILTERS,
    EXPECTED_SECRET_FILTER_CONFIGS,
    EXPECTED_SECRET_PLUGIN_CONFIGS,
    EXPECTED_SEMANTIC_WAIVERS,
    SEMANTIC_MANIFEST_PATH,
    SecretGateError,
    parse_scan_output,
    scan_repository,
)
from tools.check_toolchain import ToolchainError, check_toolchain, validate_versions

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_HASH_FIELD = re.compile(
    r'\s*"expected_(?:source|mutant)_sha256": "(?P<value>[0-9a-f]{64})",?\s*\Z'
)


def completed(
    *, stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["fake"], returncode, stdout, stderr)


def is_git_command(command: list[str]) -> bool:
    return "rev-parse" in command or "ls-files" in command


def fake_git_success(command: list[str], listing: str) -> subprocess.CompletedProcess[str]:
    assert Path(command[0]).is_absolute()
    assert "-C" in command
    repo = Path(command[command.index("-C") + 1])
    if "rev-parse" in command:
        return completed(stdout=f"{repo}\n")
    if "ls-files" in command:
        return completed(stdout=listing)
    raise AssertionError(f"未知 Git 命令：{command!r}")


def scanner_payload_for_command(
    command: list[str],
    results: dict[str, list[object]],
) -> str:
    scanned = command[-1].removeprefix("./").replace("\\", "/")
    selected = {
        path: findings for path, findings in results.items() if path.replace("\\", "/") == scanned
    }
    return secret_payload(selected)


def secret_payload(results: dict[str, list[object]]) -> str:
    return json.dumps(
        {
            "version": DETECT_SECRETS_VERSION,
            "plugins_used": [dict(config) for config in EXPECTED_SECRET_PLUGIN_CONFIGS],
            "filters_used": [dict(config) for config in EXPECTED_SECRET_FILTER_CONFIGS],
            "results": results,
        }
    )


def isolated_scanner_prefix() -> list[str]:
    command = [
        sys.executable,
        "-I",
        "-X",
        "utf8",
        "-B",
        "-m",
        "detect_secrets",
        "scan",
        "--no-verify",
    ]
    for filter_path in DISABLED_SECRET_FILTERS:
        command.extend(("--disable-filter", filter_path))
    return command


def secret_finding(
    secret_type: str = "AWS Access Key",
    *,
    filename: str = "tracked.txt",
    line_number: int = 1,
    hashed_secret: str = "a" * 40,
    is_verified: bool = False,
) -> dict[str, object]:
    return {
        "type": secret_type,
        "filename": filename,
        "hashed_secret": hashed_secret,
        "is_verified": is_verified,
        "line_number": line_number,
    }


def semantic_input_paths() -> tuple[str, ...]:
    payload = json.loads((PROJECT_ROOT / SEMANTIC_MANIFEST_PATH).read_text(encoding="utf-8"))
    paths = {SEMANTIC_MANIFEST_PATH}
    for mutant in payload["mutants"]:
        paths.add(mutant["source"])
        paths.update(selector.split("::", 1)[0] for selector in mutant["selectors"])
    return tuple(sorted(paths))


def semantic_results() -> dict[str, list[object]]:
    findings: list[object] = []
    seen: set[str] = set()
    manifest = PROJECT_ROOT / SEMANTIC_MANIFEST_PATH
    result_path = SEMANTIC_MANIFEST_PATH.replace("/", "\\")
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        match = _HASH_FIELD.fullmatch(line)
        if match is None:
            continue
        hashed_secret = hashlib.sha1(
            match["value"].encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        if hashed_secret in seen:
            continue
        seen.add(hashed_secret)
        findings.append(
            secret_finding(
                "Hex High Entropy String",
                filename=result_path,
                line_number=line_number,
                hashed_secret=hashed_secret,
            )
        )
    assert len(findings) == EXPECTED_SEMANTIC_WAIVERS
    return {result_path: findings}


def copy_semantic_inputs(destination: Path) -> tuple[str, ...]:
    paths = semantic_input_paths()
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, target)
    return paths


def test_工具链要求精确版本() -> None:
    validate_versions("3.12.14", "uv 0.12.5\n")
    with pytest.raises(ToolchainError, match="Python 版本错误"):
        validate_versions("3.12.4", "uv 0.12.5\n")
    with pytest.raises(ToolchainError, match="uv 版本错误"):
        validate_versions("3.12.14", "uv 0.6.9\n")


def test_工具链同时核验仓库元数据且拒绝仓库内_uv_影子(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".python-version").write_text("3.12.14\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.uv]\nrequired-version = "==0.12.5"\n', encoding="utf-8"
    )
    shadow_name = "uv.exe" if os.name == "nt" else "uv"
    shutil.copy2(sys.executable, tmp_path / shadow_name)
    (tmp_path / shadow_name).chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))

    def runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        executable = Path(command[0])
        assert executable.is_absolute()
        assert not executable.is_relative_to(tmp_path)
        assert kwargs["cwd"] == executable.parent
        return completed(stdout="uv 0.12.5\n")

    check_toolchain(tmp_path, runner=runner, python_version="3.12.14")


def test_secret_scan_json_发现内容时_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")
    payload: dict[str, list[object]] = {"tracked.txt": [secret_finding()]}

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        return completed(stdout=scanner_payload_for_command(command, payload))

    with pytest.raises(SecretGateError, match="发现 1 个"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_破损输出和扫描器错误均拒绝(tmp_path: Path) -> None:
    with pytest.raises(SecretGateError, match="有效 JSON"):
        parse_scan_output("not-json")

    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        return completed(returncode=2, stderr="boom")

    with pytest.raises(SecretGateError, match="退出码"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_在只读_staged_snapshot_显式扫描全部_git_输入(tmp_path: Path) -> None:
    tracked = ("tools/scan-input.json", "-leading-name.txt")
    for relative in tracked:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        if is_git_command(command):
            environment = kwargs["env"]
            assert isinstance(environment, dict)
            assert Path(str(kwargs["cwd"])) == Path(command[0]).parent
            assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
            assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
            assert environment["GIT_ATTR_NOSYSTEM"] == "1"
            assert environment["GIT_CONFIG_COUNT"] == "0"
            assert not {
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_INDEX_FILE",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            }.intersection(environment)
            return fake_git_success(command, "tools/scan-input.json\0-leading-name.txt\0")
        staged = Path(str(kwargs["cwd"]))
        assert staged != tmp_path
        assert (staged / "tools/scan-input.json").read_text(encoding="utf-8") == "fixture\n"
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert environment["PYTHONUTF8"] == "1"
        assert environment["PYTHONIOENCODING"] == "utf-8"
        assert "PYTHONPATH" not in environment
        assert "PYTHONHOME" not in environment
        assert "PATH" not in environment
        assert "HOME" not in environment
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["shell"] is False
        return completed(stdout=secret_payload({}))

    evidence = scan_repository(tmp_path, runner=runner)
    assert evidence.waived_findings == 0
    git_calls = [(command, kwargs) for command, kwargs in calls if is_git_command(command)]
    scanner_calls = [(command, kwargs) for command, kwargs in calls if not is_git_command(command)]
    assert ["rev-parse" if "rev-parse" in command else "ls-files" for command, _ in git_calls] == [
        "rev-parse",
        "ls-files",
        "rev-parse",
        "ls-files",
    ]
    assert [command for command, _ in scanner_calls] == [
        [*isolated_scanner_prefix(), "./tools/scan-input.json"],
        [*isolated_scanner_prefix(), "./-leading-name.txt"],
    ]
    staged_path = Path(str(scanner_calls[0][1]["cwd"]))
    assert all(Path(str(kwargs["cwd"])) == staged_path for _, kwargs in scanner_calls)
    assert not staged_path.exists()


def test_secret_scan_拒绝_repo_不是_git_worktree_根(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    different_root = tmp_path / "different-root"
    repo.mkdir()
    different_root.mkdir()

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert "rev-parse" in command
        return completed(stdout=f"{different_root}\n")

    with pytest.raises(SecretGateError, match="不是受信 Git 报告的 worktree 根"):
        scan_repository(repo, runner=runner)


@pytest.mark.parametrize("phase", ["rev-parse", "ls-files"])
def test_secret_scan_拒绝_git_rc0_但_stderr_含诊断(tmp_path: Path, phase: str) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in command:
            result = fake_git_success(command, "tracked.txt\0")
            if phase == "rev-parse":
                return completed(stdout=result.stdout, stderr="warning")
            return result
        assert "ls-files" in command
        return completed(stdout="tracked.txt\0", stderr="warning")

    with pytest.raises(SecretGateError, match="成功但写入诊断"):
        scan_repository(tmp_path, runner=runner)


@pytest.mark.parametrize(
    "listing", ["", "tracked.txt", "../escape\0", "tracked.txt\0tracked.txt\0"]
)
def test_secret_scan_拒绝空_非_nul_逃逸和重复_git_清单(
    tmp_path: Path,
    listing: str,
) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return fake_git_success(command, listing)

    with pytest.raises(SecretGateError, match="清单|路径"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_git_枚举失败时_fail_closed(tmp_path: Path) -> None:
    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "rev-parse" in command:
            return fake_git_success(command, "")
        return completed(returncode=3, stderr="not-a-repository")

    with pytest.raises(SecretGateError, match="Git 输入枚举失败"):
        scan_repository(tmp_path, runner=runner)


@pytest.mark.parametrize(
    "payload",
    [
        {"results": {}},
        {"version": DETECT_SECRETS_VERSION, "plugins_used": [], "results": {}},
    ],
)
def test_secret_scan_拒绝缺失版本或必需插件的伪成功输出(payload: dict[str, object]) -> None:
    with pytest.raises(SecretGateError, match="版本|插件"):
        parse_scan_output(json.dumps(payload))


def test_secret_scan_拒绝任意层级的重复_json_key() -> None:
    payload = secret_payload({}).replace(
        '"results": {}',
        '"results": {}, "results": {}',
    )
    with pytest.raises(SecretGateError, match="重复键"):
        parse_scan_output(payload)


@pytest.mark.parametrize(
    "damage",
    [
        "missing-plugin",
        "duplicate-plugin",
        "extra-plugin",
        "plugin-limit",
        "missing-filter",
        "duplicate-filter",
        "custom-filter",
    ],
)
def test_secret_scan_拒绝插件或过滤器锁定配置漂移(damage: str) -> None:
    payload = json.loads(secret_payload({}))
    plugins = payload["plugins_used"]
    filters = payload["filters_used"]
    assert isinstance(plugins, list)
    assert isinstance(filters, list)
    if damage == "missing-plugin":
        plugins.pop()
    elif damage == "duplicate-plugin":
        plugins.append(dict(plugins[-1]))
    elif damage == "extra-plugin":
        plugins.append({"name": "UntrustedDetector"})
    elif damage == "plugin-limit":
        base64_plugin = next(
            plugin for plugin in plugins if plugin["name"] == "Base64HighEntropyString"
        )
        base64_plugin["limit"] = 4.4
    elif damage == "missing-filter":
        payload.pop("filters_used")
    elif damage == "duplicate-filter":
        filters.extend(
            [
                {"path": "detect_secrets.filters.heuristic.is_lock_file"},
                {"path": "detect_secrets.filters.heuristic.is_lock_file"},
            ]
        )
    else:
        filters.append({"path": "untrusted.custom_filter"})

    with pytest.raises(SecretGateError, match="插件|过滤器"):
        parse_scan_output(json.dumps(payload))


def test_secret_scan_拒绝非_utf8_git_输入(tmp_path: Path) -> None:
    (tmp_path / "binary.txt").write_bytes(b"\xff\xfe")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return fake_git_success(command, "binary.txt\0")

    with pytest.raises(SecretGateError, match="严格 UTF-8"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_拒绝已存在但未列入_git_清单的_semantic_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")
    manifest = tmp_path / SEMANTIC_MANIFEST_PATH
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return fake_git_success(command, "tracked.txt\0")

    with pytest.raises(SecretGateError, match="manifest 存在但未进入"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_拒绝扫描期间新增但未列入_git_清单的_semantic_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        manifest = tmp_path / SEMANTIC_MANIFEST_PATH
        manifest.parent.mkdir(parents=True)
        manifest.write_text("{}\n", encoding="utf-8")
        return completed(stdout=secret_payload({}))

    with pytest.raises(SecretGateError, match="manifest 存在但未进入"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_拒绝_rc0_但_stderr_含警告(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")
    staged_paths: list[Path] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        staged_paths.append(Path(str(kwargs["cwd"])))
        return completed(stdout=secret_payload({}), stderr="Unable to open file")

    with pytest.raises(SecretGateError, match="成功退出但写入诊断"):
        scan_repository(tmp_path, runner=runner)
    assert len(staged_paths) == 1
    assert not staged_paths[0].exists()


def test_secret_scan_最后一批跨越全局_deadline_即使_rc0_也拒绝(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = tmp_path / "snapshot"
    scratch = tmp_path / "scratch"
    snapshot.mkdir()
    scratch.mkdir()
    clock = iter((10.0, 10.0, 610.0))
    monkeypatch.setattr(secrets_module.time, "monotonic", lambda: next(clock))

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[-1] == "./tracked.txt"
        return completed(stdout=secret_payload({}))

    with pytest.raises(SecretGateError, match="全局 deadline"):
        secrets_module._run_detect_secrets(
            snapshot,
            scratch,
            ("./tracked.txt",),
            runner,
        )


def test_secret_scan_仅后置豁免十条已证明的_semantic_hash() -> None:
    listing = "".join(f"{path}\0" for path in semantic_input_paths())
    detector_cwds: list[Path] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, listing)
        detector_cwds.append(Path(str(kwargs["cwd"])))
        return completed(stdout=scanner_payload_for_command(command, semantic_results()))

    evidence = scan_repository(PROJECT_ROOT, runner=runner)

    assert evidence.waived_findings == EXPECTED_SEMANTIC_WAIVERS
    assert (
        evidence.manifest_sha256
        == hashlib.sha256((PROJECT_ROOT / SEMANTIC_MANIFEST_PATH).read_bytes()).hexdigest()
    )
    assert len(detector_cwds) == len(semantic_input_paths())
    assert len(set(detector_cwds)) == 1
    assert detector_cwds[0] != PROJECT_ROOT


def test_secret_scan_缺失任一预期_semantic_finding_即拒绝() -> None:
    listing = "".join(f"{path}\0" for path in semantic_input_paths())
    results = semantic_results()
    next(iter(results.values())).pop()

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, listing)
        return completed(stdout=scanner_payload_for_command(command, results))

    with pytest.raises(SecretGateError, match="未观测到.*10 条"):
        scan_repository(PROJECT_ROOT, runner=runner)


def test_secret_scan_重复任一预期_semantic_finding_即拒绝() -> None:
    listing = "".join(f"{path}\0" for path in semantic_input_paths())
    results = json.loads(json.dumps(semantic_results()))
    findings = next(iter(results.values()))
    findings.append(dict(findings[0]))

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, listing)
        return completed(stdout=scanner_payload_for_command(command, results))

    with pytest.raises(SecretGateError, match="重复 finding 身份"):
        scan_repository(PROJECT_ROOT, runner=runner)


@pytest.mark.parametrize("axis", ["path", "type", "line", "hash", "verified"])
def test_secret_scan_semantic_豁免身份任一维度不匹配均拒绝(axis: str) -> None:
    listing = "".join(f"{path}\0" for path in semantic_input_paths())
    results = json.loads(json.dumps(semantic_results()))
    result_path = next(iter(results))
    first = results[result_path][0]
    if axis == "path":
        results["outside.json"] = results.pop(result_path)
    elif axis == "type":
        first["type"] = "Base64 High Entropy String"
    elif axis == "line":
        first["line_number"] = 999
    elif axis == "hash":
        hash_field = "".join(("hashed_", "se", "cret"))
        first[hash_field] = "f" * 40
    else:
        first["is_verified"] = True

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, listing)
        if axis == "path" and command[-1].endswith(SEMANTIC_MANIFEST_PATH):
            return completed(stdout=secret_payload(results))
        return completed(stdout=scanner_payload_for_command(command, results))

    with pytest.raises(SecretGateError, match="清单外|未观测到|疑似秘密"):
        scan_repository(PROJECT_ROOT, runner=runner)


@pytest.mark.parametrize("damage", ["source", "mutant-hash", "duplicate-key"])
def test_secret_scan_semantic_权威证明任一损坏均拒绝(tmp_path: Path, damage: str) -> None:
    paths = copy_semantic_inputs(tmp_path)
    manifest_path = tmp_path / SEMANTIC_MANIFEST_PATH
    if damage == "source":
        source = tmp_path / "src/sigmacoder/domain/events.py"
        source.write_bytes(source.read_bytes() + b"\n")
    elif damage == "mutant-hash":
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        payload["mutants"][0]["expected_mutant_sha256"] = "0" * 64
        manifest_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        text = manifest_path.read_text(encoding="utf-8")
        manifest_path.write_text(
            text.replace(
                '  "schema_version": 1,', '  "schema_version": 1,\n  "schema_version": 1,'
            ),
            encoding="utf-8",
        )
    listing = "".join(f"{path}\0" for path in paths)

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return fake_git_success(command, listing)

    with pytest.raises(SecretGateError, match="权威证明|重复键"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_拒绝_live_输入在_staged_扫描期间漂移(tmp_path: Path) -> None:
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("before\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        tracked.write_text("after\n", encoding="utf-8")
        return completed(stdout=secret_payload({}))

    with pytest.raises(SecretGateError, match="live Git 输入字节"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_拒绝_staged_snapshot_被扫描器改写(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("before\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if is_git_command(command):
            return fake_git_success(command, "tracked.txt\0")
        staged = Path(str(kwargs["cwd"])) / "tracked.txt"
        staged.chmod(0o600)
        staged.write_text("after\n", encoding="utf-8")
        return completed(stdout=secret_payload({}))

    with pytest.raises(SecretGateError, match="staged snapshot"):
        scan_repository(tmp_path, runner=runner)
