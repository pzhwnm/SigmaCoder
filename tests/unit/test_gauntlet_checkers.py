"""Gauntlet 自制检查器的负控单元测试。"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from tools.check_secrets import (
    DETECT_SECRETS_VERSION,
    REQUIRED_SECRET_PLUGINS,
    SecretGateError,
    parse_scan_output,
    scan_repository,
)
from tools.check_toolchain import ToolchainError, check_toolchain, validate_versions


def completed(
    *, stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["fake"], returncode, stdout, stderr)


def secret_payload(results: dict[str, list[object]]) -> str:
    return json.dumps(
        {
            "version": DETECT_SECRETS_VERSION,
            "plugins_used": [{"name": name} for name in sorted(REQUIRED_SECRET_PLUGINS)],
            "results": results,
        }
    )


def test_工具链要求精确版本() -> None:
    validate_versions("3.12.14", "uv 0.12.5\n")
    with pytest.raises(ToolchainError, match="Python 版本错误"):
        validate_versions("3.12.4", "uv 0.12.5\n")
    with pytest.raises(ToolchainError, match="uv 版本错误"):
        validate_versions("3.12.14", "uv 0.6.9\n")


def test_工具链同时核验仓库元数据(tmp_path: Path) -> None:
    (tmp_path / ".python-version").write_text("3.12.14\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.uv]\nrequired-version = "==0.12.5"\n', encoding="utf-8"
    )

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(stdout="uv 0.12.5\n")

    check_toolchain(tmp_path, runner=runner, python_version="3.12.14")


def test_secret_scan_json_发现内容时_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")
    payload = {"tracked.txt": [{"type": "AWS Access Key"}]}

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "git":
            return completed(stdout="tracked.txt\0")
        return completed(stdout=secret_payload(payload))

    with pytest.raises(SecretGateError, match="发现 1 个"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_破损输出和扫描器错误均拒绝(tmp_path: Path) -> None:
    with pytest.raises(SecretGateError, match="有效 JSON"):
        parse_scan_output("not-json")

    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "git":
            return completed(stdout="tracked.txt\0")
        return completed(returncode=2, stderr="boom")

    with pytest.raises(SecretGateError, match="退出码"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_显式扫描全部跟踪文件并规范化_cli_路径(tmp_path: Path) -> None:
    tracked = ("tools/semantic_mutants.json", "-leading-name.txt")
    for relative in tracked:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[0] == "git":
            return completed(stdout="tools/semantic_mutants.json\0-leading-name.txt\0")
        return completed(stdout=secret_payload({}))

    assert scan_repository(tmp_path, runner=runner) == {}
    assert commands == [
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        [
            "detect-secrets",
            "scan",
            "--no-verify",
            "./tools/semantic_mutants.json",
            "./-leading-name.txt",
        ],
    ]


@pytest.mark.parametrize(
    "listing", ["", "tracked.txt", "../escape\0", "tracked.txt\0tracked.txt\0"]
)
def test_secret_scan_拒绝空_非_nul_逃逸和重复_git_清单(
    tmp_path: Path,
    listing: str,
) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[0] == "git"
        return completed(stdout=listing)

    with pytest.raises(SecretGateError, match="清单|路径"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_git_枚举失败时_fail_closed(tmp_path: Path) -> None:
    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[0] == "git"
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


def test_secret_scan_拒绝_rc0_但_stderr_含警告(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("fixture\n", encoding="utf-8")

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "git":
            return completed(stdout="tracked.txt\0")
        return completed(stdout=secret_payload({}), stderr="Unable to open file")

    with pytest.raises(SecretGateError, match="成功退出但写入诊断"):
        scan_repository(tmp_path, runner=runner)
