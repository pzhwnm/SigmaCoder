from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from tools.check_secrets import SecretGateError, parse_scan_output, scan_repository
from tools.check_toolchain import ToolchainError, check_toolchain, validate_versions


def completed(
    *, stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["fake"], returncode, stdout, stderr)


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
    payload = {"results": {"tracked.txt": [{"type": "AWS Access Key"}]}}

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(stdout=json.dumps(payload))

    with pytest.raises(SecretGateError, match="发现 1 个"):
        scan_repository(tmp_path, runner=runner)


def test_secret_scan_破损输出和扫描器错误均拒绝(tmp_path: Path) -> None:
    with pytest.raises(SecretGateError, match="有效 JSON"):
        parse_scan_output("not-json")

    def runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(returncode=2, stderr="boom")

    with pytest.raises(SecretGateError, match="退出码"):
        scan_repository(tmp_path, runner=runner)
