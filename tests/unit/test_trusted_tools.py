"""受信工具与测试 Git runtime 的最小权限契约。"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from coverage import Coverage
from tests.e2e.test_cli_real_run import isolated_environment
from tests.support.git_repo_factory import isolated_cli_environment
from tests.support.isolated_git import (
    FixtureGitError,
    active_coverage_subprocess_environment,
    create_fixture_git_runtime,
)
from tools.trusted_tools import (
    TrustedGit,
    TrustedToolError,
    resolve_trusted_executable,
)


def _tool_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def _copy_executable(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sys.executable, destination)
    destination.chmod(0o755)


def test_trusted_git_跳过仓库内影子并只传最小环境(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    shadow_bin = repo / "shadow-bin"
    repo.mkdir()
    _copy_executable(shadow_bin / _tool_name("git"))
    monkeypatch.setenv("PATH", str(shadow_bin) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "redirected"))
    monkeypatch.setenv("HOME", str(tmp_path / "host-home"))
    monkeypatch.setenv("PYTHONPATH", str(repo))
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        if "--show-toplevel" in command:
            stdout = f"{repo}\n".encode()
        elif "HEAD^{commit}" in command:
            stdout = ("a" * 40 + "\n").encode()
        else:
            stdout = b""
        return subprocess.CompletedProcess(command, 0, stdout, b"")

    git = TrustedGit.open(repo, runner=runner)

    assert git.head_commit() == "a" * 40
    assert len(calls) == 2
    for command, kwargs in calls:
        executable = Path(command[0])
        assert executable.is_absolute()
        assert not executable.is_relative_to(repo)
        assert kwargs["cwd"] == executable.parent
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert kwargs["shell"] is False
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert "PATH" not in environment
        assert "HOME" not in environment
        assert "PYTHONPATH" not in environment
        assert "GIT_DIR" not in environment
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_trusted_git_成功但_stderr_非空也拒绝(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def runner(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        return subprocess.CompletedProcess(command, 0, f"{repo}\n".encode(), b"warning")

    with pytest.raises(TrustedToolError, match="成功但写入诊断"):
        TrustedGit.open(repo, runner=runner)


def test_受信可执行文件优先项必须位于仓库外(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    inside = repo / _tool_name("uv")
    outside = tmp_path / "control" / _tool_name("uv")
    _copy_executable(inside)
    _copy_executable(outside)

    resolved = resolve_trusted_executable(
        repo,
        "uv",
        environment={"PATH": str(repo)},
        preferred=outside,
    )

    assert resolved == outside.resolve(strict=True)


def test_fixture_git_不继承宿主_authority_或_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_template = tmp_path / "host-template"
    (hostile_template / "hooks").mkdir(parents=True)
    (hostile_template / "info").mkdir()
    (hostile_template / "hooks/post-commit").write_text("hostile\n", encoding="utf-8")
    (hostile_template / "info/exclude").write_text("hidden.txt\n", encoding="utf-8")
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(hostile_template))
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "redirected"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hostile_template / "hooks"))
    repo = tmp_path / "repo"
    runtime = create_fixture_git_runtime(
        tmp_path / "control",
        untrusted_boundary=tmp_path,
    )

    initialized = runtime.init(repo)

    assert initialized.returncode == 0, initialized.stderr
    assert (repo / ".git").is_dir()
    assert not (repo / ".git/hooks/post-commit").exists()
    assert not (repo / ".git/info/exclude").exists()
    assert "GIT_DIR" not in runtime.environment
    assert runtime.environment["GIT_CONFIG_COUNT"] == "0"
    assert runtime.environment["GIT_TEMPLATE_DIR"] == str(runtime.template)


@pytest.mark.parametrize(
    "environment_builder",
    (isolated_cli_environment, isolated_environment),
)
def test_cli_环境剥离_inactive_ambient_coverage_注入(
    monkeypatch: pytest.MonkeyPatch,
    environment_builder: object,
) -> None:
    monkeypatch.setenv("COVERAGE_PROCESS_CONFIG", "ambient-config")
    monkeypatch.setenv("COVERAGE_PROCESS_START", "ambient-start")
    monkeypatch.setattr(Coverage, "current", staticmethod(lambda: None))
    assert callable(environment_builder)

    environment = environment_builder(
        {
            "COVERAGE_PROCESS_CONFIG": "base-config",
            "COVERAGE_PROCESS_START": "base-start",
        }
    )

    assert active_coverage_subprocess_environment() == {}
    assert "COVERAGE_PROCESS_CONFIG" not in environment
    assert "COVERAGE_PROCESS_START" not in environment


@pytest.mark.parametrize(
    "environment_builder",
    (isolated_cli_environment, isolated_environment),
)
def test_cli_环境只加入当前活动_coverage_配置(
    monkeypatch: pytest.MonkeyPatch,
    environment_builder: object,
) -> None:
    monkeypatch.setenv("COVERAGE_PROCESS_CONFIG", "current-config")
    monkeypatch.setenv("COVERAGE_PROCESS_START", "ambient-start")
    monkeypatch.setattr(Coverage, "current", staticmethod(object))
    assert callable(environment_builder)

    environment = environment_builder(
        {
            "COVERAGE_PROCESS_CONFIG": "base-config",
            "COVERAGE_PROCESS_START": "base-start",
        }
    )

    assert environment["COVERAGE_PROCESS_CONFIG"] == "current-config"
    assert "COVERAGE_PROCESS_START" not in environment


def test_活动_coverage_缺少子进程配置时_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(Coverage, "current", staticmethod(object))
    monkeypatch.delenv("COVERAGE_PROCESS_CONFIG", raising=False)

    with pytest.raises(FixtureGitError, match="缺少子进程插桩配置"):
        active_coverage_subprocess_environment()
