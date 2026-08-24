"""测试仓库专用的绝对 Git、空配置与空 template 运行时。"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from coverage import Coverage
from tools.trusted_tools import TrustedToolError, resolve_trusted_executable

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FixtureGitError(RuntimeError):
    """测试 Git 运行时无法建立或命令失败。"""


COVERAGE_PROCESS_ENVIRONMENT_KEYS = (
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_PROCESS_START",
)


def active_coverage_subprocess_environment() -> dict[str, str]:
    """仅把当前活动 coverage 实例生成的子进程配置传入真实 CLI。"""

    if Coverage.current() is None:
        return {}
    serialized = os.environ.get("COVERAGE_PROCESS_CONFIG")
    if not serialized:
        raise FixtureGitError("当前 coverage 测量缺少子进程插桩配置。")
    return {"COVERAGE_PROCESS_CONFIG": serialized}


def isolated_coverage_subprocess_environment(
    base: Mapping[str, str],
) -> dict[str, str]:
    """剥离 ambient coverage 控制项，再加入当前活动测量器配置。"""

    environment = dict(base)
    for key in COVERAGE_PROCESS_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment.update(active_coverage_subprocess_environment())
    return environment


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _sanitized_path(boundary: Path, git_executable: Path) -> str:
    directories = [str(git_executable.parent)]
    seen = {git_executable.parent}
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        normalized = raw.strip().strip('"')
        if not normalized:
            continue
        path = Path(os.path.expandvars(normalized))
        if not path.is_absolute():
            continue
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_dir() or _is_within(resolved, boundary) or resolved in seen:
            continue
        seen.add(resolved)
        directories.append(str(resolved))
    return os.pathsep.join(directories)


@dataclass(frozen=True, slots=True)
class FixtureGitRuntime:
    """不继承宿主 Git 权威配置的测试运行时。"""

    executable: Path
    environment: Mapping[str, str]
    template: Path

    def run(
        self,
        repository: Path,
        arguments: Sequence[str],
        *,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.executable),
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.autocrlf=false",
                "-C",
                str(repository),
                *arguments,
            ],
            cwd=self.executable.parent,
            env=dict(self.environment),
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

    def init(
        self,
        repository: Path,
        *,
        initial_branch: str = "main",
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        try:
            resolved_repository = repository.resolve(strict=False)
            resolved_template = self.template.resolve(strict=True)
        except OSError as exc:
            raise FixtureGitError(f"测试 Git 路径无法解析：{exc}") from exc
        if _is_within(resolved_template, resolved_repository):
            raise FixtureGitError("测试 Git 控制目录不得位于待初始化仓库内。")
        return subprocess.run(
            [
                str(self.executable),
                "--no-pager",
                "--no-optional-locks",
                "init",
                f"--initial-branch={initial_branch}",
                f"--template={resolved_template}",
                str(resolved_repository),
            ],
            cwd=self.executable.parent,
            env=dict(self.environment),
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )


def create_fixture_git_runtime(
    control_root: Path,
    *,
    untrusted_boundary: Path = PROJECT_ROOT,
) -> FixtureGitRuntime:
    """在测试拥有的控制目录内创建空 HOME、配置、临时目录和 template。"""

    resolved_control = control_root.resolve(strict=False)
    home = resolved_control / "home"
    xdg = home / ".config"
    temporary = resolved_control / "tmp"
    template = resolved_control / "template"
    for directory in (home, xdg, temporary, template):
        directory.mkdir(parents=True, exist_ok=True)
    global_config = resolved_control / "global.gitconfig"
    global_config.write_text("", encoding="utf-8")
    try:
        resolved_boundary = untrusted_boundary.resolve(strict=True)
        executable = resolve_trusted_executable(resolved_boundary, "git")
    except TrustedToolError as exc:
        raise FixtureGitError(str(exc)) from exc

    environment: dict[str, str] = {}
    for key in ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": str(global_config),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "",
            "GIT_TEMPLATE_DIR": str(template),
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "NoDefaultCurrentDirectoryInExePath": "1",
            "PAGER": "",
            "PATH": _sanitized_path(resolved_boundary, executable),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(xdg),
        }
    )
    return FixtureGitRuntime(executable, environment, template)


def sibling_control_root(repository: Path) -> Path:
    """为直接把 tmp_path 当仓库根的测试选择唯一 sibling 控制目录。"""

    return repository.parent / f"{repository.name}-git-control"
