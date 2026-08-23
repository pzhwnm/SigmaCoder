"""控制面解析并执行仓库外受信工具的共享能力。"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path


class TrustedToolError(RuntimeError):
    """受信工具无法解析、执行或证明其权威边界。"""


ToolRunner = Callable[
    ...,
    subprocess.CompletedProcess[bytes] | subprocess.CompletedProcess[str],
]


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _is_link_or_junction(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
        is_junction = path.is_junction()
    except OSError:
        return True
    return stat.S_ISLNK(metadata.st_mode) or is_junction


def _validated_candidate(repo: Path, candidate: Path, expected_names: set[str]) -> Path | None:
    if candidate.name.lower() not in expected_names or _is_link_or_junction(candidate):
        return None
    try:
        metadata = os.lstat(candidate)
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_within(resolved, repo)
        or not os.access(resolved, os.X_OK)
    ):
        return None
    return resolved


def _resolved_search_directory(repo: Path, raw_directory: str) -> Path | None:
    normalized = raw_directory.strip().strip('"')
    if not normalized:
        return None
    directory = Path(os.path.expandvars(normalized))
    if not directory.is_absolute() or _is_link_or_junction(directory):
        return None
    try:
        resolved = directory.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_dir() or _is_within(resolved, repo):
        return None
    return resolved


def _preferred_candidate(
    repo: Path,
    preferred: str | os.PathLike[str] | None,
    expected_names: set[str],
) -> Path | None:
    if preferred is None:
        return None
    preferred_path = Path(os.path.expandvars(os.fspath(preferred)))
    if not preferred_path.is_absolute():
        return None
    return _validated_candidate(repo, preferred_path, expected_names)


def resolve_trusted_executable(
    repo: Path,
    name: str,
    *,
    environment: Mapping[str, str] | None = None,
    preferred: str | os.PathLike[str] | None = None,
) -> Path:
    """只从仓库外绝对位置解析普通、非链接的控制面可执行文件。"""

    resolved_repo = repo.resolve(strict=True)
    source = os.environ if environment is None else environment
    expected_names = {f"{name.lower()}.exe"} if os.name == "nt" else {name.lower()}

    resolved_preferred = _preferred_candidate(resolved_repo, preferred, expected_names)
    if resolved_preferred is not None:
        return resolved_preferred

    for raw_directory in source.get("PATH", "").split(os.pathsep):
        resolved_directory = _resolved_search_directory(resolved_repo, raw_directory)
        if resolved_directory is None:
            continue
        for expected_name in sorted(expected_names):
            resolved = _validated_candidate(
                resolved_repo,
                resolved_directory / expected_name,
                expected_names,
            )
            if resolved is not None:
                return resolved
    raise TrustedToolError(f"无法从仓库外绝对位置定位受信 {name} 可执行文件。")


def resolve_trusted_uv(repo: Path) -> Path:
    """优先采用当前 uv 进程提供的绝对 UV 能力，否则使用受控 PATH。"""

    return resolve_trusted_executable(
        repo,
        "uv",
        preferred=os.environ.get("UV"),
    )


def trusted_git_environment() -> dict[str, str]:
    """构造不继承宿主 Git/Python 配置的最小只读 Git 环境。"""

    environment: dict[str, str] = {}
    for key in ("SystemRoot", "WINDIR"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C.UTF-8",
        }
    )
    return environment


@dataclass(frozen=True, slots=True)
class TrustedGit:
    """绑定仓库根、绝对 Git、最小环境和确定性读取协议。"""

    repo: Path
    executable: Path
    runner: ToolRunner = field(repr=False, compare=False)

    @classmethod
    def open(
        cls,
        repo: Path,
        *,
        runner: ToolRunner | None = None,
    ) -> TrustedGit:
        try:
            resolved_repo = repo.resolve(strict=True)
        except OSError as exc:
            raise TrustedToolError(f"Git 仓库根不可解析：{exc}") from exc
        if not resolved_repo.is_dir():
            raise TrustedToolError("Git 仓库根不是普通目录。")
        session = cls(
            repo=resolved_repo,
            executable=resolve_trusted_executable(resolved_repo, "git"),
            runner=subprocess.run if runner is None else runner,
        )
        session.assert_root()
        return session

    def command(self, arguments: Sequence[str]) -> list[str]:
        return [
            str(self.executable),
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-C",
            str(self.repo),
            *arguments,
        ]

    def read(
        self,
        arguments: Sequence[str],
        *,
        label: str,
        timeout: int = 30,
    ) -> bytes:
        command = self.command(arguments)
        try:
            result = self.runner(
                command,
                cwd=self.executable.parent,
                capture_output=True,
                env=trusted_git_environment(),
                stdin=subprocess.DEVNULL,
                shell=False,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise TrustedToolError(f"{label}无法执行：{exc}") from exc
        stdout = result.stdout.encode("utf-8") if isinstance(result.stdout, str) else result.stdout
        stderr = result.stderr.encode("utf-8") if isinstance(result.stderr, str) else result.stderr
        if result.returncode != 0:
            diagnostic = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedToolError(f"{label}失败：{diagnostic}")
        if stderr.strip():
            diagnostic = stderr.decode("utf-8", errors="replace").strip()
            raise TrustedToolError(f"{label}成功但写入诊断：{diagnostic}")
        return stdout

    def assert_root(self) -> None:
        raw = self.read(
            ("rev-parse", "--path-format=absolute", "--show-toplevel"),
            label="Git 仓库根核验",
            timeout=60,
        )
        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise TrustedToolError("Git 仓库根不是严格 UTF-8。") from exc
        lines = value.splitlines()
        if len(lines) != 1 or not lines[0] or "\0" in lines[0]:
            raise TrustedToolError("Git 仓库根输出为空或结构无效。")
        try:
            reported = Path(lines[0]).resolve(strict=True)
            is_same_root = os.path.samefile(reported, self.repo)
        except OSError as exc:
            raise TrustedToolError("无法比较 Git 仓库根的文件系统身份。") from exc
        if not is_same_root:
            raise TrustedToolError("--repo 不是受信 Git 报告的 worktree 根目录。")

    def head_commit(self) -> str:
        raw = self.read(
            ("rev-parse", "--verify", "HEAD^{commit}"),
            label="Git HEAD",
        )
        try:
            head = raw.decode("ascii", errors="strict").strip()
        except UnicodeError as exc:
            raise TrustedToolError("Git HEAD 不是严格 ASCII。") from exc
        if len(head) not in {40, 64} or any(
            not (("0" <= character <= "9") or ("a" <= character <= "f")) for character in head
        ):
            raise TrustedToolError("Git HEAD 不是小写 SHA-1/SHA-256 commit OID。")
        return head
