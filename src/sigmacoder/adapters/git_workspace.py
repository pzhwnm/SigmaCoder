"""可信宿主上的 Git 仓库与 linked-worktree 适配器。

本模块只负责可观测的 Git/文件系统事实，不解释 Task 状态，也不写事件。
所有 Git 调用均使用结构化 argv 和受控环境，绝不经过 shell。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from sigmacoder.ports.workspace import (
    PreparedWorkspaceStatus,
    RepositoryInspection,
    SourceWorktreeFingerprint,
    WorkspaceAvailability,
    WorkspaceError,
    WorkspaceObservation,
    WorktreeEntryDigest,
)

_HEX_RE: Final = re.compile(r"^[0-9a-f]+$")
_NONCE_RE: Final = re.compile(r"^[0-9a-f]{32}$")
_DIGEST_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_PORTABLE_COMPONENT_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_FILTER_KEY_RE: Final = r"^filter\..*\.(clean|smudge|process)$"
_MAX_DIAGNOSTIC: Final = 2_000
_WINDOWS_RESERVED_NAMES: Final = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class GitWorkspaceError(WorkspaceError):
    """带稳定错误码、可由服务层映射的适配器失败。"""


@dataclass(frozen=True, slots=True)
class _PointerObservation:
    admin_realpath: Path | None
    admin_points_to_workspace: bool
    workspace_points_to_admin: bool
    common_dir_matches: bool
    pointer_digest: str | None
    problems: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _GitResult:
    stdout: str
    stderr: str
    returncode: int


@dataclass(frozen=True, slots=True)
class _WorkspaceTreeDiff:
    extra: tuple[str, ...]
    missing: tuple[str, ...]
    hidden_index_entries: tuple[str, ...]


def workspace_slot_name(ownership_nonce: str) -> str:
    """由 128-bit nonce 派生不可预测且跨平台安全的槽位名。"""

    if not _NONCE_RE.fullmatch(ownership_nonce):
        raise GitWorkspaceError(
            "INVALID_OWNERSHIP_NONCE",
            "ownership nonce 必须是 32 位小写十六进制字符串。",
        )
    return f"workspace-{ownership_nonce}"


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def _same_path(left: Path, right: Path) -> bool:
    return _path_key(left) == _path_key(right)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_plain_text(value: str, *, field: str) -> None:
    if "\x00" in value or "\r" in value or "\n" in value:
        raise GitWorkspaceError(
            "INVALID_GIT_ARGUMENT",
            f"{field} 不能包含 NUL 或换行符。",
        )


def _is_junction(path: Path) -> bool:
    checker = getattr(os.path, "isjunction", None)
    return bool(checker is not None and checker(path))


def _is_reparse(path: Path) -> bool:
    if path.is_symlink() or _is_junction(path):
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & marker)


def _resolve_path(path: str | Path, *, strict: bool, field: str) -> Path:
    raw = os.fspath(path)
    _validate_plain_text(raw, field=field)
    try:
        return Path(raw).expanduser().resolve(strict=strict)
    except (OSError, RuntimeError) as error:
        raise GitWorkspaceError(
            "INVALID_PATH",
            f"{field} 无法解析为规范路径。",
            details={"error_type": type(error).__name__},
        ) from error


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _normalize_json(value: object) -> object:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list | tuple):
        return [_normalize_json(item) for item in value]
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(key)): _normalize_json(item)
            for key, item in value.items()
        }
    raise TypeError(f"无法规范化的 JSON 类型：{type(value).__name__}")


def _canonical_digest(value: object) -> str:
    normalized = _normalize_json(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _sanitized_diagnostic(stderr: str) -> str:
    compact = stderr.replace("\x00", "�").strip()
    if len(compact) <= _MAX_DIAGNOSTIC:
        return compact
    return compact[-_MAX_DIAGNOSTIC:]


def _read_stable_file(path: Path) -> bytes:
    """避免把读到一半的并发写入内容纳入源指纹。"""

    for _ in range(3):
        before = path.stat(follow_symlinks=False)
        content = path.read_bytes()
        after = path.stat(follow_symlinks=False)
        stable = (
            before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_mode == after.st_mode
        )
        if stable:
            return content
    raise GitWorkspaceError(
        "SOURCE_WORKTREE_UNSTABLE",
        "源 worktree 文件在生成指纹时持续变化。",
        details={"path": str(path)},
    )


def _link_target_bytes(path: Path) -> bytes:
    try:
        return os.fsencode(os.readlink(path))
    except OSError:
        return b"<unreadable-reparse-target>"


def _entry_digest(root: Path, path: Path) -> WorktreeEntryDigest:
    relative = path.relative_to(root).as_posix()
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if _is_reparse(path):
        content = _link_target_bytes(path)
        return WorktreeEntryDigest(relative, "reparse", mode, len(content), _sha256_bytes(content))
    if stat.S_ISREG(metadata.st_mode):
        content = _read_stable_file(path)
        return WorktreeEntryDigest(relative, "file", mode, len(content), _sha256_bytes(content))
    kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "special"
    marker = f"{kind}:{metadata.st_mode}:{metadata.st_size}".encode("ascii")
    return WorktreeEntryDigest(relative, kind, mode, metadata.st_size, _sha256_bytes(marker))


def _business_entries(root: Path) -> tuple[WorktreeEntryDigest, ...]:
    entries: list[WorktreeEntryDigest] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            children = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as error:
            raise GitWorkspaceError(
                "SOURCE_WORKTREE_UNREADABLE",
                "无法完整读取源 worktree。",
                details={"error_type": type(error).__name__},
            ) from error
        for child in children:
            path = Path(child.path)
            relative = path.relative_to(root)
            if len(relative.parts) == 1 and relative.name == ".git":
                continue
            digest = _entry_digest(root, path)
            if digest.kind == "directory":
                pending.append(path)
            else:
                entries.append(digest)
    return tuple(sorted(entries, key=lambda item: item.relative_path))


def _existing_path_has_reparse(root: Path, relative: PurePosixPath) -> bool:
    current = root
    for part in relative.parts:
        current /= part
        if not current.exists() and not current.is_symlink():
            return False
        if _is_reparse(current):
            return True
    return False


def _validate_portable_relative_path(raw: str) -> PurePosixPath:
    if unicodedata.normalize("NFC", raw) != raw or "\\" in raw:
        raise GitWorkspaceError(
            "INVALID_WORKSPACE_PATH",
            "workspace_relative_path 必须是 NFC 且只能使用正斜杠。",
        )
    relative = PurePosixPath(raw)
    if relative.is_absolute() or relative.as_posix() != raw:
        raise GitWorkspaceError(
            "INVALID_WORKSPACE_PATH",
            "workspace_relative_path 必须是未折叠点段的规范相对路径。",
        )
    for part in relative.parts:
        _validate_portable_component(part)
    return relative


def _validate_portable_component(part: str) -> None:
    reserved = part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
    if not part or part in {".", ".."} or part.rstrip(" .") != part:
        raise GitWorkspaceError("INVALID_WORKSPACE_PATH", "workspace 路径包含不规范组件。")
    if not _PORTABLE_COMPONENT_RE.fullmatch(part) or reserved:
        raise GitWorkspaceError(
            "INVALID_WORKSPACE_PATH",
            "workspace 路径包含跨平台保留组件。",
        )


class GitWorkspaceAdapter:
    """仅暴露 T01 所需 Git 能力的窄接口。"""

    def __init__(
        self,
        hooks_dir: str | Path,
        *,
        git_executable: str | Path | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Git 超时必须大于零。")
        self._git = self._resolve_git(git_executable)
        self._hooks_dir = self._prepare_hooks_dir(hooks_dir)
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _resolve_git(candidate: str | Path | None) -> Path:
        requested = os.fspath(candidate) if candidate is not None else "git"
        _validate_plain_text(requested, field="git_executable")
        located = shutil.which(requested)
        if located is None:
            raise GitWorkspaceError("GIT_UNAVAILABLE", "找不到受支持的 Git 可执行文件。")
        return _resolve_path(located, strict=True, field="git_executable")

    @staticmethod
    def _prepare_hooks_dir(hooks_dir: str | Path) -> Path:
        path = _resolve_path(hooks_dir, strict=False, field="hooks_dir")
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise GitWorkspaceError(
                "CONTROLLED_HOOKS_PATH_UNAVAILABLE",
                "无法创建受控空 hooks 目录。",
                details={"error_type": type(error).__name__},
            ) from error
        return _resolve_path(path, strict=True, field="hooks_dir")

    def _assert_hooks_dir_safe(self) -> None:
        if _is_reparse(self._hooks_dir) or not self._hooks_dir.is_dir():
            raise GitWorkspaceError(
                "CONTROLLED_HOOKS_PATH_UNSAFE",
                "受控 hooks 路径不是可信普通目录。",
            )
        try:
            has_entries = next(self._hooks_dir.iterdir(), None) is not None
        except OSError as error:
            raise GitWorkspaceError(
                "CONTROLLED_HOOKS_PATH_UNSAFE",
                "无法验证受控 hooks 目录为空。",
            ) from error
        if has_entries:
            raise GitWorkspaceError(
                "CONTROLLED_HOOKS_PATH_UNSAFE",
                "受控 hooks 目录必须为空。",
            )

    @staticmethod
    def _controlled_env() -> dict[str, str]:
        allowed = ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TMP", "TEMP")
        environment = {key: os.environ[key] for key in allowed if key in os.environ}
        environment.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_PAGER": "",
                "PAGER": "",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_ALLOW_PROTOCOL": "",
                "GCM_INTERACTIVE": "Never",
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
            }
        )
        return environment

    def _base_argv(self) -> list[str]:
        return [
            str(self._git),
            "-c",
            f"core.hooksPath={self._hooks_dir}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.pager=",
            "-c",
            "pager.status=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "credential.interactive=never",
            "-c",
            "core.askPass=",
            "-c",
            "core.quotepath=false",
        ]

    def _run(
        self,
        repository: Path,
        arguments: tuple[str, ...],
        *,
        allowed_codes: tuple[int, ...] = (0,),
    ) -> _GitResult:
        self._assert_hooks_dir_safe()
        for argument in arguments:
            _validate_plain_text(argument, field="Git argv")
        command = [*self._base_argv(), "-C", str(repository), *arguments]
        try:
            result = subprocess.run(
                command,
                check=False,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self._controlled_env(),
                timeout=self._timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise GitWorkspaceError(
                "GIT_COMMAND_TIMEOUT",
                "Git 命令超过受控超时。",
                details={"subcommand": arguments[0]},
            ) from error
        except OSError as error:
            raise GitWorkspaceError(
                "GIT_COMMAND_UNAVAILABLE",
                "无法启动 Git 子进程。",
                details={"error_type": type(error).__name__},
            ) from error
        if result.returncode not in allowed_codes:
            raise GitWorkspaceError(
                "GIT_COMMAND_FAILED",
                "Git 命令未成功完成。",
                details={
                    "subcommand": arguments[0],
                    "returncode": result.returncode,
                    "diagnostic": _sanitized_diagnostic(result.stderr),
                },
            )
        return _GitResult(result.stdout, result.stderr, result.returncode)

    def inspect_repository(
        self,
        repository: str | Path,
        baseline: str,
    ) -> RepositoryInspection:
        """验证源 worktree、拒绝危险配置并冻结 commit OID。"""

        requested = _resolve_path(repository, strict=True, field="repo")
        if not requested.is_dir():
            raise GitWorkspaceError("INVALID_REPOSITORY", "repo 必须是现有目录。")
        inside = self._run(requested, ("rev-parse", "--is-inside-work-tree"))
        if inside.stdout.strip() != "true":
            raise GitWorkspaceError("INVALID_REPOSITORY", "repo 不是 Git worktree。")
        top_level = self._absolute_git_path(requested, "--show-toplevel")
        common_dir = self._absolute_git_path(top_level, "--git-common-dir")
        git_dir = self._absolute_git_path(top_level, "--absolute-git-dir")
        self._reject_external_filters(top_level)
        object_format = self._object_format(top_level)
        head = self._run(
            top_level,
            ("rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}"),
            allowed_codes=(0, 1),
        )
        if head.returncode != 0:
            raise GitWorkspaceError("REPOSITORY_UNBORN", "仓库尚无可冻结的 HEAD commit。")
        frozen_oid = self._freeze_commit(top_level, baseline, object_format)
        fingerprint = self.source_fingerprint(top_level, object_format=object_format)
        return RepositoryInspection(
            repository_realpath=top_level,
            git_dir_realpath=git_dir,
            git_common_dir_realpath=common_dir,
            object_format=object_format,
            baseline_commit=frozen_oid,
            source_dirty=bool(fingerprint.porcelain_v2),
            source_fingerprint=fingerprint,
        )

    def _absolute_git_path(self, repository: Path, selector: str) -> Path:
        output = self._run(
            repository,
            ("rev-parse", "--path-format=absolute", selector),
        ).stdout.strip()
        if not output:
            raise GitWorkspaceError("INVALID_REPOSITORY", "Git 未返回所需仓库路径。")
        candidate = Path(output)
        if not candidate.is_absolute():
            candidate = repository / candidate
        return _resolve_path(candidate, strict=True, field=selector)

    def _object_format(self, repository: Path) -> str:
        result = self._run(repository, ("rev-parse", "--show-object-format=storage"))
        object_format = result.stdout.strip().lower()
        if object_format not in {"sha1", "sha256"}:
            raise GitWorkspaceError(
                "UNSUPPORTED_GIT_OBJECT_FORMAT",
                "仓库使用了不受支持的 Git object format。",
            )
        return object_format

    def _freeze_commit(self, repository: Path, baseline: str, object_format: str) -> str:
        _validate_plain_text(baseline, field="baseline")
        if not baseline or baseline.startswith("-"):
            raise GitWorkspaceError("INVALID_BASELINE", "baseline 不能为空或以前导连字符开头。")
        expression = f"{baseline}^{{commit}}"
        result = self._run(
            repository,
            ("rev-parse", "--verify", "--quiet", "--end-of-options", expression),
            allowed_codes=(0, 1),
        )
        if result.returncode != 0:
            raise GitWorkspaceError("BASELINE_NOT_COMMIT", "baseline 不能解析为 commit 对象。")
        oid = result.stdout.strip().lower()
        self._validate_oid(oid, object_format, error_code="BASELINE_NOT_COMMIT")
        object_type = self._run(repository, ("cat-file", "-t", oid)).stdout.strip()
        if object_type != "commit":
            raise GitWorkspaceError("BASELINE_NOT_COMMIT", "baseline 不是 commit 对象。")
        return oid

    @staticmethod
    def _validate_oid(oid: str, object_format: str, *, error_code: str) -> None:
        expected_length = 40 if object_format == "sha1" else 64
        if len(oid) != expected_length or not _HEX_RE.fullmatch(oid):
            raise GitWorkspaceError(error_code, "Git 返回了格式无效的完整 OID。")

    def _reject_external_filters(self, repository: Path) -> None:
        result = self._run(
            repository,
            ("config", "--null", "--name-only", "--get-regexp", _FILTER_KEY_RE),
            allowed_codes=(0, 1),
        )
        if result.returncode == 0 and result.stdout:
            keys = tuple(sorted(filter(None, result.stdout.split("\x00"))))
            raise GitWorkspaceError(
                "UNSAFE_GIT_CHECKOUT_CONFIG",
                "仓库配置了可能执行外部进程的 Git filter，已拒绝 checkout。",
                details={"filter_keys": keys},
            )

    def source_fingerprint(
        self,
        repository: str | Path,
        *,
        object_format: str | None = None,
    ) -> SourceWorktreeFingerprint:
        """锁定源文件、index、HEAD、refs 与 porcelain v2 状态。"""

        root = _resolve_path(repository, strict=True, field="repo")
        selected_format = object_format or self._object_format(root)
        head_oid = self._run(root, ("rev-parse", "--verify", "HEAD")).stdout.strip().lower()
        self._validate_oid(head_oid, selected_format, error_code="REPOSITORY_UNBORN")
        symbolic = self._run(
            root,
            ("symbolic-ref", "-q", "HEAD"),
            allowed_codes=(0, 1),
        )
        symbolic_head = symbolic.stdout.strip() if symbolic.returncode == 0 else None
        refs = self._run(
            root,
            ("for-each-ref", "--format=%(refname)%00%(objectname)%00%(symref)"),
        ).stdout
        porcelain = self._status(root)
        index_path = self._git_path(root, "index")
        index_bytes = _read_stable_file(index_path)
        return SourceWorktreeFingerprint(
            entries=_business_entries(root),
            index_size=len(index_bytes),
            index_sha256=_sha256_bytes(index_bytes),
            head_oid=head_oid,
            symbolic_head=symbolic_head,
            refs=refs,
            porcelain_v2=porcelain,
        )

    def _git_path(self, repository: Path, name: str) -> Path:
        output = self._run(
            repository,
            ("rev-parse", "--path-format=absolute", "--git-path", name),
        ).stdout.strip()
        candidate = Path(output)
        if not candidate.is_absolute():
            candidate = repository / candidate
        return _resolve_path(candidate, strict=True, field=f"git-path:{name}")

    def _status(self, repository: Path) -> str:
        self._reject_external_filters(repository)
        return self._run(
            repository,
            (
                "status",
                "--porcelain=v2",
                "--untracked-files=all",
                "--ignored=matching",
                "--no-renames",
            ),
        ).stdout

    @staticmethod
    def assert_source_unchanged(
        expected: SourceWorktreeFingerprint,
        actual: SourceWorktreeFingerprint,
    ) -> None:
        """只允许 common-dir 的 linked-worktree 管理元数据变化。"""

        if expected != actual:
            raise GitWorkspaceError(
                "SOURCE_WORKTREE_CHANGED",
                "Task workspace 准备期间源 worktree 的业务状态发生变化。",
            )

    def validate_data_root(
        self,
        data_root: str | Path,
        repository: RepositoryInspection,
        *,
        existing_workspaces: tuple[str | Path, ...] = (),
    ) -> Path:
        """拒绝 data root 落入源 worktree、common dir 或现有 workspace。"""

        root = _resolve_path(data_root, strict=False, field="data_root")
        forbidden = (
            repository.repository_realpath,
            repository.git_common_dir_realpath,
            *(_resolve_path(path, strict=False, field="workspace") for path in existing_workspaces),
        )
        if any(_same_path(root, path) or _is_within(root, path) for path in forbidden):
            raise GitWorkspaceError(
                "INVALID_DATA_ROOT",
                "data root 不得位于源 worktree、Git common directory 或 Task Workspace 内。",
            )
        return root

    def create_detached_worktree(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> Path:
        """从已冻结 OID 创建 detached linked worktree，不执行网络或插件。"""

        self._validate_action_digests(expected_action_digest, recomputed_action_digest)
        if expected_action_digest != recomputed_action_digest:
            raise GitWorkspaceError(
                "WORKSPACE_AUTHORIZATION_MISMATCH",
                "workspace action digest 与权威事实重算结果不一致。",
            )
        workspace = self._authorized_workspace_path(
            data_root,
            workspace_relative_path,
            ownership_nonce,
            require_exists=False,
        )
        if workspace.exists() or workspace.is_symlink() or _is_junction(workspace):
            raise GitWorkspaceError(
                "WORKSPACE_PATH_COLLISION",
                "目标 workspace 槽位已存在或是链接，拒绝覆盖。",
            )
        workspace.parent.mkdir(parents=True, exist_ok=True)
        if _is_reparse(workspace.parent):
            raise GitWorkspaceError(
                "INVALID_WORKSPACE_PATH",
                "workspace 父目录不能是符号链接、junction 或 reparse point。",
            )
        before = self.source_fingerprint(
            repository.repository_realpath,
            object_format=repository.object_format,
        )
        self.assert_source_unchanged(repository.source_fingerprint, before)
        try:
            self._run(
                repository.repository_realpath,
                (
                    "worktree",
                    "add",
                    "--detach",
                    "--",
                    str(workspace),
                    repository.baseline_commit,
                ),
            )
        except GitWorkspaceError as error:
            raise GitWorkspaceError(
                "WORKSPACE_PROVISIONING_FAILED",
                "Git linked worktree 创建失败；未自动清理不确定资源。",
                details={
                    "cause_code": error.code,
                    "workspace_exists": workspace.exists(),
                    **error.details,
                },
            ) from error
        after = self.source_fingerprint(
            repository.repository_realpath,
            object_format=repository.object_format,
        )
        self.assert_source_unchanged(before, after)
        return _resolve_path(workspace, strict=True, field="workspace")

    def _authorized_workspace_path(
        self,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        *,
        require_exists: bool,
    ) -> Path:
        root = _resolve_path(data_root, strict=require_exists, field="data_root")
        _validate_plain_text(workspace_relative_path, field="workspace_relative_path")
        relative = _validate_portable_relative_path(workspace_relative_path)
        if relative.name != workspace_slot_name(ownership_nonce):
            raise GitWorkspaceError(
                "INVALID_WORKSPACE_PATH",
                "workspace 槽位名未绑定授权的 ownership nonce。",
            )
        if _existing_path_has_reparse(root, relative):
            raise GitWorkspaceError(
                "INVALID_WORKSPACE_PATH",
                "workspace 路径不能经过符号链接、junction 或 reparse point。",
            )
        lexical = root.joinpath(*relative.parts)
        resolved = _resolve_path(lexical, strict=require_exists, field="workspace")
        if not _is_within(resolved, root) or _same_path(resolved, root):
            raise GitWorkspaceError(
                "INVALID_WORKSPACE_PATH",
                "workspace 解析后逃逸 data root。",
            )
        return resolved

    def observe_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> WorkspaceObservation:
        """只读收集七项采纳证据；任何不确定状态均返回 false。"""

        self._validate_action_digests(expected_action_digest, recomputed_action_digest)
        try:
            workspace = self._authorized_workspace_path(
                data_root,
                workspace_relative_path,
                ownership_nonce,
                require_exists=False,
            )
        except GitWorkspaceError as error:
            return self._empty_observation(
                action_digest=recomputed_action_digest,
                problem=error.code,
            )
        root = _resolve_path(data_root, strict=False, field="data_root")
        try:
            workspace_metadata = workspace.lstat()
        except FileNotFoundError:
            return self._empty_observation(
                workspace=workspace,
                within_data_root=_is_within(workspace, root),
                action_digest=recomputed_action_digest,
                problem="WORKSPACE_MISSING",
            )
        except OSError:
            return self._empty_observation(
                workspace=workspace,
                exists=True,
                within_data_root=_is_within(workspace, root),
                action_digest=recomputed_action_digest,
                problem="WORKSPACE_UNREADABLE",
            )
        if not stat.S_ISDIR(workspace_metadata.st_mode):
            return self._empty_observation(
                workspace=workspace,
                exists=True,
                within_data_root=_is_within(workspace, root),
                action_digest=recomputed_action_digest,
                problem="WORKSPACE_NOT_DIRECTORY",
            )
        problems: list[str] = []
        pointers = self._observe_pointers(repository, workspace)
        problems.extend(pointers.problems)
        nonce_observed, relative_matches, authorization_problems = self._authorization_observation(
            root,
            workspace,
            workspace_relative_path,
            ownership_nonce,
            expected_action_digest,
            recomputed_action_digest,
        )
        problems.extend(authorization_problems)
        pointer_trusted = (
            pointers.admin_points_to_workspace
            and pointers.workspace_points_to_admin
            and pointers.common_dir_matches
        )
        if not pointer_trusted:
            return WorkspaceObservation(
                workspace_realpath=str(workspace),
                workspace_exists=True,
                within_data_root=_is_within(workspace, root),
                relative_path_matches=relative_matches,
                git_admin_realpath=(
                    str(pointers.admin_realpath) if pointers.admin_realpath is not None else None
                ),
                git_admin_points_to_workspace=pointers.admin_points_to_workspace,
                workspace_git_points_to_admin=pointers.workspace_points_to_admin,
                common_dir_matches=pointers.common_dir_matches,
                head_detached=False,
                head_oid=None,
                index_and_tracked_clean=False,
                no_extra_files=False,
                ownership_nonce=nonce_observed,
                action_digest=recomputed_action_digest,
                git_pointer_digest=None,
                problems=tuple(dict.fromkeys(problems)),
            )
        detached, head_oid = self._observe_head(repository, workspace, problems)
        clean, no_extra = self._observe_cleanliness(workspace, problems)
        return WorkspaceObservation(
            workspace_realpath=str(workspace),
            workspace_exists=True,
            within_data_root=_is_within(workspace, root),
            relative_path_matches=relative_matches,
            git_admin_realpath=(
                str(pointers.admin_realpath) if pointers.admin_realpath is not None else None
            ),
            git_admin_points_to_workspace=pointers.admin_points_to_workspace,
            workspace_git_points_to_admin=pointers.workspace_points_to_admin,
            common_dir_matches=pointers.common_dir_matches,
            head_detached=detached,
            head_oid=head_oid,
            index_and_tracked_clean=clean,
            no_extra_files=no_extra,
            ownership_nonce=nonce_observed,
            action_digest=recomputed_action_digest,
            git_pointer_digest=pointers.pointer_digest,
            problems=tuple(dict.fromkeys(problems)),
        )

    @staticmethod
    def _authorization_observation(
        root: Path,
        workspace: Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> tuple[str | None, bool, tuple[str, ...]]:
        problems: list[str] = []
        nonce = ownership_nonce if workspace.name == workspace_slot_name(ownership_nonce) else None
        if nonce is None:
            problems.append("OWNERSHIP_NONCE_MISMATCH")
        if expected_action_digest != recomputed_action_digest:
            problems.append("ACTION_DIGEST_MISMATCH")
        relative_matches = GitWorkspaceAdapter._relative_matches(
            root, workspace, workspace_relative_path
        )
        if not relative_matches:
            problems.append("WORKSPACE_RELATIVE_PATH_MISMATCH")
        return nonce, relative_matches, tuple(problems)

    @staticmethod
    def _validate_action_digests(expected: str, recomputed: str) -> None:
        if not _DIGEST_RE.fullmatch(expected) or not _DIGEST_RE.fullmatch(recomputed):
            raise GitWorkspaceError(
                "INVALID_ACTION_DIGEST",
                "action digest 必须是 64 位小写十六进制字符串。",
            )

    @staticmethod
    def _relative_matches(root: Path, workspace: Path, expected: str) -> bool:
        try:
            actual = workspace.relative_to(root).as_posix()
        except ValueError:
            return False
        return actual == expected

    @staticmethod
    def _empty_observation(
        *,
        action_digest: str,
        problem: str,
        workspace: Path | None = None,
        exists: bool = False,
        within_data_root: bool = False,
    ) -> WorkspaceObservation:
        return WorkspaceObservation(
            workspace_realpath=str(workspace) if workspace is not None else None,
            workspace_exists=exists,
            within_data_root=within_data_root,
            relative_path_matches=False,
            git_admin_realpath=None,
            git_admin_points_to_workspace=False,
            workspace_git_points_to_admin=False,
            common_dir_matches=False,
            head_detached=False,
            head_oid=None,
            index_and_tracked_clean=False,
            no_extra_files=False,
            ownership_nonce=None,
            action_digest=action_digest,
            git_pointer_digest=None,
            problems=(problem,),
        )

    def _observe_pointers(
        self,
        repository: RepositoryInspection,
        workspace: Path,
    ) -> _PointerObservation:
        problems: list[str] = []
        git_file = workspace / ".git"
        admin = self._read_gitdir_pointer(git_file, problems, "WORKSPACE_GIT_POINTER_INVALID")
        if admin is None:
            return _PointerObservation(None, False, False, False, None, tuple(problems))
        expected_admin_root = repository.git_common_dir_realpath / "worktrees"
        admin_in_common = _same_path(admin.parent, expected_admin_root)
        if not admin_in_common:
            problems.append("GIT_ADMIN_OUTSIDE_COMMON_DIR")
        reverse = self._read_plain_path(admin / "gitdir", problems, "GIT_ADMIN_REVERSE_INVALID")
        admin_points = reverse is not None and _same_path(reverse, git_file)
        if not admin_points:
            problems.append("GIT_ADMIN_REVERSE_MISMATCH")
        if not admin_in_common or not admin_points:
            return _PointerObservation(
                admin,
                admin_points and admin_in_common,
                False,
                False,
                None,
                tuple(problems),
            )
        workspace_points = _same_path(admin, self._safe_absolute_git_dir(workspace, problems))
        common = self._safe_common_dir(workspace, problems)
        common_matches = common is not None and _same_path(
            common, repository.git_common_dir_realpath
        )
        if not workspace_points:
            problems.append("WORKSPACE_GIT_POINTER_MISMATCH")
        if not common_matches:
            problems.append("GIT_COMMON_DIR_MISMATCH")
        digest = None
        if workspace_points and common_matches:
            digest = _canonical_digest(
                {
                    "workspace_git_file": str(git_file),
                    "git_admin_realpath": str(admin),
                    "admin_gitdir_target": str(reverse),
                    "git_common_dir_realpath": str(common),
                }
            )
        return _PointerObservation(
            admin,
            admin_points and admin_in_common,
            workspace_points,
            common_matches,
            digest,
            tuple(problems),
        )

    @staticmethod
    def _read_gitdir_pointer(path: Path, problems: list[str], code: str) -> Path | None:
        if _is_reparse(path):
            problems.append(code)
            return None
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                problems.append(code)
                return None
            content = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            problems.append(code)
            return None
        prefix = "gitdir: "
        if not content.startswith(prefix) or "\n" in content or "\r" in content:
            problems.append(code)
            return None
        candidate = Path(content[len(prefix) :])
        if not candidate.is_absolute():
            candidate = path.parent / candidate
        if _is_reparse(candidate) or _is_reparse(candidate.parent):
            problems.append(code)
            return None
        try:
            return _resolve_path(candidate, strict=True, field="workspace .git pointer")
        except GitWorkspaceError:
            problems.append(code)
            return None

    @staticmethod
    def _read_plain_path(path: Path, problems: list[str], code: str) -> Path | None:
        if _is_reparse(path):
            problems.append(code)
            return None
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                problems.append(code)
                return None
            content = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            problems.append(code)
            return None
        if not content or "\n" in content or "\r" in content:
            problems.append(code)
            return None
        candidate = Path(content)
        if not candidate.is_absolute():
            candidate = path.parent / candidate
        if _is_reparse(candidate):
            problems.append(code)
            return None
        try:
            return _resolve_path(candidate, strict=True, field="Git reverse pointer")
        except GitWorkspaceError:
            problems.append(code)
            return None

    def _safe_absolute_git_dir(self, workspace: Path, problems: list[str]) -> Path:
        try:
            return self._absolute_git_path(workspace, "--absolute-git-dir")
        except GitWorkspaceError:
            problems.append("WORKSPACE_GIT_DIR_UNREADABLE")
            return workspace / ".invalid-git-admin"

    def _safe_common_dir(self, workspace: Path, problems: list[str]) -> Path | None:
        try:
            return self._absolute_git_path(workspace, "--git-common-dir")
        except GitWorkspaceError:
            problems.append("WORKSPACE_COMMON_DIR_UNREADABLE")
            return None

    def _observe_head(
        self,
        repository: RepositoryInspection,
        workspace: Path,
        problems: list[str],
    ) -> tuple[bool, str | None]:
        try:
            symbolic = self._run(
                workspace,
                ("symbolic-ref", "-q", "HEAD"),
                allowed_codes=(0, 1),
            )
            head_oid = (
                self._run(
                    workspace,
                    ("rev-parse", "--verify", "HEAD"),
                )
                .stdout.strip()
                .lower()
            )
            self._validate_oid(
                head_oid,
                repository.object_format,
                error_code="WORKSPACE_HEAD_INVALID",
            )
        except GitWorkspaceError:
            problems.append("WORKSPACE_HEAD_INVALID")
            return False, None
        detached = symbolic.returncode == 1
        if not detached:
            problems.append("WORKSPACE_HEAD_NOT_DETACHED")
        if head_oid != repository.baseline_commit:
            problems.append("WORKSPACE_BASELINE_MISMATCH")
        return detached, head_oid

    def _observe_cleanliness(
        self,
        workspace: Path,
        problems: list[str],
    ) -> tuple[bool, bool]:
        try:
            status_output = self._status(workspace)
            tree_diff = self._workspace_tree_diff(workspace)
        except GitWorkspaceError:
            problems.append("WORKSPACE_CLEANLINESS_UNVERIFIED")
            return False, False
        clean = not status_output and not tree_diff.missing and not tree_diff.hidden_index_entries
        no_extra = not tree_diff.extra
        if not clean:
            problems.append("WORKSPACE_NOT_CLEAN")
        if not no_extra:
            problems.append("WORKSPACE_HAS_EXTRA_FILES")
        if tree_diff.missing:
            problems.append("WORKSPACE_MISSING_TRACKED_FILES")
        if tree_diff.hidden_index_entries:
            problems.append("WORKSPACE_UNSAFE_INDEX_FLAGS")
        return clean, no_extra

    def _workspace_tree_diff(self, workspace: Path) -> _WorkspaceTreeDiff:
        hidden = self._hidden_index_entries(workspace)
        staged = self._run(workspace, ("ls-files", "--stage", "-z")).stdout
        tracked_modes = self._parse_staged_entries(staged)
        actual = {entry.relative_path for entry in _business_entries(workspace)}
        tracked = set(tracked_modes)
        materialized = {
            path for path, mode in tracked_modes.items() if mode not in {"040000", "160000"}
        }
        return _WorkspaceTreeDiff(
            extra=tuple(sorted(actual - tracked)),
            missing=tuple(sorted(materialized - actual)),
            hidden_index_entries=hidden,
        )

    def _hidden_index_entries(self, workspace: Path) -> tuple[str, ...]:
        sparse_checkout = self._config_bool(workspace, "core.sparseCheckout")
        tagged = self._run(workspace, ("ls-files", "-v", "-z")).stdout
        hidden: list[str] = []
        for record in filter(None, tagged.split("\x00")):
            if len(record) < 3 or record[1] != " ":
                raise GitWorkspaceError(
                    "WORKSPACE_INDEX_UNREADABLE",
                    "Git index 标志输出格式无法验证。",
                )
            if record[0] == "S" or record[0].islower():
                hidden.append(record[2:])
        if sparse_checkout:
            hidden.append("<core.sparseCheckout>")
        return tuple(sorted(hidden))

    def _config_bool(self, repository: Path, key: str) -> bool:
        result = self._run(
            repository,
            ("config", "--bool", "--get", key),
            allowed_codes=(0, 1),
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    @staticmethod
    def _parse_staged_entries(output: str) -> dict[str, str]:
        tracked: dict[str, str] = {}
        for record in filter(None, output.split("\x00")):
            try:
                header, path = record.split("\t", 1)
                mode, _oid, stage = header.split(" ", 2)
            except ValueError as error:
                raise GitWorkspaceError(
                    "WORKSPACE_INDEX_UNREADABLE",
                    "Git index 条目输出格式无法验证。",
                ) from error
            if stage != "0" or mode == "040000":
                raise GitWorkspaceError(
                    "WORKSPACE_UNSAFE_INDEX_FLAGS",
                    "Git index 包含冲突或 sparse directory 条目。",
                )
            tracked[path] = mode
        return tracked

    def inspect_prepared_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
        expected_git_pointer_digest: str,
    ) -> PreparedWorkspaceStatus:
        """把只读证据映射为 Prepared Task 的四种物理状态。"""

        if not _DIGEST_RE.fullmatch(expected_git_pointer_digest):
            raise GitWorkspaceError(
                "INVALID_GIT_POINTER_DIGEST",
                "git pointer digest 必须是 64 位小写十六进制字符串。",
            )
        observation = self.observe_workspace(
            repository,
            data_root=data_root,
            workspace_relative_path=workspace_relative_path,
            ownership_nonce=ownership_nonce,
            expected_action_digest=expected_action_digest,
            recomputed_action_digest=recomputed_action_digest,
        )
        missing_is_verified = (
            observation.problems == ("WORKSPACE_MISSING",)
            and observation.action_digest == expected_action_digest
        )
        if not observation.workspace_exists and missing_is_verified:
            return PreparedWorkspaceStatus(
                WorkspaceAvailability.MISSING,
                None,
                observation,
                "WORKSPACE_UNAVAILABLE",
            )
        if not observation.workspace_exists:
            return PreparedWorkspaceStatus(
                WorkspaceAvailability.UNVERIFIED,
                None,
                observation,
                "CREATION_RECOVERY_REQUIRED",
            )
        if self._is_baseline_only_mismatch(
            repository,
            observation,
            expected_action_digest,
            expected_git_pointer_digest,
        ):
            return PreparedWorkspaceStatus(
                WorkspaceAvailability.BASELINE_MISMATCH,
                observation.head_oid,
                observation,
                "WORKSPACE_BASELINE_MISMATCH",
            )
        if self._is_available(
            repository,
            observation,
            expected_action_digest,
            expected_git_pointer_digest,
        ):
            return PreparedWorkspaceStatus(
                WorkspaceAvailability.AVAILABLE,
                observation.head_oid,
                observation,
                None,
            )
        return PreparedWorkspaceStatus(
            WorkspaceAvailability.UNVERIFIED,
            None,
            observation,
            "CREATION_RECOVERY_REQUIRED",
        )

    @staticmethod
    def _is_available(
        repository: RepositoryInspection,
        observation: WorkspaceObservation,
        expected_action_digest: str,
        expected_git_pointer_digest: str,
    ) -> bool:
        return all(
            (
                observation.within_data_root,
                observation.relative_path_matches,
                observation.git_admin_points_to_workspace,
                observation.workspace_git_points_to_admin,
                observation.common_dir_matches,
                observation.head_detached,
                observation.head_oid == repository.baseline_commit,
                observation.index_and_tracked_clean,
                observation.no_extra_files,
                observation.ownership_nonce is not None,
                observation.action_digest == expected_action_digest,
                observation.git_pointer_digest == expected_git_pointer_digest,
            )
        )

    @staticmethod
    def _is_baseline_only_mismatch(
        repository: RepositoryInspection,
        observation: WorkspaceObservation,
        expected_action_digest: str,
        expected_git_pointer_digest: str,
    ) -> bool:
        return all(
            (
                observation.workspace_exists,
                observation.within_data_root,
                observation.relative_path_matches,
                observation.git_admin_points_to_workspace,
                observation.workspace_git_points_to_admin,
                observation.common_dir_matches,
                observation.head_detached,
                observation.head_oid is not None,
                observation.head_oid != repository.baseline_commit,
                observation.index_and_tracked_clean,
                observation.no_extra_files,
                observation.ownership_nonce is not None,
                observation.action_digest == expected_action_digest,
                observation.git_pointer_digest == expected_git_pointer_digest,
            )
        )
