"""Gauntlet 与 standalone mutation 共享的仓库级父 lease。"""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

REPOSITORY_LEASE_FILE = ".gauntlet-run.lock"
REPOSITORY_LEASE_TOKEN_ENV = "SIGMACODER_REPOSITORY_LEASE_TOKEN"


class RepositoryLeaseError(RuntimeError):
    """仓库父 lease 无法安全取得、验证或释放。"""


@dataclass(frozen=True)
class RepositoryLease:
    path: Path
    device: int
    inode: int
    owner: str
    token: str
    payload: bytes


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _managed_lease_path(repo: Path) -> Path:
    resolved_repo = repo.resolve()
    report_root = resolved_repo / "mutation-reports"
    if _is_link_or_junction(report_root) or report_root.resolve(strict=False) != report_root:
        raise RepositoryLeaseError("仓库父 lease 根目录不得是链接、junction 或逃逸仓库。")
    if report_root.exists() and not report_root.is_dir():
        raise RepositoryLeaseError("仓库父 lease 根目录必须是普通目录。")
    path = report_root / REPOSITORY_LEASE_FILE
    if _is_link_or_junction(path) or path.resolve(strict=False) != path:
        raise RepositoryLeaseError("仓库父 lease 不得是链接、junction 或逃逸仓库。")
    if path.exists() and not path.is_file():
        raise RepositoryLeaseError("仓库父 lease 路径必须是普通文件或不存在。")
    return path


def _lease_problem(lease: RepositoryLease) -> str | None:
    try:
        current = lease.path.lstat()
    except OSError as exc:
        return f"无法核验仓库父 lease：{exc}"
    if (
        _is_link_or_junction(lease.path)
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (lease.device, lease.inode)
    ):
        return "仓库父 lease 文件身份已变化，拒绝删除未知路径。"
    try:
        if lease.path.read_bytes() != lease.payload:
            return "仓库父 lease 内容已变化，拒绝删除未知文件。"
        verified = lease.path.lstat()
    except OSError as exc:
        return f"无法复核仓库父 lease：{exc}"
    if (
        _is_link_or_junction(lease.path)
        or not stat.S_ISREG(verified.st_mode)
        or (verified.st_dev, verified.st_ino) != (lease.device, lease.inode)
    ):
        return "仓库父 lease 在复核期间被替换，拒绝删除未知路径。"
    return None


def _read_reentrant_lease(repo: Path, token: str) -> RepositoryLease:
    if len(token) != 32 or any(
        not (("0" <= character <= "9") or ("a" <= character <= "f")) for character in token
    ):
        raise RepositoryLeaseError("继承的仓库父 lease token 格式无效。")
    path = _managed_lease_path(repo)
    try:
        current = path.lstat()
        payload = path.read_bytes()
        parsed = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RepositoryLeaseError(f"无法读取继承的仓库父 lease：{exc}") from exc
    if (
        _is_link_or_junction(path)
        or not stat.S_ISREG(current.st_mode)
        or not isinstance(parsed, dict)
        or set(parsed) != {"owner", "pid", "token"}
        or not isinstance(parsed.get("owner"), str)
        or not isinstance(parsed.get("pid"), int)
        or isinstance(parsed.get("pid"), bool)
        or not isinstance(parsed.get("token"), str)
        or not secrets.compare_digest(parsed["token"], token)
    ):
        raise RepositoryLeaseError("继承的仓库父 lease 与当前锁文件不精确匹配。")
    lease = RepositoryLease(
        path=path,
        device=current.st_dev,
        inode=current.st_ino,
        owner=parsed["owner"],
        token=token,
        payload=payload,
    )
    problem = _lease_problem(lease)
    if problem:
        raise RepositoryLeaseError(problem)
    return lease


@contextmanager
def acquire_repository_lease(repo: Path, owner: str) -> Iterator[RepositoryLease]:
    if not owner:
        raise RepositoryLeaseError("仓库父 lease owner 不得为空。")
    path = _managed_lease_path(repo)
    token = uuid4().hex
    payload = json.dumps(
        {"owner": owner, "pid": os.getpid(), "token": token},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = path.open("xb")
    except FileExistsError as exc:
        raise RepositoryLeaseError(
            f"仓库父 lease 已被占用或为崩溃残留：{path}；拒绝并发或自动清理。"
        ) from exc
    except OSError as exc:
        raise RepositoryLeaseError(f"无法创建仓库父 lease：{exc}") from exc
    lease: RepositoryLease | None = None
    try:
        opened = os.fstat(handle.fileno())
        lease = RepositoryLease(
            path=path,
            device=opened.st_dev,
            inode=opened.st_ino,
            owner=owner,
            token=token,
            payload=payload,
        )
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        yield lease
    finally:
        if not handle.closed:
            handle.close()
        if lease is None:
            raise RepositoryLeaseError("仓库父 lease 创建后缺少所有权证据，拒绝清理未知文件。")
        problem = _lease_problem(lease)
        if problem:
            raise RepositoryLeaseError(problem)
        try:
            lease.path.unlink()
        except OSError as exc:
            raise RepositoryLeaseError(f"无法释放仓库父 lease：{exc}") from exc


@contextmanager
def parent_or_standalone_repository_lease(
    repo: Path,
    owner: str,
) -> Iterator[RepositoryLease]:
    inherited_token = os.environ.get(REPOSITORY_LEASE_TOKEN_ENV)
    if inherited_token is None:
        with acquire_repository_lease(repo, owner) as lease:
            yield lease
        return
    lease = _read_reentrant_lease(repo, inherited_token)
    try:
        yield lease
    finally:
        problem = _lease_problem(lease)
        if problem:
            raise RepositoryLeaseError(problem)
