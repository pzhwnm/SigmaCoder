"""扫描 Git 输入，只豁免可由源码字节证明的语义变异哈希。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, cast

if __package__:
    from tools import mutation_equivalents, semantic_mutants
    from tools.trusted_tools import TrustedGit, TrustedToolError
else:  # pragma: no cover - 由真实脚本入口覆盖
    import mutation_equivalents  # type: ignore[import-not-found,no-redef]
    import semantic_mutants  # type: ignore[import-not-found,no-redef]
    from trusted_tools import (  # type: ignore[import-not-found,no-redef]
        TrustedGit,
        TrustedToolError,
    )


class SecretGateError(RuntimeError):
    """秘密扫描器不可用、输出损坏或发现疑似秘密。"""


ScanRunner = Callable[..., subprocess.CompletedProcess[str]]
DETECT_SECRETS_VERSION: Final = "1.5.0"
WAIVER_CONTRACT_VERSION: Final = "mutation-manifests-derived-v2"
SEMANTIC_MANIFEST_PATH: Final = "tools/semantic_mutants.json"
MUTATION_MANIFEST_PATH: Final = mutation_equivalents.MANIFEST_RELATIVE_PATH
EXPECTED_SEMANTIC_WAIVERS: Final = 10
EXPECTED_MUTATION_WAIVERS: Final = 5
HEX_ENTROPY_FINDING_TYPE: Final = "Hex High Entropy String"
ConfigValue = str | float
ConfigSpec = tuple[tuple[str, ConfigValue], ...]
EXPECTED_SECRET_PLUGIN_CONFIGS: Final[tuple[ConfigSpec, ...]] = (
    (("name", "ArtifactoryDetector"),),
    (("name", "AWSKeyDetector"),),
    (("name", "AzureStorageKeyDetector"),),
    (("name", "Base64HighEntropyString"), ("limit", 4.5)),
    (("name", "BasicAuthDetector"),),
    (("name", "CloudantDetector"),),
    (("name", "DiscordBotTokenDetector"),),
    (("name", "GitHubTokenDetector"),),
    (("name", "GitLabTokenDetector"),),
    (("name", "HexHighEntropyString"), ("limit", 3.0)),
    (("name", "IbmCloudIamDetector"),),
    (("name", "IbmCosHmacDetector"),),
    (("name", "IPPublicDetector"),),
    (("name", "JwtTokenDetector"),),
    (("name", "KeywordDetector"), ("keyword_exclude", "")),
    (("name", "MailchimpDetector"),),
    (("name", "NpmDetector"),),
    (("name", "OpenAIDetector"),),
    (("name", "PrivateKeyDetector"),),
    (("name", "PypiTokenDetector"),),
    (("name", "SendGridDetector"),),
    (("name", "SlackDetector"),),
    (("name", "SoftlayerDetector"),),
    (("name", "SquareOAuthDetector"),),
    (("name", "StripeDetector"),),
    (("name", "TelegramBotTokenDetector"),),
    (("name", "TwilioKeyDetector"),),
)
EXPECTED_SECRET_FILTER_CONFIGS: Final[tuple[ConfigSpec, ...]] = ()
DISABLED_SECRET_FILTERS: Final[tuple[str, ...]] = (
    "detect_secrets.filters.allowlist.is_line_allowlisted",
    "detect_secrets.filters.heuristic.is_indirect_reference",
    "detect_secrets.filters.heuristic.is_likely_id_string",
    "detect_secrets.filters.heuristic.is_lock_file",
    "detect_secrets.filters.heuristic.is_non_text_file",
    "detect_secrets.filters.heuristic.is_not_alphanumeric_string",
    "detect_secrets.filters.heuristic.is_potential_uuid",
    "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign",
    "detect_secrets.filters.heuristic.is_sequential_string",
    "detect_secrets.filters.heuristic.is_swagger_file",
    "detect_secrets.filters.heuristic.is_templated_secret",
)
# detect-secrets 1.5.0 的多文件 worker 会从不可序列化的 DEFAULT_FILTERS
# 重建 is_non_text_file；每次只扫描一个显式路径，才能证明该过滤器确实被禁用。
MAX_SCAN_BATCH_PATHS: Final = 1
MAX_SCAN_COMMAND_CHARS: Final = 16_000
MAX_SCAN_FILE_SECONDS: Final = 60.0
MAX_SCAN_TOTAL_SECONDS: Final = 600.0
_PASSTHROUGH_ENVIRONMENT_KEYS: Final = (
    "SystemRoot",
    "WINDIR",
)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SEMANTIC_HASH_LINE = re.compile(
    r'\s*"(?P<field>expected_(?:source|mutant)_sha256)": '
    r'"(?P<value>[0-9a-f]{64})",?\s*\Z'
)
_MUTATION_HASH_LINE = re.compile(
    r'\s*"(?P<field>uv_lock_sha256|profile_sha256|expected_mutant_names_sha256|'
    r'expected_equivalent_names_sha256)": '
    r'"(?P<value>[0-9a-f]{64})",?\s*\Z'
)
_MUTATION_SOURCE_HASH_LINE = re.compile(
    r'\s*"source": \{"path": "src/sigmacoder/domain/events\.py", '
    r'"function": "[A-Za-z_][A-Za-z0-9_]*", "sha256": '
    r'"(?P<value>[0-9a-f]{64})"\},?\s*\Z'
)


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """detect-secrets finding 的完整、不可宽化身份。"""

    path: str
    secret_type: str
    line_number: int
    hashed_secret: str
    is_verified: bool


@dataclass(frozen=True, slots=True)
class SemanticWaiverContract:
    """由语义变异清单及其源码字节派生的精确豁免。"""

    manifest_sha256: str
    source_hashes: tuple[tuple[str, str], ...]
    expected_findings: frozenset[FindingIdentity]


@dataclass(frozen=True, slots=True)
class SecretScanEvidence:
    """成功门禁返回的可审计证据摘要。"""

    waived_findings: int
    manifest_sha256: str | None
    mutation_manifest_sha256: str | None


@dataclass(frozen=True, slots=True)
class SnapshotEntryIdentity:
    """创建 staged snapshot 时记录的普通文件或目录身份。"""

    path: Path
    device: int
    inode: int
    is_directory: bool


@dataclass(frozen=True, slots=True)
class SnapshotLayout:
    """仅包含门禁创建的已知节点，解封时不得重新遍历目录树。"""

    directories: tuple[SnapshotEntryIdentity, ...]
    files: tuple[SnapshotEntryIdentity, ...]


def _validated_relative_path(raw: str) -> PurePosixPath:
    relative = PurePosixPath(raw)
    if (
        not raw
        or relative.is_absolute()
        or relative.as_posix() != raw
        or any(part in {".", ".."} for part in raw.split("/"))
    ):
        raise SecretGateError(f"Git 输入路径不规范：{raw!r}。")
    return relative


def _require_plain_repository_file(root: Path, relative: PurePosixPath, raw: str) -> Path:
    unresolved = root
    try:
        for part in relative.parts:
            unresolved /= part
            if unresolved.is_symlink() or unresolved.is_junction():
                raise SecretGateError(f"Git 输入路径经过链接或 junction：{raw!r}。")
        candidate = unresolved.resolve(strict=True)
    except OSError as exc:
        raise SecretGateError(f"Git 输入文件不可读：{raw!r}。") from exc
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SecretGateError(f"Git 输入路径逃逸仓库：{raw!r}。") from exc
    if not candidate.is_file():
        raise SecretGateError(f"Git 输入不是仓库内普通文件：{raw!r}。")
    return candidate


def _minimal_subprocess_environment(*, scratch: Path | None = None) -> dict[str, str]:
    """只传递启动系统进程必需的宿主变量，拒绝 Python/Git 注入变量。"""

    environment: dict[str, str] = {}
    for key in _PASSTHROUGH_ENVIRONMENT_KEYS:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTHONUTF8": "1",
        }
    )
    if scratch is not None:
        for key in ("TEMP", "TMP", "TMPDIR"):
            environment[key] = str(scratch)
    return environment


def _repository_scan_paths(
    repo: Path,
    git: TrustedGit,
) -> tuple[str, ...]:
    """从 Git 的 NUL 分隔索引中生成显式、不可注入的扫描路径。"""

    try:
        stdout = git.read(
            (
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "--full-name",
                "-z",
                "--",
            ),
            label="Git 输入枚举",
            timeout=60,
        )
        decoded = stdout.decode("utf-8", errors="strict")
    except (TrustedToolError, UnicodeError) as exc:
        raise SecretGateError(str(exc)) from exc
    if not decoded or not decoded.endswith("\0"):
        raise SecretGateError("Git 输入清单为空或不是规范 NUL 分隔格式。")

    raw_paths = decoded[:-1].split("\0")
    if not raw_paths or len(raw_paths) != len(set(raw_paths)):
        raise SecretGateError("Git 输入清单为空或包含重复路径。")

    root = repo.resolve(strict=True)
    scan_paths: list[str] = []
    for raw in raw_paths:
        relative = _validated_relative_path(raw)
        _require_plain_repository_file(root, relative, raw)
        # 前缀阻断以连字符开头的文件名被下游 CLI 当成选项；始终使用 POSIX 分隔符，
        # 避免 detect-secrets 在 Windows 递归扫描时对反斜杠路径应用不一致过滤。
        scan_paths.append(f"./{relative.as_posix()}")
    return tuple(scan_paths)


def _live_manifest_path_part_exists(path: Path, *, is_leaf: bool) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SecretGateError("无法按 lexical 路径核验 live 语义变异 manifest。") from exc
    try:
        is_junction = path.is_junction()
    except OSError as exc:
        raise SecretGateError("无法确认 live 语义变异 manifest 的 junction 状态。") from exc
    if stat.S_ISLNK(metadata.st_mode) or is_junction:
        raise SecretGateError("live 语义变异 manifest 路径经过链接或 junction。")
    if is_leaf and not stat.S_ISREG(metadata.st_mode):
        raise SecretGateError("live 语义变异 manifest 不是普通文件。")
    if not is_leaf and not stat.S_ISDIR(metadata.st_mode):
        raise SecretGateError("live 语义变异 manifest 的祖先不是普通目录。")
    return True


def _live_manifest_exists(repo: Path, relative_path: str, label: str) -> bool:
    current = repo
    parts = PurePosixPath(relative_path).parts
    for index, part in enumerate(parts):
        current /= part
        try:
            exists = _live_manifest_path_part_exists(
                current,
                is_leaf=index == len(parts) - 1,
            )
        except SecretGateError as exc:
            raise SecretGateError(f"{label} 路径核验失败：{exc}") from exc
        if not exists:
            return False
    return True


def _assert_live_manifest_membership(repo: Path, scan_paths: Sequence[str]) -> None:
    manifests = (
        (SEMANTIC_MANIFEST_PATH, "live 语义变异 manifest"),
        (MUTATION_MANIFEST_PATH, "live 等价 mutant manifest"),
    )
    for relative_path, label in manifests:
        if (
            _live_manifest_exists(repo, relative_path, label)
            and f"./{relative_path}" not in scan_paths
        ):
            raise SecretGateError(f"{label} 存在但未进入 Git 秘密扫描清单。")


def _capture_live_inputs(repo: Path, scan_paths: Sequence[str]) -> dict[str, bytes]:
    """在两次身份检查之间读取 live 输入，供隔离快照使用。"""

    captured: dict[str, bytes] = {}
    for cli_path in scan_paths:
        raw = cli_path.removeprefix("./")
        relative = _validated_relative_path(raw)
        candidate = _require_plain_repository_file(repo, relative, raw)
        try:
            before = candidate.stat()
            payload = candidate.read_bytes()
            after = candidate.stat()
        except OSError as exc:
            raise SecretGateError(f"Git 输入读取失败：{raw!r}。") from exc
        try:
            payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SecretGateError(f"Git 输入不是严格 UTF-8 文本：{raw!r}。") from exc
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise SecretGateError(f"Git 输入在快照读取期间发生变化：{raw!r}。")
        if _require_plain_repository_file(repo, relative, raw) != candidate:
            raise SecretGateError(f"Git 输入在快照读取期间被替换：{raw!r}。")
        captured[raw] = payload
    return captured


def _write_staged_snapshot(root: Path, captured: Mapping[str, bytes]) -> None:
    for raw, payload in captured.items():
        destination = root.joinpath(*PurePosixPath(raw).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)


def _snapshot_directories(root: Path) -> tuple[Path, ...]:
    directories = {root}
    for current, names, _ in os.walk(root):
        current_path = Path(current)
        directories.add(current_path)
        directories.update(current_path / name for name in names)
    return tuple(sorted(directories, key=lambda item: len(item.parts)))


def _snapshot_entry_identity(path: Path, *, is_directory: bool) -> SnapshotEntryIdentity:
    try:
        metadata = os.lstat(path)
        is_junction = path.is_junction()
    except OSError as exc:
        raise SecretGateError("无法记录 staged snapshot 节点身份。") from exc
    expected_type = (
        stat.S_ISDIR(metadata.st_mode) if is_directory else stat.S_ISREG(metadata.st_mode)
    )
    if stat.S_ISLNK(metadata.st_mode) or is_junction or not expected_type:
        raise SecretGateError("staged snapshot 创建阶段出现链接、junction 或异常节点。")
    return SnapshotEntryIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        is_directory=is_directory,
    )


def _snapshot_layout(root: Path, captured: Mapping[str, bytes]) -> SnapshotLayout:
    directories = tuple(
        _snapshot_entry_identity(path, is_directory=True) for path in _snapshot_directories(root)
    )
    files = tuple(
        _snapshot_entry_identity(
            root.joinpath(*PurePosixPath(raw).parts),
            is_directory=False,
        )
        for raw in captured
    )
    return SnapshotLayout(directories=directories, files=files)


def _snapshot_entry_matches(identity: SnapshotEntryIdentity) -> bool:
    try:
        metadata = os.lstat(identity.path)
        if stat.S_ISLNK(metadata.st_mode) or identity.path.is_junction():
            return False
    except OSError:
        return False
    expected_type = (
        stat.S_ISDIR(metadata.st_mode) if identity.is_directory else stat.S_ISREG(metadata.st_mode)
    )
    return (
        expected_type and metadata.st_dev == identity.device and metadata.st_ino == identity.inode
    )


def _chmod_known_snapshot_entry(
    identity: SnapshotEntryIdentity,
    mode: int,
    *,
    required: bool,
) -> None:
    if not _snapshot_entry_matches(identity):
        if required:
            raise SecretGateError("staged snapshot 节点在权限切换前被替换。")
        return
    try:
        if os.chmod in os.supports_follow_symlinks:
            identity.path.chmod(mode, follow_symlinks=False)
        else:
            # Windows 不实现 chmod(follow_symlinks=False)；紧邻的 lexical 类型与
            # dev/inode 身份检查是此平台可用的安全前置条件。
            identity.path.chmod(mode)
    except (NotImplementedError, OSError) as exc:
        if required:
            raise SecretGateError("无法锁定 staged snapshot 节点权限。") from exc


def _seal_staged_snapshot(layout: SnapshotLayout) -> None:
    for identity in layout.files:
        _chmod_known_snapshot_entry(identity, stat.S_IREAD, required=True)
    for identity in reversed(layout.directories):
        _chmod_known_snapshot_entry(
            identity,
            stat.S_IREAD | stat.S_IEXEC,
            required=True,
        )


def _unseal_staged_snapshot(layout: SnapshotLayout) -> None:
    # 只处理创建阶段记录的身份；绝不遍历或 chmod 扫描器新增的节点。
    for identity in layout.directories:
        _chmod_known_snapshot_entry(
            identity,
            stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC,
            required=False,
        )
    for identity in layout.files:
        _chmod_known_snapshot_entry(
            identity,
            stat.S_IREAD | stat.S_IWRITE,
            required=False,
        )


def _read_staged_snapshot(root: Path) -> dict[str, bytes]:
    observed: dict[str, bytes] = {}
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in (*directories, *names):
            entry = current_path / name
            if entry.is_symlink() or entry.is_junction():
                raise SecretGateError("秘密扫描 staged snapshot 中出现了链接或 junction。")
        for name in names:
            path = current_path / name
            if not path.is_file():
                raise SecretGateError("秘密扫描 staged snapshot 中出现了非普通文件。")
            relative = path.relative_to(root).as_posix()
            observed[relative] = path.read_bytes()
    return observed


def _assert_staged_snapshot_unchanged(root: Path, captured: Mapping[str, bytes]) -> None:
    if _read_staged_snapshot(root) != dict(captured):
        raise SecretGateError("秘密扫描 staged snapshot 在扫描期间发生变化。")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise SecretGateError(f"JSON 包含重复键：{key!r}。")
        output[key] = value
    return output


def _validate_strict_manifest_json(raw: bytes, label: str) -> None:
    try:
        text = raw.decode("utf-8", errors="strict")
        json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except SecretGateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecretGateError(f"{label} 不是严格 UTF-8 JSON：{exc}") from exc


def _manifest_hash_rows(
    raw: bytes,
    manifest: semantic_mutants.Manifest,
) -> tuple[tuple[int, str, str], ...]:
    """把严格单行哈希字段绑定到解析后的 mutant 顺序和值。"""

    rows: list[tuple[int, str, str]] = []
    text = raw.decode("utf-8", errors="strict")
    for line_number, line in enumerate(text.splitlines(), start=1):
        mentions_hash_field = (
            '"expected_source_sha256"' in line or '"expected_mutant_sha256"' in line
        )
        if not mentions_hash_field:
            continue
        match = _SEMANTIC_HASH_LINE.fullmatch(line)
        if match is None:
            raise SecretGateError("语义变异 manifest 的 SHA-256 字段必须独占规范单行。")
        rows.append((line_number, match["field"], match["value"]))

    expected = tuple(
        item
        for mutant in manifest.mutants
        for item in (
            ("expected_source_sha256", mutant.expected_source_sha256),
            ("expected_mutant_sha256", mutant.expected_mutant_sha256),
        )
    )
    actual = tuple((field, value) for _, field, value in rows)
    if actual != expected:
        raise SecretGateError("语义变异 manifest 的哈希字段顺序、数量或值不符合固定契约。")
    return tuple(rows)


def _semantic_waiver_identities(
    rows: Sequence[tuple[int, str, str]],
) -> frozenset[FindingIdentity]:
    """复现 detect-secrets 1.5.0 按文件、值哈希和类型的首次出现去重。"""

    identities: list[FindingIdentity] = []
    seen: set[tuple[str, str, str]] = set()
    for line_number, _, value in rows:
        hashed_secret = hashlib.sha1(value.encode("utf-8"), usedforsecurity=False).hexdigest()
        comparison_key = (
            SEMANTIC_MANIFEST_PATH,
            hashed_secret,
            HEX_ENTROPY_FINDING_TYPE,
        )
        if comparison_key in seen:
            continue
        seen.add(comparison_key)
        identities.append(
            FindingIdentity(
                path=SEMANTIC_MANIFEST_PATH,
                secret_type=HEX_ENTROPY_FINDING_TYPE,
                line_number=line_number,
                hashed_secret=hashed_secret,
                is_verified=False,
            )
        )
    if len(identities) != EXPECTED_SEMANTIC_WAIVERS:
        raise SecretGateError(
            f"语义变异 manifest 必须派生恰好 {EXPECTED_SEMANTIC_WAIVERS} 条固定秘密扫描豁免。"
        )
    return frozenset(identities)


def _build_semantic_waiver_contract(
    repo: Path,
    scan_paths: Sequence[str],
) -> SemanticWaiverContract | None:
    manifest_path = repo / SEMANTIC_MANIFEST_PATH
    manifest_is_scanned = f"./{SEMANTIC_MANIFEST_PATH}" in scan_paths
    if not manifest_path.exists():
        return None
    if not manifest_is_scanned:
        raise SecretGateError("语义变异 manifest 存在但未进入 Git 秘密扫描清单。")

    try:
        raw = manifest_path.read_bytes()
        _validate_strict_manifest_json(raw, "语义变异 manifest")
        manifest = semantic_mutants.load_manifest(manifest_path)
        if manifest.sha256 != hashlib.sha256(raw).hexdigest():
            raise SecretGateError("语义变异 manifest 在解析期间发生变化。")
        source_hashes = semantic_mutants._validate_repo_inputs(repo, manifest)
    except SecretGateError:
        raise
    except (OSError, UnicodeError, semantic_mutants.SemanticMutationError) as exc:
        raise SecretGateError(f"语义变异哈希豁免无法获得权威证明：{exc}") from exc

    for source in source_hashes:
        if f"./{source}" not in scan_paths:
            raise SecretGateError(f"语义变异源码未进入 Git 秘密扫描清单：{source}。")
    rows = _manifest_hash_rows(raw, manifest)
    return SemanticWaiverContract(
        manifest_sha256=manifest.sha256,
        source_hashes=tuple(sorted(source_hashes.items())),
        expected_findings=_semantic_waiver_identities(rows),
    )


def _mutation_manifest_hash_rows(
    raw: bytes,
    manifest: Mapping[str, object],
) -> tuple[tuple[int, str, str], ...]:
    """把 r5 清单中的五类固定 SHA 字段绑定到严格解析后的值。"""

    rows: list[tuple[int, str, str]] = []
    field_tokens = (
        '"uv_lock_sha256"',
        '"profile_sha256"',
        '"expected_mutant_names_sha256"',
        '"expected_equivalent_names_sha256"',
        '"sha256"',
    )
    for line_number, line in enumerate(raw.decode("utf-8", errors="strict").splitlines(), start=1):
        if not any(token in line for token in field_tokens):
            continue
        match = _MUTATION_HASH_LINE.fullmatch(line)
        if match is not None:
            rows.append((line_number, match["field"], match["value"]))
            continue
        source_match = _MUTATION_SOURCE_HASH_LINE.fullmatch(line)
        if source_match is None:
            raise SecretGateError("等价 mutant manifest 的 SHA-256 字段必须独占规范单行。")
        rows.append((line_number, "sha256", source_match["value"]))

    generator = cast(Mapping[str, object], manifest["generator"])
    profile = cast(Mapping[str, object], manifest["profile"])
    equivalents = cast(Sequence[Mapping[str, object]], manifest["equivalents"])
    expected = (
        ("uv_lock_sha256", generator["uv_lock_sha256"]),
        ("profile_sha256", profile["profile_sha256"]),
        ("expected_mutant_names_sha256", profile["expected_mutant_names_sha256"]),
        (
            "expected_equivalent_names_sha256",
            profile["expected_equivalent_names_sha256"],
        ),
        *(
            ("sha256", cast(Mapping[str, object], entry["source"])["sha256"])
            for entry in equivalents
        ),
    )
    if tuple((field, value) for _, field, value in rows) != expected:
        raise SecretGateError("等价 mutant manifest 的哈希字段顺序、数量或值不符合固定契约。")
    return tuple(rows)


def _mutation_waiver_identities(
    rows: Sequence[tuple[int, str, str]],
) -> frozenset[FindingIdentity]:
    identities: list[FindingIdentity] = []
    seen: set[str] = set()
    for line_number, _field, value in rows:
        hashed_secret = hashlib.sha1(value.encode("utf-8"), usedforsecurity=False).hexdigest()
        if hashed_secret in seen:
            continue
        seen.add(hashed_secret)
        identities.append(
            FindingIdentity(
                path=MUTATION_MANIFEST_PATH,
                secret_type=HEX_ENTROPY_FINDING_TYPE,
                line_number=line_number,
                hashed_secret=hashed_secret,
                is_verified=False,
            )
        )
    if len(identities) != EXPECTED_MUTATION_WAIVERS:
        raise SecretGateError(
            f"等价 mutant manifest 必须派生恰好 {EXPECTED_MUTATION_WAIVERS} 条固定秘密扫描豁免。"
        )
    return frozenset(identities)


def _build_mutation_waiver_contract(
    repo: Path,
    scan_paths: Sequence[str],
) -> SemanticWaiverContract | None:
    manifest_path = repo / MUTATION_MANIFEST_PATH
    if not manifest_path.exists():
        return None
    if f"./{MUTATION_MANIFEST_PATH}" not in scan_paths:
        raise SecretGateError("等价 mutant manifest 存在但未进入 Git 秘密扫描清单。")

    try:
        raw = manifest_path.read_bytes()
        _validate_strict_manifest_json(raw, "等价 mutant manifest")
        manifest = mutation_equivalents.load_equivalent_manifest(repo, manifest_path)
        manifest_sha256 = hashlib.sha256(raw).hexdigest()
        if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_sha256:
            raise SecretGateError("等价 mutant manifest 在解析期间发生变化。")
    except SecretGateError:
        raise
    except (OSError, UnicodeError, mutation_equivalents.EquivalentManifestError) as exc:
        raise SecretGateError(f"等价 mutant 哈希豁免无法获得权威证明：{exc}") from exc

    required_paths = (
        mutation_equivalents.LOCK_RELATIVE_PATH,
        mutation_equivalents.PROFILE_RELATIVE_PATH,
        mutation_equivalents.SOURCE_RELATIVE_PATH,
        mutation_equivalents.SPEC_RELATIVE_PATH,
    )
    source_hashes: list[tuple[str, str]] = []
    for relative in required_paths:
        if f"./{relative}" not in scan_paths:
            raise SecretGateError(f"等价 mutant 绑定输入未进入 Git 秘密扫描清单：{relative}。")
        source_hashes.append((relative, hashlib.sha256((repo / relative).read_bytes()).hexdigest()))
    rows = _mutation_manifest_hash_rows(raw, manifest)
    return SemanticWaiverContract(
        manifest_sha256=manifest_sha256,
        source_hashes=tuple(source_hashes),
        expected_findings=_mutation_waiver_identities(rows),
    )


def _canonical_finding_path(raw: str) -> str:
    if not raw or "\0" in raw or raw.startswith(("/", "\\")):
        raise SecretGateError(f"detect-secrets finding 路径不规范：{raw!r}。")
    normalized = raw.replace("\\", "/")
    if re.match(r"[A-Za-z]:", normalized) is not None:
        raise SecretGateError(f"detect-secrets finding 路径不规范：{raw!r}。")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return _validated_relative_path(normalized).as_posix()


def _finding_identities(
    results: Mapping[str, list[object]],
    scan_paths: Sequence[str],
) -> tuple[FindingIdentity, ...]:
    allowed_paths = {path.removeprefix("./") for path in scan_paths}
    identities: list[FindingIdentity] = []
    required_fields = {"type", "filename", "hashed_secret", "is_verified", "line_number"}
    for raw_path, findings in results.items():
        path = _canonical_finding_path(raw_path)
        if path not in allowed_paths:
            raise SecretGateError(f"detect-secrets 返回了扫描清单外路径：{raw_path!r}。")
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != required_fields:
                raise SecretGateError("detect-secrets finding 字段集合无效。")
            secret_type = finding["type"]
            filename = finding["filename"]
            hashed_secret = finding["hashed_secret"]
            is_verified = finding["is_verified"]
            line_number = finding["line_number"]
            if (
                not isinstance(secret_type, str)
                or not secret_type
                or not isinstance(filename, str)
                or _canonical_finding_path(filename) != path
                or not isinstance(hashed_secret, str)
                or _SHA1.fullmatch(hashed_secret) is None
                or type(is_verified) is not bool
                or type(line_number) is not int
                or line_number <= 0
            ):
                raise SecretGateError("detect-secrets finding 字段类型或值无效。")
            identities.append(
                FindingIdentity(path, secret_type, line_number, hashed_secret, is_verified)
            )
    if len(identities) != len(set(identities)):
        raise SecretGateError("detect-secrets 返回了重复 finding 身份。")
    return tuple(identities)


def _validate_exact_configurations(
    value: object,
    expected: Sequence[ConfigSpec],
    *,
    label: str,
) -> None:
    if not isinstance(value, list) or len(value) != len(expected):
        raise SecretGateError(f"detect-secrets {label} 数量与锁定配置不一致。")
    for index, (raw_item, expected_item) in enumerate(zip(value, expected, strict=True)):
        if not isinstance(raw_item, dict) or any(not isinstance(key, str) for key in raw_item):
            raise SecretGateError(f"detect-secrets {label} 第 {index + 1} 项结构无效。")
        item = cast(dict[str, object], raw_item)
        locked = dict(expected_item)
        if set(item) != set(locked):
            raise SecretGateError(f"detect-secrets {label} 第 {index + 1} 项字段漂移。")
        for key, expected_value in locked.items():
            actual_value = item[key]
            if type(actual_value) is not type(expected_value) or actual_value != expected_value:
                raise SecretGateError(
                    f"detect-secrets {label} 第 {index + 1} 项参数 {key!r} 漂移。"
                )


def parse_scan_output(output: str) -> dict[str, list[object]]:
    try:
        payload = json.loads(output, object_pairs_hook=_reject_duplicate_json_keys)
    except SecretGateError:
        raise
    except json.JSONDecodeError as exc:
        raise SecretGateError(f"detect-secrets 输出不是有效 JSON：{exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != DETECT_SECRETS_VERSION:
        raise SecretGateError("detect-secrets 输出版本缺失或与锁定版本不一致。")
    _validate_exact_configurations(
        payload.get("plugins_used"),
        EXPECTED_SECRET_PLUGIN_CONFIGS,
        label="插件",
    )
    _validate_exact_configurations(
        payload.get("filters_used"),
        EXPECTED_SECRET_FILTER_CONFIGS,
        label="过滤器",
    )
    if not isinstance(payload.get("results"), dict):
        raise SecretGateError("detect-secrets 输出缺少 results 对象。")
    results: Mapping[object, object] = payload["results"]
    normalized: dict[str, list[object]] = {}
    for path, findings in results.items():
        if not isinstance(path, str) or not isinstance(findings, list):
            raise SecretGateError("detect-secrets results 结构无效。")
        normalized[path] = findings
    return normalized


def _detect_secrets_base_command() -> list[str]:
    interpreter = Path(sys.executable)
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise SecretGateError("Python 解释器不是可核验的绝对文件，无法隔离启动 detect-secrets。")
    command = [
        str(interpreter),
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


def _scan_path_batches(
    base_command: Sequence[str], scan_paths: Sequence[str]
) -> tuple[tuple[str, ...], ...]:
    """按路径数和 Windows 命令行长度的保守上限确定性分批。"""

    batches: list[tuple[str, ...]] = []
    current: list[str] = []
    for path in scan_paths:
        candidate = [*base_command, *current, path]
        exceeds_limit = (
            len(current) >= MAX_SCAN_BATCH_PATHS
            or len(subprocess.list2cmdline(candidate)) > MAX_SCAN_COMMAND_CHARS
        )
        if exceeds_limit:
            if not current:
                raise SecretGateError(f"单个 Git 输入路径超过安全命令行上限：{path!r}。")
            batches.append(tuple(current))
            current = []
            candidate = [*base_command, path]
            if len(subprocess.list2cmdline(candidate)) > MAX_SCAN_COMMAND_CHARS:
                raise SecretGateError(f"单个 Git 输入路径超过安全命令行上限：{path!r}。")
        current.append(path)
    if current:
        batches.append(tuple(current))
    if not batches:
        raise SecretGateError("Git 输入清单为空，无法分批执行秘密扫描。")
    return tuple(batches)


def _execute_detect_secrets_batch(
    snapshot: Path,
    command: Sequence[str],
    environment: Mapping[str, str],
    remaining: float,
    deadline: float,
    runner: ScanRunner,
) -> subprocess.CompletedProcess[str]:
    """执行一个扫描批次，并在读取结果前重新验证全局 deadline。"""

    try:
        result = runner(
            command,
            cwd=snapshot,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=environment,
            stdin=subprocess.DEVNULL,
            shell=False,
            timeout=min(MAX_SCAN_FILE_SECONDS, remaining),
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SecretGateError(f"无法执行 detect-secrets：{exc}") from exc
    if time.monotonic() >= deadline:
        raise SecretGateError("detect-secrets 全局 deadline 已耗尽。")
    if result.returncode != 0:
        raise SecretGateError(
            f"detect-secrets 退出码为 {result.returncode}：{result.stderr.strip()}"
        )
    if result.stderr.strip():
        raise SecretGateError(f"detect-secrets 成功退出但写入诊断：{result.stderr.strip()}")
    return result


def _run_detect_secrets(
    snapshot: Path,
    scratch: Path,
    scan_paths: Sequence[str],
    runner: ScanRunner,
) -> dict[str, list[object]]:
    base_command = _detect_secrets_base_command()
    batches = _scan_path_batches(base_command, scan_paths)
    environment = _minimal_subprocess_environment(scratch=scratch)
    aggregated: dict[str, list[object]] = {}
    completed_paths: list[str] = []
    deadline = time.monotonic() + MAX_SCAN_TOTAL_SECONDS
    for batch in batches:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretGateError("detect-secrets 全局 deadline 已耗尽。")
        command = [*base_command, *batch]
        result = _execute_detect_secrets_batch(
            snapshot,
            command,
            environment,
            remaining,
            deadline,
            runner,
        )
        batch_results = parse_scan_output(result.stdout)
        overlap = set(aggregated).intersection(batch_results)
        if overlap:
            raise SecretGateError("detect-secrets 分批结果返回了重复路径。")
        aggregated.update(batch_results)
        completed_paths.extend(batch)
    if tuple(completed_paths) != tuple(scan_paths):
        raise SecretGateError("detect-secrets 未完成全部 Git 输入的单文件扫描。")
    return aggregated


def _assert_live_inputs_unchanged(
    repo: Path,
    scan_paths: Sequence[str],
    captured: Mapping[str, bytes],
    git: TrustedGit,
) -> None:
    try:
        git.assert_root()
    except TrustedToolError as exc:
        raise SecretGateError(str(exc)) from exc
    after_paths = _repository_scan_paths(repo, git)
    _assert_live_manifest_membership(repo, after_paths)
    if tuple(scan_paths) != after_paths:
        raise SecretGateError("Git 秘密扫描清单在 staged 扫描期间发生变化。")
    if _capture_live_inputs(repo, after_paths) != dict(captured):
        raise SecretGateError("live Git 输入字节在 staged 扫描期间发生变化。")


def _evaluate_findings(
    results: Mapping[str, list[object]],
    scan_paths: Sequence[str],
    semantic_contract: SemanticWaiverContract | None,
    mutation_contract: SemanticWaiverContract | None,
) -> SecretScanEvidence:
    observed = frozenset(_finding_identities(results, scan_paths))
    contracts = (
        ("语义变异", EXPECTED_SEMANTIC_WAIVERS, semantic_contract),
        ("等价 mutant", EXPECTED_MUTATION_WAIVERS, mutation_contract),
    )
    for label, count, contract in contracts:
        if contract is not None and contract.expected_findings - observed:
            raise SecretGateError(
                f"detect-secrets 未观测到{label} manifest 固定的 "
                f"{count} 条哈希 finding，疑似跳过了输入。"
            )
    expected = frozenset(
        finding
        for _label, _count, contract in contracts
        if contract is not None
        for finding in contract.expected_findings
    )
    unexpected = observed - expected
    if unexpected:
        locations = ", ".join(
            sorted(
                f"{finding.path}:{finding.line_number}:{finding.secret_type}"
                for finding in unexpected
            )
        )
        raise SecretGateError(f"发现 {len(unexpected)} 个未获证明的疑似秘密，涉及：{locations}。")
    return SecretScanEvidence(
        waived_findings=len(expected),
        manifest_sha256=(
            semantic_contract.manifest_sha256 if semantic_contract is not None else None
        ),
        mutation_manifest_sha256=(
            mutation_contract.manifest_sha256 if mutation_contract is not None else None
        ),
    )


def scan_repository(
    repo: Path,
    *,
    runner: ScanRunner = subprocess.run,
) -> SecretScanEvidence:
    live_repo = repo.resolve(strict=True)
    try:
        git = TrustedGit.open(live_repo, runner=runner)
    except TrustedToolError as exc:
        raise SecretGateError(str(exc)) from exc
    scan_paths = _repository_scan_paths(live_repo, git)
    _assert_live_manifest_membership(live_repo, scan_paths)
    captured = _capture_live_inputs(live_repo, scan_paths)
    try:
        with tempfile.TemporaryDirectory(prefix="sigmacoder-secret-scan-") as temporary:
            temporary_root = Path(temporary).resolve(strict=True)
            snapshot = temporary_root / "snapshot"
            scratch = temporary_root / "scratch"
            snapshot.mkdir()
            scratch.mkdir()
            layout: SnapshotLayout | None = None
            try:
                _write_staged_snapshot(snapshot, captured)
                layout = _snapshot_layout(snapshot, captured)
                _seal_staged_snapshot(layout)
                semantic_contract = _build_semantic_waiver_contract(snapshot, scan_paths)
                mutation_contract = _build_mutation_waiver_contract(snapshot, scan_paths)
                results = _run_detect_secrets(snapshot, scratch, scan_paths, runner)
                _assert_staged_snapshot_unchanged(snapshot, captured)
                _assert_live_inputs_unchanged(
                    live_repo,
                    scan_paths,
                    captured,
                    git,
                )
                return _evaluate_findings(
                    results,
                    scan_paths,
                    semantic_contract,
                    mutation_contract,
                )
            finally:
                if layout is not None:
                    _unseal_staged_snapshot(layout)
    except SecretGateError:
        raise
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SecretGateError(f"无法建立或核验秘密扫描 staged snapshot：{exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="扫描 Git 跟踪及非忽略输入中的疑似秘密。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        evidence = scan_repository(args.repo.resolve())
    except SecretGateError as exc:
        print(f"秘密扫描门禁失败：{exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "ok": True,
                "findings": 0,
                "waived_findings": evidence.waived_findings,
                "waiver_contract": (
                    WAIVER_CONTRACT_VERSION
                    if evidence.manifest_sha256 is not None
                    or evidence.mutation_manifest_sha256 is not None
                    else None
                ),
                "manifest_sha256": evidence.manifest_sha256,
                "mutation_manifest_sha256": evidence.mutation_manifest_sha256,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
