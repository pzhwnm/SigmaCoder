"""以 detect-secrets 扫描 Git 跟踪及非忽略输入并拒绝任何发现。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Final


class SecretGateError(RuntimeError):
    """秘密扫描器不可用、输出损坏或发现疑似秘密。"""


ScanRunner = Callable[..., subprocess.CompletedProcess[str]]
DETECT_SECRETS_VERSION: Final = "1.5.0"
REQUIRED_SECRET_PLUGINS: Final = frozenset(
    {
        "AWSKeyDetector",
        "Base64HighEntropyString",
        "GitHubTokenDetector",
        "HexHighEntropyString",
        "KeywordDetector",
        "PrivateKeyDetector",
    }
)


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


def _require_plain_repository_file(root: Path, relative: PurePosixPath, raw: str) -> None:
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


def _repository_scan_paths(repo: Path, runner: ScanRunner) -> tuple[str, ...]:
    """从 Git 的 NUL 分隔索引中生成显式、不可注入的扫描路径。"""

    try:
        result = runner(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SecretGateError(f"无法枚举 Git 扫描输入：{exc}") from exc
    if result.returncode != 0:
        raise SecretGateError(f"Git 输入枚举失败：{result.stderr.strip()}")
    if not result.stdout or not result.stdout.endswith("\0"):
        raise SecretGateError("Git 输入清单为空或不是规范 NUL 分隔格式。")

    raw_paths = result.stdout[:-1].split("\0")
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


def parse_scan_output(output: str) -> dict[str, list[object]]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SecretGateError(f"detect-secrets 输出不是有效 JSON：{exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != DETECT_SECRETS_VERSION:
        raise SecretGateError("detect-secrets 输出版本缺失或与锁定版本不一致。")
    plugins = payload.get("plugins_used")
    if not isinstance(plugins, list):
        raise SecretGateError("detect-secrets 输出缺少 plugins_used 数组。")
    plugin_names = {
        item.get("name")
        for item in plugins
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if not REQUIRED_SECRET_PLUGINS.issubset(plugin_names):
        raise SecretGateError("detect-secrets 输出缺少必需的秘密检测插件。")
    if not isinstance(payload.get("results"), dict):
        raise SecretGateError("detect-secrets 输出缺少 results 对象。")
    results: Mapping[object, object] = payload["results"]
    normalized: dict[str, list[object]] = {}
    for path, findings in results.items():
        if not isinstance(path, str) or not isinstance(findings, list):
            raise SecretGateError("detect-secrets results 结构无效。")
        normalized[path] = findings
    return normalized


def scan_repository(
    repo: Path,
    *,
    runner: ScanRunner = subprocess.run,
) -> dict[str, list[object]]:
    scan_paths = _repository_scan_paths(repo, runner)
    command = ["detect-secrets", "scan", "--no-verify", *scan_paths]
    try:
        result = runner(
            command,
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise SecretGateError(f"无法执行 detect-secrets：{exc}") from exc
    if result.returncode != 0:
        raise SecretGateError(
            f"detect-secrets 退出码为 {result.returncode}：{result.stderr.strip()}"
        )
    if result.stderr.strip():
        raise SecretGateError(f"detect-secrets 成功退出但写入诊断：{result.stderr.strip()}")
    findings = parse_scan_output(result.stdout)
    count = sum(len(items) for items in findings.values())
    if count:
        paths = ", ".join(sorted(path for path, items in findings.items() if items))
        raise SecretGateError(f"发现 {count} 个疑似秘密，涉及：{paths}。")
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="扫描 Git 跟踪及非忽略输入中的疑似秘密。")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scan_repository(args.repo.resolve())
    except SecretGateError as exc:
        print(f"秘密扫描门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "findings": 0}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
