"""以 detect-secrets 扫描 Git 跟踪文件并拒绝任何发现。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path


class SecretGateError(RuntimeError):
    """秘密扫描器不可用、输出损坏或发现疑似秘密。"""


ScanRunner = Callable[..., subprocess.CompletedProcess[str]]


def parse_scan_output(output: str) -> dict[str, list[object]]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SecretGateError(f"detect-secrets 输出不是有效 JSON：{exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
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
    command = ["detect-secrets", "scan", "--no-verify", "."]
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
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretGateError(f"无法执行 detect-secrets：{exc}") from exc
    if result.returncode != 0:
        raise SecretGateError(
            f"detect-secrets 退出码为 {result.returncode}：{result.stderr.strip()}"
        )
    findings = parse_scan_output(result.stdout)
    count = sum(len(items) for items in findings.values())
    if count:
        paths = ", ".join(sorted(path for path, items in findings.items() if items))
        raise SecretGateError(f"发现 {count} 个疑似秘密，涉及：{paths}。")
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="扫描 Git 跟踪文件中的疑似秘密。")
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
