"""对 pip-licenses JSON 执行精确许可证 allowlist 门禁。"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ALLOWED_LICENSES = frozenset(
    {
        "MIT",
        "0BSD",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "ISC",
        "Python-2.0",
        "PSF-2.0",
        "MPL-2.0",
    }
)

LICENSE_ALIASES = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "ISC License (ISCL)": "ISC",
    "Zero-Clause BSD": "0BSD",
    "Apache 2.0": "Apache-2.0",
    "PSFL": "PSF-2.0",
}

# 这些旧包只发布宽泛的 Trove classifier；版本绑定映射来自其锁定 wheel 的 LICENSE。
PACKAGE_LICENSE_OVERRIDES = {
    ("Jinja2", "3.1.6", "BSD License"): "BSD-3-Clause",
    ("colorama", "0.4.6", "BSD License"): "BSD-3-Clause",
    ("setproctitle", "1.3.7", "BSD License"): "BSD-3-Clause",
}


class LicenseGateError(RuntimeError):
    """许可证清单不完整或包含未批准许可证。"""


def load_records(path: Path) -> list[Mapping[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LicenseGateError(f"无法读取许可证 JSON：{exc}") from exc
    if not isinstance(payload, list) or not payload:
        raise LicenseGateError("许可证 JSON 必须是非空数组。")
    if not all(isinstance(item, dict) for item in payload):
        raise LicenseGateError("许可证 JSON 的每一项都必须是对象。")
    return payload


def _atoms(expression: str) -> tuple[str, ...]:
    expression = LICENSE_ALIASES.get(expression.strip(), expression.strip())
    if not expression or expression.lower() in {"unknown", "custom", "n/a", "none"}:
        raise LicenseGateError(f"许可证 {expression!r} 不可识别。")
    parts = re.split(r"\s+(?:AND|OR)\s+", expression)
    atoms = tuple(part.strip().strip("()") for part in parts)
    if not atoms or any(not atom or not re.fullmatch(r"[A-Za-z0-9.+-]+", atom) for atom in atoms):
        raise LicenseGateError(f"许可证表达式 {expression!r} 无法安全解析。")
    return atoms


def check_records(records: Sequence[Mapping[str, Any]]) -> list[dict[str, object]]:
    checked: list[dict[str, object]] = []
    for index, record in enumerate(records):
        name = record.get("Name", record.get("name"))
        version = record.get("Version", record.get("version"))
        license_value = record.get("License", record.get("license"))
        if not all(
            isinstance(value, str) and value.strip() for value in (name, version, license_value)
        ):
            raise LicenseGateError(f"第 {index + 1} 项缺少 Name、Version 或 License。")
        normalized_license = PACKAGE_LICENSE_OVERRIDES.get(
            (name, version, license_value), license_value
        )
        atoms = _atoms(normalized_license)
        denied = sorted(set(atoms) - ALLOWED_LICENSES)
        if denied:
            raise LicenseGateError(
                f"依赖 {name}=={version} 包含未批准许可证：{', '.join(denied)}。"
            )
        checked.append({"name": name, "version": version, "licenses": list(atoms)})
    return checked


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="校验第三方依赖许可证清单。")
    parser.add_argument("input", type=Path, help="pip-licenses JSON 文件。")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        checked = check_records(load_records(args.input))
    except LicenseGateError as exc:
        print(f"许可证门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "packages": checked}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
