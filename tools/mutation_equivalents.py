"""T01 r5 等价 mutant 清单的封闭 schema 与仓库绑定校验。"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tomllib
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

MANIFEST_RELATIVE_PATH = "tools/mutation_equivalents.json"
SPEC_RELATIVE_PATH = "docs/specs/T01-persistent-coding-task.md"
PROFILE_RELATIVE_PATH = "tools/mutation_profiles.json"
SOURCE_RELATIVE_PATH = "src/sigmacoder/domain/events.py"
LOCK_RELATIVE_PATH = "uv.lock"

MANIFEST_ID = "T01-events-equivalent-mutants-v1"
SPEC_REVISION = "r5"
MUTMUT_VERSION = "3.7.0"


def _fixed_sha256(*parts: str) -> str:
    value = "".join(parts)
    if len(value) != 64:
        raise RuntimeError("固定 SHA-256 必须精确包含 64 个十六进制字符。")
    return value


EXPECTED_LOCK_SHA256 = _fixed_sha256(
    "029d68f7",
    "d05a56a2",
    "3a7d6dbf",
    "31a18356",
    "bc674a00",
    "19e1ea62",
    "d09cfaee",
    "ebce0c43",
)
EXPECTED_PROFILE_SHA256 = _fixed_sha256(
    "278d176a",
    "0a648a04",
    "a7b4d0e9",
    "cc72c746",
    "2faaf574",
    "31c5bb56",
    "2aa5d301",
    "edd5dd45",
)
EXPECTED_SOURCE_SHA256 = _fixed_sha256(
    "facffbf2",
    "130ee099",
    "41b21018",
    "b9962733",
    "5b40cd63",
    "a9fd9eea",
    "2f017ef2",
    "6dfcf480",
)
EXPECTED_MUTANT_COUNT = 1601
EXPECTED_MUTANT_NAMES_SHA256 = _fixed_sha256(
    "319603cc",
    "8eb5992c",
    "ae790595",
    "6734de23",
    "ef3172a8",
    "b991fb18",
    "49f8560d",
    "346405dd",
)
EXPECTED_EQUIVALENT_COUNT = 49
EXPECTED_EQUIVALENT_NAMES_SHA256 = _fixed_sha256(
    "3efbac39",
    "32d88e1a",
    "6d063d8b",
    "4752399b",
    "6d1b8c86",
    "769f34c7",
    "cce0548f",
    "2b4cf7e5",
)

TYPE_ONLY_CAST = "TYPE_ONLY_CAST"
OBSERVATIONALLY_EQUIVALENT_RUNTIME = "OBSERVATIONALLY_EQUIVALENT_RUNTIME"
GUARD_DOMINATED_EQUIVALENCE = "GUARD_DOMINATED_EQUIVALENCE"
NON_CONTRACT_DIAGNOSTIC = "NON_CONTRACT_DIAGNOSTIC"
UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK = "UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK"

EXPECTED_CATEGORY_COUNTS: dict[str, int] = {
    TYPE_ONLY_CAST: 4,
    OBSERVATIONALLY_EQUIVALENT_RUNTIME: 14,
    GUARD_DOMINATED_EQUIVALENCE: 11,
    NON_CONTRACT_DIAGNOSTIC: 6,
    UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK: 14,
}

_PREFIX = "sigmacoder.domain.events."
_APPROVED_SUFFIX_CATEGORIES: dict[str, str] = {
    "x__apply_event__mutmut_105": TYPE_ONLY_CAST,
    "x__event_int__mutmut_4": NON_CONTRACT_DIAGNOSTIC,
    "x__event_payload__mutmut_5": NON_CONTRACT_DIAGNOSTIC,
    "x__event_payload__mutmut_6": NON_CONTRACT_DIAGNOSTIC,
    "x__event_payload__mutmut_7": NON_CONTRACT_DIAGNOSTIC,
    "x__event_text__mutmut_3": NON_CONTRACT_DIAGNOSTIC,
    "x__fallback_sort_atom__mutmut_1": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__fallback_sort_atom__mutmut_10": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__fallback_sort_atom__mutmut_11": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__fallback_sort_atom__mutmut_12": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__fallback_sort_atom__mutmut_14": NON_CONTRACT_DIAGNOSTIC,
    "x__fallback_sort_atom__mutmut_3": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__fallback_sort_atom__mutmut_5": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__fallback_sort_atom__mutmut_6": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__fallback_sort_atom__mutmut_7": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__fallback_sort_atom__mutmut_9": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__is_oid__mutmut_2": GUARD_DOMINATED_EQUIVALENCE,
    "x__is_portable_relative_path__mutmut_13": GUARD_DOMINATED_EQUIVALENCE,
    "x__is_portable_relative_path__mutmut_28": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__is_portable_relative_path__mutmut_31": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__is_portable_relative_path__mutmut_37": GUARD_DOMINATED_EQUIVALENCE,
    "x__is_portable_relative_path__mutmut_5": GUARD_DOMINATED_EQUIVALENCE,
    "x__is_uuid4__mutmut_1": GUARD_DOMINATED_EQUIVALENCE,
    "x__normalized_event_copy__mutmut_2": TYPE_ONLY_CAST,
    "x__normalized_event_copy__mutmut_6": TYPE_ONLY_CAST,
    "x__oid_matches_object_format__mutmut_10": GUARD_DOMINATED_EQUIVALENCE,
    "x__oid_matches_object_format__mutmut_21": GUARD_DOMINATED_EQUIVALENCE,
    "x__prevalidation_order_key__mutmut_1": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_order_key__mutmut_12": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_order_key__mutmut_13": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_order_key__mutmut_14": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__prevalidation_order_key__mutmut_2": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_order_key__mutmut_4": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__prevalidation_order_key__mutmut_5": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__prevalidation_token__mutmut_1": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_token__mutmut_10": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_token__mutmut_13": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_token__mutmut_15": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__prevalidation_token__mutmut_4": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__prevalidation_token__mutmut_6": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x__prevalidation_token__mutmut_9": UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK,
    "x__validated_checkpoint_prefix__mutmut_42": TYPE_ONLY_CAST,
    "x__validated_checkpoint_prefix__mutmut_55": GUARD_DOMINATED_EQUIVALENCE,
    "x_canonical_json_bytes__mutmut_13": GUARD_DOMINATED_EQUIVALENCE,
    "x_canonical_json_bytes__mutmut_18": GUARD_DOMINATED_EQUIVALENCE,
    "x_canonical_json_bytes__mutmut_21": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x_canonical_json_bytes__mutmut_5": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x_canonical_json_bytes__mutmut_8": OBSERVATIONALLY_EQUIVALENT_RUNTIME,
    "x_restore_task_projection__mutmut_43": GUARD_DOMINATED_EQUIVALENCE,
}
APPROVED_CATEGORIES: dict[str, str] = {
    f"{_PREFIX}{suffix}": category for suffix, category in _APPROVED_SUFFIX_CATEGORIES.items()
}

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "manifest_id",
        "approved_spec",
        "generator",
        "profile",
        "category_counts",
        "equivalents",
    }
)
_SPEC_FIELDS = frozenset({"path", "revision"})
_GENERATOR_FIELDS = frozenset({"distribution", "version", "uv_lock_sha256"})
_PROFILE_FIELDS = frozenset(
    {
        "name",
        "profile_sha256",
        "expected_mutant_count",
        "expected_mutant_names_sha256",
        "expected_equivalent_count",
        "expected_equivalent_names_sha256",
    }
)
_ENTRY_FIELDS = frozenset({"name", "category", "reason_code", "reason", "source"})
_SOURCE_FIELDS = frozenset({"path", "function", "sha256"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CJK = re.compile(r"[\u4e00-\u9fff]")
_RULE_META = frozenset("*?[]^$\\")


class EquivalentManifestError(RuntimeError):
    """等价 mutant 清单不满足 r5 封闭契约。"""


def _mapping(
    value: object,
    label: str,
    expected_fields: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EquivalentManifestError(f"{label} 必须是 JSON 对象。")
    keys = set(value)
    if keys != expected_fields:
        raise EquivalentManifestError(f"{label} 字段不符合封闭 schema。")
    return cast(Mapping[str, object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EquivalentManifestError(f"{label} 必须是非空字符串。")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EquivalentManifestError(f"{label} 必须是整数且不得是布尔值。")
    return value


def _sha256(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise EquivalentManifestError(f"{label} 必须是小写 SHA-256。")
    return text


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _ordinary_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EquivalentManifestError(f"无法读取{label}：{exc}") from exc
    if _is_link_or_junction(path) or not stat.S_ISREG(metadata.st_mode):
        raise EquivalentManifestError(f"{label}必须是普通文件且不得是链接或 junction。")


def _file_sha256(path: Path, label: str) -> str:
    _ordinary_file(path, label)
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise EquivalentManifestError(f"无法读取{label}摘要：{exc}") from exc


def _require_file_digest(repo: Path, relative: str, expected: str, label: str) -> None:
    actual = _file_sha256(repo / relative, label)
    if actual != expected:
        raise EquivalentManifestError(f"{label}指纹与获批绑定不一致。")


def _pairs_without_duplicates(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EquivalentManifestError(f"JSON 包含重复字段：{key}")
        result[key] = value
    return result


def _decode_json(raw_bytes: bytes) -> object:
    try:
        text = raw_bytes.decode("utf-8")
        return json.loads(text, object_pairs_hook=_pairs_without_duplicates)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EquivalentManifestError(f"等价清单不是有效 UTF-8 JSON：{exc}") from exc


def _manifest_location(repo: Path, path: Path) -> Path:
    resolved_repo = repo.resolve()
    candidate = path if path.is_absolute() else resolved_repo / path
    expected = resolved_repo / MANIFEST_RELATIVE_PATH
    if candidate.resolve(strict=False) != expected:
        raise EquivalentManifestError("等价清单路径必须是仓库内固定位置。")
    _ordinary_file(expected, "等价清单")
    return expected


def _validate_header(
    root: Mapping[str, object],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    if _integer(root["schema_version"], "schema_version") != 1:
        raise EquivalentManifestError("等价清单 schema_version 必须为 1。")
    if _string(root["manifest_id"], "manifest_id") != MANIFEST_ID:
        raise EquivalentManifestError("manifest_id 不属于已批准 T01 r5 清单。")
    approved_spec = _mapping(root["approved_spec"], "approved_spec", _SPEC_FIELDS)
    if approved_spec != {"path": SPEC_RELATIVE_PATH, "revision": SPEC_REVISION}:
        raise EquivalentManifestError("SPEC 路径或 revision 与 r5 批准不一致。")
    generator = _mapping(root["generator"], "generator", _GENERATOR_FIELDS)
    expected_generator = {
        "distribution": "mutmut",
        "version": MUTMUT_VERSION,
        "uv_lock_sha256": EXPECTED_LOCK_SHA256,
    }
    if generator != expected_generator:
        raise EquivalentManifestError("mutmut 版本或 uv.lock 绑定与批准不一致。")
    return approved_spec, generator


def _validate_profile(root: Mapping[str, object]) -> Mapping[str, object]:
    profile = _mapping(root["profile"], "profile", _PROFILE_FIELDS)
    expected_profile: dict[str, object] = {
        "name": "events",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "expected_mutant_count": EXPECTED_MUTANT_COUNT,
        "expected_mutant_names_sha256": EXPECTED_MUTANT_NAMES_SHA256,
        "expected_equivalent_count": EXPECTED_EQUIVALENT_COUNT,
        "expected_equivalent_names_sha256": EXPECTED_EQUIVALENT_NAMES_SHA256,
    }
    for field in ("expected_mutant_count", "expected_equivalent_count"):
        _integer(profile[field], f"profile.{field}")
    for field in (
        "profile_sha256",
        "expected_mutant_names_sha256",
        "expected_equivalent_names_sha256",
    ):
        _sha256(profile[field], f"profile.{field}")
    if profile != expected_profile:
        raise EquivalentManifestError("events profile、全集数量或名称摘要已漂移。")
    return profile


def _expected_function(name: str) -> str:
    try:
        stem = name.rsplit("__mutmut_", 1)[0].rsplit(".x", 1)[1]
    except (IndexError, ValueError) as exc:
        raise EquivalentManifestError("mutant 名称无法映射到源函数。") from exc
    return stem[1:]


def _validate_source(repo: Path, name: str, value: object) -> None:
    source = _mapping(value, f"{name}.source", _SOURCE_FIELDS)
    expected = {
        "path": SOURCE_RELATIVE_PATH,
        "function": _expected_function(name),
        "sha256": EXPECTED_SOURCE_SHA256,
    }
    _sha256(source["sha256"], f"{name}.source.sha256")
    if source != expected:
        raise EquivalentManifestError(f"{name} 的 source 绑定不符合批准。")


def _validate_entry(repo: Path, value: object) -> tuple[str, str]:
    entry = _mapping(value, "equivalents 条目", _ENTRY_FIELDS)
    name = _string(entry["name"], "equivalent.name")
    if any(character in name for character in _RULE_META):
        raise EquivalentManifestError("mutant 名称不得包含通配符或正则元字符。")
    category = _string(entry["category"], f"{name}.category")
    if APPROVED_CATEGORIES.get(name) != category:
        raise EquivalentManifestError(f"{name} 的名称或类别未经 r5 逐项批准。")
    _string(entry["reason_code"], f"{name}.reason_code")
    reason = _string(entry["reason"], f"{name}.reason")
    if _CJK.search(reason) is None:
        raise EquivalentManifestError(f"{name}.reason 必须包含中文逐项理由。")
    _validate_source(repo, name, entry["source"])
    return name, category


def _validate_entries(repo: Path, root: Mapping[str, object]) -> None:
    raw_entries = root["equivalents"]
    if not isinstance(raw_entries, list):
        raise EquivalentManifestError("equivalents 必须是数组。")
    pairs = [_validate_entry(repo, entry) for entry in raw_entries]
    names = [name for name, _category in pairs]
    if len(names) != len(set(names)):
        raise EquivalentManifestError("equivalents 包含重复 mutant 名称。")
    if names != sorted(names, key=lambda value: value.encode("utf-8")):
        raise EquivalentManifestError("equivalents 必须按 UTF-8 字节序排序。")
    if {name: category for name, category in pairs} != APPROVED_CATEGORIES:
        raise EquivalentManifestError("equivalents 不是获批的精确 49 项集合。")
    digest = hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest()
    if digest != EXPECTED_EQUIVALENT_NAMES_SHA256:
        raise EquivalentManifestError("等价 mutant 名称摘要与 r5 批准不一致。")
    counts = Counter(category for _name, category in pairs)
    category_counts = _mapping(
        root["category_counts"],
        "category_counts",
        frozenset(EXPECTED_CATEGORY_COUNTS),
    )
    for category, value in category_counts.items():
        _integer(value, f"category_counts.{category}")
    if dict(category_counts) != EXPECTED_CATEGORY_COUNTS or counts != Counter(
        EXPECTED_CATEGORY_COUNTS
    ):
        raise EquivalentManifestError("等价 mutant 类别计数与批准不一致。")


def _validate_repository_bindings(repo: Path) -> None:
    _require_file_digest(repo, LOCK_RELATIVE_PATH, EXPECTED_LOCK_SHA256, "uv.lock")
    _require_file_digest(
        repo,
        PROFILE_RELATIVE_PATH,
        EXPECTED_PROFILE_SHA256,
        "mutation profile",
    )
    _require_file_digest(repo, SOURCE_RELATIVE_PATH, EXPECTED_SOURCE_SHA256, "events 源文件")
    _ordinary_file(repo / SPEC_RELATIVE_PATH, "T01 SPEC")
    try:
        lock_payload = tomllib.loads((repo / LOCK_RELATIVE_PATH).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise EquivalentManifestError(f"无法解析 uv.lock：{exc}") from exc
    packages = lock_payload.get("package")
    if not isinstance(packages, list):
        raise EquivalentManifestError("uv.lock 缺少 package 清单。")
    versions = {
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == "mutmut"
    }
    if versions != {MUTMUT_VERSION}:
        raise EquivalentManifestError("uv.lock 中 mutmut 版本不精确等于 3.7.0。")


def validate_equivalent_manifest(
    repo: Path,
    payload: object,
    raw_bytes: bytes,
    path: Path,
) -> Mapping[str, object]:
    """校验 payload、原始 JSON 和仓库绑定，返回不变的封闭映射。"""

    resolved_repo = repo.resolve()
    _manifest_location(resolved_repo, path)
    decoded = _decode_json(raw_bytes)
    if decoded != payload:
        raise EquivalentManifestError("原始 manifest 字节与待校验 payload 不一致。")
    root = _mapping(payload, "manifest", _TOP_LEVEL_FIELDS)
    _validate_header(root)
    _validate_profile(root)
    _validate_entries(resolved_repo, root)
    _validate_repository_bindings(resolved_repo)
    return cast(Mapping[str, object], decoded)


def load_equivalent_manifest(repo: Path, path: Path) -> Mapping[str, object]:
    """从固定普通文件加载并验证 T01 r5 等价 mutant 清单。"""

    resolved_repo = repo.resolve()
    manifest_path = _manifest_location(resolved_repo, path)
    try:
        raw_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise EquivalentManifestError(f"无法读取等价清单：{exc}") from exc
    payload = _decode_json(raw_bytes)
    return validate_equivalent_manifest(resolved_repo, payload, raw_bytes, manifest_path)
