"""T01 r5 等价 mutant 清单的封闭契约与负控。"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import re
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = PROJECT_ROOT / "tools/mutation_equivalents.json"
SOURCE_PATH = "src/sigmacoder/domain/events.py"
SPEC_PATH = "docs/specs/T01-persistent-coding-task.md"


def _fixed_sha256(*parts: str) -> str:
    value = "".join(parts)
    assert len(value) == 64
    return value


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
EXPECTED_UV_LOCK_SHA256 = _fixed_sha256(
    "029d68f7",
    "d05a56a2",
    "3a7d6dbf",
    "31a18356",
    "bc674a00",
    "19e1ea62",
    "d09cfaee",
    "ebce0c43",
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

# 这是独立于生产清单的获批事实，不能从被测 manifest 反向生成。
EXPECTED_EQUIVALENTS: dict[str, str] = {
    "sigmacoder.domain.events.x__apply_event__mutmut_105": TYPE_ONLY_CAST,
    "sigmacoder.domain.events.x__normalized_event_copy__mutmut_2": TYPE_ONLY_CAST,
    "sigmacoder.domain.events.x__normalized_event_copy__mutmut_6": TYPE_ONLY_CAST,
    "sigmacoder.domain.events.x__validated_checkpoint_prefix__mutmut_42": TYPE_ONLY_CAST,
    "sigmacoder.domain.events.x_canonical_json_bytes__mutmut_5": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x_canonical_json_bytes__mutmut_8": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x_canonical_json_bytes__mutmut_21": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_6": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_7": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_10": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_12": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__is_portable_relative_path__mutmut_28": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__is_portable_relative_path__mutmut_31": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_6": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_15": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_4": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_5": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_14": (
        OBSERVATIONALLY_EQUIVALENT_RUNTIME
    ),
    "sigmacoder.domain.events.x_canonical_json_bytes__mutmut_13": (GUARD_DOMINATED_EQUIVALENCE),
    "sigmacoder.domain.events.x_canonical_json_bytes__mutmut_18": (GUARD_DOMINATED_EQUIVALENCE),
    "sigmacoder.domain.events.x__is_oid__mutmut_2": GUARD_DOMINATED_EQUIVALENCE,
    "sigmacoder.domain.events.x__is_portable_relative_path__mutmut_5": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x__is_portable_relative_path__mutmut_13": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x__is_portable_relative_path__mutmut_37": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x__is_uuid4__mutmut_1": GUARD_DOMINATED_EQUIVALENCE,
    "sigmacoder.domain.events.x__oid_matches_object_format__mutmut_10": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x__oid_matches_object_format__mutmut_21": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x__validated_checkpoint_prefix__mutmut_55": (
        GUARD_DOMINATED_EQUIVALENCE
    ),
    "sigmacoder.domain.events.x_restore_task_projection__mutmut_43": (GUARD_DOMINATED_EQUIVALENCE),
    "sigmacoder.domain.events.x__event_int__mutmut_4": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__event_payload__mutmut_5": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__event_payload__mutmut_6": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__event_payload__mutmut_7": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__event_text__mutmut_3": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_14": NON_CONTRACT_DIAGNOSTIC,
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_1": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_3": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_5": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_9": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__fallback_sort_atom__mutmut_11": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_1": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_4": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_9": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_10": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_token__mutmut_13": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_1": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_2": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_12": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
    "sigmacoder.domain.events.x__prevalidation_order_key__mutmut_13": (
        UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK
    ),
}

EXPECTED_CATEGORY_COUNTS = {
    TYPE_ONLY_CAST: 4,
    OBSERVATIONALLY_EQUIVALENT_RUNTIME: 14,
    GUARD_DOMINATED_EQUIVALENCE: 11,
    NON_CONTRACT_DIAGNOSTIC: 6,
    UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK: 14,
}

REASON_CODES = {
    TYPE_ONLY_CAST: "CAST_RUNTIME_IDENTITY",
    OBSERVATIONALLY_EQUIVALENT_RUNTIME: "FIXED_RUNTIME_OBSERVATIONAL_IDENTITY",
    GUARD_DOMINATED_EQUIVALENCE: "GUARD_DOMINATED",
    NON_CONTRACT_DIAGNOSTIC: "NON_PUBLIC_DIAGNOSTIC",
    UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK: "UNSPECIFIED_MULTI_MALFORMED_TIE_BREAK",
}


def _utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


def _equivalent_names_sha256(names: list[str]) -> str:
    material = "\n".join(sorted(names, key=_utf8_key)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _function_name(mutant_name: str) -> str:
    stem = mutant_name.rsplit("__mutmut_", 1)[0].rsplit(".x", 1)[1]
    return stem[1:]


def _manifest_payload() -> dict[str, Any]:
    equivalents = [
        {
            "name": name,
            "category": category,
            "reason_code": REASON_CODES[category],
            "reason": "该项已按 T01 SPEC r5 逐项审查，运行时公共观测与获批契约一致。",
            "source": {
                "path": SOURCE_PATH,
                "function": _function_name(name),
                "sha256": EXPECTED_SOURCE_SHA256,
            },
        }
        for name, category in sorted(
            EXPECTED_EQUIVALENTS.items(), key=lambda item: _utf8_key(item[0])
        )
    ]
    return {
        "schema_version": 1,
        "manifest_id": "T01-events-equivalent-mutants-v1",
        "approved_spec": {"path": SPEC_PATH, "revision": "r5"},
        "generator": {
            "distribution": "mutmut",
            "version": "3.7.0",
            "uv_lock_sha256": EXPECTED_UV_LOCK_SHA256,
        },
        "profile": {
            "name": "events",
            "profile_sha256": EXPECTED_PROFILE_SHA256,
            "expected_mutant_count": EXPECTED_MUTANT_COUNT,
            "expected_mutant_names_sha256": EXPECTED_MUTANT_NAMES_SHA256,
            "expected_equivalent_count": 49,
            "expected_equivalent_names_sha256": EXPECTED_EQUIVALENT_NAMES_SHA256,
        },
        "category_counts": dict(EXPECTED_CATEGORY_COUNTS),
        "equivalents": equivalents,
    }


def _manifest_bytes(payload: Mapping[str, object]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _api() -> ModuleType:
    # 动态导入确保缺少实现表现为测试执行失败，而不是 collection error。
    return importlib.import_module("tools.mutation_equivalents")


def _validate(payload: dict[str, Any]) -> Mapping[str, object]:
    api = _api()
    return cast(
        Mapping[str, object],
        api.validate_equivalent_manifest(
            PROJECT_ROOT,
            payload,
            _manifest_bytes(payload),
            MANIFEST_PATH,
        ),
    )


def _equivalents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], payload["equivalents"])


def _damage_missing(payload: dict[str, Any]) -> None:
    _equivalents(payload).pop()


def _damage_forged_extra(payload: dict[str, Any]) -> None:
    forged = copy.deepcopy(_equivalents(payload)[0])
    forged["name"] = "sigmacoder.domain.events.x_forged__mutmut_9999"
    cast(dict[str, object], forged["source"])["function"] = "forged"
    _equivalents(payload).append(forged)
    _equivalents(payload).sort(key=lambda item: _utf8_key(cast(str, item["name"])))


def _damage_typo(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["name"] += "x"
    _equivalents(payload).sort(key=lambda item: _utf8_key(cast(str, item["name"])))


def _damage_duplicate(payload: dict[str, Any]) -> None:
    _equivalents(payload).append(copy.deepcopy(_equivalents(payload)[0]))
    _equivalents(payload).sort(key=lambda item: _utf8_key(cast(str, item["name"])))


def _damage_wildcard(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["name"] = "sigmacoder.domain.events.*"


def _damage_regex(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["name"] = r"^sigmacoder\.domain\.events\..+$"


def _damage_unknown_category(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["category"] = "UNKNOWN_EQUIVALENCE"


def _damage_empty_reason(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["reason"] = ""


def _damage_category_count(payload: dict[str, Any]) -> None:
    cast(dict[str, int], payload["category_counts"])[TYPE_ONLY_CAST] = 5


def _damage_unknown_top_field(payload: dict[str, Any]) -> None:
    payload["unapproved"] = True


def _damage_unknown_item_field(payload: dict[str, Any]) -> None:
    _equivalents(payload)[0]["unapproved"] = True


def _damage_spec_revision(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["approved_spec"])["revision"] = "r4"


def _damage_mutmut_version(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["generator"])["version"] = "3.7.1"


def _damage_source_sha(payload: dict[str, Any]) -> None:
    cast(dict[str, object], _equivalents(payload)[0]["source"])["sha256"] = "0" * 64


def _damage_source_path(payload: dict[str, Any]) -> None:
    cast(dict[str, object], _equivalents(payload)[0]["source"])["path"] = (
        "src/sigmacoder/domain/tasks.py"
    )


def _damage_profile_sha(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["profile"])["profile_sha256"] = "0" * 64


def _damage_lock_sha(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["generator"])["uv_lock_sha256"] = "0" * 64


def _damage_mutant_count(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["profile"])["expected_mutant_count"] = 1600


def _damage_mutant_names_digest(payload: dict[str, Any]) -> None:
    cast(dict[str, object], payload["profile"])["expected_mutant_names_sha256"] = "0" * 64


Damage = Callable[[dict[str, Any]], None]

MANIFEST_DAMAGE_CASES: tuple[tuple[str, Damage], ...] = (
    ("缺少获批项", _damage_missing),
    ("伪增不存在项", _damage_forged_extra),
    ("名称拼错", _damage_typo),
    ("名称重复", _damage_duplicate),
    ("通配符", _damage_wildcard),
    ("正则表达式", _damage_regex),
    ("未知类别", _damage_unknown_category),
    ("空理由", _damage_empty_reason),
    ("类别计数错误", _damage_category_count),
    ("顶层未知字段", _damage_unknown_top_field),
    ("条目未知字段", _damage_unknown_item_field),
    ("SPEC revision 漂移", _damage_spec_revision),
    ("mutmut version 漂移", _damage_mutmut_version),
    ("source SHA 漂移", _damage_source_sha),
    ("source path 漂移", _damage_source_path),
    ("profile SHA 漂移", _damage_profile_sha),
    ("uv.lock SHA 漂移", _damage_lock_sha),
    ("mutant 总数漂移", _damage_mutant_count),
    ("mutant 全集摘要漂移", _damage_mutant_names_digest),
)


def test_独立获批常量_精确包含四十九项与五类摘要() -> None:
    assert len(EXPECTED_EQUIVALENTS) == 49
    assert Counter(EXPECTED_EQUIVALENTS.values()) == Counter(EXPECTED_CATEGORY_COUNTS)
    assert _equivalent_names_sha256(list(EXPECTED_EQUIVALENTS)) == EXPECTED_EQUIVALENT_NAMES_SHA256


def test_仓库_manifest_精确匹配_t01_r5_获批契约() -> None:
    api = _api()
    loaded = cast(
        Mapping[str, object],
        api.load_equivalent_manifest(PROJECT_ROOT, MANIFEST_PATH),
    )

    assert set(loaded) == {
        "schema_version",
        "manifest_id",
        "approved_spec",
        "generator",
        "profile",
        "category_counts",
        "equivalents",
    }
    assert loaded["schema_version"] == 1
    assert loaded["manifest_id"] == "T01-events-equivalent-mutants-v1"
    assert loaded["approved_spec"] == {"path": SPEC_PATH, "revision": "r5"}
    assert loaded["generator"] == {
        "distribution": "mutmut",
        "version": "3.7.0",
        "uv_lock_sha256": EXPECTED_UV_LOCK_SHA256,
    }
    assert loaded["profile"] == {
        "name": "events",
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "expected_mutant_count": EXPECTED_MUTANT_COUNT,
        "expected_mutant_names_sha256": EXPECTED_MUTANT_NAMES_SHA256,
        "expected_equivalent_count": 49,
        "expected_equivalent_names_sha256": EXPECTED_EQUIVALENT_NAMES_SHA256,
    }
    assert loaded["category_counts"] == EXPECTED_CATEGORY_COUNTS

    raw_equivalents = loaded["equivalents"]
    assert isinstance(raw_equivalents, list)
    equivalents = cast(list[dict[str, object]], raw_equivalents)
    names = [cast(str, item["name"]) for item in equivalents]
    assert names == sorted(EXPECTED_EQUIVALENTS, key=_utf8_key)
    assert _equivalent_names_sha256(names) == EXPECTED_EQUIVALENT_NAMES_SHA256
    assert {cast(str, item["name"]): item["category"] for item in equivalents} == (
        EXPECTED_EQUIVALENTS
    )
    for item in equivalents:
        assert set(item) == {"name", "category", "reason_code", "reason", "source"}
        assert isinstance(item["reason_code"], str) and item["reason_code"]
        assert isinstance(item["reason"], str) and item["reason"]
        source = cast(dict[str, object], item["source"])
        assert set(source) == {"path", "function", "sha256"}
        assert source["path"] == SOURCE_PATH
        assert source["function"] == _function_name(cast(str, item["name"]))
        assert source["sha256"] == EXPECTED_SOURCE_SHA256


def test_r5_逐字节信任根显式固定为_lf() -> None:
    attributes = {
        line.strip()
        for line in (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {
        ".gitattributes text eol=lf",
        "*.py text eol=lf",
        "uv.lock text eol=lf",
        "tools/mutation_profiles.json text eol=lf",
        "tools/mutation_equivalents.json text eol=lf",
        "docs/specs/T01-persistent-coding-task.md text eol=lf",
    } <= attributes


@pytest.mark.parametrize(
    ("case", "damage"),
    MANIFEST_DAMAGE_CASES,
    ids=[case for case, _damage in MANIFEST_DAMAGE_CASES],
)
def test_synthetic_manifest_任一未获批漂移都_fail_closed(
    case: str,
    damage: Damage,
) -> None:
    del case  # 参数名称只用于生成可读的 pytest case id。
    payload = copy.deepcopy(_manifest_payload())
    damage(payload)
    api = _api()

    with pytest.raises(api.EquivalentManifestError) as captured:
        api.validate_equivalent_manifest(
            PROJECT_ROOT,
            payload,
            _manifest_bytes(payload),
            MANIFEST_PATH,
        )

    assert re.search(r"[\u4e00-\u9fff]", str(captured.value)) is not None


def test_synthetic_manifest_未损坏基线可通过并保持完整映射() -> None:
    payload = _manifest_payload()

    validated = _validate(payload)

    assert validated == payload
