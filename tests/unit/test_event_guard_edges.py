"""T01 事件字段防御校验器的负控合同。"""

from __future__ import annotations

import pytest

from sigmacoder.domain import events as event_module


@pytest.mark.parametrize("value", [None, ""], ids=("non-string", "empty-string"))
def test_absolute_path_guard_rejects_non_string_and_empty_values(value: object) -> None:
    assert event_module._is_normalized_absolute_path(value) is False


@pytest.mark.parametrize(
    "payload",
    [
        {"object_format": "sha1", "baseline_commit": 7},
        {"object_format": "sha512", "baseline_commit": "1" * 40},
    ],
    ids=("non-string-oid", "unsupported-object-format"),
)
def test_oid_object_format_guard_rejects_defensive_edge_cases(
    payload: dict[str, object],
) -> None:
    assert event_module._oid_matches_object_format(payload) is False
