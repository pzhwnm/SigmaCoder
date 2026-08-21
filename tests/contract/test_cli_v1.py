"""CLI v1 JSON Schema 的发布契约与条件联合测试。"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas" / "cli" / "v1"
SCHEMA_FILES = (
    "error.schema.json",
    "task-view.schema.json",
    "task-list.schema.json",
    "envelope.schema.json",
)
HASH = "a" * 64
BASELINE_OID = "1" * 40
CURRENT_OID = "2" * 40
TASK_ID = "123e4567-e89b-42d3-a456-426614174000"
BAD_TASK_ID = "123e4567-e89b-42d3-a456-426614174001"


def load_schemas() -> dict[str, dict[str, Any]]:
    """从版本化 Artifact 加载 Schema，不借用产品内部模型。"""

    schemas: dict[str, dict[str, Any]] = {}
    for filename in SCHEMA_FILES:
        parsed = json.loads((SCHEMA_ROOT / filename).read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)
        schemas[filename] = parsed
    return schemas


SCHEMAS = load_schemas()
REGISTRY = Registry().with_resources(
    (
        str(schema["$id"]),
        Resource.from_contents(schema),
    )
    for schema in SCHEMAS.values()
)


def validator(filename: str) -> Draft202012Validator:
    """构造能够解析同版本相对引用的 Draft 2020-12 校验器。"""

    return Draft202012Validator(SCHEMAS[filename], registry=REGISTRY)


def assert_valid(filename: str, instance: object) -> None:
    """给出稳定、可读的 Schema 失败位置。"""

    errors = sorted(validator(filename).iter_errors(instance), key=lambda item: list(item.path))
    assert not errors, "\n".join(
        f"{filename} 在 {list(error.absolute_path)!r} 失败：{error.message}" for error in errors
    )


def assert_invalid(filename: str, instance: object) -> None:
    """断言矛盾机器状态会被公开 Schema fail closed。"""

    assert not validator(filename).is_valid(instance)


def task_view(variant: str = "available") -> dict[str, Any]:
    """生成五种 TaskViewV1 的最小可信样例。"""

    task: dict[str, Any] = {
        "task_id": TASK_ID,
        "objective": "验证持久 Task",
        "lifecycle_state": "PREPARING",
        "health": "HEALTHY",
        "baseline": {
            "repository_realpath": "C:/fixtures/source",
            "git_common_dir_realpath": "C:/fixtures/source/.git",
            "object_format": "sha1",
            "commit_oid": BASELINE_OID,
            "source_dirty": False,
            "dirty_content_included": False,
        },
        "workspace": {
            "kind": "git_linked_worktree",
            "mode": "DETACHED",
            "path": "C:/fixtures/data/workspaces/task",
            "head_oid": BASELINE_OID,
            "availability": "AVAILABLE",
        },
        "preparation": {
            "workspace": "READY",
            "event_store": "READY",
            "sandbox": "NOT_REQUIRED_FOR_READ_ONLY_ANALYSIS",
            "agent_run": "NOT_STARTED",
        },
        "event_position": {"sequence": 4, "event_hash": HASH},
        "checkpoint": {
            "through_sequence": 4,
            "through_event_hash": HASH,
            "load_mode": "CHECKPOINT",
        },
        "runtime": {
            "process_restored": False,
            "terminal_restored": False,
            "memory_restored": False,
            "network_transaction_restored": False,
        },
    }
    if variant == "available":
        return task

    task["lifecycle_state"] = "NEEDS_ATTENTION"
    task["health"] = "NEEDS_ATTENTION"
    if variant == "not_created":
        task["workspace"]["availability"] = "NOT_CREATED"
        task["workspace"]["head_oid"] = None
        task["preparation"]["workspace"] = "FAILED"
        task["event_position"]["sequence"] = 5
        task["checkpoint"]["through_sequence"] = 5
    elif variant == "unverified":
        task["workspace"]["availability"] = "UNVERIFIED"
        task["workspace"]["head_oid"] = None
        task["preparation"]["workspace"] = "RECOVERY_REQUIRED"
        task["event_position"]["sequence"] = 5
        task["checkpoint"]["through_sequence"] = 5
    elif variant == "missing":
        task["workspace"]["availability"] = "MISSING"
        task["workspace"]["head_oid"] = None
    elif variant == "baseline_mismatch":
        task["workspace"]["availability"] = "BASELINE_MISMATCH"
        task["workspace"]["head_oid"] = CURRENT_OID
    else:
        raise ValueError(f"未知 TaskViewV1 样例：{variant}")
    return task


def error(code: str) -> dict[str, object]:
    """构造只依赖稳定错误码的公开错误对象。"""

    return {"code": code, "message": "命令失败。", "details": {}}


def envelope(
    *,
    command: str,
    ok: bool,
    data: object,
    error_value: object,
) -> dict[str, object]:
    """构造完整的 v1 外壳。"""

    return {
        "schema_version": 1,
        "command": command,
        "ok": ok,
        "data": data,
        "error": error_value,
    }


def invalid_list_item() -> dict[str, object]:
    """损坏 Task 只能暴露最小定位字段。"""

    return {
        "task_id": BAD_TASK_ID,
        "error_code": "EVENT_HASH_MISMATCH",
        "first_invalid_sequence": 2,
    }


def test_published_schemas_are_valid_draft_2020_12_artifacts() -> None:
    """四个文件本身必须是合法且带稳定 ID 的公开 Schema。"""

    for filename, schema in SCHEMAS.items():
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].endswith(f"/schemas/cli/v1/{filename}")


@pytest.mark.parametrize(
    "variant",
    ["available", "not_created", "unverified", "missing", "baseline_mismatch"],
)
def test_task_view_one_of_accepts_exactly_the_five_governed_variants(variant: str) -> None:
    """§4.4：五种经过证据验证的视图均能单独通过 oneOf。"""

    assert_valid("task-view.schema.json", task_view(variant))


@pytest.mark.parametrize(
    ("variant", "path", "invalid_value"),
    [
        ("available", ("workspace", "head_oid"), None),
        ("not_created", ("preparation", "workspace"), "READY"),
        ("unverified", ("health",), "HEALTHY"),
        ("missing", ("workspace", "head_oid"), CURRENT_OID),
        ("baseline_mismatch", ("workspace", "head_oid"), None),
    ],
)
def test_task_view_one_of_rejects_cross_variant_combinations(
    variant: str,
    path: tuple[str, ...],
    invalid_value: object,
) -> None:
    """§4.4：AVAILABLE+null、NOT_CREATED+READY 等组合不得漏过。"""

    instance = task_view(variant)
    target: dict[str, Any] = instance
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = invalid_value
    assert_invalid("task-view.schema.json", instance)


def test_task_view_rejects_runtime_restoration_and_object_format_mismatch() -> None:
    """S05：重开只重建投影；OID 长度必须服从 Git object format。"""

    restored = task_view()
    restored["runtime"]["process_restored"] = True
    assert_invalid("task-view.schema.json", restored)

    wrong_oid = task_view()
    wrong_oid["baseline"]["object_format"] = "sha256"
    assert_invalid("task-view.schema.json", wrong_oid)


def test_success_envelopes_bind_data_shape_to_command() -> None:
    """§4.3：成功时 error=null，且 data 必须与命令匹配。"""

    for command in ("task.start", "task.status"):
        assert_valid(
            "envelope.schema.json",
            envelope(command=command, ok=True, data={"task": task_view()}, error_value=None),
        )
    assert_valid(
        "envelope.schema.json",
        envelope(
            command="task.list",
            ok=True,
            data={"items": [task_view()], "invalid_items": []},
            error_value=None,
        ),
    )

    wrong_shape = envelope(
        command="task.list",
        ok=True,
        data={"task": task_view()},
        error_value=None,
    )
    assert_invalid("envelope.schema.json", wrong_shape)


def test_ordinary_failure_requires_null_data() -> None:
    """§4.3：普通失败不得夹带未验证业务投影。"""

    ordinary = envelope(
        command="task.status",
        ok=False,
        data=None,
        error_value=error("TASK_NOT_FOUND"),
    )
    assert_valid("envelope.schema.json", ordinary)

    leaked = copy.deepcopy(ordinary)
    leaked["data"] = {"task": task_view()}
    assert_invalid("envelope.schema.json", leaked)


@pytest.mark.parametrize(
    ("command", "code", "data"),
    [
        (
            "task.list",
            "PARTIAL_INTEGRITY_FAILURE",
            {"items": [task_view()], "invalid_items": [invalid_list_item()]},
        ),
        ("task.status", "WORKSPACE_UNAVAILABLE", {"task": task_view("missing")}),
        (
            "task.status",
            "WORKSPACE_BASELINE_MISMATCH",
            {"task": task_view("baseline_mismatch")},
        ),
        ("task.start", "TASK_PREPARATION_FAILED", {"task": task_view("not_created")}),
        (
            "task.status",
            "CREATION_RECOVERY_REQUIRED",
            {"task": task_view("unverified")},
        ),
    ],
)
def test_only_governed_failures_accept_their_verified_partial_data(
    command: str,
    code: str,
    data: Mapping[str, object],
) -> None:
    """S14：五个获准错误码分别绑定唯一可信数据形态。"""

    assert_valid(
        "envelope.schema.json",
        envelope(command=command, ok=False, data=data, error_value=error(code)),
    )


def test_partial_failure_codes_reject_null_wrong_command_and_wrong_variant() -> None:
    """错误码不能绕开条件联合，也不能借用另一退化视图。"""

    null_partial = envelope(
        command="task.list",
        ok=False,
        data=None,
        error_value=error("PARTIAL_INTEGRITY_FAILURE"),
    )
    assert_invalid("envelope.schema.json", null_partial)

    wrong_command = envelope(
        command="task.status",
        ok=False,
        data={"items": [], "invalid_items": [invalid_list_item()]},
        error_value=error("PARTIAL_INTEGRITY_FAILURE"),
    )
    assert_invalid("envelope.schema.json", wrong_command)

    wrong_variant = envelope(
        command="task.status",
        ok=False,
        data={"task": task_view("baseline_mismatch")},
        error_value=error("WORKSPACE_UNAVAILABLE"),
    )
    assert_invalid("envelope.schema.json", wrong_variant)


def test_partial_list_invalid_items_reject_unverified_business_fields() -> None:
    """§4.5：坏 Task 只能返回 ID、稳定错误码和首个可定位 sequence。"""

    invalid_item = invalid_list_item()
    invalid_item["objective"] = "不得泄露的未验证投影"
    response = envelope(
        command="task.list",
        ok=False,
        data={"items": [task_view()], "invalid_items": [invalid_item]},
        error_value=error("PARTIAL_INTEGRITY_FAILURE"),
    )
    assert_invalid("envelope.schema.json", response)
