"""T01 SQLite 追加、round-trip 与跨 Task 隔离属性。"""

from __future__ import annotations

import hashlib
import sqlite3
import unicodedata
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID

import pytest
from hypothesis import HealthCheck, given, settings
from tests.support.event_contract import (
    as_mapping,
    authorization_events,
    canonical_oracle,
)
from tests.support.event_property_cases import EventCase, two_event_cases

from sigmacoder.adapters.sqlite_event_store import SQLiteEventStore
from sigmacoder.domain.events import restore_task_projection
from sigmacoder.errors import SigmaCoderError


def _restore(events: list[dict[str, object]]) -> dict[str, object]:
    return as_mapping(restore_task_projection(events))


def _create_authorized(store: SQLiteEventStore, case: EventCase) -> None:
    events = deepcopy(case.events[:3])
    restored = _restore(events)
    store.create_task(
        case.task_id,
        case.workspace_relative_path,
        events,
        restored["projection"],
        restored["checkpoint"],
    )


def _derived_uuid4(seed: str, label: str) -> str:
    raw = bytearray(hashlib.sha256(f"{seed}:{label}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(raw)))


def _collision_events(
    case: EventCase,
    *,
    task_id: str,
    event_ids: tuple[str, str, str],
    workspace_relative_path: str,
) -> list[dict[str, object]]:
    return authorization_events(
        objective=case.objective,
        task_id=task_id,
        correlation_id=_derived_uuid4(task_id, "correlation"),
        event_ids=event_ids,
        repository_realpath=case.repository_realpath,
        git_common_dir_realpath=case.git_common_dir_realpath,
        object_format=case.object_format,
        baseline_commit=case.baseline_commit,
        workspace_relative_path=workspace_relative_path,
        ownership_nonce=hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:32],
    )


def _assert_create_error(
    store: SQLiteEventStore,
    events: list[dict[str, object]],
    *,
    task_id: str,
    workspace_relative_path: str,
    expected_code: str,
) -> None:
    restored = _restore(events)
    with pytest.raises(SigmaCoderError) as captured:
        store.create_task(
            task_id,
            workspace_relative_path,
            events,
            restored["projection"],
            restored["checkpoint"],
        )
    assert captured.value.code == expected_code


def _assert_round_trip(case: EventCase, restored: dict[str, object]) -> None:
    projection = as_mapping(restored["projection"])
    baseline = as_mapping(projection["baseline"])
    workspace = as_mapping(projection["workspace"])
    assert projection["task_id"] == case.task_id
    assert projection["objective"] == unicodedata.normalize("NFC", case.objective)
    assert baseline == {
        "repository_realpath": unicodedata.normalize("NFC", case.repository_realpath),
        "git_common_dir_realpath": unicodedata.normalize("NFC", case.git_common_dir_realpath),
        "object_format": case.object_format,
        "commit_oid": case.baseline_commit,
        "source_dirty": False,
        "dirty_content_included": False,
    }
    assert workspace["relative_path"] == unicodedata.normalize("NFC", case.workspace_relative_path)


def _task_snapshot(store: SQLiteEventStore, task_id: str) -> bytes:
    events = store.load_events(task_id)
    checkpoint = store.load_checkpoint(task_id)
    restored = as_mapping(restore_task_projection(events, checkpoint=checkpoint))
    return canonical_oracle(
        {
            "events": events,
            "checkpoint": checkpoint,
            "restored": restored,
            "workspace_relative_path": store.workspace_relative_path(task_id),
        }
    )


def _task_row_counts(database_path: Path, task_id: str) -> dict[str, int]:
    with closing(sqlite3.connect(database_path)) as connection:
        return {
            table: int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE task_id = ?",
                    (task_id,),
                ).fetchone()[0]
            )
            for table in ("task_registry", "events", "projections", "checkpoints")
        }


def _install_late_checkpoint_failure(database_path: Path) -> None:
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            """
            CREATE TRIGGER property_fail_checkpoint_insert
            BEFORE INSERT ON checkpoints
            BEGIN
                SELECT RAISE(ABORT, 'PROPERTY_INJECTED_LATE_FAILURE');
            END
            """
        )
        connection.commit()


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=(HealthCheck.function_scoped_fixture,),
)
@given(pair=two_event_cases())
def test_generated_sqlite_append_round_trip_and_cross_task_isolation(
    tmp_path: Path,
    pair: tuple[EventCase, EventCase],
) -> None:
    task_a, task_b = pair
    with TemporaryDirectory(prefix="case-", dir=tmp_path) as directory:
        store = SQLiteEventStore(Path(directory))
        store.initialize()
        _create_authorized(store, task_b)
        b_snapshot_before_a_operations = _task_snapshot(store, task_b.task_id)
        _create_authorized(store, task_a)
        assert _task_snapshot(store, task_b.task_id) == b_snapshot_before_a_operations

        full_a = _restore(deepcopy(task_a.events))
        store.append_events(
            task_a.task_id,
            list(reversed(deepcopy(task_a.events[3:]))),
            full_a["projection"],
            full_a["checkpoint"],
        )
        stored_a = store.load_events(task_a.task_id)
        assert [event["sequence"] for event in stored_a] == list(range(1, len(stored_a) + 1))
        assert {event["task_id"] for event in stored_a} == {task_a.task_id}
        stored_event_ids = [event["event_id"] for event in stored_a]
        assert len(set(stored_event_ids)) == len(stored_event_ids)
        restored_a = as_mapping(
            restore_task_projection(stored_a, checkpoint=store.load_checkpoint(task_a.task_id))
        )
        expected_a = dict(full_a)
        expected_a["load_mode"] = "CHECKPOINT"
        assert canonical_oracle(restored_a) == canonical_oracle(expected_a)
        _assert_round_trip(task_a, restored_a)
        assert _task_snapshot(store, task_b.task_id) == b_snapshot_before_a_operations

        a_snapshot_before = _task_snapshot(store, task_a.task_id)
        b_snapshot_before = _task_snapshot(store, task_b.task_id)

        duplicate_task_events = _collision_events(
            task_b,
            task_id=task_a.task_id,
            event_ids=(
                _derived_uuid4(task_a.task_id, "task-collision-1"),
                _derived_uuid4(task_a.task_id, "task-collision-2"),
                _derived_uuid4(task_a.task_id, "task-collision-3"),
            ),
            workspace_relative_path=f"collisions/{task_a.task_id}",
        )
        _assert_create_error(
            store,
            duplicate_task_events,
            task_id=task_a.task_id,
            workspace_relative_path=f"collisions/{task_a.task_id}",
            expected_code="TASK_ID_COLLISION",
        )

        duplicate_event_task_id = _derived_uuid4(task_a.task_id, "event-collision-task")
        duplicate_event_path = f"collisions/{duplicate_event_task_id}"
        duplicate_event_events = _collision_events(
            task_b,
            task_id=duplicate_event_task_id,
            event_ids=(
                str(stored_a[0]["event_id"]),
                _derived_uuid4(task_a.task_id, "event-collision-2"),
                _derived_uuid4(task_a.task_id, "event-collision-3"),
            ),
            workspace_relative_path=duplicate_event_path,
        )
        _assert_create_error(
            store,
            duplicate_event_events,
            task_id=duplicate_event_task_id,
            workspace_relative_path=duplicate_event_path,
            expected_code="EVENT_ID_DUPLICATE",
        )
        assert _task_row_counts(store.database_path, duplicate_event_task_id) == {
            "task_registry": 0,
            "events": 0,
            "projections": 0,
            "checkpoints": 0,
        }

        late_failure_task_id = _derived_uuid4(task_b.task_id, "late-failure-task")
        late_failure_path = f"late-failure/{late_failure_task_id}"
        late_failure_events = _collision_events(
            task_a,
            task_id=late_failure_task_id,
            event_ids=(
                _derived_uuid4(late_failure_task_id, "event-1"),
                _derived_uuid4(late_failure_task_id, "event-2"),
                _derived_uuid4(late_failure_task_id, "event-3"),
            ),
            workspace_relative_path=late_failure_path,
        )
        _install_late_checkpoint_failure(store.database_path)
        _assert_create_error(
            store,
            late_failure_events,
            task_id=late_failure_task_id,
            workspace_relative_path=late_failure_path,
            expected_code="STORE_UNAVAILABLE",
        )

        reopened = SQLiteEventStore(Path(directory))
        assert set(reopened.task_ids()) == {task_a.task_id, task_b.task_id}
        assert _task_snapshot(reopened, task_a.task_id) == a_snapshot_before
        assert _task_snapshot(reopened, task_b.task_id) == b_snapshot_before
        assert _task_row_counts(reopened.database_path, late_failure_task_id) == {
            "task_registry": 0,
            "events": 0,
            "projections": 0,
            "checkpoints": 0,
        }
