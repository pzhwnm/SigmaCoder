"""T01 SQLite/WAL 权威、并发 CAS 与跨连接重开集成测试。"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier

import pytest
from tests.support.event_contract import digest_oracle, event_hash_oracle

from sigmacoder.adapters.sqlite_event_store import DATABASE_NAME, SQLiteEventStore
from sigmacoder.domain.events import (
    ProjectionRestoreResult,
    canonical_json_bytes,
    restore_task_projection,
)
from sigmacoder.errors import SigmaCoderError

ZERO_HASH = "0" * 64
BASELINE_OID = "1" * 40
GIT_COMMON_DIR = "C:/fixture/repository/.git"


@dataclass(frozen=True)
class StoredTask:
    """一个已经写入前三个授权事件的真实 SQLite Task。"""

    task_id: str
    workspace_relative_path: str
    events: list[dict[str, object]]
    restored: ProjectionRestoreResult


def _task_id(seed: int) -> str:
    return f"10000000-0000-4000-8000-{seed:012x}"


def _correlation_id(seed: int) -> str:
    return f"30000000-0000-4000-8000-{seed:012x}"


def _event_ids(seed: int) -> tuple[str, str, str]:
    return tuple(f"20000000-0000-4000-8000-{seed * 16 + index:012x}" for index in range(1, 4))  # type: ignore[return-value]


def _authorization_events(
    seed: int,
    *,
    event_ids: tuple[str, str, str] | None = None,
) -> tuple[str, str, list[dict[str, object]]]:
    """生成可由正式 reducer 验证的独立 Task 授权事件。"""

    task_id = _task_id(seed)
    correlation_id = _correlation_id(seed)
    workspace_relative_path = f"tasks/{task_id}/workspace-{seed:032x}"
    ownership_nonce = f"{seed:032x}"
    digest = digest_oracle(
        {
            "task_id": task_id,
            "git_common_dir_identity": GIT_COMMON_DIR,
            "baseline_commit": BASELINE_OID,
            "workspace_relative_path": workspace_relative_path,
            "ownership_nonce": ownership_nonce,
            "mode": "DETACHED",
            "bootstrap_policy_id": "builtin.workspace-provision.v1",
        }
    )
    payloads: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "TaskCreatedV1",
            {
                "objective": f"SQLite 集成测试 {seed}",
                "repository_realpath": "C:/fixture/repository",
                "git_common_dir_realpath": GIT_COMMON_DIR,
                "object_format": "sha1",
                "baseline_commit": BASELINE_OID,
                "source_dirty": False,
                "dirty_content_included": False,
            },
        ),
        (
            "TaskPreparationStartedV1",
            {
                "workspace_relative_path": workspace_relative_path,
                "ownership_nonce": ownership_nonce,
                "proposed_action_digest": digest,
            },
        ),
        (
            "WorkspaceProvisioningAuthorizedV1",
            {
                "bootstrap_policy_id": "builtin.workspace-provision.v1",
                "decision": "AUTO_ALLOWED",
                "workspace_relative_path": workspace_relative_path,
                "ownership_nonce": ownership_nonce,
                "action_digest": digest,
                "mode": "DETACHED",
                "baseline_commit": BASELINE_OID,
            },
        ),
    )
    ids = event_ids or _event_ids(seed)
    events: list[dict[str, object]] = []
    previous_hash = ZERO_HASH
    previous_event_id: str | None = None
    for sequence, ((event_type, payload), event_id) in enumerate(
        zip(payloads, ids, strict=True),
        start=1,
    ):
        event: dict[str, object] = {
            "event_id": event_id,
            "task_id": task_id,
            "sequence": sequence,
            "event_type": event_type,
            "schema_version": 1,
            "occurred_at": f"2026-08-21T00:01:0{sequence}.000000Z",
            "actor": "local_user",
            "correlation_id": correlation_id,
            "causation_id": previous_event_id,
            "workspace_revision": None,
            "sensitivity": "INTERNAL",
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event["event_hash"] = event_hash_oracle(event)
        events.append(event)
        previous_hash = str(event["event_hash"])
        previous_event_id = event_id
    return task_id, workspace_relative_path, events


def _prepared_event(
    seed: int,
    authorization_events: Sequence[Mapping[str, object]],
    *,
    variant: int,
) -> dict[str, object]:
    """生成与给定授权逐字节绑定的合法 Prepared 终态。"""

    authorization = authorization_events[2]
    payload = authorization["payload"]
    assert isinstance(payload, Mapping)
    previous = authorization_events[-1]
    event: dict[str, object] = {
        "event_id": f"50000000-0000-4000-8000-{seed * 16 + variant:012x}",
        "task_id": authorization_events[0]["task_id"],
        "sequence": 4,
        "event_type": "TaskWorkspacePreparedV1",
        "schema_version": 1,
        "occurred_at": f"2026-08-21T00:02:{variant:02d}.000000Z",
        "actor": "local_user",
        "correlation_id": authorization_events[0]["correlation_id"],
        "causation_id": previous["event_id"],
        "workspace_revision": None,
        "sensitivity": "INTERNAL",
        "payload": {
            "action_digest": payload["action_digest"],
            "ownership_nonce": payload["ownership_nonce"],
            "workspace_relative_path": payload["workspace_relative_path"],
            "mode": "DETACHED",
            "head_oid": payload["baseline_commit"],
            "git_pointer_digest": f"{variant:x}" * 64,
            "recovered_after_interruption": False,
        },
        "previous_hash": previous["event_hash"],
    }
    event["event_hash"] = event_hash_oracle(event)
    return event


def _store(tmp_path: Path, name: str = "data") -> SQLiteEventStore:
    store = SQLiteEventStore(tmp_path / name)
    store.initialize()
    return store


def _create_authorized(store: SQLiteEventStore, seed: int) -> StoredTask:
    task_id, workspace_relative_path, events = _authorization_events(seed)
    restored = restore_task_projection(events)
    store.create_task(
        task_id,
        workspace_relative_path,
        events,
        restored.projection,
        restored.checkpoint,
    )
    return StoredTask(task_id, workspace_relative_path, events, restored)


def _derived_rows(
    database_path: Path, task_id: str
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    with sqlite3.connect(database_path) as connection:
        projection = connection.execute(
            "SELECT through_sequence, through_event_hash, projection "
            "FROM projections WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        checkpoint = connection.execute(
            "SELECT through_sequence, through_event_hash, checkpoint, checkpoint_hash "
            "FROM checkpoints WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    assert projection is not None
    assert checkpoint is not None
    return tuple(projection), tuple(checkpoint)


def _assert_error_code(error: pytest.ExceptionInfo[SigmaCoderError], expected: str) -> None:
    assert error.value.code == expected


@pytest.mark.parametrize("event_count", [2, 4])
def test_create_task_requires_exact_initial_sequences_one_through_three(
    tmp_path: Path,
    event_count: int,
) -> None:
    """SPEC §6.3/§7：首次事务不能少写或偷带终态。"""

    store = _store(tmp_path)
    task_id, workspace_relative_path, events = _authorization_events(1)
    candidate = events[:2]
    if event_count == 4:
        candidate = [*events, _prepared_event(1, events, variant=1)]
    restored = restore_task_projection(candidate)

    with pytest.raises(SigmaCoderError) as error:
        store.create_task(
            task_id,
            workspace_relative_path,
            candidate,
            restored.projection,
            restored.checkpoint,
        )

    _assert_error_code(error, "EVENT_TRANSITION_INVALID")
    assert store.task_ids() == []


def test_event_id_is_unique_across_tasks_in_one_data_root(tmp_path: Path) -> None:
    """SPEC §6.1/S12/S18：event_id 唯一性跨 Task 生效。"""

    store = _store(tmp_path)
    first = _create_authorized(store, 1)
    second_ids = list(_event_ids(2))
    second_ids[0] = str(first.events[0]["event_id"])
    task_id, workspace_relative_path, events = _authorization_events(
        2,
        event_ids=(second_ids[0], second_ids[1], second_ids[2]),
    )
    restored = restore_task_projection(events)

    with pytest.raises(SigmaCoderError) as error:
        store.create_task(
            task_id,
            workspace_relative_path,
            events,
            restored.projection,
            restored.checkpoint,
        )

    _assert_error_code(error, "EVENT_ID_DUPLICATE")
    assert store.task_ids() == [first.task_id]
    assert [event["event_id"] for event in store.load_events(first.task_id)] == [
        event["event_id"] for event in first.events
    ]


def test_two_connections_competing_for_same_tail_commit_one_terminal_event(
    tmp_path: Path,
) -> None:
    """SPEC F07/S12：同一尾部的并发写者只能有一个提交成功。"""

    first_store = _store(tmp_path)
    task = _create_authorized(first_store, 3)
    contenders = [
        _prepared_event(3, task.events, variant=1),
        _prepared_event(3, task.events, variant=2),
    ]
    barrier = Barrier(2)

    def append(contender: dict[str, object]) -> tuple[str, str]:
        store = SQLiteEventStore(first_store.data_root)
        store.initialize()
        restored = restore_task_projection([*task.events, contender])
        barrier.wait(timeout=10)
        try:
            store.append_events(
                task.task_id,
                [contender],
                restored.projection,
                restored.checkpoint,
            )
        except SigmaCoderError as error:
            return error.code, str(contender["event_id"])
        return "COMMITTED", str(contender["event_id"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(append, contenders))

    assert sorted(code for code, _event_id in outcomes) == ["COMMITTED", "STORE_BUSY"]
    winner = next(event_id for code, event_id in outcomes if code == "COMMITTED")
    reopened = SQLiteEventStore(first_store.data_root)
    reopened.initialize()
    stored = reopened.load_events(task.task_id)
    assert [event["sequence"] for event in stored] == [1, 2, 3, 4]
    assert stored[-1]["event_id"] == winner


def test_stale_replace_derived_cas_never_downgrades_tail(tmp_path: Path) -> None:
    """SPEC §6.5：旧读取者不得把 sequence 4 派生状态倒退到 3。"""

    store = _store(tmp_path)
    task = _create_authorized(store, 4)
    terminal = _prepared_event(4, task.events, variant=1)
    current = restore_task_projection([*task.events, terminal])
    store.append_events(task.task_id, [terminal], current.projection, current.checkpoint)
    before = _derived_rows(store.database_path, task.task_id)

    with pytest.raises(SigmaCoderError) as error:
        store.replace_derived(
            task.task_id,
            task.restored.projection,
            task.restored.checkpoint,
            expected_sequence=3,
            expected_event_hash=str(task.events[-1]["event_hash"]),
        )

    _assert_error_code(error, "STORE_BUSY")
    assert _derived_rows(store.database_path, task.task_id) == before
    checkpoint = store.load_checkpoint(task.task_id)
    assert checkpoint is not None
    assert checkpoint["through_sequence"] == 4
    assert checkpoint["through_event_hash"] == terminal["event_hash"]


def test_invalid_authoritative_event_json_fails_closed_without_derived_write(
    tmp_path: Path,
) -> None:
    """SPEC S09：非法权威 JSON 不能由投影或 checkpoint 掩盖。"""

    store = _store(tmp_path)
    task = _create_authorized(store, 5)
    before = _derived_rows(store.database_path, task.task_id)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER events_reject_update")
        connection.execute(
            "UPDATE events SET payload = ? WHERE task_id = ? AND sequence = 1",
            ('{"objective":', task.task_id),
        )
        connection.executescript(
            """
            CREATE TRIGGER events_reject_update
            BEFORE UPDATE ON events
            BEGIN
                SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
            END;
            """
        )
        connection.commit()

    reopened = SQLiteEventStore(store.data_root)
    reopened.initialize()
    with pytest.raises(SigmaCoderError) as error:
        reopened.load_events(task.task_id)

    _assert_error_code(error, "EVENT_PAYLOAD_INVALID")
    assert _derived_rows(store.database_path, task.task_id) == before


def test_invalid_checkpoint_is_discarded_and_rebuilt_from_full_event_stream(
    tmp_path: Path,
) -> None:
    """SPEC S08：坏 checkpoint 不是权威，合法事件可完整重放。"""

    store = _store(tmp_path)
    task = _create_authorized(store, 6)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE checkpoints SET checkpoint = ? WHERE task_id = ?",
            ('{"checkpoint_version":', task.task_id),
        )
        connection.commit()

    reopened = SQLiteEventStore(store.data_root)
    reopened.initialize()
    events = reopened.load_events(task.task_id)
    assert reopened.load_checkpoint(task.task_id) is None
    rebuilt = restore_task_projection(events, checkpoint=None)
    assert rebuilt.load_mode == "FULL_REPLAY"
    reopened.replace_derived(
        task.task_id,
        rebuilt.projection,
        rebuilt.checkpoint,
        expected_sequence=3,
        expected_event_hash=str(events[-1]["event_hash"]),
    )

    final_checkpoint = reopened.load_checkpoint(task.task_id)
    assert final_checkpoint is not None
    assert canonical_json_bytes(final_checkpoint) == canonical_json_bytes(rebuilt.checkpoint)
    verified = restore_task_projection(
        reopened.load_events(task.task_id),
        checkpoint=final_checkpoint,
    )
    assert verified.load_mode == "CHECKPOINT"
    assert canonical_json_bytes(verified.projection) == canonical_json_bytes(
        task.restored.projection
    )


def test_valid_older_checkpoint_advances_to_authoritative_tail_on_reopen(
    tmp_path: Path,
) -> None:
    """SPEC S07：完整链先验证，再从有效旧 checkpoint 继续到新尾部。"""

    store = _store(tmp_path)
    task = _create_authorized(store, 7)
    old_checkpoint = deepcopy(task.restored.checkpoint)
    terminal = _prepared_event(7, task.events, variant=1)
    latest = restore_task_projection([*task.events, terminal])
    store.append_events(task.task_id, [terminal], latest.projection, latest.checkpoint)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE checkpoints
            SET through_sequence = ?, through_event_hash = ?, checkpoint = ?, checkpoint_hash = ?
            WHERE task_id = ?
            """,
            (
                old_checkpoint["through_sequence"],
                old_checkpoint["through_event_hash"],
                canonical_json_bytes(old_checkpoint).decode("utf-8"),
                old_checkpoint["checkpoint_hash"],
                task.task_id,
            ),
        )
        connection.commit()

    reopened = SQLiteEventStore(store.data_root)
    reopened.initialize()
    restored = restore_task_projection(
        reopened.load_events(task.task_id),
        checkpoint=reopened.load_checkpoint(task.task_id),
    )
    assert restored.load_mode == "CHECKPOINT"
    assert restored.projection["event_position"] == {
        "sequence": 4,
        "event_hash": terminal["event_hash"],
    }


def test_unsupported_database_schema_version_fails_closed(tmp_path: Path) -> None:
    """SPEC §6.1：未知数据库 schema 不得被就地猜测升级。"""

    store = _store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("PRAGMA user_version=99")

    with pytest.raises(SigmaCoderError) as error:
        SQLiteEventStore(store.data_root).initialize()

    _assert_error_code(error, "SQLITE_CORRUPT")


def test_initialize_preserves_store_error_when_connection_setup_fails(
    tmp_path: Path,
) -> None:
    """连接尚未交给 initialize 时失败，也必须保留稳定存储异常。"""

    data_root = tmp_path / "locked-data"
    data_root.mkdir()
    database_path = data_root / DATABASE_NAME
    with sqlite3.connect(database_path) as lock_owner:
        lock_owner.execute("CREATE TABLE lock_owner(value INTEGER NOT NULL)")
        lock_owner.commit()
        lock_owner.execute("BEGIN EXCLUSIVE")

        with pytest.raises(SigmaCoderError) as error:
            SQLiteEventStore(data_root).initialize()

    _assert_error_code(error, "STORE_BUSY")


def test_counterfeit_append_only_trigger_fails_schema_verification(tmp_path: Path) -> None:
    """SPEC S19：同名伪触发器不能冒充数据库不可变约束。"""

    store = _store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.executescript(
            """
            DROP TRIGGER events_reject_update;
            CREATE TRIGGER events_reject_update
            AFTER INSERT ON events
            BEGIN
                SELECT 1;
            END;
            """
        )

    with pytest.raises(SigmaCoderError) as error:
        SQLiteEventStore(store.data_root).initialize()

    _assert_error_code(error, "SQLITE_CORRUPT")


def test_store_connections_enforce_wal_full_and_foreign_keys(tmp_path: Path) -> None:
    """SPEC §6.1：真实连接保持 WAL、FULL 与外键执行。"""

    store = _store(tmp_path)
    with store._connection() as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        assert journal_mode is not None and str(journal_mode[0]).lower() == "wal"
        assert synchronous is not None and int(synchronous[0]) == 2
        assert foreign_keys is not None and int(foreign_keys[0]) == 1
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO projections(task_id, through_sequence, through_event_hash, projection)
                VALUES (?, 1, ?, '{}')
                """,
                (_task_id(999), ZERO_HASH),
            )


def test_database_rejects_update_and_delete_across_independent_connections(
    tmp_path: Path,
) -> None:
    """SPEC S19：UPDATE 与 DELETE 必须由 SQLite 边界直接拒绝。"""

    store = _store(tmp_path)
    task = _create_authorized(store, 8)
    original = canonical_json_bytes(store.load_events(task.task_id))
    statements = (
        "UPDATE events SET actor = 'attacker' WHERE task_id = ?",
        "DELETE FROM events WHERE task_id = ?",
    )
    for statement in statements:
        with sqlite3.connect(store.database_path) as connection:
            with pytest.raises(sqlite3.IntegrityError, match="EVENTS_APPEND_ONLY"):
                connection.execute(statement, (task.task_id,))

    reopened = SQLiteEventStore(store.data_root)
    reopened.initialize()
    events = reopened.load_events(task.task_id)
    assert canonical_json_bytes(events) == original
    assert [event["sequence"] for event in events] == [1, 2, 3]
    assert restore_task_projection(events).projection == task.restored.projection


def test_projection_and_checkpoint_remain_canonical_after_new_store_reopens(
    tmp_path: Path,
) -> None:
    """SPEC S05/S06：新连接仅从持久事实得到同一投影与 checkpoint。"""

    first = _store(tmp_path)
    task = _create_authorized(first, 9)
    first_rows = _derived_rows(first.database_path, task.task_id)

    reopened = SQLiteEventStore(first.data_root)
    reopened.initialize()
    events = reopened.load_events(task.task_id)
    checkpoint = reopened.load_checkpoint(task.task_id)
    assert checkpoint is not None
    restored = restore_task_projection(events, checkpoint=checkpoint)

    assert restored.load_mode == "CHECKPOINT"
    assert canonical_json_bytes(restored.projection) == canonical_json_bytes(
        task.restored.projection
    )
    assert canonical_json_bytes(restored.checkpoint) == canonical_json_bytes(
        task.restored.checkpoint
    )
    assert _derived_rows(reopened.database_path, task.task_id) == first_rows
    assert reopened.database_path == first.data_root / DATABASE_NAME
