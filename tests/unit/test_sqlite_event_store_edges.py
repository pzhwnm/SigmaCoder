"""SQLite 事件存储的拒绝路径与低层错误映射。"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.support.event_contract import (
    TASK_ID,
    WORKSPACE_RELATIVE_PATH,
    authorization_events,
)

from sigmacoder.adapters.sqlite_event_store import (
    DATABASE_NAME,
    SQLiteEventStore,
    _plain_mapping,
    _validated_write,
    _workspace_relative_path,
)
from sigmacoder.domain.events import restore_task_projection
from sigmacoder.errors import SigmaCoderError


@dataclass(frozen=True)
class _MappedValue:
    value: int


def _assert_code(captured: pytest.ExceptionInfo[SigmaCoderError], code: str) -> None:
    assert captured.value.code == code


def _valid_state() -> tuple[list[dict[str, object]], dict[str, object], dict[str, object]]:
    events = authorization_events()
    restored = restore_task_projection(events)
    return events, dict(restored.projection), dict(restored.checkpoint)


def _initialized_store(tmp_path: Path) -> SQLiteEventStore:
    store = SQLiteEventStore(tmp_path / "data")
    store.initialize()
    return store


def _create_task(store: SQLiteEventStore) -> None:
    events, projection, checkpoint = _valid_state()
    store.create_task(TASK_ID, WORKSPACE_RELATIVE_PATH, events, projection, checkpoint)


def test_plain_mapping_accepts_dataclass_and_rejects_other_objects() -> None:
    assert _plain_mapping(_MappedValue(7)) == {"value": 7}
    with pytest.raises(TypeError, match="mapping 或 dataclass"):
        _plain_mapping(object())


def test_plain_mapping_rejects_impossible_non_mapping_dataclass_conversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sigmacoder.adapters.sqlite_event_store.asdict",
        lambda _value: ["counterfeit"],
    )
    with pytest.raises(TypeError, match="mapping 或 dataclass"):
        _plain_mapping(_MappedValue(7))


def test_validated_write_rejects_empty_invalid_and_mismatched_material() -> None:
    events, projection, checkpoint = _valid_state()
    with pytest.raises(SigmaCoderError) as empty:
        _validated_write(TASK_ID, (), (), projection, checkpoint)
    _assert_code(empty, "EVENT_SEQUENCE_GAP")

    corrupt = deepcopy(events)
    corrupt[0]["event_hash"] = "f" * 64
    with pytest.raises(SigmaCoderError) as invalid:
        _validated_write(TASK_ID, (), corrupt, projection, checkpoint)
    assert invalid.value.code.startswith("EVENT_")

    wrong_projection = deepcopy(projection)
    wrong_projection["objective"] = "伪造投影"
    with pytest.raises(SigmaCoderError) as projection_error:
        _validated_write(TASK_ID, (), events, wrong_projection, checkpoint)
    _assert_code(projection_error, "EVENT_PAYLOAD_INVALID")

    wrong_checkpoint = deepcopy(checkpoint)
    wrong_checkpoint["through_event_hash"] = "e" * 64
    with pytest.raises(SigmaCoderError) as checkpoint_error:
        _validated_write(TASK_ID, (), events, projection, wrong_checkpoint)
    _assert_code(checkpoint_error, "EVENT_PAYLOAD_INVALID")

    with pytest.raises(SigmaCoderError) as task_error:
        _validated_write("99999999-9999-4999-8999-999999999999", (), events, projection, checkpoint)
    _assert_code(task_error, "EVENT_PAYLOAD_INVALID")


@pytest.mark.parametrize(
    "projection",
    [
        {},
        {"workspace": None},
        {"workspace": {}},
        {"workspace": {"relative_path": ""}},
        {"workspace": {"relative_path": 1}},
    ],
)
def test_workspace_path_extractor_rejects_incomplete_projection(
    projection: dict[str, object],
) -> None:
    with pytest.raises(SigmaCoderError) as captured:
        _workspace_relative_path(projection)
    _assert_code(captured, "EVENT_PAYLOAD_INVALID")


def test_initialize_rejects_unversioned_existing_schema(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    with sqlite3.connect(data_root / DATABASE_NAME) as connection:
        connection.execute("CREATE TABLE counterfeit(value INTEGER)")

    with pytest.raises(SigmaCoderError) as captured:
        SQLiteEventStore(data_root).initialize()

    _assert_code(captured, "SQLITE_CORRUPT")


class _InitializeConnection:
    def __init__(self, *, version: object = 1, quick_check: str = "ok") -> None:
        self.version = version
        self.quick_check = quick_check

    def execute(self, statement: str) -> _SingleRow | _Rows:
        if statement == "PRAGMA user_version":
            return _SingleRow(self.version)
        if "FROM sqlite_master" in statement and "LIMIT 1" in statement:
            return _SingleRow(None)
        if statement == "PRAGMA quick_check":
            return _Rows([(self.quick_check,)])
        raise AssertionError(statement)

    @staticmethod
    def executescript(_script: str) -> None:
        return None


class _Rows:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


@contextmanager
def _yield_connection(connection: object, **_kwargs: object) -> Iterator[Any]:
    yield connection


def test_initialize_rejects_failed_quick_check_and_bad_schema_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteEventStore(tmp_path / "data")
    monkeypatch.setattr(
        store,
        "_connection",
        lambda **kwargs: _yield_connection(_InitializeConnection(quick_check="bad"), **kwargs),
    )
    monkeypatch.setattr(
        SQLiteEventStore, "_verify_schema", classmethod(lambda _cls, _connection: None)
    )
    with pytest.raises(SigmaCoderError) as quick_check:
        store.initialize()
    _assert_code(quick_check, "SQLITE_CORRUPT")

    monkeypatch.setattr(
        store,
        "_connection",
        lambda **kwargs: _yield_connection(_InitializeConnection(version=99), **kwargs),
    )
    with pytest.raises(SigmaCoderError) as version:
        store.initialize()
    _assert_code(version, "SQLITE_CORRUPT")


def test_initialize_translates_filesystem_and_database_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteEventStore(tmp_path / "data")
    original_mkdir = Path.mkdir

    def denied(path: Path, *args: object, **kwargs: object) -> None:
        if path == store.data_root:
            raise PermissionError("denied")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", denied)
    with pytest.raises(SigmaCoderError) as filesystem:
        store.initialize()
    _assert_code(filesystem, "STORE_UNAVAILABLE")

    monkeypatch.setattr(Path, "mkdir", original_mkdir)
    monkeypatch.setattr(SQLiteEventStore, "_connection", _database_failure)
    with pytest.raises(SigmaCoderError) as database:
        store.initialize()
    _assert_code(database, "STORE_UNAVAILABLE")


@pytest.mark.parametrize(
    ("sqlite_code", "expected"),
    [
        (sqlite3.SQLITE_BUSY, "STORE_BUSY"),
        (sqlite3.SQLITE_LOCKED, "STORE_BUSY"),
        (sqlite3.SQLITE_CORRUPT, "SQLITE_CORRUPT"),
        (sqlite3.SQLITE_NOTADB, "SQLITE_CORRUPT"),
        (sqlite3.SQLITE_IOERR, "STORE_UNAVAILABLE"),
        (None, "STORE_UNAVAILABLE"),
    ],
)
def test_database_errors_map_to_stable_codes(sqlite_code: int | None, expected: str) -> None:
    error = sqlite3.DatabaseError("fixture")
    if sqlite_code is not None:
        error.sqlite_errorcode = sqlite_code
    with pytest.raises(SigmaCoderError) as captured:
        SQLiteEventStore._raise_database_error(error)
    _assert_code(captured, expected)


class _PragmaConnection:
    def __init__(self, synchronous: object, foreign_keys: object) -> None:
        self._synchronous = synchronous
        self._foreign_keys = foreign_keys

    def execute(self, statement: str) -> object:
        if statement == "PRAGMA synchronous":
            return _SingleRow(self._synchronous)
        if statement == "PRAGMA foreign_keys":
            return _SingleRow(self._foreign_keys)
        raise AssertionError(statement)


class _SingleRow:
    def __init__(self, value: object) -> None:
        self._value = value

    def fetchone(self) -> tuple[object] | None:
        return None if self._value is None else (self._value,)


class _BadWalConnection:
    row_factory: object = None

    @staticmethod
    def execute(statement: str) -> _SingleRow:
        assert statement == "PRAGMA journal_mode"
        return _SingleRow("delete")

    @staticmethod
    def close() -> None:
        return None


def test_connection_rejects_non_wal_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteEventStore(tmp_path)
    monkeypatch.setattr(sqlite3, "connect", lambda *_args, **_kwargs: _BadWalConnection())
    with pytest.raises(SigmaCoderError) as captured:
        with store._connection():
            pytest.fail("非 WAL 连接不应进入调用方。")
    _assert_code(captured, "STORE_UNAVAILABLE")


def test_connection_closes_safely_when_sqlite_connect_never_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteEventStore(tmp_path)
    error = sqlite3.DatabaseError("connect failed")
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(SigmaCoderError) as captured:
        with store._connection():
            pytest.fail("连接失败时不应进入调用方。")
    _assert_code(captured, "STORE_UNAVAILABLE")


@pytest.mark.parametrize(
    ("synchronous", "foreign_keys"),
    [(None, 1), (1, 1), (2, None), (2, 0)],
)
def test_connection_pragmas_fail_closed(synchronous: object, foreign_keys: object) -> None:
    with pytest.raises(SigmaCoderError) as captured:
        SQLiteEventStore._verify_connection_pragmas(
            _PragmaConnection(synchronous, foreign_keys)  # type: ignore[arg-type]
        )
    _assert_code(captured, "STORE_UNAVAILABLE")


def test_schema_verification_rejects_columns_foreign_keys_and_unique_constraints(
    tmp_path: Path,
) -> None:
    column_store = _initialized_store(tmp_path / "columns")
    with sqlite3.connect(column_store.database_path) as connection:
        connection.execute("ALTER TABLE projections RENAME COLUMN projection TO counterfeit")
    with pytest.raises(SigmaCoderError) as columns:
        column_store.initialize()
    _assert_code(columns, "SQLITE_CORRUPT")

    unique_store = _initialized_store(tmp_path / "unique")
    with sqlite3.connect(unique_store.database_path) as connection:
        connection.execute("ALTER TABLE task_registry RENAME TO old_task_registry")
        connection.execute("CREATE TABLE task_registry(task_id TEXT, workspace_relative_path TEXT)")
    with pytest.raises(SigmaCoderError) as unique:
        unique_store.initialize()
    _assert_code(unique, "SQLITE_CORRUPT")

    foreign_store = _initialized_store(tmp_path / "foreign")
    with sqlite3.connect(foreign_store.database_path) as connection:
        connection.execute("ALTER TABLE checkpoints RENAME TO old_checkpoints")
        connection.execute(
            """
            CREATE TABLE checkpoints(
                task_id TEXT PRIMARY KEY,
                through_sequence INTEGER NOT NULL,
                through_event_hash TEXT NOT NULL,
                checkpoint TEXT NOT NULL,
                checkpoint_hash TEXT NOT NULL
            )
            """
        )
    with pytest.raises(SigmaCoderError) as foreign:
        foreign_store.initialize()
    _assert_code(foreign, "SQLITE_CORRUPT")


class _SchemaProxy:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, statement: str) -> Any:
        if "SELECT sql FROM sqlite_master" in statement and "name='events'" in statement:
            return _SingleRow(None)
        return self._connection.execute(statement)


class _BadSchemaVersion:
    @staticmethod
    def execute(statement: str) -> _SingleRow:
        assert statement == "PRAGMA user_version"
        return _SingleRow(99)


def test_schema_verification_rejects_unknown_version_directly() -> None:
    with pytest.raises(SigmaCoderError) as captured:
        SQLiteEventStore._verify_schema(_BadSchemaVersion())  # type: ignore[arg-type]
    _assert_code(captured, "SQLITE_CORRUPT")


def test_schema_verification_requires_sequence_check_constraint(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(SigmaCoderError) as captured:
            SQLiteEventStore._verify_schema(_SchemaProxy(connection))  # type: ignore[arg-type]
    _assert_code(captured, "SQLITE_CORRUPT")


def test_non_unique_indexes_are_ignored_when_required_unique_indexes_exist(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    with store._connection() as connection:
        connection.execute("CREATE INDEX ordinary_actor_idx ON events(actor)")
        SQLiteEventStore._verify_unique_indexes(
            connection,
            "events",
            {("task_id", "sequence"), ("event_id",)},
        )


def test_store_accessors_and_missing_task_paths(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    _create_task(store)
    assert store.workspace_relative_path(TASK_ID) == WORKSPACE_RELATIVE_PATH

    unknown = "99999999-9999-4999-8999-999999999999"
    for operation in (
        lambda: store.workspace_relative_path(unknown),
        lambda: store.load_events(unknown),
        lambda: store.append_events(unknown, [], {}, {}),
        lambda: store.replace_derived(
            unknown,
            {},
            {},
            expected_sequence=1,
            expected_event_hash="0" * 64,
        ),
    ):
        with pytest.raises(SigmaCoderError) as captured:
            operation()
        _assert_code(captured, "TASK_NOT_FOUND")

    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DELETE FROM checkpoints WHERE task_id = ?", (TASK_ID,))
    assert store.load_checkpoint(TASK_ID) is None


def test_append_rejects_invalid_id_sequence_gap_and_collision(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    events, projection, checkpoint = _valid_state()
    store.create_task(TASK_ID, WORKSPACE_RELATIVE_PATH, events, projection, checkpoint)

    with pytest.raises(SigmaCoderError) as empty:
        store.append_events(TASK_ID, [], projection, checkpoint)
    _assert_code(empty, "EVENT_SEQUENCE_GAP")

    invalid_id = {"event_id": 7, "sequence": 4}
    with pytest.raises(SigmaCoderError) as identifier:
        store.append_events(TASK_ID, [invalid_id], projection, checkpoint)
    _assert_code(identifier, "EVENT_PAYLOAD_INVALID")

    future = {"event_id": "ffffffff-ffff-4fff-8fff-ffffffffffff", "sequence": 5}
    with pytest.raises(SigmaCoderError) as gap:
        store.append_events(TASK_ID, [future], projection, checkpoint)
    _assert_code(gap, "EVENT_SEQUENCE_GAP")

    with pytest.raises(SigmaCoderError) as collision:
        store.create_task(TASK_ID, WORKSPACE_RELATIVE_PATH, events, projection, checkpoint)
    _assert_code(collision, "TASK_ID_COLLISION")


def test_registry_path_mismatch_is_rejected_before_transaction(tmp_path: Path) -> None:
    store = _initialized_store(tmp_path)
    events, projection, checkpoint = _valid_state()
    with pytest.raises(SigmaCoderError) as captured:
        store.create_task(TASK_ID, "tasks/counterfeit", events, projection, checkpoint)
    _assert_code(captured, "EVENT_PAYLOAD_INVALID")


def test_create_and_append_translate_integrity_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _initialized_store(tmp_path)
    events, projection, checkpoint = _valid_state()

    monkeypatch.setattr(
        SQLiteEventStore,
        "_assert_event_ids_available",
        staticmethod(lambda *_args: (_ for _ in ()).throw(sqlite3.IntegrityError("fixture"))),
    )
    with pytest.raises(SigmaCoderError) as create:
        store.create_task(TASK_ID, WORKSPACE_RELATIVE_PATH, events, projection, checkpoint)
    _assert_code(create, "STORE_UNAVAILABLE")

    monkeypatch.undo()
    store = _initialized_store(tmp_path / "append")
    _create_task(store)
    monkeypatch.setattr(
        SQLiteEventStore,
        "_assert_event_ids_available",
        staticmethod(lambda *_args: (_ for _ in ()).throw(sqlite3.IntegrityError("fixture"))),
    )
    with pytest.raises(SigmaCoderError) as append:
        store.append_events(
            TASK_ID,
            [{"event_id": "ffffffff-ffff-4fff-8fff-ffffffffffff", "sequence": 4}],
            projection,
            checkpoint,
        )
    _assert_code(append, "STORE_UNAVAILABLE")


def test_json_and_row_decoders_fail_closed_with_location() -> None:
    assert SQLiteEventStore._decode_json(b'{"ok":true}') == {"ok": True}
    with pytest.raises(TypeError, match="JSON 列"):
        SQLiteEventStore._decode_json(7)

    row: dict[str, Any] = {"sequence": "not-an-integer"}
    with pytest.raises(SigmaCoderError) as captured:
        SQLiteEventStore._event_from_row(row)  # type: ignore[arg-type]
    _assert_code(captured, "EVENT_PAYLOAD_INVALID")
    assert captured.value.details["first_invalid_sequence"] is None


@contextmanager
def _database_failure(*_args: object, **_kwargs: object) -> Iterator[Any]:
    error = sqlite3.DatabaseError("注入式数据库故障")
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR
    raise error
    yield  # pragma: no cover - contextmanager 需要生成器形状


def test_public_operations_translate_connection_database_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteEventStore(tmp_path / "data")
    events, projection, checkpoint = _valid_state()
    monkeypatch.setattr(SQLiteEventStore, "_connection", _database_failure)

    operations = (
        lambda: store.create_task(
            TASK_ID,
            WORKSPACE_RELATIVE_PATH,
            events,
            projection,
            checkpoint,
        ),
        lambda: store.append_events(TASK_ID, events, projection, checkpoint),
        lambda: store.replace_derived(
            TASK_ID,
            projection,
            checkpoint,
            expected_sequence=3,
            expected_event_hash=str(events[-1]["event_hash"]),
        ),
        store.task_ids,
        lambda: store.workspace_relative_path(TASK_ID),
        lambda: store.load_events(TASK_ID),
        lambda: store.load_checkpoint(TASK_ID),
    )
    for operation in operations:
        with pytest.raises(SigmaCoderError) as captured:
            operation()
        _assert_code(captured, "STORE_UNAVAILABLE")
