"""SQLite/WAL 只增事件存储适配器。"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Final, NoReturn, cast

from sigmacoder.domain.events import (
    DomainValidationError,
    ProjectionRestoreResult,
    canonical_json_bytes,
    restore_task_projection,
)
from sigmacoder.errors import SigmaCoderError, error_code

DATABASE_NAME = "sigmacoder.sqlite3"
SCHEMA_VERSION = 1

_EXPECTED_COLUMNS = {
    "task_registry": ("task_id", "workspace_relative_path"),
    "events": (
        "task_id",
        "sequence",
        "event_id",
        "event_type",
        "schema_version",
        "occurred_at",
        "actor",
        "correlation_id",
        "causation_id",
        "workspace_revision",
        "sensitivity",
        "payload",
        "previous_hash",
        "event_hash",
    ),
    "projections": (
        "task_id",
        "through_sequence",
        "through_event_hash",
        "projection",
    ),
    "checkpoints": (
        "task_id",
        "through_sequence",
        "through_event_hash",
        "checkpoint",
        "checkpoint_hash",
    ),
}
_EXPECTED_EVENT_TRIGGER_SQL: Final = {
    "events_reject_update": (
        "CREATE TRIGGER EVENTS_REJECT_UPDATE BEFORE UPDATE ON EVENTS "
        "BEGIN SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY'); END"
    ),
    "events_reject_delete": (
        "CREATE TRIGGER EVENTS_REJECT_DELETE BEFORE DELETE ON EVENTS "
        "BEGIN SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY'); END"
    ),
}


def _plain_mapping(value: object) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value) and not isinstance(value, type):
        mapped = asdict(value)
        if isinstance(mapped, dict):
            return mapped
    raise TypeError("持久化对象必须是 mapping 或 dataclass。")


def _json_text(value: object) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _validated_write(
    task_id: str,
    existing: Sequence[Mapping[str, object]],
    incoming: Sequence[Mapping[str, object]],
    projection: object,
    checkpoint: object,
) -> ProjectionRestoreResult:
    """把写入参数绑定到同一条完整、连续、语义合法的 Task 事件链。"""

    if not incoming:
        raise SigmaCoderError("EVENT_SEQUENCE_GAP", "待追加事件不能为空。")
    combined = [*existing, *incoming]
    try:
        restored = restore_task_projection(combined)
    except DomainValidationError as error:
        raise SigmaCoderError(error_code(error), str(error)) from error
    supplied_projection = _plain_mapping(projection)
    supplied_checkpoint = _plain_mapping(checkpoint)
    if canonical_json_bytes(supplied_projection) != canonical_json_bytes(restored.projection):
        raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "投影与同事务事件尾不一致。")
    if canonical_json_bytes(supplied_checkpoint) != canonical_json_bytes(restored.checkpoint):
        raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "checkpoint 与同事务事件尾不一致。")
    if restored.projection.get("task_id") != task_id:
        raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "事件 batch 未绑定目标 Task。")
    return restored


def _workspace_relative_path(projection: Mapping[str, object]) -> str:
    workspace = projection.get("workspace")
    if not isinstance(workspace, Mapping):
        raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "投影缺少 workspace。")
    relative_path = workspace.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "投影缺少 workspace 相对路径。")
    return relative_path


class SQLiteEventStore:
    """在单个本地 data root 中提供 Task 隔离的事件权威。"""

    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root.resolve(strict=False)
        self.database_path = self.data_root / DATABASE_NAME

    def initialize(self) -> None:
        """创建数据库与不可变约束；重复调用安全。"""

        try:
            self.data_root.mkdir(parents=True, exist_ok=True)
            with self._connection(configure_wal=True) as connection:
                current_version = connection.execute("PRAGMA user_version").fetchone()
                if current_version is None or int(current_version[0]) not in {0, SCHEMA_VERSION}:
                    raise SigmaCoderError("SQLITE_CORRUPT", "SQLite schema 版本不受支持。")
                existing_objects = connection.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'trigger', 'index')
                    LIMIT 1
                    """
                ).fetchone()
                if int(current_version[0]) == 0 and existing_objects is not None:
                    raise SigmaCoderError("SQLITE_CORRUPT", "未版本化的 SQLite schema 已存在。")
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS task_registry (
                        task_id TEXT PRIMARY KEY,
                        workspace_relative_path TEXT NOT NULL UNIQUE
                    );
                    CREATE TABLE IF NOT EXISTS events (
                        task_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence > 0),
                        event_id TEXT NOT NULL UNIQUE,
                        event_type TEXT NOT NULL,
                        schema_version INTEGER NOT NULL,
                        occurred_at TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        correlation_id TEXT NOT NULL,
                        causation_id TEXT,
                        workspace_revision TEXT,
                        sensitivity TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (task_id, sequence),
                        FOREIGN KEY (task_id) REFERENCES task_registry(task_id)
                    );
                    CREATE TABLE IF NOT EXISTS projections (
                        task_id TEXT PRIMARY KEY,
                        through_sequence INTEGER NOT NULL,
                        through_event_hash TEXT NOT NULL,
                        projection TEXT NOT NULL,
                        FOREIGN KEY (task_id) REFERENCES task_registry(task_id)
                    );
                    CREATE TABLE IF NOT EXISTS checkpoints (
                        task_id TEXT PRIMARY KEY,
                        through_sequence INTEGER NOT NULL,
                        through_event_hash TEXT NOT NULL,
                        checkpoint TEXT NOT NULL,
                        checkpoint_hash TEXT NOT NULL,
                        FOREIGN KEY (task_id) REFERENCES task_registry(task_id)
                    );
                    CREATE TRIGGER IF NOT EXISTS events_reject_update
                    BEFORE UPDATE ON events
                    BEGIN
                        SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
                    END;
                    CREATE TRIGGER IF NOT EXISTS events_reject_delete
                    BEFORE DELETE ON events
                    BEGIN
                        SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
                    END;
                    PRAGMA user_version=1;
                    COMMIT;
                    """
                )
                self._verify_schema(connection)
                quick_check = connection.execute("PRAGMA quick_check").fetchall()
                if [str(row[0]) for row in quick_check] != ["ok"]:
                    raise SigmaCoderError("SQLITE_CORRUPT", "SQLite quick_check 未通过。")
        except OSError as error:
            raise SigmaCoderError("STORE_UNAVAILABLE", "无法初始化事件存储。") from error
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)

    @contextmanager
    def _connection(
        self,
        *,
        configure_wal: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            try:
                connection = sqlite3.connect(self.database_path, timeout=5.0)
                connection.row_factory = sqlite3.Row
                if configure_wal:
                    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
                else:
                    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
                if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                    raise SigmaCoderError(
                        "STORE_UNAVAILABLE",
                        "SQLite 无法启用或保持 WAL 模式。",
                    )
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=5000")
                self._verify_connection_pragmas(connection)
            except sqlite3.DatabaseError as error:
                self._raise_database_error(error)
            yield connection
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _raise_database_error(error: sqlite3.DatabaseError) -> NoReturn:
        raw_code = getattr(error, "sqlite_errorcode", None)
        base_code = raw_code & 0xFF if isinstance(raw_code, int) else None
        if base_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise SigmaCoderError("STORE_BUSY", "事件存储暂时繁忙。") from error
        if base_code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
            raise SigmaCoderError("SQLITE_CORRUPT", "SQLite 权威库损坏。") from error
        raise SigmaCoderError("STORE_UNAVAILABLE", "事件存储不可用。") from error

    @staticmethod
    def _verify_connection_pragmas(connection: sqlite3.Connection) -> None:
        synchronous = connection.execute("PRAGMA synchronous").fetchone()
        foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
        if synchronous is None or int(synchronous[0]) != 2:
            raise SigmaCoderError("STORE_UNAVAILABLE", "SQLite synchronous 未保持 FULL。")
        if foreign_keys is None or int(foreign_keys[0]) != 1:
            raise SigmaCoderError("STORE_UNAVAILABLE", "SQLite foreign_keys 未启用。")

    @classmethod
    def _verify_schema(cls, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()
        if version is None or int(version[0]) != SCHEMA_VERSION:
            raise SigmaCoderError("SQLITE_CORRUPT", "SQLite schema 版本不受支持。")
        for table, expected in _EXPECTED_COLUMNS.items():
            rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
            actual = tuple(str(row["name"]) for row in rows)
            if actual != expected:
                raise SigmaCoderError("SQLITE_CORRUPT", f"SQLite 表 {table} 结构不匹配。")
        cls._verify_unique_indexes(
            connection,
            "task_registry",
            {("task_id",): "pk", ("workspace_relative_path",): "u"},
        )
        cls._verify_unique_indexes(
            connection,
            "events",
            {("task_id", "sequence"): "pk", ("event_id",): "u"},
        )
        for table in ("events", "projections", "checkpoints"):
            foreign_keys = connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
            bindings = {
                (str(row["from"]), str(row["table"]), str(row["to"])) for row in foreign_keys
            }
            if ("task_id", "task_registry", "task_id") not in bindings:
                raise SigmaCoderError("SQLITE_CORRUPT", f"SQLite 表 {table} 外键缺失。")
        trigger_rows = connection.execute(
            """
            SELECT name, sql FROM sqlite_master
            WHERE type='trigger' AND tbl_name='events'
            """
        ).fetchall()
        trigger_sql = {
            str(row["name"]): " ".join(str(row["sql"]).upper().split()) for row in trigger_rows
        }
        if trigger_sql != _EXPECTED_EVENT_TRIGGER_SQL:
            raise SigmaCoderError("SQLITE_CORRUPT", "events 只增触发器定义不匹配。")
        events_sql_row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='events'"
        ).fetchone()
        events_sql = (
            " ".join(str(events_sql_row["sql"]).upper().split())
            if events_sql_row is not None
            else ""
        )
        if "CHECK (SEQUENCE > 0)" not in events_sql:
            raise SigmaCoderError("SQLITE_CORRUPT", "events sequence CHECK 约束缺失。")

    @staticmethod
    def _verify_unique_indexes(
        connection: sqlite3.Connection,
        table: str,
        required: Mapping[tuple[str, ...], str],
    ) -> None:
        found: list[tuple[tuple[str, ...], str]] = []
        for row in connection.execute(f'PRAGMA index_list("{table}")').fetchall():
            if int(row["unique"]) != 1:
                continue
            name = str(row["name"]).replace('"', '""')
            columns = connection.execute(f'PRAGMA index_info("{name}")').fetchall()
            found.append(
                (
                    tuple(str(column["name"]) for column in columns),
                    str(row["origin"]),
                )
            )
        expected = set(required.items())
        if len(found) != len(expected) or set(found) != expected:
            raise SigmaCoderError("SQLITE_CORRUPT", f"SQLite 表 {table} 唯一约束不匹配。")

    @staticmethod
    def _insert_event(connection: sqlite3.Connection, event: Mapping[str, object]) -> None:
        connection.execute(
            """
            INSERT INTO events (
                task_id, sequence, event_id, event_type, schema_version,
                occurred_at, actor, correlation_id, causation_id,
                workspace_revision, sensitivity, payload, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["task_id"],
                event["sequence"],
                event["event_id"],
                event["event_type"],
                event["schema_version"],
                event["occurred_at"],
                event["actor"],
                event["correlation_id"],
                event["causation_id"],
                event["workspace_revision"],
                event["sensitivity"],
                _json_text(event["payload"]),
                event["previous_hash"],
                event["event_hash"],
            ),
        )

    @staticmethod
    def _write_derived(
        connection: sqlite3.Connection,
        task_id: str,
        projection: object,
        checkpoint: object,
    ) -> None:
        projection_value = _plain_mapping(projection)
        checkpoint_value = _plain_mapping(checkpoint)
        through_sequence = int(checkpoint_value["through_sequence"])
        through_hash = str(checkpoint_value["through_event_hash"])
        connection.execute(
            """
            INSERT INTO projections(task_id, through_sequence, through_event_hash, projection)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                through_sequence=excluded.through_sequence,
                through_event_hash=excluded.through_event_hash,
                projection=excluded.projection
            """,
            (task_id, through_sequence, through_hash, _json_text(projection_value)),
        )
        connection.execute(
            """
            INSERT INTO checkpoints(
                task_id, through_sequence, through_event_hash, checkpoint, checkpoint_hash
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                through_sequence=excluded.through_sequence,
                through_event_hash=excluded.through_event_hash,
                checkpoint=excluded.checkpoint,
                checkpoint_hash=excluded.checkpoint_hash
            """,
            (
                task_id,
                through_sequence,
                through_hash,
                _json_text(checkpoint_value),
                checkpoint_value["checkpoint_hash"],
            ),
        )

    def create_task(
        self,
        task_id: str,
        workspace_relative_path: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None:
        """在一个事务中耐久提交 Task、授权事件和派生数据。"""

        restored = _validated_write(task_id, (), events, projection, checkpoint)
        logical_events = sorted(events, key=lambda event: cast(int, event["sequence"]))
        event_types = tuple(str(event.get("event_type")) for event in logical_events)
        expected_types = (
            "TaskCreatedV1",
            "TaskPreparationStartedV1",
            "WorkspaceProvisioningAuthorizedV1",
        )
        if event_types != expected_types:
            raise SigmaCoderError(
                "EVENT_TRANSITION_INVALID",
                "Task 首次事务必须恰好提交三条 workspace 授权事件。",
            )
        if _workspace_relative_path(restored.projection) != workspace_relative_path:
            raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "registry 路径未绑定事件事实。")
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                collision = connection.execute(
                    """
                    SELECT 1 FROM task_registry
                    WHERE task_id = ? OR workspace_relative_path = ?
                    """,
                    (task_id, workspace_relative_path),
                ).fetchone()
                if collision is not None:
                    raise SigmaCoderError(
                        "TASK_ID_COLLISION",
                        "Task 标识或工作区槽位发生碰撞。",
                    )
                self._assert_event_ids_available(connection, events)
                connection.execute(
                    "INSERT INTO task_registry(task_id, workspace_relative_path) VALUES (?, ?)",
                    (task_id, workspace_relative_path),
                )
                for event in events:
                    self._insert_event(connection, event)
                self._write_derived(
                    connection,
                    task_id,
                    restored.projection,
                    restored.checkpoint,
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise SigmaCoderError("STORE_UNAVAILABLE", "Task 事务违反 SQLite 约束。") from error
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)

    def append_events(
        self,
        task_id: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None:
        """按期望连续位置追加事件，并同事务更新派生数据。"""

        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY sequence",
                    (task_id,),
                ).fetchall()
                if not rows:
                    raise SigmaCoderError("TASK_NOT_FOUND", "Task 不存在。")
                existing = [self._event_from_row(row) for row in rows]
                self._assert_event_ids_available(connection, events)
                incoming_sequences = [event.get("sequence") for event in events]
                if not incoming_sequences or any(
                    not isinstance(sequence, int) or isinstance(sequence, bool)
                    for sequence in incoming_sequences
                ):
                    raise SigmaCoderError("EVENT_SEQUENCE_GAP", "追加事件缺少合法 sequence。")
                first_sequence = min(cast(list[int], incoming_sequences))
                expected_sequence = int(rows[-1]["sequence"]) + 1
                if first_sequence < expected_sequence:
                    raise SigmaCoderError("STORE_BUSY", "Task 已由并发写者推进，请重新读取。")
                if first_sequence > expected_sequence:
                    raise SigmaCoderError("EVENT_SEQUENCE_GAP", "追加事件起点不连续。")
                restored = _validated_write(
                    task_id,
                    existing,
                    events,
                    projection,
                    checkpoint,
                )
                for event in events:
                    self._insert_event(connection, event)
                self._write_derived(
                    connection,
                    task_id,
                    restored.projection,
                    restored.checkpoint,
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise SigmaCoderError("STORE_UNAVAILABLE", "事件事务违反 SQLite 约束。") from error
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)

    @staticmethod
    def _assert_event_ids_available(
        connection: sqlite3.Connection,
        events: Sequence[Mapping[str, object]],
    ) -> None:
        for event in events:
            event_id = event.get("event_id")
            if not isinstance(event_id, str):
                raise SigmaCoderError("EVENT_PAYLOAD_INVALID", "事件缺少合法 event_id。")
            exists = connection.execute(
                "SELECT 1 FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if exists is not None:
                raise SigmaCoderError("EVENT_ID_DUPLICATE", "event_id 已存在。")

    def replace_derived(
        self,
        task_id: str,
        projection: object,
        checkpoint: object,
        *,
        expected_sequence: int,
        expected_event_hash: str,
    ) -> None:
        """事件链有效时原子重建可删除的派生数据。"""

        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY sequence",
                    (task_id,),
                ).fetchall()
                if not rows:
                    raise SigmaCoderError("TASK_NOT_FOUND", "Task 不存在。")
                tail = rows[-1]
                if (
                    int(tail["sequence"]) != expected_sequence
                    or str(tail["event_hash"]) != expected_event_hash
                ):
                    raise SigmaCoderError("STORE_BUSY", "Task 已由并发写者推进，请重新读取。")
                existing = [self._event_from_row(row) for row in rows]
                restored = _validated_write(
                    task_id,
                    (),
                    existing,
                    projection,
                    checkpoint,
                )
                self._write_derived(
                    connection,
                    task_id,
                    restored.projection,
                    restored.checkpoint,
                )
                connection.commit()
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)

    def task_ids(self) -> list[str]:
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT task_id FROM task_registry ORDER BY task_id"
                ).fetchall()
            return [str(row["task_id"]) for row in rows]
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)

    def workspace_relative_path(self, task_id: str) -> str:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT workspace_relative_path FROM task_registry WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)
        if row is None:
            raise SigmaCoderError("TASK_NOT_FOUND", "Task 不存在。")
        return str(row["workspace_relative_path"])

    def load_events(self, task_id: str) -> list[dict[str, object]]:
        try:
            with self._connection() as connection:
                exists = connection.execute(
                    "SELECT 1 FROM task_registry WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
                if exists is None:
                    raise SigmaCoderError("TASK_NOT_FOUND", "Task 不存在。")
                rows = connection.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY sequence",
                    (task_id,),
                ).fetchall()
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)
        return [self._event_from_row(row) for row in rows]

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> dict[str, object]:
        try:
            sequence = int(row["sequence"])
            payload = SQLiteEventStore._decode_json(row["payload"])
            return {
                "event_id": str(row["event_id"]),
                "task_id": str(row["task_id"]),
                "sequence": sequence,
                "event_type": str(row["event_type"]),
                "schema_version": int(row["schema_version"]),
                "occurred_at": str(row["occurred_at"]),
                "actor": str(row["actor"]),
                "correlation_id": str(row["correlation_id"]),
                "causation_id": row["causation_id"],
                "workspace_revision": row["workspace_revision"],
                "sensitivity": str(row["sensitivity"]),
                "payload": payload,
                "previous_hash": str(row["previous_hash"]),
                "event_hash": str(row["event_hash"]),
            }
        except (IndexError, KeyError, TypeError, ValueError, UnicodeError) as error:
            raw_sequence = row["sequence"] if "sequence" in row.keys() else None
            located = raw_sequence if isinstance(raw_sequence, int) else None
            raise SigmaCoderError(
                "EVENT_PAYLOAD_INVALID",
                "SQLite 中的权威事件行无法解码。",
                details={"first_invalid_sequence": located},
            ) from error

    @staticmethod
    def _decode_json(value: object) -> object:
        if isinstance(value, bytes):
            text = value.decode("utf-8")
        elif isinstance(value, str):
            text = value
        else:
            raise TypeError("JSON 列不是文本或 UTF-8 bytes。")
        return json.loads(text)

    def load_checkpoint(self, task_id: str) -> dict[str, object] | None:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT checkpoint FROM checkpoints WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
        except sqlite3.DatabaseError as error:
            self._raise_database_error(error)
        if row is None:
            return None
        try:
            value = self._decode_json(row["checkpoint"])
        except (TypeError, ValueError, UnicodeError):
            return None
        return dict(value) if isinstance(value, dict) else None
