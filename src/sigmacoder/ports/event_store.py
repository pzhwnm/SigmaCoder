"""事件权威的应用端口。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol


class EventStore(Protocol):
    """应用服务所需的最小只增事件端口。"""

    def initialize(self) -> None: ...

    def create_task(
        self,
        task_id: str,
        workspace_relative_path: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None: ...

    def append_events(
        self,
        task_id: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None: ...

    def replace_derived(
        self,
        task_id: str,
        projection: object,
        checkpoint: object,
        *,
        expected_sequence: int,
        expected_event_hash: str,
    ) -> None: ...

    def task_ids(self) -> list[str]: ...

    def workspace_relative_path(self, task_id: str) -> str: ...

    def load_events(self, task_id: str) -> list[dict[str, object]]: ...

    def load_checkpoint(self, task_id: str) -> dict[str, object] | None: ...
