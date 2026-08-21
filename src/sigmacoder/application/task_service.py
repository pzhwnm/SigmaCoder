"""T01 持久 Coding Task 应用服务。"""

from __future__ import annotations

import hashlib
import secrets
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from sigmacoder.adapters.git_workspace import (
    GitWorkspaceAdapter,
)
from sigmacoder.adapters.sqlite_event_store import SQLiteEventStore
from sigmacoder.domain.events import (
    BOOTSTRAP_POLICY_ID,
    ZERO_HASH,
    DomainValidationError,
    ProjectionRestoreResult,
    calculate_event_hash,
    canonical_json_bytes,
    restore_task_projection,
)
from sigmacoder.domain.tasks import evaluate_workspace_adoption
from sigmacoder.errors import SigmaCoderError, error_code
from sigmacoder.ports.event_store import EventStore
from sigmacoder.ports.workspace import (
    RepositoryInspection,
    WorkspaceError,
    WorkspaceObservation,
    WorkspacePort,
)

type JsonObject = dict[str, Any]


@dataclass(frozen=True)
class TaskOutcome:
    """一个可信 TaskView 及其可选退化错误。"""

    task: JsonObject
    error_code: str | None = None


@dataclass(frozen=True)
class TaskListOutcome:
    """逐 Task 验证后的列表。"""

    items: list[JsonObject]
    invalid_items: list[JsonObject]


_INPUT_GIT_CODES = {
    "INVALID_PATH": "INVALID_GIT_REPOSITORY",
    "INVALID_REPOSITORY": "INVALID_GIT_REPOSITORY",
    "GIT_UNAVAILABLE": "INVALID_GIT_REPOSITORY",
    "UNSUPPORTED_GIT_OBJECT_FORMAT": "INVALID_GIT_REPOSITORY",
    "REPOSITORY_UNBORN": "UNBORN_REPOSITORY",
    "INVALID_BASELINE": "INVALID_BASELINE",
    "BASELINE_NOT_COMMIT": "INVALID_BASELINE",
    "UNSAFE_GIT_CHECKOUT_CONFIG": "UNSAFE_GIT_CHECKOUT_CONFIG",
    "INVALID_DATA_ROOT": "PATH_OUTSIDE_ALLOWED_ROOT",
}


def _mapping(value: object, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SigmaCoderError("INTERNAL_ERROR", f"{name} 不是对象。")
    return dict(value)


def _normalized_objective(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not normalized.strip() or len(normalized) > 4096:
        raise SigmaCoderError(
            "INVALID_ARGUMENT",
            "objective 必须是 NFC 后 1 至 4096 个字符的非空文本。",
        )
    return normalized


def _occurred_at() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _action_digest(
    *,
    task_id: str,
    git_common_dir_identity: str,
    baseline_commit: str,
    workspace_relative_path: str,
    ownership_nonce: str,
) -> str:
    material = {
        "task_id": task_id,
        "git_common_dir_identity": git_common_dir_identity,
        "baseline_commit": baseline_commit,
        "workspace_relative_path": workspace_relative_path,
        "ownership_nonce": ownership_nonce,
        "mode": "DETACHED",
        "bootstrap_policy_id": BOOTSTRAP_POLICY_ID,
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _event(
    *,
    task_id: str,
    sequence: int,
    event_type: str,
    correlation_id: str,
    payload: Mapping[str, object],
    previous: Mapping[str, object] | None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "event_id": str(uuid4()),
        "task_id": task_id,
        "sequence": sequence,
        "event_type": event_type,
        "schema_version": 1,
        "occurred_at": _occurred_at(),
        "actor": "local_user",
        "correlation_id": correlation_id,
        "causation_id": previous["event_id"] if previous is not None else None,
        "workspace_revision": None,
        "sensitivity": "INTERNAL",
        "payload": dict(payload),
        "previous_hash": previous["event_hash"] if previous is not None else ZERO_HASH,
    }
    value["event_hash"] = calculate_event_hash(value)
    return value


def _initial_events(
    *,
    task_id: str,
    correlation_id: str,
    objective: str,
    repository: RepositoryInspection,
    workspace_relative_path: str,
    ownership_nonce: str,
    action_digest: str,
) -> list[dict[str, object]]:
    created = _event(
        task_id=task_id,
        sequence=1,
        event_type="TaskCreatedV1",
        correlation_id=correlation_id,
        previous=None,
        payload={
            "objective": objective,
            "repository_realpath": str(repository.repository_realpath),
            "git_common_dir_realpath": str(repository.git_common_dir_realpath),
            "object_format": repository.object_format,
            "baseline_commit": repository.baseline_commit,
            "source_dirty": repository.source_dirty,
            "dirty_content_included": False,
        },
    )
    preparation = _event(
        task_id=task_id,
        sequence=2,
        event_type="TaskPreparationStartedV1",
        correlation_id=correlation_id,
        previous=created,
        payload={
            "workspace_relative_path": workspace_relative_path,
            "ownership_nonce": ownership_nonce,
            "proposed_action_digest": action_digest,
        },
    )
    authorization = _event(
        task_id=task_id,
        sequence=3,
        event_type="WorkspaceProvisioningAuthorizedV1",
        correlation_id=correlation_id,
        previous=preparation,
        payload={
            "bootstrap_policy_id": BOOTSTRAP_POLICY_ID,
            "decision": "AUTO_ALLOWED",
            "workspace_relative_path": workspace_relative_path,
            "ownership_nonce": ownership_nonce,
            "action_digest": action_digest,
            "mode": "DETACHED",
            "baseline_commit": repository.baseline_commit,
        },
    )
    return [created, preparation, authorization]


class TaskService:
    """协调事件权威与 Git linked-worktree，但不恢复任何运行态。"""

    def __init__(self, data_root: str | Path) -> None:
        self.data_root = Path(data_root).expanduser().resolve(strict=False)
        self.store: EventStore = SQLiteEventStore(self.data_root)
        self._hooks: tempfile.TemporaryDirectory[str] | None = None
        self._git: WorkspacePort | None = None

    def __enter__(self) -> TaskService:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._hooks is not None:
            self._hooks.cleanup()
            self._hooks = None
            self._git = None

    @property
    def git(self) -> WorkspacePort:
        if self._git is None:
            self._hooks = tempfile.TemporaryDirectory(prefix="sigmacoder-empty-hooks-")
            self._git = GitWorkspaceAdapter(self._hooks.name)
        return self._git

    def start_task(
        self,
        *,
        repository: str | Path,
        baseline: str,
        objective: str,
        acknowledge_excluded_changes: bool,
    ) -> TaskOutcome:
        normalized_objective = _normalized_objective(objective)
        inspection = self._inspect_start_repository(repository, baseline)
        validated_root = self._validate_start_root(inspection)
        self.data_root = validated_root
        self.store = SQLiteEventStore(validated_root)
        if inspection.source_dirty and not acknowledge_excluded_changes:
            raise SigmaCoderError(
                "DIRTY_SOURCE_REQUIRES_ACK",
                "源 worktree 含有未提交变化，必须明确确认这些变化不会进入 Task。",
            )
        self.store.initialize()
        return self._create_authorized_task(inspection, normalized_objective)

    def _inspect_start_repository(
        self,
        repository: str | Path,
        baseline: str,
    ) -> RepositoryInspection:
        try:
            return self.git.inspect_repository(repository, baseline)
        except WorkspaceError as error:
            code = _INPUT_GIT_CODES.get(error.code, "INVALID_GIT_REPOSITORY")
            raise SigmaCoderError(
                code,
                str(error),
                details={"adapter_code": error.code},
            ) from error

    def _validate_start_root(self, repository: RepositoryInspection) -> Path:
        try:
            return self.git.validate_data_root(self.data_root, repository)
        except WorkspaceError as error:
            code = _INPUT_GIT_CODES.get(error.code, "PATH_OUTSIDE_ALLOWED_ROOT")
            raise SigmaCoderError(
                code,
                str(error),
                details={"adapter_code": error.code},
            ) from error

    def _create_authorized_task(
        self,
        repository: RepositoryInspection,
        objective: str,
    ) -> TaskOutcome:
        task_id = str(uuid4())
        correlation_id = str(uuid4())
        ownership_nonce = secrets.token_hex(16)
        workspace_relative_path = f"tasks/{task_id}/workspace-{ownership_nonce}"
        digest = _action_digest(
            task_id=task_id,
            git_common_dir_identity=str(repository.git_common_dir_realpath),
            baseline_commit=repository.baseline_commit,
            workspace_relative_path=workspace_relative_path,
            ownership_nonce=ownership_nonce,
        )
        events = _initial_events(
            task_id=task_id,
            correlation_id=correlation_id,
            objective=objective,
            repository=repository,
            workspace_relative_path=workspace_relative_path,
            ownership_nonce=ownership_nonce,
            action_digest=digest,
        )
        restored = restore_task_projection(events)
        self.store.create_task(
            task_id,
            workspace_relative_path,
            events,
            restored.projection,
            restored.checkpoint,
        )
        return self._provision_workspace(repository, events, restored)

    def _provision_workspace(
        self,
        repository: RepositoryInspection,
        events: list[dict[str, object]],
        restored: ProjectionRestoreResult,
    ) -> TaskOutcome:
        projection = restored.projection
        workspace = _mapping(projection["workspace"], name="workspace 投影")
        relative_path = cast(str, workspace["relative_path"])
        nonce = cast(str, workspace["ownership_nonce"])
        digest = cast(str, workspace["action_digest"])
        try:
            created_path = self.git.create_detached_worktree(
                repository,
                data_root=self.data_root,
                workspace_relative_path=relative_path,
                ownership_nonce=nonce,
                expected_action_digest=digest,
                recomputed_action_digest=self._recomputed_digest(projection),
            )
            observation = self.git.observe_workspace(
                repository,
                data_root=self.data_root,
                workspace_relative_path=relative_path,
                ownership_nonce=nonce,
                expected_action_digest=digest,
                recomputed_action_digest=self._recomputed_digest(projection),
            )
            self._require_adoptable(projection, created_path, observation)
        except WorkspaceError as error:
            return self._record_preparation_failure(events, projection, error, "WORKTREE_CREATE")
        return self._record_prepared(events, observation, recovered=False, load_mode="CREATED")

    def _require_adoptable(
        self,
        projection: Mapping[str, object],
        workspace_path: Path,
        observation: WorkspaceObservation,
    ) -> None:
        authorization = self._adoption_authorization(
            projection,
            workspace_path,
            observation,
        )
        decision = evaluate_workspace_adoption(
            authorization,
            observation.as_adoption_mapping(),
        )
        if not decision.adopted or observation.git_pointer_digest is None:
            raise WorkspaceError(
                "WORKSPACE_EVIDENCE_MISMATCH",
                "workspace 七项证据不完整，拒绝采纳。",
                details={"failed_evidence": decision.failed_evidence},
            )

    def _adoption_authorization(
        self,
        projection: Mapping[str, object],
        workspace_path: Path,
        observation: WorkspaceObservation,
    ) -> dict[str, object]:
        baseline = _mapping(projection["baseline"], name="baseline 投影")
        workspace = _mapping(projection["workspace"], name="workspace 投影")
        git_admin = observation.git_admin_realpath
        if git_admin is None:
            git_admin = str(Path(cast(str, baseline["git_common_dir_realpath"])) / "worktrees")
        return {
            "data_root": str(self.data_root),
            "workspace_realpath": str(workspace_path),
            "workspace_relative_path": workspace["relative_path"],
            "git_admin_realpath": git_admin,
            "baseline_commit": baseline["commit_oid"],
            "ownership_nonce": workspace["ownership_nonce"],
            "action_digest": workspace["action_digest"],
        }

    def _recomputed_digest(self, projection: Mapping[str, object]) -> str:
        baseline = _mapping(projection["baseline"], name="baseline 投影")
        workspace = _mapping(projection["workspace"], name="workspace 投影")
        return _action_digest(
            task_id=cast(str, projection["task_id"]),
            git_common_dir_identity=cast(str, baseline["git_common_dir_realpath"]),
            baseline_commit=cast(str, baseline["commit_oid"]),
            workspace_relative_path=cast(str, workspace["relative_path"]),
            ownership_nonce=cast(str, workspace["ownership_nonce"]),
        )

    def _record_prepared(
        self,
        events: list[dict[str, object]],
        observation: WorkspaceObservation,
        *,
        recovered: bool,
        load_mode: str,
    ) -> TaskOutcome:
        authorization = _mapping(events[2]["payload"], name="授权事件 payload")
        pointer_digest = observation.git_pointer_digest
        if pointer_digest is None or observation.head_oid is None:
            raise SigmaCoderError("CREATION_RECOVERY_REQUIRED", "workspace 证据不完整。")
        prepared = _event(
            task_id=cast(str, events[0]["task_id"]),
            sequence=4,
            event_type="TaskWorkspacePreparedV1",
            correlation_id=cast(str, events[0]["correlation_id"]),
            previous=events[2],
            payload={
                "action_digest": authorization["action_digest"],
                "ownership_nonce": authorization["ownership_nonce"],
                "workspace_relative_path": authorization["workspace_relative_path"],
                "mode": "DETACHED",
                "head_oid": observation.head_oid,
                "git_pointer_digest": pointer_digest,
                "recovered_after_interruption": recovered,
            },
        )
        combined = [*events, prepared]
        result = restore_task_projection(combined)
        self.store.append_events(
            cast(str, events[0]["task_id"]),
            [prepared],
            result.projection,
            result.checkpoint,
        )
        return TaskOutcome(self._task_view(result, load_mode=load_mode))

    def _record_preparation_failure(
        self,
        events: list[dict[str, object]],
        projection: Mapping[str, object],
        error: BaseException,
        stage: str,
        *,
        force_uncertain: bool = False,
    ) -> TaskOutcome:
        workspace = _mapping(projection["workspace"], name="workspace 投影")
        path = self.data_root / cast(str, workspace["relative_path"])
        uncertain = force_uncertain or path.exists() or path.is_symlink()
        resource_state = "UNVERIFIED" if uncertain else "NOT_CREATED"
        public_code = "CREATION_RECOVERY_REQUIRED" if uncertain else "TASK_PREPARATION_FAILED"
        adapter_code = getattr(error, "code", error_code(error))
        failure = _event(
            task_id=cast(str, events[0]["task_id"]),
            sequence=4,
            event_type="TaskWorkspaceProvisioningFailedV1",
            correlation_id=cast(str, events[0]["correlation_id"]),
            previous=events[2],
            payload={
                "action_digest": workspace["action_digest"],
                "failure_stage": stage,
                "error_code": adapter_code,
                "resource_state": resource_state,
                "diagnostic": str(error).replace("\x00", "�")[-2000:],
            },
        )
        reason = (
            "WORKSPACE_PROVISIONING_UNCERTAIN" if uncertain else "WORKSPACE_PROVISIONING_FAILED"
        )
        attention = _event(
            task_id=cast(str, events[0]["task_id"]),
            sequence=5,
            event_type="TaskAttentionRequiredV1",
            correlation_id=cast(str, events[0]["correlation_id"]),
            previous=failure,
            payload={"reason": reason},
        )
        combined = [*events, failure, attention]
        result = restore_task_projection(combined)
        self.store.append_events(
            cast(str, events[0]["task_id"]),
            [failure, attention],
            result.projection,
            result.checkpoint,
        )
        return TaskOutcome(
            self._task_view(result, load_mode="CREATED"),
            error_code=public_code,
        )

    def status(self, task_id: str) -> TaskOutcome:
        self.store.initialize()
        events, restored = self._restore_task(task_id)
        terminal_type = cast(str, events[-1]["event_type"])
        if terminal_type == "WorkspaceProvisioningAuthorizedV1":
            return self._recover_authorized(events, restored)
        if terminal_type == "TaskAttentionRequiredV1":
            availability = cast(
                str,
                _mapping(restored.projection["workspace"], name="workspace 投影")["availability"],
            )
            code = (
                "TASK_PREPARATION_FAILED"
                if availability == "NOT_CREATED"
                else "CREATION_RECOVERY_REQUIRED"
            )
            return TaskOutcome(self._task_view(restored), error_code=code)
        return self._prepared_outcome(restored)

    def _restore_task(
        self,
        task_id: str,
    ) -> tuple[list[dict[str, object]], ProjectionRestoreResult]:
        return self._restore_task_attempt(task_id, retry_on_tail_change=True)

    def _restore_task_attempt(
        self,
        task_id: str,
        *,
        retry_on_tail_change: bool,
    ) -> tuple[list[dict[str, object]], ProjectionRestoreResult]:
        events = self.store.load_events(task_id)
        checkpoint = self.store.load_checkpoint(task_id)
        try:
            result = restore_task_projection(events, checkpoint=checkpoint)
        except DomainValidationError as error:
            code = error_code(error)
            raise SigmaCoderError(
                code,
                str(error),
                details={
                    "first_invalid_sequence": self._first_invalid_sequence(events),
                },
            ) from error
        if result.load_mode == "FULL_REPLAY":
            try:
                self.store.replace_derived(
                    task_id,
                    result.projection,
                    result.checkpoint,
                    expected_sequence=result.through_sequence,
                    expected_event_hash=result.through_event_hash,
                )
            except SigmaCoderError as error:
                if error.code == "STORE_BUSY" and retry_on_tail_change:
                    return self._restore_task_attempt(
                        task_id,
                        retry_on_tail_change=False,
                    )
                raise
        return events, result

    @staticmethod
    def _first_invalid_sequence(events: Sequence[Mapping[str, object]]) -> int | None:
        sequences: list[int] = []
        for event in events:
            value = event.get("sequence")
            if isinstance(value, int) and not isinstance(value, bool):
                sequences.append(value)
        sequences.sort()
        for expected, actual in enumerate(sequences, start=1):
            if actual != expected:
                return expected
        ordered = sorted(
            events,
            key=lambda event: cast(int, event.get("sequence", 0)),
        )
        for index in range(1, len(ordered) + 1):
            try:
                restore_task_projection(ordered[:index])
            except DomainValidationError:
                sequence = ordered[index - 1].get("sequence")
                return sequence if isinstance(sequence, int) else index
        return None

    def _recover_authorized(
        self,
        events: list[dict[str, object]],
        restored: ProjectionRestoreResult,
    ) -> TaskOutcome:
        projection = restored.projection
        try:
            repository = self._repository_from_projection(projection)
            workspace = _mapping(projection["workspace"], name="workspace 投影")
            relative = cast(str, workspace["relative_path"])
            nonce = cast(str, workspace["ownership_nonce"])
            digest = cast(str, workspace["action_digest"])
            observation = self.git.observe_workspace(
                repository,
                data_root=self.data_root,
                workspace_relative_path=relative,
                ownership_nonce=nonce,
                expected_action_digest=digest,
                recomputed_action_digest=self._recomputed_digest(projection),
            )
            path = self.data_root / relative
            self._require_adoptable(projection, path.resolve(strict=False), observation)
        except (WorkspaceError, SigmaCoderError) as error:
            return self._record_preparation_failure(
                events,
                projection,
                error,
                "RECOVERY",
                force_uncertain=True,
            )
        try:
            return self._record_prepared(
                events,
                observation,
                recovered=True,
                load_mode="FULL_REPLAY",
            )
        except SigmaCoderError as error:
            if error.code != "STORE_BUSY":
                raise
            refreshed_events, refreshed = self._restore_task_attempt(
                cast(str, events[0]["task_id"]),
                retry_on_tail_change=False,
            )
            if refreshed_events[-1]["event_type"] == "TaskWorkspacePreparedV1":
                return self._prepared_outcome(refreshed)
            if refreshed_events[-1]["event_type"] == "TaskAttentionRequiredV1":
                availability = cast(
                    str,
                    _mapping(refreshed.projection["workspace"], name="workspace 投影")[
                        "availability"
                    ],
                )
                code = (
                    "TASK_PREPARATION_FAILED"
                    if availability == "NOT_CREATED"
                    else "CREATION_RECOVERY_REQUIRED"
                )
                return TaskOutcome(self._task_view(refreshed), error_code=code)
            raise

    def _repository_from_projection(
        self,
        projection: Mapping[str, object],
    ) -> RepositoryInspection:
        baseline = _mapping(projection["baseline"], name="baseline 投影")
        try:
            current = self.git.inspect_repository(
                cast(str, baseline["repository_realpath"]),
                cast(str, baseline["commit_oid"]),
            )
        except WorkspaceError as error:
            raise SigmaCoderError(
                "CREATION_RECOVERY_REQUIRED",
                "无法核验 Task 的 Git 权威来源。",
                details={"adapter_code": error.code},
            ) from error
        expected = (
            Path(cast(str, baseline["repository_realpath"])).resolve(strict=False),
            Path(cast(str, baseline["git_common_dir_realpath"])).resolve(strict=False),
            baseline["object_format"],
            baseline["commit_oid"],
        )
        actual = (
            current.repository_realpath,
            current.git_common_dir_realpath,
            current.object_format,
            current.baseline_commit,
        )
        if actual != expected:
            raise SigmaCoderError(
                "CREATION_RECOVERY_REQUIRED",
                "Git 权威来源与已提交 Task 事实不一致。",
            )
        return current

    def _prepared_outcome(self, restored: ProjectionRestoreResult) -> TaskOutcome:
        projection = restored.projection
        try:
            repository = self._repository_from_projection(projection)
            workspace = _mapping(projection["workspace"], name="workspace 投影")
            status = self.git.inspect_prepared_workspace(
                repository,
                data_root=self.data_root,
                workspace_relative_path=cast(str, workspace["relative_path"]),
                ownership_nonce=cast(str, workspace["ownership_nonce"]),
                expected_action_digest=cast(str, workspace["action_digest"]),
                recomputed_action_digest=self._recomputed_digest(projection),
                expected_git_pointer_digest=cast(str, workspace["git_pointer_digest"]),
            )
        except (WorkspaceError, SigmaCoderError):
            return TaskOutcome(
                self._task_view(restored, availability="UNVERIFIED", head_oid=None),
                error_code="CREATION_RECOVERY_REQUIRED",
            )
        availability = str(status.availability)
        if availability == "AVAILABLE":
            return TaskOutcome(self._task_view(restored))
        if availability == "MISSING":
            return TaskOutcome(
                self._task_view(restored, availability=availability, head_oid=None),
                error_code="WORKSPACE_UNAVAILABLE",
            )
        if availability == "BASELINE_MISMATCH":
            return TaskOutcome(
                self._task_view(
                    restored,
                    availability=availability,
                    head_oid=status.head_oid,
                ),
                error_code="WORKSPACE_BASELINE_MISMATCH",
            )
        return TaskOutcome(
            self._task_view(restored, availability="UNVERIFIED", head_oid=None),
            error_code="CREATION_RECOVERY_REQUIRED",
        )

    def _task_view(
        self,
        restored: ProjectionRestoreResult,
        *,
        load_mode: str | None = None,
        availability: str | None = None,
        head_oid: str | None = None,
    ) -> JsonObject:
        projection = restored.projection
        baseline = _mapping(projection["baseline"], name="baseline 投影")
        workspace = _mapping(projection["workspace"], name="workspace 投影")
        preparation = _mapping(projection["preparation"], name="preparation 投影")
        selected_availability = availability or cast(str, workspace["availability"])
        selected_head = workspace["head_oid"] if availability is None else head_oid
        lifecycle = cast(str, projection["lifecycle_state"])
        health = cast(str, projection["health"])
        workspace_state = cast(str, preparation["workspace"])
        if selected_availability != "AVAILABLE":
            lifecycle = "NEEDS_ATTENTION"
            health = "NEEDS_ATTENTION"
            workspace_state = self._degraded_workspace_state(
                selected_availability,
                workspace_state,
            )
        relative = cast(str, workspace["relative_path"])
        return {
            "task_id": projection["task_id"],
            "objective": projection["objective"],
            "lifecycle_state": lifecycle,
            "health": health,
            "baseline": baseline,
            "workspace": {
                "kind": workspace["kind"],
                "mode": workspace["mode"],
                "path": str((self.data_root / relative).resolve(strict=False)),
                "head_oid": selected_head,
                "availability": selected_availability,
            },
            "preparation": {
                "workspace": workspace_state,
                "event_store": preparation["event_store"],
                "sandbox": preparation["sandbox"],
                "agent_run": preparation["agent_run"],
            },
            "event_position": {
                "sequence": restored.through_sequence,
                "event_hash": restored.through_event_hash,
            },
            "checkpoint": {
                "through_sequence": restored.through_sequence,
                "through_event_hash": restored.through_event_hash,
                "load_mode": load_mode or restored.load_mode,
            },
            "runtime": dict(cast(Mapping[str, object], projection["runtime"])),
        }

    @staticmethod
    def _degraded_workspace_state(availability: str, historical: str) -> str:
        if availability == "NOT_CREATED":
            return "FAILED"
        if availability == "UNVERIFIED":
            return "RECOVERY_REQUIRED"
        return historical

    def list_tasks(self) -> TaskListOutcome:
        self.store.initialize()
        items: list[JsonObject] = []
        invalid_items: list[JsonObject] = []
        for task_id in self.store.task_ids():
            try:
                outcome = self.status(task_id)
            except SigmaCoderError as error:
                if error.exit_code != 4:
                    raise
                invalid_items.append(
                    {
                        "task_id": task_id,
                        "error_code": error.code,
                        "first_invalid_sequence": error.details.get("first_invalid_sequence"),
                    }
                )
            else:
                items.append(outcome.task)
        return TaskListOutcome(items=items, invalid_items=invalid_items)
