"""TaskService 恢复、竞争与退化状态的分支契约测试。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path, PureWindowsPath
from typing import cast

import pytest
from tests.support.event_contract import (
    BASELINE_OID,
    CORRELATION_ID,
    GIT_COMMON_DIR,
    OWNERSHIP_NONCE,
    TASK_ID,
    WORKSPACE_RELATIVE_PATH,
    authorization_events,
    failed_events,
    rehash_chain,
)

from sigmacoder.application.task_service import (
    TaskOutcome,
    TaskService,
    _event,
    _mapping,
    _normalized_objective,
)
from sigmacoder.domain.events import ProjectionRestoreResult, restore_task_projection
from sigmacoder.errors import SigmaCoderError
from sigmacoder.ports.event_store import EventStore
from sigmacoder.ports.workspace import (
    PreparedWorkspaceStatus,
    RepositoryInspection,
    SourceWorktreeFingerprint,
    WorkspaceAvailability,
    WorkspaceError,
    WorkspaceObservation,
    WorkspacePort,
)


class _StoreStub:
    """可注入 CAS 结果的最小事件存储替身。"""

    def __init__(
        self,
        events: Sequence[Mapping[str, object]] = (),
        checkpoint: Mapping[str, object] | None = None,
    ) -> None:
        self.events = [dict(event) for event in events]
        self.checkpoint = dict(checkpoint) if checkpoint is not None else None
        self.replace_errors: list[SigmaCoderError] = []
        self.replace_calls = 0
        self.appended: list[dict[str, object]] = []

    def initialize(self) -> None:
        return None

    def create_task(
        self,
        task_id: str,
        workspace_relative_path: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None:
        del task_id, workspace_relative_path, projection, checkpoint
        self.events = [dict(event) for event in events]

    def append_events(
        self,
        task_id: str,
        events: Sequence[Mapping[str, object]],
        projection: object,
        checkpoint: object,
    ) -> None:
        del task_id, projection, checkpoint
        values = [dict(event) for event in events]
        self.appended.extend(values)
        self.events.extend(values)

    def replace_derived(
        self,
        task_id: str,
        projection: object,
        checkpoint: object,
        *,
        expected_sequence: int,
        expected_event_hash: str,
    ) -> None:
        del task_id, projection, checkpoint, expected_sequence, expected_event_hash
        self.replace_calls += 1
        if self.replace_errors:
            raise self.replace_errors.pop(0)

    def task_ids(self) -> list[str]:
        return [TASK_ID]

    def workspace_relative_path(self, task_id: str) -> str:
        del task_id
        return WORKSPACE_RELATIVE_PATH

    def load_events(self, task_id: str) -> list[dict[str, object]]:
        del task_id
        return [dict(event) for event in self.events]

    def load_checkpoint(self, task_id: str) -> dict[str, object] | None:
        del task_id
        return dict(self.checkpoint) if self.checkpoint is not None else None


class _WorkspaceStub:
    """覆盖应用端口全部分支的确定性 workspace 替身。"""

    def __init__(self, repository: RepositoryInspection) -> None:
        self.repository = repository
        self.inspect_error: WorkspaceError | None = None
        self.validate_error: WorkspaceError | None = None
        self.create_error: WorkspaceError | None = None
        self.observe_error: WorkspaceError | None = None
        self.observation: WorkspaceObservation | None = None
        self.prepared_status: PreparedWorkspaceStatus | None = None
        self.prepared_error: WorkspaceError | None = None

    def inspect_repository(
        self,
        repository: str | Path,
        baseline: str,
    ) -> RepositoryInspection:
        del repository, baseline
        if self.inspect_error is not None:
            raise self.inspect_error
        return self.repository

    def validate_data_root(
        self,
        data_root: str | Path,
        repository: RepositoryInspection,
        *,
        existing_workspaces: tuple[str | Path, ...] = (),
    ) -> Path:
        del repository, existing_workspaces
        if self.validate_error is not None:
            raise self.validate_error
        return Path(data_root).resolve(strict=False)

    def create_detached_worktree(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> Path:
        del repository, ownership_nonce, expected_action_digest, recomputed_action_digest
        if self.create_error is not None:
            raise self.create_error
        return Path(data_root) / workspace_relative_path

    def observe_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
    ) -> WorkspaceObservation:
        del (
            repository,
            data_root,
            workspace_relative_path,
            ownership_nonce,
            expected_action_digest,
            recomputed_action_digest,
        )
        if self.observe_error is not None:
            raise self.observe_error
        assert self.observation is not None
        return self.observation

    def inspect_prepared_workspace(
        self,
        repository: RepositoryInspection,
        *,
        data_root: str | Path,
        workspace_relative_path: str,
        ownership_nonce: str,
        expected_action_digest: str,
        recomputed_action_digest: str,
        expected_git_pointer_digest: str,
    ) -> PreparedWorkspaceStatus:
        del (
            repository,
            data_root,
            workspace_relative_path,
            ownership_nonce,
            expected_action_digest,
            recomputed_action_digest,
            expected_git_pointer_digest,
        )
        if self.prepared_error is not None:
            raise self.prepared_error
        assert self.prepared_status is not None
        return self.prepared_status


def _repository() -> RepositoryInspection:
    return RepositoryInspection(
        repository_realpath=Path("C:/fixture/repository").resolve(strict=False),
        git_dir_realpath=Path("C:/fixture/repository/.git").resolve(strict=False),
        git_common_dir_realpath=Path(GIT_COMMON_DIR).resolve(strict=False),
        object_format="sha1",
        baseline_commit=BASELINE_OID,
        source_dirty=False,
        source_fingerprint=SourceWorktreeFingerprint(
            entries=(),
            index_size=0,
            index_sha256="0" * 64,
            head_oid=BASELINE_OID,
            symbolic_head="refs/heads/main",
            refs="",
            porcelain_v2="",
        ),
    )


def _authorized() -> tuple[list[dict[str, object]], ProjectionRestoreResult]:
    events = authorization_events()
    return events, restore_task_projection(events)


def _prepared() -> tuple[list[dict[str, object]], ProjectionRestoreResult]:
    events, restored = _authorized()
    workspace = cast(Mapping[str, object], restored.projection["workspace"])
    prepared = _event(
        task_id=TASK_ID,
        sequence=4,
        event_type="TaskWorkspacePreparedV1",
        correlation_id=CORRELATION_ID,
        previous=events[-1],
        payload={
            "action_digest": workspace["action_digest"],
            "ownership_nonce": OWNERSHIP_NONCE,
            "workspace_relative_path": WORKSPACE_RELATIVE_PATH,
            "mode": "DETACHED",
            "head_oid": BASELINE_OID,
            "git_pointer_digest": "f" * 64,
            "recovered_after_interruption": True,
        },
    )
    combined = [*events, prepared]
    return combined, restore_task_projection(combined)


def _attention(
    availability: str,
) -> tuple[list[dict[str, object]], ProjectionRestoreResult]:
    events, restored = _authorized()
    workspace = cast(Mapping[str, object], restored.projection["workspace"])
    failure = _event(
        task_id=TASK_ID,
        sequence=4,
        event_type="TaskWorkspaceProvisioningFailedV1",
        correlation_id=CORRELATION_ID,
        previous=events[-1],
        payload={
            "action_digest": workspace["action_digest"],
            "failure_stage": "RECOVERY",
            "error_code": "WORKSPACE_EVIDENCE_MISMATCH",
            "resource_state": availability,
            "diagnostic": "fixture",
        },
    )
    reason = (
        "WORKSPACE_PROVISIONING_FAILED"
        if availability == "NOT_CREATED"
        else "WORKSPACE_PROVISIONING_UNCERTAIN"
    )
    attention = _event(
        task_id=TASK_ID,
        sequence=5,
        event_type="TaskAttentionRequiredV1",
        correlation_id=CORRELATION_ID,
        previous=failure,
        payload={"reason": reason},
    )
    combined = [*events, failure, attention]
    return combined, restore_task_projection(combined)


def _observation(
    data_root: Path,
    restored: ProjectionRestoreResult,
    *,
    pointer_digest: str | None = "f" * 64,
) -> WorkspaceObservation:
    workspace = cast(Mapping[str, object], restored.projection["workspace"])
    relative = cast(str, workspace["relative_path"])
    return WorkspaceObservation(
        workspace_realpath=str((data_root / relative).resolve(strict=False)),
        workspace_exists=True,
        within_data_root=True,
        relative_path_matches=True,
        git_admin_realpath=str(Path(GIT_COMMON_DIR).resolve(strict=False) / "worktrees"),
        git_admin_points_to_workspace=True,
        workspace_git_points_to_admin=True,
        common_dir_matches=True,
        head_detached=True,
        head_oid=BASELINE_OID,
        index_and_tracked_clean=True,
        no_extra_files=True,
        ownership_nonce=OWNERSHIP_NONCE,
        action_digest=cast(str, workspace["action_digest"]),
        git_pointer_digest=pointer_digest,
        problems=(),
    )


def _service(tmp_path: Path) -> tuple[TaskService, _StoreStub, _WorkspaceStub]:
    service = TaskService(tmp_path)
    store = _StoreStub()
    workspace = _WorkspaceStub(_repository())
    service.store = cast(EventStore, store)
    service._git = cast(WorkspacePort, workspace)
    return service, store, workspace


def test_mapping_and_objective_validation_fail_closed() -> None:
    with pytest.raises(SigmaCoderError, match="不是对象"):
        _mapping([], name="fixture")
    with pytest.raises(SigmaCoderError, match="objective"):
        _normalized_objective(" \n")
    with pytest.raises(SigmaCoderError, match="objective"):
        _normalized_objective("x" * 4097)


@pytest.mark.parametrize(
    ("adapter_code", "public_code"),
    [
        ("REPOSITORY_UNBORN", "UNBORN_REPOSITORY"),
        ("PRIVATE_GIT_FAILURE", "INVALID_GIT_REPOSITORY"),
    ],
)
def test_repository_inspection_maps_adapter_errors(
    tmp_path: Path,
    adapter_code: str,
    public_code: str,
) -> None:
    service, _, workspace = _service(tmp_path)
    workspace.inspect_error = WorkspaceError(adapter_code, "拒绝仓库")

    with pytest.raises(SigmaCoderError) as raised:
        service._inspect_start_repository("repo", "HEAD")
    assert raised.value.code == public_code
    assert raised.value.details == {"adapter_code": adapter_code}


@pytest.mark.parametrize(
    ("adapter_code", "public_code"),
    [
        ("INVALID_DATA_ROOT", "PATH_OUTSIDE_ALLOWED_ROOT"),
        ("PRIVATE_ROOT_FAILURE", "PATH_OUTSIDE_ALLOWED_ROOT"),
    ],
)
def test_data_root_validation_maps_adapter_errors(
    tmp_path: Path,
    adapter_code: str,
    public_code: str,
) -> None:
    service, _, workspace = _service(tmp_path)
    workspace.validate_error = WorkspaceError(adapter_code, "拒绝 data root")

    with pytest.raises(SigmaCoderError) as raised:
        service._validate_start_root(_repository())
    assert raised.value.code == public_code


def test_provision_failure_records_not_created_attention(tmp_path: Path) -> None:
    service, store, workspace = _service(tmp_path)
    events, restored = _authorized()
    workspace.create_error = WorkspaceError("WORKSPACE_CREATE_FAILED", "创建失败\x00详情")

    outcome = service._provision_workspace(_repository(), events, restored)

    assert outcome.error_code == "TASK_PREPARATION_FAILED"
    assert outcome.task["workspace"]["availability"] == "NOT_CREATED"
    assert [event["event_type"] for event in store.appended] == [
        "TaskWorkspaceProvisioningFailedV1",
        "TaskAttentionRequiredV1",
    ]
    assert "\x00" not in cast(
        str, cast(Mapping[str, object], store.appended[0]["payload"])["diagnostic"]
    )


def test_adoption_authorization_falls_back_to_common_worktrees_directory(
    tmp_path: Path,
) -> None:
    service, _, _ = _service(tmp_path)
    _, restored = _authorized()
    observation = replace(_observation(tmp_path, restored), git_admin_realpath=None)

    authorization = service._adoption_authorization(
        restored.projection,
        tmp_path / WORKSPACE_RELATIVE_PATH,
        observation,
    )

    assert PureWindowsPath(cast(str, authorization["git_admin_realpath"])) == (
        PureWindowsPath(GIT_COMMON_DIR) / "worktrees"
    )


def test_require_adoptable_rejects_missing_pointer_digest(tmp_path: Path) -> None:
    service, _, _ = _service(tmp_path)
    _, restored = _authorized()
    observation = _observation(tmp_path, restored, pointer_digest=None)

    with pytest.raises(WorkspaceError) as raised:
        service._require_adoptable(
            restored.projection,
            tmp_path / WORKSPACE_RELATIVE_PATH,
            observation,
        )
    assert raised.value.code == "WORKSPACE_EVIDENCE_MISMATCH"


def test_record_prepared_rejects_incomplete_observation(tmp_path: Path) -> None:
    service, _, _ = _service(tmp_path)
    events, restored = _authorized()
    observation = replace(_observation(tmp_path, restored), head_oid=None)

    with pytest.raises(SigmaCoderError) as raised:
        service._record_prepared(events, observation, recovered=False, load_mode="CREATED")
    assert raised.value.code == "CREATION_RECOVERY_REQUIRED"


@pytest.mark.parametrize(
    ("availability", "expected_code"),
    [
        ("NOT_CREATED", "TASK_PREPARATION_FAILED"),
        ("UNVERIFIED", "CREATION_RECOVERY_REQUIRED"),
    ],
)
def test_status_maps_persisted_attention_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    availability: str,
    expected_code: str,
) -> None:
    service, _, _ = _service(tmp_path)
    events, restored = _attention(availability)
    monkeypatch.setattr(service, "_restore_task", lambda _task_id: (events, restored))

    outcome = service.status(TASK_ID)

    assert outcome.error_code == expected_code


def test_restore_retries_once_when_projection_cas_sees_new_tail(tmp_path: Path) -> None:
    events, _ = _authorized()
    service, store, _ = _service(tmp_path)
    store.events = events
    store.replace_errors = [SigmaCoderError("STORE_BUSY", "尾部变化")]

    restored_events, restored = service._restore_task(TASK_ID)

    assert len(restored_events) == 3
    assert restored.load_mode == "FULL_REPLAY"
    assert store.replace_calls == 2


def test_restore_orders_reversed_port_rows_before_returning(tmp_path: Path) -> None:
    service, store, _ = _service(tmp_path)
    store.events = list(reversed(authorization_events()))

    restored_events, restored = service._restore_task(TASK_ID)

    assert [event["sequence"] for event in restored_events] == [1, 2, 3]
    assert restored.through_sequence == 3


@pytest.mark.parametrize("retry", [False, True])
def test_restore_propagates_non_retryable_or_second_store_busy(
    tmp_path: Path,
    retry: bool,
) -> None:
    events, _ = _authorized()
    service, store, _ = _service(tmp_path)
    store.events = events
    if retry:
        store.replace_errors = [
            SigmaCoderError("STORE_BUSY", "第一次"),
            SigmaCoderError("STORE_BUSY", "第二次"),
        ]
    else:
        store.replace_errors = [SigmaCoderError("STORE_UNAVAILABLE", "不可用")]

    with pytest.raises(SigmaCoderError) as raised:
        service._restore_task_attempt(TASK_ID, retry_on_tail_change=retry)
    assert raised.value.code in {"STORE_BUSY", "STORE_UNAVAILABLE"}


def test_restore_reports_first_gap_for_invalid_authoritative_events(tmp_path: Path) -> None:
    events = authorization_events()
    events = [events[0], events[2]]
    service, store, _ = _service(tmp_path)
    store.events = events

    with pytest.raises(SigmaCoderError) as raised:
        service._restore_task(TASK_ID)

    assert raised.value.exit_code == 4
    assert raised.value.details["first_invalid_sequence"] == 2


def test_first_invalid_sequence_handles_non_integer_and_valid_chains() -> None:
    assert TaskService._first_invalid_sequence([{"sequence": 0}]) == 1
    assert TaskService._first_invalid_sequence([{"sequence": 2}]) == 1
    assert TaskService._first_invalid_sequence([{"sequence": "not-an-int"}]) == 1
    assert (
        TaskService._first_invalid_sequence(
            [{"sequence": 1}, {"sequence": 2}, {"sequence": "not-an-int"}]
        )
        == 3
    )
    assert (
        TaskService._first_invalid_sequence(
            [{"sequence": 1}, {"sequence": 3}, {"sequence": "not-an-int"}]
        )
        == 3
    )
    assert (
        TaskService._first_invalid_sequence([{"sequence": 1}, {"sequence": 2}, {"sequence": False}])
        == 3
    )
    assert (
        TaskService._first_invalid_sequence([{"sequence": 1}, {"sequence": 2}, {"sequence": 2}])
        == 2
    )
    assert TaskService._first_invalid_sequence(authorization_events()[:1]) == 1
    assert TaskService._first_invalid_sequence(authorization_events()[:2]) == 2
    assert TaskService._first_invalid_sequence(authorization_events()) is None
    failed = failed_events(
        authorization_events(),
        failure_event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
        attention_event_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5",
        resource_state="NOT_CREATED",
    )
    assert TaskService._first_invalid_sequence(failed) is None
    invalid_payload = authorization_events()
    invalid_payload[1]["payload"] = {}
    assert TaskService._first_invalid_sequence(rehash_chain(invalid_payload)) == 2


def test_recover_authorized_records_uncertain_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, store, _ = _service(tmp_path)
    events, restored = _authorized()
    monkeypatch.setattr(
        service,
        "_repository_from_projection",
        lambda _projection: (_ for _ in ()).throw(
            SigmaCoderError("CREATION_RECOVERY_REQUIRED", "无法核验")
        ),
    )

    outcome = service._recover_authorized(events, restored)

    assert outcome.error_code == "CREATION_RECOVERY_REQUIRED"
    failure_payload = cast(Mapping[str, object], store.appended[0]["payload"])
    assert failure_payload["resource_state"] == "UNVERIFIED"


@pytest.mark.parametrize(
    ("terminal", "availability", "expected_code"),
    [
        ("prepared", None, None),
        ("attention", "NOT_CREATED", "TASK_PREPARATION_FAILED"),
        ("attention", "UNVERIFIED", "CREATION_RECOVERY_REQUIRED"),
    ],
)
def test_recover_authorized_resolves_store_busy_from_refreshed_tail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    terminal: str,
    availability: str | None,
    expected_code: str | None,
) -> None:
    service, _, workspace = _service(tmp_path)
    events, restored = _authorized()
    workspace.observation = _observation(tmp_path, restored)
    monkeypatch.setattr(service, "_repository_from_projection", lambda _projection: _repository())
    monkeypatch.setattr(
        service,
        "_record_prepared",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SigmaCoderError("STORE_BUSY", "竞态")),
    )
    if terminal == "prepared":
        refreshed_events, refreshed = _prepared()
        monkeypatch.setattr(
            service,
            "_prepared_outcome",
            lambda _restored: TaskOutcome({"task_id": TASK_ID}),
        )
    else:
        assert availability is not None
        refreshed_events, refreshed = _attention(availability)
    monkeypatch.setattr(
        service,
        "_restore_task_attempt",
        lambda _task_id, *, retry_on_tail_change: (refreshed_events, refreshed),
    )

    outcome = service._recover_authorized(events, restored)

    assert outcome.error_code == expected_code


@pytest.mark.parametrize("code", ["STORE_UNAVAILABLE", "STORE_BUSY"])
def test_recover_authorized_propagates_unresolved_append_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: str,
) -> None:
    service, _, workspace = _service(tmp_path)
    events, restored = _authorized()
    workspace.observation = _observation(tmp_path, restored)
    monkeypatch.setattr(service, "_repository_from_projection", lambda _projection: _repository())
    monkeypatch.setattr(
        service,
        "_record_prepared",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(SigmaCoderError(code, "失败")),
    )
    if code == "STORE_BUSY":
        monkeypatch.setattr(
            service,
            "_restore_task_attempt",
            lambda _task_id, *, retry_on_tail_change: (events, restored),
        )

    with pytest.raises(SigmaCoderError) as raised:
        service._recover_authorized(events, restored)
    assert raised.value.code == code


def test_repository_from_projection_maps_adapter_error_and_rejects_drift(
    tmp_path: Path,
) -> None:
    service, _, workspace = _service(tmp_path)
    _, restored = _authorized()
    workspace.inspect_error = WorkspaceError("INVALID_REPOSITORY", "源消失")
    with pytest.raises(SigmaCoderError) as unavailable:
        service._repository_from_projection(restored.projection)
    assert unavailable.value.code == "CREATION_RECOVERY_REQUIRED"

    workspace.inspect_error = None
    workspace.repository = replace(_repository(), baseline_commit="2" * 40)
    with pytest.raises(SigmaCoderError, match="不一致") as drifted:
        service._repository_from_projection(restored.projection)
    assert drifted.value.code == "CREATION_RECOVERY_REQUIRED"


def test_prepared_outcome_handles_inspection_failure_and_unknown_availability(
    tmp_path: Path,
) -> None:
    service, _, workspace = _service(tmp_path)
    _, restored = _prepared()
    workspace.inspect_error = WorkspaceError("INVALID_REPOSITORY", "源消失")

    failed = service._prepared_outcome(restored)
    assert failed.error_code == "CREATION_RECOVERY_REQUIRED"
    assert failed.task["workspace"]["availability"] == "UNVERIFIED"

    workspace.inspect_error = None
    observation = _observation(tmp_path, restored)
    workspace.prepared_status = PreparedWorkspaceStatus(
        availability=WorkspaceAvailability.UNVERIFIED,
        head_oid=None,
        observation=observation,
        error_code="WORKSPACE_EVIDENCE_MISMATCH",
    )
    unknown = service._prepared_outcome(restored)
    assert unknown.error_code == "CREATION_RECOVERY_REQUIRED"
    assert unknown.task["preparation"]["workspace"] == "RECOVERY_REQUIRED"


def test_degraded_workspace_state_preserves_historical_for_missing() -> None:
    assert TaskService._degraded_workspace_state("NOT_CREATED", "READY") == "FAILED"
    assert TaskService._degraded_workspace_state("UNVERIFIED", "READY") == "RECOVERY_REQUIRED"
    assert TaskService._degraded_workspace_state("MISSING", "READY") == "READY"


def test_list_tasks_propagates_non_integrity_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _, _ = _service(tmp_path)
    monkeypatch.setattr(
        service,
        "status",
        lambda _task_id: (_ for _ in ()).throw(SigmaCoderError("STORE_UNAVAILABLE", "down")),
    )

    with pytest.raises(SigmaCoderError) as raised:
        service.list_tasks()
    assert raised.value.code == "STORE_UNAVAILABLE"
