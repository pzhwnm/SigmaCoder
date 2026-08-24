"""SigmaCoder 对外稳定错误。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

EXIT_CODES: dict[str, int] = {
    "INVALID_ARGUMENT": 2,
    "INVALID_GIT_REPOSITORY": 2,
    "UNBORN_REPOSITORY": 2,
    "INVALID_BASELINE": 2,
    "DIRTY_SOURCE_REQUIRES_ACK": 2,
    "UNSAFE_GIT_CHECKOUT_CONFIG": 2,
    "PATH_OUTSIDE_ALLOWED_ROOT": 2,
    "TASK_NOT_FOUND": 3,
    "WORKSPACE_UNAVAILABLE": 3,
    "WORKSPACE_BASELINE_MISMATCH": 3,
    "EVENT_ID_DUPLICATE": 4,
    "EVENT_SEQUENCE_GAP": 4,
    "EVENT_SEQUENCE_DUPLICATE": 4,
    "EVENT_PREVIOUS_HASH_MISMATCH": 4,
    "EVENT_HASH_MISMATCH": 4,
    "EVENT_PAYLOAD_INVALID": 4,
    "EVENT_CAUSATION_INVALID": 4,
    "EVENT_TRANSITION_INVALID": 4,
    "UNSUPPORTED_EVENT_SCHEMA": 4,
    "SQLITE_CORRUPT": 4,
    "PARTIAL_INTEGRITY_FAILURE": 4,
    "TASK_CREATION_FAILED": 5,
    "TASK_PREPARATION_FAILED": 5,
    "WORKSPACE_CREATE_FAILED": 5,
    "STORE_UNAVAILABLE": 5,
    "TASK_ID_COLLISION": 5,
    "CREATION_RECOVERY_REQUIRED": 5,
    "STORE_BUSY": 6,
    "INTERNAL_ERROR": 5,
}

_PUBLIC_CODE_ALIASES = {
    "EVENT_ENVELOPE_INVALID": "EVENT_PAYLOAD_INVALID",
    "EVENT_TASK_ID_MISMATCH": "EVENT_PAYLOAD_INVALID",
}


class SigmaCoderError(Exception):
    """携带稳定错误码、退出码和安全详情的产品异常。"""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})
        self.data = dict(data) if data is not None else None
        self.exit_code = EXIT_CODES.get(code, EXIT_CODES["INTERNAL_ERROR"])


def error_code(error: BaseException) -> str:
    """从边界异常中提取稳定错误码。"""

    code = getattr(error, "code", None)
    if not isinstance(code, str):
        return "INTERNAL_ERROR"
    normalized = _PUBLIC_CODE_ALIASES.get(code, code)
    return normalized if normalized in EXIT_CODES else "INTERNAL_ERROR"
