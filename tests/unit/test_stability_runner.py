"""并发与真实崩溃重复门的 fail-closed 合同。"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest


def _completed(
    command: Sequence[str],
    *,
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, "ok\n", "")


def test_稳定性门执行一次并发矩阵和二十次崩溃矩阵(tmp_path: Path) -> None:
    from tools.run_stability import run_stability

    calls: list[tuple[list[str], dict[str, str]]] = []

    def runner(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        assert cwd == tmp_path.resolve()
        calls.append((list(command), dict(env)))
        return _completed(command)

    run_stability(tmp_path, repeats=20, runner=runner)

    assert len(calls) == 21
    assert calls[0][1]["SIGMACODER_CONCURRENCY_REPEATS"] == "20"
    assert calls[0][0][-1].endswith(
        "test_s12_concurrent_cli_starts_have_unique_isolated_event_streams"
    )
    assert [call[1]["SIGMACODER_STABILITY_ITERATION"] for call in calls[1:]] == [
        str(index) for index in range(1, 21)
    ]
    assert all(call[0][-1] == "tests/e2e/test_cli_crash_recovery.py" for call in calls[1:])


def test_稳定性门拒绝低于二十次和任一子进程失败(tmp_path: Path) -> None:
    from tools.run_stability import StabilityGateError, run_stability

    with pytest.raises(StabilityGateError, match="至少为 20"):
        run_stability(tmp_path, repeats=19)

    calls = 0

    def failing_runner(
        command: Sequence[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        return _completed(command, returncode=7 if calls == 3 else 0)

    with pytest.raises(StabilityGateError, match="第 2 次崩溃矩阵"):
        run_stability(tmp_path, repeats=20, runner=failing_runner)
    assert calls == 3
