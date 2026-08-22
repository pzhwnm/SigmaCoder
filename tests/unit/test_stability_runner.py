"""并发与真实崩溃重复门的 fail-closed 合同。"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest


def _completed(
    command: Sequence[str],
    *,
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    stdout = "ok\n"
    if "tools.check_junit" in command:
        stdout = json.dumps(
            {
                "ok": True,
                "reports": [
                    {
                        "path": command[-1],
                        "sha256": "0" * 64,
                        "tests": 1,
                        "failures": 0,
                        "errors": 0,
                        "skipped": 0,
                    }
                ],
            }
        )
    return subprocess.CompletedProcess(command, returncode, stdout, "")


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

    assert len(calls) == 42
    assert calls[0][1]["SIGMACODER_CONCURRENCY_REPEATS"] == "20"
    assert calls[0][0][-2].endswith(
        "test_s12_concurrent_cli_starts_have_unique_isolated_event_streams"
    )
    crash_pytest_calls = calls[2::2]
    assert [call[1]["SIGMACODER_STABILITY_ITERATION"] for call in crash_pytest_calls] == [
        str(index) for index in range(1, 21)
    ]
    assert all(call[0][-2] == "tests/e2e/test_cli_crash_recovery.py" for call in crash_pytest_calls)
    pytest_calls = calls[0::2]
    checker_calls = calls[1::2]
    reports = [
        argument.removeprefix("--junitxml=")
        for call in pytest_calls
        for argument in call[0]
        if argument.startswith("--junitxml=")
    ]
    assert len(reports) == 21
    assert len(set(reports)) == 21
    assert [call[0][-1] for call in checker_calls] == reports


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
        return _completed(command, returncode=7 if calls == 5 else 0)

    with pytest.raises(StabilityGateError, match="第 2 次崩溃矩阵"):
        run_stability(tmp_path, repeats=20, runner=failing_runner)
    assert calls == 5


def test_稳定性门拒绝复用陈旧_junit_证据(tmp_path: Path) -> None:
    from tools.run_stability import StabilityGateError, run_stability

    stale = tmp_path / "build/test-results/stability-concurrency.xml"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")

    with pytest.raises(StabilityGateError, match="拒绝复用陈旧证据"):
        run_stability(tmp_path, repeats=20)

    assert stale.read_text(encoding="utf-8") == "stale"
