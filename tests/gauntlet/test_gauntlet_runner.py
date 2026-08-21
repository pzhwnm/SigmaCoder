from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest
from tools.gauntlet import (
    PROFILE_WINDOWS,
    GauntletError,
    Layer,
    audit_completion,
    build_manifest,
    cleanup_paths,
    run_gauntlet,
    run_layer,
    validate_manifest,
    validate_platform,
)


def completed(
    command: Sequence[str],
    returncode: int = 0,
    stdout: str = "ok\n",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_固定层清单完整且_windows_不含_mutation() -> None:
    layers = build_manifest(PROFILE_WINDOWS)
    validate_manifest(PROFILE_WINDOWS, layers)
    assert all(not layer.name.startswith("mutation-") for layer in layers)


def test_删除一个预期层时门禁失败() -> None:
    layers = build_manifest(PROFILE_WINDOWS)
    with pytest.raises(GauntletError, match="层清单不完整"):
        validate_manifest(PROFILE_WINDOWS, layers[:-1])


def test_已知失败命令使层失败(tmp_path: Path) -> None:
    layer = Layer(name="known-failure", commands=(("fake",),))

    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command, returncode=9, stderr="预期失败")

    with pytest.raises(GauntletError, match="退出码为 9"):
        run_layer(layer, tmp_path, runner=runner)


def test_命令异常和超时均_fail_closed(tmp_path: Path) -> None:
    layer = Layer(name="broken", commands=(("fake",),))

    def missing(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("missing")

    with pytest.raises(GauntletError, match="无法执行"):
        run_layer(layer, tmp_path, runner=missing)

    def timeout(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(command, 1)

    with pytest.raises(GauntletError, match="超时"):
        run_layer(layer, tmp_path, runner=timeout)


def test_陈旧报告在执行前被删除(tmp_path: Path) -> None:
    for relative in ("coverage.json", "coverage.xml", "mutants"):
        path = tmp_path / relative
        if path.suffix:
            path.write_text("stale", encoding="utf-8")
        else:
            path.mkdir()
            (path / "old").write_text("stale", encoding="utf-8")
    cleanup_paths(tmp_path, ("coverage.json", "coverage.xml", "mutants"))
    assert not (tmp_path / "coverage.json").exists()
    assert not (tmp_path / "mutants").exists()


def test_清理路径不能逃逸仓库(tmp_path: Path) -> None:
    with pytest.raises(GauntletError, match="逃逸"):
        cleanup_paths(tmp_path, ("../outside",))


def test_完成审计拒绝缺层() -> None:
    with pytest.raises(GauntletError, match="完成审计失败"):
        audit_completion(PROFILE_WINDOWS, [])


def test_windows_profile_完整假执行产生全部结果(tmp_path: Path) -> None:
    def runner(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return completed(command)

    results = run_gauntlet(tmp_path, PROFILE_WINDOWS, runner=runner, enforce_platform=False)
    assert len(results) == len(build_manifest(PROFILE_WINDOWS))


def test_平台_profile_不允许互换() -> None:
    validate_platform(PROFILE_WINDOWS, "Windows")
    with pytest.raises(GauntletError, match="只能在 Windows"):
        validate_platform(PROFILE_WINDOWS, "Linux")
