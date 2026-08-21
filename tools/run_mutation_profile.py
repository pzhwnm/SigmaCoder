"""运行版本化 mutmut profile，并拒绝 survivor、跳过或空运行。"""

from __future__ import annotations

import argparse
import configparser
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

KNOWN_STATUSES = frozenset(
    {
        "killed",
        "survived",
        "no tests",
        "check was interrupted by user",
        "not checked",
        "skipped",
        "suspicious",
        "timeout",
        "caught by type check",
        "segfault",
    }
)


class MutationGateError(RuntimeError):
    """Mutation profile 配置或执行不满足规范。"""


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class MutationProfile:
    name: str
    source_paths: tuple[str, ...]
    only_mutate: tuple[str, ...]
    test_selection: tuple[str, ...]
    property_test_selection: tuple[str, ...]
    timeout_seconds: int
    timeout_multiplier: float
    timeout_constant: float
    max_children: int
    repeat: int
    cache_dir: str
    report_path: str


def _string_tuple(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise MutationGateError(
            f"{label} 必须是{'可为空的' if allow_empty else '非空'}字符串数组。"
        )
    if not all(isinstance(item, str) and item for item in value):
        raise MutationGateError(f"{label} 包含无效路径。")
    return tuple(value)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MutationGateError(f"{label} 必须是正整数。")
    return value


def _positive_float(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise MutationGateError(f"{label} 必须是正数。")
    return float(value)


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MutationGateError(f"{label} 必须是相对路径。")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise MutationGateError(f"{label} 不得逃逸仓库：{value}")
    return value


def load_profile(config_path: Path, name: str) -> MutationProfile:
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MutationGateError(f"无法读取 mutation profile：{exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise MutationGateError("mutation profile schema_version 必须为 1。")
    profiles = payload.get("profiles")
    if not isinstance(profiles, dict) or not isinstance(profiles.get(name), dict):
        raise MutationGateError(f"不存在 mutation profile：{name}")
    raw: Mapping[str, object] = profiles[name]
    return MutationProfile(
        name=name,
        source_paths=_string_tuple(raw.get("source_paths"), "source_paths"),
        only_mutate=_string_tuple(raw.get("only_mutate"), "only_mutate"),
        test_selection=_string_tuple(raw.get("test_selection"), "test_selection"),
        property_test_selection=_string_tuple(
            raw.get("property_test_selection"), "property_test_selection", allow_empty=True
        ),
        timeout_seconds=_positive_int(raw.get("timeout_seconds"), "timeout_seconds"),
        timeout_multiplier=_positive_float(raw.get("timeout_multiplier"), "timeout_multiplier"),
        timeout_constant=_positive_float(raw.get("timeout_constant"), "timeout_constant"),
        max_children=_positive_int(raw.get("max_children"), "max_children"),
        repeat=_positive_int(raw.get("repeat"), "repeat"),
        cache_dir=_safe_relative(raw.get("cache_dir"), "cache_dir"),
        report_path=_safe_relative(raw.get("report_path"), "report_path"),
    )


def validate_inputs(repo: Path, profile: MutationProfile) -> None:
    missing = [
        path for path in (*profile.source_paths, *profile.only_mutate) if not (repo / path).exists()
    ]
    missing += [path for path in profile.test_selection if not (repo / path).exists()]
    missing += [path for path in profile.property_test_selection if not (repo / path).exists()]
    if missing:
        raise MutationGateError(f"mutation profile 输入缺失：{', '.join(sorted(set(missing)))}")
    if (repo / "setup.cfg").exists():
        raise MutationGateError("仓库已存在 setup.cfg，拒绝临时覆盖 mutmut 配置。")


def parse_mutmut_results(output: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if ": " not in line:
            continue
        name, status = line.rsplit(": ", 1)
        if status not in KNOWN_STATUSES:
            raise MutationGateError(f"mutmut 返回未知状态：{status}")
        if not name or name in results:
            raise MutationGateError("mutmut 结果包含空名称或重复 mutant。")
        results[name] = status
    if not results:
        raise MutationGateError("mutmut 未返回任何 mutant，拒绝空运行。")
    failed = {name: status for name, status in results.items() if status != "killed"}
    if failed:
        summary = ", ".join(f"{name}={status}" for name, status in sorted(failed.items()))
        raise MutationGateError(f"存在未被测试杀死的 mutant：{summary}")
    return results


def _write_setup_cfg(repo: Path, profile: MutationProfile, tests: Sequence[str]) -> Path:
    parser = configparser.ConfigParser()
    parser["mutmut"] = {
        "source_paths": "\n".join(profile.source_paths),
        "only_mutate": "\n".join(profile.only_mutate),
        "pytest_add_cli_args": "-q",
        "pytest_add_cli_args_test_selection": "\n".join(tests),
        "timeout_multiplier": str(profile.timeout_multiplier),
        "timeout_constant": str(profile.timeout_constant),
        "use_git_change_detection": "false",
    }
    path = repo / "setup.cfg"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        parser.write(handle)
    return path


def _run_command(
    command: Sequence[str],
    *,
    repo: Path,
    timeout: int,
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    try:
        return runner(
            list(command),
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MutationGateError(f"mutation 命令无法执行：{exc}") from exc


def _run_once(
    repo: Path,
    profile: MutationProfile,
    tests: Sequence[str],
    *,
    runner: CommandRunner,
) -> dict[str, str]:
    cache = repo / profile.cache_dir
    if cache.exists():
        shutil.rmtree(cache)
    setup_cfg = _write_setup_cfg(repo, profile, tests)
    try:
        run_result = _run_command(
            ["uv", "run", "mutmut", "run", "--max-children", str(profile.max_children)],
            repo=repo,
            timeout=profile.timeout_seconds,
            runner=runner,
        )
        if run_result.returncode != 0:
            raise MutationGateError(
                f"mutmut run 退出码为 {run_result.returncode}：{run_result.stderr.strip()}"
            )
        result = _run_command(
            ["uv", "run", "mutmut", "results", "--all", "true"],
            repo=repo,
            timeout=120,
            runner=runner,
        )
        if result.returncode != 0:
            raise MutationGateError(
                f"mutmut results 退出码为 {result.returncode}：{result.stderr.strip()}"
            )
        return parse_mutmut_results(result.stdout)
    finally:
        setup_cfg.unlink(missing_ok=True)


def run_profile(
    repo: Path,
    profile: MutationProfile,
    *,
    runner: CommandRunner = subprocess.run,
    require_posix: bool = True,
) -> dict[str, object]:
    if require_posix and os.name != "posix":
        raise MutationGateError("mutmut 3.x 不支持原生 Windows；本门禁必须在 Ubuntu 执行。")
    validate_inputs(repo, profile)
    runs: list[dict[str, object]] = []
    for run_number in range(1, profile.repeat + 1):
        mutants = _run_once(repo, profile, profile.test_selection, runner=runner)
        runs.append({"kind": "full", "run": run_number, "mutants": len(mutants)})
    if profile.property_test_selection:
        mutants = _run_once(repo, profile, profile.property_test_selection, runner=runner)
        runs.append({"kind": "property-only", "run": 1, "mutants": len(mutants)})
    report = {"profile": asdict(profile), "runs": runs, "survivors": 0}
    report_path = repo / profile.report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行 T01 的持久 mutmut profile。")
    parser.add_argument("profile", choices=("events", "task-service"))
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="仓库根目录。")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("mutation_profiles.json"),
        help="profile 配置文件。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = load_profile(args.config.resolve(), args.profile)
        report = run_profile(args.repo.resolve(), profile)
    except MutationGateError as exc:
        print(f"Mutation 门禁失败：{exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **report}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
