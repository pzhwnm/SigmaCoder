"""GitHub Actions 双平台 Tier 3 工作流的固定契约。"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = PROJECT_ROOT / ".github/workflows/gauntlet.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_只声明两个固定平台_job() -> None:
    text = workflow_text()
    jobs_section = text.split("\njobs:\n", maxsplit=1)[1]
    job_ids = re.findall(r"^  ([a-z0-9-]+):\s*$", jobs_section, flags=re.MULTILINE)

    assert job_ids == ["ubuntu-tier3", "windows-compat"]
    assert text.count("runs-on: ubuntu-24.04") == 1
    assert text.count("runs-on: windows-2025") == 1


def test_workflow_分别执行精确_profile() -> None:
    text = workflow_text()

    assert text.count("uv run --frozen python tools/gauntlet.py --profile ubuntu-tier3") == 1
    assert text.count("uv run --frozen python tools/gauntlet.py --profile windows-compat") == 1


def test_workflow_精确固定_python_与_uv() -> None:
    text = workflow_text()
    pinned_python = (PROJECT_ROOT / ".python-version").read_text(encoding="utf-8").strip()

    assert pinned_python == "3.12.14"
    assert text.count("uses: astral-sh/setup-uv@v6") == 2
    assert text.count("version: 0.12.5") == 2
    assert text.count(f"run: uv python install {pinned_python}") == 2
    assert "actions/setup-python" not in text
    assert text.count("run: uv sync --frozen") == 2


def test_workflow_完整检出历史并保持最小权限() -> None:
    text = workflow_text()

    assert text.count("uses: actions/checkout@v4") == 2
    assert text.count("fetch-depth: 0") == 2
    assert "permissions:\n  contents: read\n" in text


def test_workflow_强制python标准流使用utf8() -> None:
    text = workflow_text()

    assert 'env:\n  PYTHONUTF8: "1"\n  PYTHONIOENCODING: "utf-8"\n' in text


def test_workflow_windows_job_使用短runner临时根() -> None:
    text = workflow_text()
    windows_job = text.split("  windows-compat:\n", maxsplit=1)[1]
    runner_temp = "$" + "{{ runner.temp }}"

    assert (
        "    env:\n"
        f'      TEMP: "{runner_temp}"\n'
        f'      TMP: "{runner_temp}"\n'
        f'      TMPDIR: "{runner_temp}"\n'
    ) in windows_job
