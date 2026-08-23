"""对外部 Gauntlet 门禁执行真实、隔离且可重复的负控。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tools import semantic_mutants

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEMANTIC_MANIFEST_PATH = "tools/semantic_mutants.json"


def run_command(command: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """以 UTF-8 捕获真实子进程，且让同一虚拟环境里的脚本可发现。"""

    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    environment["PATH"] = (
        str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
    )
    return subprocess.run(
        list(command),
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )


def environment_tool(name: str) -> str:
    suffix = ".exe" if os.name == "nt" else ""
    sibling = Path(sys.executable).with_name(f"{name}{suffix}")
    if sibling.is_file():
        return str(sibling)
    resolved = shutil.which(name)
    assert resolved is not None, f"测试环境缺少真实工具：{name}"
    return resolved


def copy_semantic_fixture(destination: Path) -> Path:
    manifest_source = PROJECT_ROOT / SEMANTIC_MANIFEST_PATH
    payload = json.loads(manifest_source.read_text(encoding="utf-8"))
    paths = {SEMANTIC_MANIFEST_PATH}
    for mutant in payload["mutants"]:
        paths.add(mutant["source"])
        paths.update(selector.split("::", 1)[0] for selector in mutant["selectors"])
    for relative in paths:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PROJECT_ROOT / relative, target)
    return destination / SEMANTIC_MANIFEST_PATH


def test_diff_cover_对未覆盖_changed_line_返回非零(tmp_path: Path) -> None:
    source = tmp_path / "changed.py"
    source.write_text("covered = 1\nuncovered = 2\n", encoding="utf-8")
    git_init = run_command((environment_tool("git"), "init"), cwd=tmp_path)
    assert git_init.returncode == 0, git_init.stderr
    coverage = tmp_path / "coverage.xml"
    coverage.write_text(
        """<?xml version="1.0" ?>
<coverage version="fixture" line-rate="0.5" branch-rate="0">
  <sources><source>.</source></sources>
  <packages><package name="fixture" line-rate="0.5" branch-rate="0">
    <classes><class name="changed" filename="changed.py" line-rate="0.5" branch-rate="0">
      <methods/><lines>
        <line number="1" hits="1"/>
        <line number="2" hits="0"/>
      </lines>
    </class></classes>
  </package></packages>
</coverage>
""",
        encoding="utf-8",
    )
    diff = tmp_path / "change.diff"
    diff.write_text(
        """diff --git a/changed.py b/changed.py
--- a/changed.py
+++ b/changed.py
@@ -1 +1,2 @@
 covered = 1
+uncovered = 2
""",
        encoding="utf-8",
    )

    result = run_command(
        (
            environment_tool("diff-cover"),
            str(coverage),
            "--diff-file",
            str(diff),
            "--fail-under=100",
        ),
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "Missing lines 2" in result.stdout
    assert "Failure" in result.stderr


def test_动态未跟踪_honeytoken_使真实_secret_scanner_返回非零(tmp_path: Path) -> None:
    secret_file = tmp_path / "nested" / "temporary-honeytoken.txt"
    secret_file.parent.mkdir()
    # 从公开的测试标签导出不可用 token，避免可匹配的秘密字面量进入受控源码。
    prefix = "".join(("gh", "p_"))
    digest = hashlib.sha256(b"sigmacoder-negative-control").hexdigest()
    fake_access_key = prefix + (digest[:18].upper() + digest[18:36])
    secret_file.write_text(f"github_token = {fake_access_key}\n", encoding="utf-8")
    git_init = run_command((environment_tool("git"), "init"), cwd=tmp_path)
    assert git_init.returncode == 0, git_init.stderr
    try:
        result = run_command(
            (
                sys.executable,
                str(PROJECT_ROOT / "tools/check_secrets.py"),
                "--repo",
                str(tmp_path),
            ),
            cwd=PROJECT_ROOT,
        )
    finally:
        secret_file.unlink(missing_ok=True)

    assert result.returncode != 0
    assert "秘密扫描门禁失败" in result.stderr
    assert "疑似秘密" in result.stderr
    assert not secret_file.exists()


@pytest.mark.parametrize(
    "content",
    [
        'github_token = "{token}"  # pragma: allowlist secret\n',
        '# pragma: allowlist nextline secret\ngithub_token = "{token}"\n',
    ],
)
def test_allowlist_pragma_不能隐藏真实_honeytoken(tmp_path: Path, content: str) -> None:
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(content.encode("utf-8")).hexdigest()
    token = prefix + material[:36]
    (tmp_path / "allowlisted.py").write_text(
        content.format(token=token),
        encoding="utf-8",
    )
    git_init = run_command((environment_tool("git"), "init"), cwd=tmp_path)
    assert git_init.returncode == 0, git_init.stderr

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(tmp_path),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


def test_真实_secret_scanner_观测并仅豁免十条已证明_hash() -> None:
    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(PROJECT_ROOT),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["findings"] == 0
    assert payload["waived_findings"] == 10
    assert payload["waiver_contract"] == "semantic-manifest-derived-v1"


def test_semantic_manifest_额外_token_不能借哈希豁免逃逸(tmp_path: Path) -> None:
    manifest_path = copy_semantic_fixture(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    prefix = "".join(("gh", "p_"))
    token_material = hashlib.sha256(b"sigmacoder-manifest-negative-control").hexdigest()
    mutant = payload["mutants"][0]
    mutant["new"] += f'\n# github_token = "{prefix + token_material[:36]}"'
    source = (tmp_path / mutant["source"]).read_bytes()
    old = mutant["old"].encode("utf-8")
    new = mutant["new"].encode("utf-8")
    assert source.count(old) == 1
    mutant["expected_mutant_sha256"] = hashlib.sha256(source.replace(old, new, 1)).hexdigest()
    manifest_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest = semantic_mutants.load_manifest(manifest_path)
    semantic_mutants._validate_repo_inputs(tmp_path, manifest)
    git_init = run_command((environment_tool("git"), "init"), cwd=tmp_path)
    assert git_init.returncode == 0, git_init.stderr

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(tmp_path),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode != 0
    assert "秘密扫描门禁失败" in result.stderr
    assert "未获证明的疑似秘密" in result.stderr


def test_未批准许可证使真实许可证门返回非零(tmp_path: Path) -> None:
    fixture = tmp_path / "licenses.json"
    denied_license = "-".join(("GPL", "3.0", "only"))
    fixture.write_text(
        json.dumps([{"Name": "negative-fixture", "Version": "0", "License": denied_license}]),
        encoding="utf-8",
    )

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_licenses.py"),
            str(fixture),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode != 0
    assert "许可证门禁失败" in result.stderr
    assert denied_license in result.stderr


def test_缺少锁文件使真实供应链锁门返回非零(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """[project]
name = "negative-supply-chain-fixture"
version = "0"
requires-python = ">=3.12,<3.13"
dependencies = []
""",
        encoding="utf-8",
    )

    result = run_command(
        (environment_tool("uv"), "lock", "--check"),
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "lock" in (result.stdout + result.stderr).lower()


def test_本地_osv_发现使真实_pip_audit_返回非零(tmp_path: Path) -> None:
    requirement = tmp_path / "requirements.txt"
    requirement.write_text("negative-fixture==1.0\n", encoding="utf-8")
    advisory_id = "-".join(("SIGMACODER", "NEGATIVE", "1"))

    class OsvFixtureHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            query = json.loads(self.rfile.read(length).decode("utf-8"))
            package = query["package"]
            response = {
                "vulns": [
                    {
                        "schema_version": "1.0.0",
                        "id": advisory_id,
                        "summary": "仅供门禁负控使用的本地发现。",
                        "affected": [
                            {
                                "package": package,
                                "ranges": [
                                    {
                                        "type": "ECOSYSTEM",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.0"},
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
            encoded = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), OsvFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host = server.server_address[0]
        port = server.server_address[1]
        assert isinstance(host, str)
        assert isinstance(port, int)
        result = run_command(
            (
                environment_tool("pip-audit"),
                "--requirement",
                str(requirement),
                "--strict",
                "--no-deps",
                "--disable-pip",
                "--vulnerability-service",
                "osv",
                "--osv-url",
                f"http://{host}:{port}/v1/query",
                "--progress-spinner",
                "off",
                "--format",
                "json",
            ),
            cwd=tmp_path,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.returncode != 0
    assert advisory_id in result.stdout + result.stderr
