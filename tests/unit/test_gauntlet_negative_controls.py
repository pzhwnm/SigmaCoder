"""对外部 Gauntlet 门禁执行真实、隔离且可重复的负控。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator, Mapping, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tests.support.isolated_git import create_fixture_git_runtime
from tools import semantic_mutants
from tools.check_secrets import (
    DETECT_SECRETS_VERSION,
    EXPECTED_SECRET_FILTER_CONFIGS,
    EXPECTED_SECRET_PLUGIN_CONFIGS,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEMANTIC_MANIFEST_PATH = "tools/semantic_mutants.json"


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment_overrides: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """以 UTF-8 捕获真实子进程，且让同一虚拟环境里的脚本可发现。"""

    executable_name = Path(command[0]).name.lower()
    if executable_name in {"git", "git.exe"} and tuple(command[1:]) == ("init",):
        with tempfile.TemporaryDirectory(prefix="sigmacoder-fixture-git-") as control:
            return create_fixture_git_runtime(
                Path(control),
                untrusted_boundary=cwd,
            ).init(cwd)

    with tempfile.TemporaryDirectory(prefix="sigmacoder-negative-control-") as control:
        control_root = Path(control)
        environment: dict[str, str] = {}
        for key in ("SystemRoot", "WINDIR", "ComSpec", "PATHEXT"):
            value = os.environ.get(key)
            if value:
                environment[key] = value
        environment.update(
            {
                "HOME": str(control_root),
                "NO_PROXY": "127.0.0.1,localhost",
                "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONNOUSERSITE": "1",
                "PYTHONUTF8": "1",
                "TEMP": str(control_root),
                "TMP": str(control_root),
                "TMPDIR": str(control_root),
                "USERPROFILE": str(control_root),
            }
        )
        if environment_overrides is not None:
            environment.update(environment_overrides)
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )


@pytest.fixture(autouse=True)
def _删除负控_honeytoken_与临时仓库(tmp_path: Path) -> Iterator[None]:
    yield
    shutil.rmtree(tmp_path)
    assert not tmp_path.exists()


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
    "relative_path",
    (
        "assets/secret-probe.svg",
        "package-lock.json",
        "docs/swagger/secret-probe.txt",
    ),
)
def test_文件类型启发式不能隐藏真实_honeytoken(
    tmp_path: Path,
    relative_path: str,
) -> None:
    secret_file = tmp_path / relative_path
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()
    secret_file.write_text(
        f"github_token = {prefix + material[:36]}\n",
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


def test_仓库内_git_影子不能接管秘密扫描输入枚举(tmp_path: Path) -> None:
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(b"sigmacoder-repository-git-shadow").hexdigest()
    (tmp_path / "secret.txt").write_text(
        f"github_token = {prefix + material[:36]}\n",
        encoding="utf-8",
    )
    shadow_name = "git.exe" if os.name == "nt" else "git"
    shutil.copy2(sys.executable, tmp_path / shadow_name)
    (tmp_path / shadow_name).chmod(0o755)
    (tmp_path / ".gitignore").write_text(f"{shadow_name}\n", encoding="utf-8")
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
        environment_overrides={
            "PATH": str(tmp_path) + os.pathsep + os.environ.get("PATH", ""),
        },
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


def test_git_fixture_不继承宿主_template_里的排除规则(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = tmp_path / "host-template"
    (template / "info").mkdir(parents=True)
    (template / "info/exclude").write_text("secret.txt\n", encoding="utf-8")
    monkeypatch.setenv("GIT_TEMPLATE_DIR", str(template))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "safe.txt").write_text("fixture\n", encoding="utf-8")
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(b"sigmacoder-fixture-template-isolation").hexdigest()
    (repo / "secret.txt").write_text(
        f"github_token = {prefix + material[:36]}\n",
        encoding="utf-8",
    )

    git_init = run_command((environment_tool("git"), "init"), cwd=repo)
    assert git_init.returncode == 0, git_init.stderr
    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(repo),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


def test_宿主_git_权威环境不能把扫描重定向到其他仓库(tmp_path: Path) -> None:
    target = tmp_path / "target"
    authority = tmp_path / "authority"
    target.mkdir()
    authority.mkdir()
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(b"sigmacoder-git-environment-redirection").hexdigest()
    (target / "secret.txt").write_text(
        f"github_token = {prefix + material[:36]}\n",
        encoding="utf-8",
    )
    (authority / "safe.txt").write_text("fixture\n", encoding="utf-8")
    for repository in (target, authority):
        git_init = run_command((environment_tool("git"), "init"), cwd=repository)
        assert git_init.returncode == 0, git_init.stderr

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(target),
        ),
        cwd=PROJECT_ROOT,
        environment_overrides={
            "GIT_DIR": str(authority / ".git"),
            "GIT_WORK_TREE": str(authority),
            "GIT_INDEX_FILE": str(authority / ".git" / "index"),
        },
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


def test_repo_子目录不能冒充_git_worktree_根(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subdirectory = repo / "nested"
    subdirectory.mkdir(parents=True)
    git_init = run_command((environment_tool("git"), "init"), cwd=repo)
    assert git_init.returncode == 0, git_init.stderr

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(subdirectory),
        ),
        cwd=PROJECT_ROOT,
    )

    assert result.returncode != 0
    assert "worktree 根目录" in result.stderr


def test_宿主_git_全局_excludes_不能隐藏真实_honeytoken(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(b"sigmacoder-global-excludes").hexdigest()
    (repo / "secret.txt").write_text(
        f"github_token = {prefix + material[:36]}\n",
        encoding="utf-8",
    )
    excludes = tmp_path / "global-excludes"
    excludes.write_text("secret.txt\n", encoding="utf-8")
    global_config = tmp_path / "global-git-config"
    global_config.write_text(
        f"[core]\n\texcludesFile = {excludes.as_posix()}\n",
        encoding="utf-8",
    )
    git_init = run_command((environment_tool("git"), "init"), cwd=repo)
    assert git_init.returncode == 0, git_init.stderr

    result = run_command(
        (
            sys.executable,
            str(PROJECT_ROOT / "tools/check_secrets.py"),
            "--repo",
            str(repo),
        ),
        cwd=PROJECT_ROOT,
        environment_overrides={"GIT_CONFIG_GLOBAL": str(global_config)},
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


def test_snapshot_sitecustomize_不能借相对_pythonpath_伪造_clean_output(
    tmp_path: Path,
) -> None:
    prefix = "".join(("gh", "p_"))
    material = hashlib.sha256(b"sigmacoder-snapshot-sitecustomize").hexdigest()
    (tmp_path / "secret.txt").write_text(
        f"github_token = {prefix + material[:36]}\n",
        encoding="utf-8",
    )
    clean_payload = json.dumps(
        {
            "version": DETECT_SECRETS_VERSION,
            "plugins_used": [dict(config) for config in EXPECTED_SECRET_PLUGIN_CONFIGS],
            "filters_used": [dict(config) for config in EXPECTED_SECRET_FILTER_CONFIGS],
            "results": {},
        }
    )
    (tmp_path / "sitecustomize.py").write_text(
        "import os\n"
        "import sys\n"
        f"sys.stdout.write({clean_payload!r})\n"
        "sys.stdout.flush()\n"
        "os._exit(0)\n",
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
        environment_overrides={"PYTHONPATH": "."},
    )

    assert result.returncode != 0
    assert "未获证明的疑似秘密" in result.stderr


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
    assert payload["waived_findings"] == 15
    assert payload["waiver_contract"] == "mutation-manifests-derived-v2"
    assert len(payload["mutation_manifest_sha256"]) == 64


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
