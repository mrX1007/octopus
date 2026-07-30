"""Hermetic analysis and formatting coverage for vulnerability assessment."""

from __future__ import annotations

import builtins
import importlib
import runpy
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

vuln_module = importlib.import_module("core.killchain.vuln_assess")

pytestmark = pytest.mark.unit


def test_optional_import_fallbacks_are_self_contained(monkeypatch):
    real_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"config", "paramiko"}:
            raise ImportError(f"blocked {name}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    namespace = runpy.run_path(
        vuln_module.__file__,
        run_name="_vuln_assess_without_optional_dependencies",
    )

    assert namespace["paramiko"] is None
    assert namespace["CFG"] == {}
    assert namespace["find_wordlist"]("passwords") == ""
    assert namespace["find_all_wordlists"]("passwords") == []


def test_no_service_versions_returns_actionable_message(monkeypatch):
    which = Mock(side_effect=AssertionError("tool discovery must not run"))
    run = Mock(side_effect=AssertionError("subprocess must not run"))
    monkeypatch.setattr(vuln_module.shutil, "which", which)
    monkeypatch.setattr(vuln_module.subprocess, "run", run)

    output = vuln_module.vuln_assess("target.test", "unversioned recon data")

    assert "No service versions found" in output
    assert "nmap -Pn -sT -sV -sC TARGET" in output
    which.assert_not_called()
    run.assert_not_called()


def test_alternate_service_format_with_unavailable_tools(monkeypatch):
    monkeypatch.setattr(vuln_module.shutil, "which", lambda _name: None)
    run = Mock(side_effect=AssertionError("subprocess must not run"))
    monkeypatch.setattr(vuln_module.subprocess, "run", run)

    output = vuln_module.vuln_assess(
        "target.test",
        "Port 8080 version: nginx 1.25\nPort 8443 version: TLS service",
    )

    assert "Detected 2 services with versions" in output
    assert "Port 8080: unknown — nginx 1.25" in output
    assert "searchsploit not installed" in output
    assert "nuclei not installed" in output
    assert "Total exploitable findings: 0" in output
    assert "No known exploits found" in output
    run.assert_not_called()


def test_primary_analysis_formats_searchsploit_and_nuclei_results(monkeypatch):
    monkeypatch.setattr(
        vuln_module.shutil,
        "which",
        lambda name: f"/mock/{name}",
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        if command[0] == "nuclei":
            assert kwargs["timeout"] == 180
            return SimpleNamespace(stdout="critical-one\nhigh-two\n")

        assert command[:2] == ["searchsploit", "--color"]
        assert kwargs["timeout"] == 30
        query = command[-1]
        if query.startswith("OpenSSH"):
            return SimpleNamespace(
                stdout=(
                    "Exploit Title | Path\n"
                    "OpenSSH issue | exploits/linux/remote/1.py\n"
                    "Shell payload | shellcodes/linux/2.c\n"
                    "Documentation | docs/readme\n"
                    "footer\n"
                )
            )
        if query.startswith("Apache"):
            return SimpleNamespace(stdout="No Results")
        if query.startswith("nginx"):
            return SimpleNamespace(stdout="   ")
        raise RuntimeError("search backend failed")

    monkeypatch.setattr(vuln_module.subprocess, "run", fake_run)
    recon_data = "\n".join(
        [
            "21/tcp open ftp () protocol-mode Ubuntu22",
            "22/tcp open ssh OpenSSH 7.6p1 Ubuntu",
            "23/tcp open telnet tcpwrapped",
            "24/tcp open blank ",
            "80/tcp open http Apache 2.4.49",
            "443/tcp open https nginx 1.25",
            "25/tcp open smtp Broken 1.0",
        ]
    )

    output = vuln_module.vuln_assess("target.test", recon_data)

    assert "Detected 5 services with versions" in output
    assert "[SEARCHSPLOIT: OpenSSH 7.6p1]" in output
    assert "EXPLOITABLE: OpenSSH issue (exploits/linux/remote/1.py)" in output
    assert "EXPLOITABLE: Shell payload (shellcodes/linux/2.c)" in output
    assert "searchsploit error for 'Broken 1.0'" in output
    assert "[NUCLEI RESULTS]\ncritical-one\nhigh-two" in output
    assert "Total exploitable findings: 3" in output
    assert "VULNERABILITIES FOUND" in output
    assert any(command[0][0] == "nuclei" for command in calls)


def test_nuclei_timeout_is_formatted_without_running_real_tool(monkeypatch):
    monkeypatch.setattr(
        vuln_module.shutil,
        "which",
        lambda name: "/mock/nuclei" if name == "nuclei" else None,
    )

    def timeout(command, **_kwargs):
        assert command[0] == "nuclei"
        raise subprocess.TimeoutExpired(command, 180)

    monkeypatch.setattr(vuln_module.subprocess, "run", timeout)

    output = vuln_module.vuln_assess("target.test", "80/tcp open http nginx 1.25")

    assert "nuclei timed out after 180s" in output
    assert "Total exploitable findings: 0" in output


def test_nuclei_generic_error_is_formatted(monkeypatch):
    monkeypatch.setattr(
        vuln_module.shutil,
        "which",
        lambda name: "/mock/nuclei" if name == "nuclei" else None,
    )

    def fail(command, **_kwargs):
        assert command[0] == "nuclei"
        raise RuntimeError("template failure")

    monkeypatch.setattr(vuln_module.subprocess, "run", fail)

    output = vuln_module.vuln_assess("target.test", "80/tcp open http nginx 1.25")

    assert "nuclei error: template failure" in output
    assert "Total exploitable findings: 0" in output


def test_empty_nuclei_output_is_not_reported(monkeypatch):
    monkeypatch.setattr(
        vuln_module.shutil,
        "which",
        lambda name: "/mock/nuclei" if name == "nuclei" else None,
    )

    def empty(command, **_kwargs):
        assert command[0] == "nuclei"
        return SimpleNamespace(stdout="  ")

    monkeypatch.setattr(vuln_module.subprocess, "run", empty)

    output = vuln_module.vuln_assess("target.test", "80/tcp open http nginx 1.25")

    assert "[NUCLEI RESULTS]" not in output
    assert "Total exploitable findings: 0" in output
