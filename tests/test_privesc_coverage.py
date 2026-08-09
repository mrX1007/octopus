"""Hermetic coverage for privilege-escalation analysis and orchestration."""

from __future__ import annotations

import builtins
import importlib
import runpy
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest

privesc = importlib.import_module("core.killchain.privesc")

pytestmark = pytest.mark.unit


class _Client:
    def __init__(self):
        self.close_calls = 0

    def close(self):
        self.close_calls += 1


def test_optional_import_and_color_fallbacks(monkeypatch):
    real_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"config", "paramiko", "core.colors"}:
            raise ImportError(f"blocked {name}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    namespace = runpy.run_path(
        privesc.__file__,
        run_name="_privesc_without_optional_dependencies",
    )

    assert namespace["paramiko"] is None
    assert namespace["CFG"] == {}
    assert namespace["find_wordlist"]("passwords") == ""
    assert namespace["find_all_wordlists"]("passwords") == []
    assert namespace["C_GREEN"] == "\033[92m"


def test_linpeas_download_failure_is_reported(monkeypatch):
    commands = []

    def ssh_exec(_client, command, **_kwargs):
        commands.append(command)
        return "download failed"

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)

    output, cves = privesc._run_linpeas(object())

    assert "LinPEAS download failed" in output
    assert cves == []
    assert any(command.startswith("curl") for command in commands)
    assert any(command.startswith("wget") for command in commands)


def test_linpeas_rejects_small_download(monkeypatch):
    commands = []

    def ssh_exec(_client, command, **_kwargs):
        commands.append(command)
        if command.startswith("curl"):
            return "DL_OK"
        if command.startswith("wc -c < /dev/shm/.lp.sh"):
            return "9999\n"
        return ""

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)

    output, cves = privesc._run_linpeas(object())

    assert "download incomplete (9999B)" in output
    assert cves == []
    assert "rm -f /dev/shm/.lp.sh" in commands


def test_linpeas_wget_inline_and_short_output_paths(monkeypatch):
    def ssh_exec(_client, command, **_kwargs):
        if command.startswith("curl"):
            return "failed"
        if command.startswith("wget"):
            return "DL_OK"
        if command.startswith("wc -c < /dev/shm/.lp.sh"):
            return "wc unavailable"
        if command.startswith("nohup bash"):
            return "not-a-pid\nstill-not"
        if command.startswith("head -c 50000"):
            return "tiny"
        return ""

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)

    output, cves = privesc._run_linpeas(object(), timeout=7)

    assert "produced no useful output" in output
    assert cves == []


def test_linpeas_pid_completion_cves_and_truncation(monkeypatch):
    important = "\n".join(f"SUID finding {index}" for index in range(400))
    linpeas_output = f"\nshort\nordinary harmless line\nCVE-2021-4034 CVE-2021-4034 CVE-2022-0847\n{important}"

    def ssh_exec(_client, command, **_kwargs):
        if command.startswith("curl"):
            return "DL_OK"
        if command.startswith("wc -c < /dev/shm/.lp.sh"):
            return "12000"
        if command.startswith("nohup bash"):
            return "notice\n4321\nignored"
        if command.startswith("kill -0"):
            return "DONE"
        if command.startswith("head -c 50000"):
            return linpeas_output
        return ""

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)
    monkeypatch.setattr(privesc.time, "time", Mock(side_effect=[10, 11, 12]))

    output, cves = privesc._run_linpeas(object(), timeout=7)

    assert cves == ["CVE-2021-4034", "CVE-2022-0847"]
    assert "[TRUNCATED]" in output
    assert "LinPEAS CVEs" in output


def test_linpeas_poll_timeout_without_cves(monkeypatch):
    sleep = Mock()

    def ssh_exec(_client, command, **_kwargs):
        if command.startswith("curl"):
            return "DL_OK"
        if command.startswith("wc -c < /dev/shm/.lp.sh"):
            return "not-a-number"
        if command.startswith("nohup bash"):
            return "9876"
        if command.startswith("kill -0"):
            return "RUNNING"
        if command.startswith("wc -c < /dev/shm/.lp.out"):
            return "123"
        if command.startswith("head -c 50000"):
            return "ordinary output " * 10
        return ""

    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)
    monkeypatch.setattr(privesc.time, "time", Mock(side_effect=[0, 0, 1, 99]))
    monkeypatch.setattr(privesc.time, "sleep", sleep)

    output, cves = privesc._run_linpeas(object(), timeout=5)

    assert cves == []
    assert "[LinPEAS KEY FINDINGS]\n\n" in output
    sleep.assert_called_once_with(5)


def test_credential_harvest_is_fail_closed_without_reading_or_serializing_secrets(
    monkeypatch,
):
    canary = "post-privesc-plaintext-canary"
    calls = []
    monkeypatch.setattr(
        privesc,
        "_ssh_exec",
        lambda *_args, **_kwargs: calls.append((_args, _kwargs)) or canary,
    )

    output = privesc._harvest_credentials(object(), "10.0.0.5")

    assert calls == []
    assert "Automatic credential harvesting is disabled" in output
    assert "No credential material was read, retained, cracked, or added" in output
    assert canary not in output
    for forbidden in (
        "/etc/shadow",
        "PRIVATE KEY",
        "DATABASE CREDENTIALS",
        "WIFI CONFIG",
        "KERBEROS TICKETS",
    ):
        assert forbidden not in output


class _AuthenticationException(Exception):
    pass


class _Stdout:
    def __init__(self, value: str):
        self.value = value

    def read(self):
        return self.value.encode()


class _LoginClient(_Client):
    def __init__(self, *, id_output="uid=1000", connect_error=None):
        super().__init__()
        self.id_output = id_output
        self.connect_error = connect_error
        self.connect_calls = []

    def set_missing_host_key_policy(self, _policy):
        self.policy_set = True

    def connect(self, host, **kwargs):
        self.connect_calls.append((host, kwargs))
        if self.connect_error:
            raise self.connect_error

    def exec_command(self, command, timeout):
        assert command == "id"
        assert timeout == 3
        return None, _Stdout(self.id_output), None


def _install_paramiko(monkeypatch, clients=(), *, rsa_error=None):
    queued = list(clients)
    module = ModuleType("paramiko")
    module.AuthenticationException = _AuthenticationException
    module.AutoAddPolicy = lambda: object()

    def ssh_client():
        if queued:
            return queued.pop(0)
        return _LoginClient(connect_error=RuntimeError("connection blocked"))

    class RSAKey:
        @staticmethod
        def from_private_key_file(path):
            if rsa_error:
                raise rsa_error
            return f"private-key:{path}"

    module.SSHClient = ssh_client
    module.RSAKey = RSAKey
    monkeypatch.setitem(sys.modules, "paramiko", module)
    monkeypatch.setattr(privesc, "paramiko", module)
    return module


def _install_credentials(monkeypatch):
    calls = []
    module = ModuleType("core.credentials")
    module.register_credential = lambda *args: calls.append(args)
    monkeypatch.setitem(sys.modules, "core.credentials", module)
    return calls


def _prepare_run(
    monkeypatch,
    ssh_exec,
    *,
    checks=(),
    quick=True,
    linpeas_cves=(),
    adapters=(),
):
    client = _Client()
    monkeypatch.setattr(
        privesc,
        "_ssh_connect",
        lambda *_args, **_kwargs: (client, None),
    )
    monkeypatch.setattr(privesc, "_ssh_exec", ssh_exec)
    monkeypatch.setattr(
        privesc,
        "_run_linpeas",
        lambda *_args, **_kwargs: ("[LINPEAS]\n", list(linpeas_cves)),
    )
    monkeypatch.setattr(privesc, "_PRIVESC_CHECKS", list(checks))
    monkeypatch.setattr(
        privesc,
        "CFG",
        {"killchain": {"quick_privesc_after_root": quick}},
    )
    monkeypatch.setattr(privesc, "get_privesc_exploits", lambda: list(adapters))
    _install_credentials(monkeypatch)
    return client


def test_run_privesc_connection_error_and_already_root(monkeypatch):
    monkeypatch.setattr(
        privesc,
        "_ssh_connect",
        lambda *_args, **_kwargs: (None, "denied"),
    )
    assert "SSH connection failed: denied" in privesc.run_privesc(
        "host",
        "user",
        "password",
    )

    client = _Client()
    monkeypatch.setattr(
        privesc,
        "_ssh_connect",
        lambda *_args, **_kwargs: (client, None),
    )
    monkeypatch.setattr(privesc, "_ssh_exec", lambda *_args, **_kwargs: "uid=0(root)")
    output = privesc.run_privesc("host", "root", "password", 2222)
    assert "ALREADY ROOT" in output
    assert client.close_calls == 1


def test_manual_analysis_and_non_suid_vectors(monkeypatch):
    results = {
        "suid_none": "\n/usr/bin/passwd\n/usr/bin/not-exploitable",
        "sudo": "Defaults entries\n(root) NOPASSWD: /usr/bin/id\nplain line",
        "docker": "user docker",
        "lxd": "user lxd",
        "passwd_writable": "-rw-rw-rw- /etc/passwd",
        "passwd_safe": "-rw-r--r-- /etc/passwd",
        "passwd_error": "--------",
        "shadow_writable": "-rw-rw-rw- /etc/shadow",
        "shadow_safe": "-rw-r--r-- /etc/shadow",
        "shadow_error": "--------",
        "show": "one\n\ntwo\nthree\nfour\nfive\nsix\nseven",
        "generic": "ordinary evidence",
        "bad": "[!] command failed",
    }

    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command in results:
            return results[command]
        if command == "sudo -n id 2>&1":
            return "uid=1000(user)"
        if command.startswith("docker run"):
            return "permission denied"
        if command.startswith("echo 'mtr0n:"):
            return ""
        if command.startswith("grep mtr0n"):
            return "mtr0n:x:0:0"
        return ""

    checks = [
        ("SUID binaries", "suid_none"),
        ("Sudo permissions", "sudo"),
        ("Docker group", "docker"),
        ("LXD group", "lxd"),
        ("Writable /etc/passwd", "passwd_writable"),
        ("Writable /etc/passwd", "passwd_safe"),
        ("Writable /etc/passwd", "passwd_error"),
        ("Writable /etc/shadow", "shadow_writable"),
        ("Writable /etc/shadow", "shadow_safe"),
        ("Writable /etc/shadow", "shadow_error"),
        ("Backup files", "show"),
        ("Other check", "generic"),
        ("Failed check", "bad"),
    ]
    monkeypatch.setattr(privesc, "_SUID_SKIP", {"passwd"})
    monkeypatch.setattr(privesc, "_EXPLOITABLE_SUIDS", {})
    client = _prepare_run(monkeypatch, ssh_exec, checks=checks)

    output = privesc.run_privesc("host", "user", "password")

    assert "SUDO_NOPASSWD" in output
    assert "DOCKER" in output
    assert "LXD" in output
    assert "WRITABLE_PASSWD" in output
    assert "WRITABLE_SHADOW" in output
    assert "WRITABLE PASSWD PRIVESC" in output
    assert "PRIVILEGE ESCALATION CONFIRMED" in output
    assert client.close_calls == 1


@pytest.mark.parametrize("shadow", ["root:$6$hash", ""])
def test_sudo_vector_success_with_optional_shadow(monkeypatch, shadow):
    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command == "sudo_check":
            return "(root) NOPASSWD: /usr/bin/id"
        if command == "sudo -n id 2>&1":
            return "uid=0(root)"
        if command.startswith("sudo cat /etc/shadow"):
            return shadow
        if command.startswith("sudo whoami"):
            return "root"
        return ""

    _prepare_run(
        monkeypatch,
        ssh_exec,
        checks=[("Sudo permissions", "sudo_check")],
    )

    output = privesc.run_privesc("host", "user", "password")

    assert "PRIVESC SUCCESSFUL via sudo" in output
    assert ("PROOF: /etc/shadow" in output) is bool(shadow)


def test_suid_failed_adapters_then_generic_success(monkeypatch):
    binaries = ["bash", "find", "python3", "vim", "env", "mount", "custom"]
    mapping = {binary: f"exploit-{binary}" for binary in binaries}

    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command == "sudo_check":
            return "(root) NOPASSWD: /usr/bin/id"
        if command == "suid_check":
            return "\n".join(f"/usr/bin/{binary}" for binary in binaries)
        if command == "sudo -n id 2>&1":
            return "not root"
        if command.startswith("exploit-custom"):
            return "euid=0(root)"
        return "not root"

    monkeypatch.setattr(privesc, "_SUID_SKIP", set())
    monkeypatch.setattr(privesc, "_EXPLOITABLE_SUIDS", mapping)
    _prepare_run(
        monkeypatch,
        ssh_exec,
        checks=[
            ("Sudo permissions", "sudo_check"),
            ("SUID binaries", "suid_check"),
        ],
    )

    output = privesc.run_privesc("host", "user", "password")

    for marker in ("bash -p", "find -exec", "python3 setuid", "vim", "env bash"):
        assert marker in output
    assert "mount SUID" in output
    assert "exploit-custom" in output


@pytest.mark.parametrize(
    ("binary", "proof_command", "shadow"),
    [
        ("bash", "bash -p -c 'id'", "root:$6$hash"),
        ("bash", "bash -p -c 'id'", ""),
        ("find", "find /dev/null -exec id", ""),
        ("python", "python -c 'import os", ""),
        ("env", "/usr/bin/env /bin/bash", ""),
    ],
)
def test_suid_success_adapters(monkeypatch, binary, proof_command, shadow):
    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command == "suid_check":
            return f"/usr/bin/{binary}"
        if proof_command in command:
            return "uid=0(root)"
        if "cat /etc/shadow" in command:
            return shadow
        return ""

    monkeypatch.setattr(privesc, "_SUID_SKIP", set())
    monkeypatch.setattr(privesc, "_EXPLOITABLE_SUIDS", {binary: f"exploit-{binary}"})
    _prepare_run(
        monkeypatch,
        ssh_exec,
        checks=[("SUID binaries", "suid_check")],
    )

    output = privesc.run_privesc("host", "user", "password")

    assert "PRIVILEGE ESCALATION CONFIRMED" in output
    if binary == "bash":
        assert ("shadow via bash" in output) is bool(shadow)


def test_docker_vector_success(monkeypatch):
    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command == "docker_check":
            return "docker group"
        if command.startswith("docker run"):
            return "root:$6$hash:1:2:3"
        return ""

    _prepare_run(
        monkeypatch,
        ssh_exec,
        checks=[("Docker group", "docker_check")],
    )
    output = privesc.run_privesc("host", "user", "password")
    assert "DOCKER PRIVESC SUCCESSFUL" in output


def test_writable_passwd_failed_then_suid_success(monkeypatch):
    def ssh_exec(_client, command, **_kwargs):
        if command == "id":
            return "uid=1000(user)"
        if command == "passwd_check":
            return "-rw-rw-rw- /etc/passwd"
        if command == "suid_check":
            return "/usr/bin/custom"
        if command.startswith("grep mtr0n"):
            return "missing"
        if command.startswith("exploit-custom"):
            return "uid=0(root)"
        return ""

    monkeypatch.setattr(privesc, "_SUID_SKIP", set())
    monkeypatch.setattr(privesc, "_EXPLOITABLE_SUIDS", {"custom": "exploit-custom"})
    _prepare_run(
        monkeypatch,
        ssh_exec,
        checks=[
            ("Writable /etc/passwd", "passwd_check"),
            ("SUID binaries", "suid_check"),
        ],
    )
    output = privesc.run_privesc("host", "user", "password")
    assert "grep mtr0n" in output
    assert "PRIVILEGE ESCALATION CONFIRMED" in output
