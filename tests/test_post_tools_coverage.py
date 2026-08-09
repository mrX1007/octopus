"""Hermetic statement and branch coverage for the post-tools adapters."""

from __future__ import annotations

import builtins
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, ClassVar

import pytest

from core.credentials import CredentialRef
from core.execution import ExecutionContext, bind_execution_context
from core.tools import post_tools

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _ref(
    user: str = "alice",
    *,
    service: str = "ssh",
    target: str = "host",
    port: int = 22,
    auth_kind: str = "password",
    suffix: str = "1",
) -> CredentialRef:
    return CredentialRef(
        handle=f"credential://{suffix}",
        service=service,
        target=target,
        username=user,
        auth_kind=auth_kind,
        port=port,
    )


def _module(monkeypatch: pytest.MonkeyPatch, name: str, **attrs: Any) -> ModuleType:
    module = ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@contextmanager
def _blocked_import(module_name: str, *, exact: bool = False):
    original = builtins.__import__

    def blocking_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == module_name or (not exact and name.startswith(f"{module_name}.")):
            raise ImportError(f"blocked {module_name}")
        return original(name, globals, locals, fromlist, level)

    builtins.__import__ = blocking_import
    try:
        yield
    finally:
        builtins.__import__ = original


class _Client:
    def __init__(self, *, close_error: bool = False):
        self.closed = False
        self.close_error = close_error

    def close(self):
        self.closed = True
        if self.close_error:
            raise RuntimeError("close failed")


def _material_context(password: str = "secret"):
    @contextmanager
    def material_for(credential):
        yield SimpleNamespace(
            username=credential.username,
            password=password,
            service=credential.service,
            port=credential.port,
        )

    return material_for


def _call_provider(credential, provider):
    return str(
        provider(
            SimpleNamespace(
                username=credential.username,
                password="secret",
                service=credential.service,
                port=credential.port,
            )
        )
    )


def test_ssh_analysis_clipping_and_command_policy(monkeypatch):
    arbitrary_allowed = post_tools._arbitrary_ssh_exec_allowed
    is_controlled = post_tools._is_controlled_ssh_command
    assert post_tools._clip_ssh_output("") == "(no output)"
    assert post_tools._clip_ssh_output(" short ", 10) == "short"
    assert "truncated 2 chars" in post_tools._clip_ssh_output("abcdef", 4)
    assert "requires host" in post_tools._ssh_analyze("", "user", "password")

    with _blocked_import("core.killchain.ssh_helpers"):
        assert "SSH helpers unavailable" in post_tools._ssh_analyze("host", "user", "password")

    client = _Client()
    helpers = _module(
        monkeypatch,
        "core.killchain.ssh_helpers",
        _ssh_connect=lambda *args, **kwargs: (client, "denied"),
        _ssh_exec=lambda *args, **kwargs: "unused",
    )
    assert "SSH connection failed: denied" in post_tools._ssh_analyze("host", "user", "password")
    assert client.closed

    helpers._ssh_connect = lambda *args, **kwargs: (None, "")
    assert "unknown error" in post_tools._ssh_analyze("host", "user", "password")

    client = _Client(close_error=True)
    calls = []
    helpers._ssh_connect = lambda *args, **kwargs: (client, "")

    def fake_exec(_client, command, *, timeout):
        calls.append((command, timeout))
        return "[!] unavailable" if len(calls) == 1 else " ok "

    helpers._ssh_exec = fake_exec
    output = post_tools._ssh_analyze("host", "user", "password", port=2222)
    assert "[-] System" in output
    assert "[+] Identity" in output
    assert len(calls) == 15
    assert client.closed

    assert post_tools._ssh_exec_block_reason("") == "empty command"
    for command, reason in (
        ("rm -rf /", "recursive delete"),
        ("shutdown now", "destructive system"),
        ("init 0", "runlevel"),
        ("dd if=/tmp/x of=/dev/sda", "block-device"),
        (":(){ :|:& };:", "fork-bomb"),
    ):
        assert reason in post_tools._ssh_exec_block_reason(command)

    monkeypatch.setattr(post_tools, "_arbitrary_ssh_exec_allowed", lambda: False)
    monkeypatch.setattr(post_tools, "_is_controlled_ssh_command", lambda command: command == "id")
    assert "outside controlled" in post_tools._ssh_exec_block_reason("echo hello")
    assert post_tools._ssh_exec_block_reason("id") == ""
    monkeypatch.setattr(post_tools, "_arbitrary_ssh_exec_allowed", lambda: True)
    assert post_tools._ssh_exec_block_reason("echo hello") == ""

    assert post_tools._strip_wrapping_quotes(" 'value' ") == "value"
    assert post_tools._strip_wrapping_quotes('"value"') == "value"
    assert post_tools._strip_wrapping_quotes("x") == "x"
    assert post_tools._normalize_controlled_ssh_command("  sudo  -n -l 2>/dev/null || true ") == "sudo -n -l"
    assert is_controlled("whoami")
    assert is_controlled("ip -o addr show || ip addr show")
    assert not is_controlled("echo no")

    import config

    monkeypatch.setattr(config, "CFG", {"strategy": {"allow_arbitrary_ssh_exec": True}})
    assert post_tools._arbitrary_ssh_exec_allowed()
    with _blocked_import("config"):
        assert not arbitrary_allowed()


def test_interactive_ssh_session_paths(monkeypatch):
    known = _ref()
    monkeypatch.setattr(post_tools, "call_credential_provider", _call_provider)
    monkeypatch.setattr(post_tools, "_ssh_analyze", lambda *args, **kwargs: f"analyzed:{args[1]}")
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: known)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert post_tools._run_ssh_session_interactive("host") == "analyzed:alice"

    answers = iter(["n", "bob", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "No password" in post_tools._run_ssh_session_interactive("host")

    registered = []
    refs = iter([None, None])
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: next(refs))
    monkeypatch.setattr(post_tools, "register_credential", lambda *args, **kwargs: registered.append((args, kwargs)))
    answers = iter(["", "password"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "registration failed" in post_tools._run_ssh_session_interactive("host")
    assert registered

    refs = iter([None, known])
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: next(refs))
    answers = iter(["bob", "password"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert post_tools._run_ssh_session_interactive("host") == "analyzed:alice"


def test_killchain_menu_helpers(monkeypatch):
    import core.killchain as killchain
    import core.killchain.policy as policy

    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: f"denied:{stage}")
    assert post_tools._run_killchain_stage("vuln_assess", "host") == "denied:vuln_assess"

    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "")
    monkeypatch.setattr(killchain, "vuln_assess", lambda target: f"vuln:{target}")
    monkeypatch.setattr(killchain, "auto_exploit", lambda target: f"exploit:{target}")
    assert post_tools._run_killchain_stage("vuln_assess", "host") == "vuln:host"
    assert post_tools._run_killchain_stage("auto_exploit", "host") == "exploit:host"
    assert "Unknown stage" in post_tools._run_killchain_stage("other", "host")
    with _blocked_import("core.killchain", exact=True):
        assert "package not found" in post_tools._run_killchain_stage("vuln_assess", "host")

    monkeypatch.setattr(policy, "master_gate_message", lambda: "master denied")
    assert post_tools._run_killchain_interactive("full", "host") == "master denied"
    monkeypatch.setattr(policy, "master_gate_message", lambda: "")
    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "stage denied")
    assert post_tools._run_killchain_interactive("privesc", "host") == "stage denied"
    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "")
    with _blocked_import("core.killchain", exact=True):
        assert "package not found" in post_tools._run_killchain_interactive("privesc", "host")

    for name in (
        "run_privesc",
        "plant_persistence",
        "lateral_move",
        "data_exfil",
        "stealth_cleanup",
    ):
        monkeypatch.setattr(killchain, name, lambda target, user, password, n=name: f"{n}:{user}")
    monkeypatch.setattr(
        killchain,
        "run_full_killchain",
        lambda target, credential, callback_host: f"full:{credential.username}:{callback_host}",
    )
    monkeypatch.setattr(post_tools, "call_credential_provider", _call_provider)
    known = _ref()
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: known)
    answers = iter(["callback.example", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert post_tools._run_killchain_interactive("full", "host") == ("full:alice:callback.example")

    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert "explicit callback_host is required" in post_tools._run_killchain_interactive("full", "host")
    assert "must be one host" in post_tools._run_killchain_interactive("full", "host", "https://callback.example/path")

    for stage, expected in (
        ("privesc", "run_privesc"),
        ("persist", "plant_persistence"),
        ("lateral", "lateral_move"),
        ("exfil", "data_exfil"),
        ("cleanup", "stealth_cleanup"),
    ):
        assert expected in post_tools._run_killchain_interactive(stage, "host")
    assert "Unknown kill chain" in post_tools._run_killchain_interactive("other", "host")

    answers = iter(["n", "bob", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "No password" in post_tools._run_killchain_interactive("privesc", "host")

    answers = iter(["n", "bob", "password"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "run_privesc" in post_tools._run_killchain_interactive("privesc", "host")

    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: None)
    answers = iter(["", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "No password" in post_tools._run_killchain_interactive("privesc", "host")

    answers = iter(["bob", "password"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(post_tools, "register_credential", lambda *args, **kwargs: None)
    assert "registration failed" in post_tools._run_killchain_interactive("privesc", "host")


def test_waf_shodan_and_hash_menu_helpers(monkeypatch):
    class WafSession:
        def detect_waf(self, url):
            return {"waf_detected": True, "waf_type": "Example", "details": [url, "detail"]}

    _module(monkeypatch, "evasion", WebEvasionSession=WafSession)
    assert "detail" in post_tools._run_waf_detect("host")
    with _blocked_import("evasion"):
        assert "evasion.py not found" in post_tools._run_waf_detect("host")

    shodan_calls = []
    _module(
        monkeypatch,
        "shodan_module",
        run_shodan_interactive=lambda target: f"interactive:{target}",
        run_shodan_host=lambda target: f"host:{target}",
        run_shodan_vulns=lambda target: f"vulns:{target}",
        run_shodan_range=lambda cidr: shodan_calls.append(cidr) or f"range:{cidr}",
    )
    assert post_tools._run_shodan_interactive("x") == "interactive:x"
    assert post_tools._run_shodan_host("x") == "host:x"
    assert post_tools._run_shodan_vulns("x") == "vulns:x"
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert post_tools._run_shodan_range("10.1.2.3") == "range:10.1.2.0/24"
    assert "No CIDR" in post_tools._run_shodan_range("query")
    monkeypatch.setattr("builtins.input", lambda prompt="": "10.0.0.0/8")
    assert post_tools._run_shodan_range("query") == "range:10.0.0.0/8"
    for function in (
        post_tools._run_shodan_interactive,
        post_tools._run_shodan_host,
        post_tools._run_shodan_vulns,
        post_tools._run_shodan_range,
    ):
        with _blocked_import("shodan_module"):
            assert "not found" in function("x")

    cracked = []
    _module(monkeypatch, "hash_cracker", run_crack_hashes=lambda path: cracked.append(path) or f"cracked:{path}")
    monkeypatch.setattr(post_tools.os.path, "isfile", lambda path: path in {"direct", "picked"})
    assert post_tools._run_crack_hashes("direct") == "cracked:direct"

    monkeypatch.setattr(post_tools.os.path, "expanduser", lambda path: "/loot")
    monkeypatch.setattr(post_tools.os.path, "isdir", lambda path: True)
    monkeypatch.setattr(post_tools.os, "listdir", lambda path: ["ignore.txt", "shadow.one", "two.hash"])
    answers = iter(["1"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert post_tools._run_crack_hashes("target") == "cracked:/loot/shadow.one"

    answers = iter(["picked"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert post_tools._run_crack_hashes("target") == "cracked:picked"

    answers = iter(["invalid", "fallback"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert post_tools._run_crack_hashes("target") == "cracked:fallback"
    answers = iter(["invalid", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert "No input" in post_tools._run_crack_hashes("target")
    monkeypatch.setattr(post_tools.os.path, "isdir", lambda path: False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert "No input" in post_tools._run_crack_hashes("target")
    with _blocked_import("hash_cracker"):
        assert "hash_cracker.py not found" in post_tools._run_crack_hashes("target")


def test_default_recon_is_process_and_network_free(monkeypatch):
    names = (
        "run_nmap",
        "run_whois",
        "run_whatweb",
        "run_curl_headers",
        "run_dig",
        "run_sslscan",
        "run_ffuf",
        "run_enum4linux",
        "run_smbclient",
    )
    for name in names:
        monkeypatch.setattr(post_tools, name, lambda target, n=name: f"{n}:{target}")
    monkeypatch.setattr(post_tools, "run_nmap", lambda target: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(post_tools, "effective_parallel_workers", lambda count: 2)
    shodan = _module(monkeypatch, "shodan_module", run_shodan_host=lambda target: "enriched")
    results = post_tools.run_default_recon("10.0.0.1")
    assert "generated an exception" in results["nmap"]
    assert results["shodan"] == "enriched"

    shodan.run_shodan_host = lambda target: "[!] unavailable"
    assert "shodan" not in post_tools.run_default_recon("10.0.0.1")
    assert "shodan" not in post_tools.run_default_recon("example.test")
    shodan.run_shodan_host = lambda target: (_ for _ in ()).throw(RuntimeError("offline"))
    assert "shodan" not in post_tools.run_default_recon("10.0.0.1")


def test_credential_reference_resolution_and_ad_shapes(monkeypatch):
    valid = _ref()
    other_target = _ref(target="other", suffix="target")
    other_service = _ref(service="ldap", suffix="service")
    other_user = _ref(user="bob", suffix="user")
    other_port = _ref(port=2222, suffix="port")
    resolved = {ref.handle: ref for ref in (valid, other_target, other_service, other_user, other_port)}
    monkeypatch.setattr(post_tools, "is_credential_handle", lambda value: str(value).startswith("credential://"))
    monkeypatch.setattr(
        post_tools, "resolve_credential_handle", lambda value: resolved.get(getattr(value, "handle", value))
    )

    assert "Plaintext" in post_tools._resolve_credential_ref("host", credential_handle="secret")[1]
    assert "Unknown" in post_tools._resolve_credential_ref("host", credential_handle="credential://missing")[1]
    assert "scope mismatch" in post_tools._resolve_credential_ref("host", credential_handle=other_target)[1]
    assert "scope mismatch" in post_tools._resolve_credential_ref("host", credential_handle=other_service)[1]
    assert "username mismatch" in post_tools._resolve_credential_ref("host", "alice", other_user)[1]
    assert "port mismatch" in post_tools._resolve_credential_ref("host", credential_handle=other_port, port=22)[1]
    assert post_tools._resolve_credential_ref("host", "alice", valid, port=22) == (valid, "")

    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: None)
    assert "Credentials required" in post_tools._resolve_credential_ref("host")[1]
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: valid)
    assert post_tools._resolve_ai_creds("host") == (valid, "")

    assert "Plaintext/hash" in post_tools._resolve_ad_creds("host", nthash="hash")[1]
    ldap = _ref(service="ldap", port=389)
    resolutions = iter([(ldap, ""), (None, "ldap missing"), (valid, "")])
    monkeypatch.setattr(post_tools, "_resolve_credential_ref", lambda *args, **kwargs: next(resolutions))
    assert post_tools._resolve_ad_creds("host") == (ldap, "")
    assert post_tools._resolve_ad_creds("host") == (valid, "")
    monkeypatch.setattr(post_tools, "_resolve_credential_ref", lambda *args, **kwargs: (None, "missing"))
    assert post_tools._resolve_ad_creds("host", pwd="credential://x") == (None, "missing")

    assert post_tools._ad_provider_identity("CORP\\alice") == ("alice", "CORP")
    assert post_tools._ad_provider_identity("alice@example.test") == ("alice", "example.test")
    assert post_tools._ad_provider_identity("alice", "OVERRIDE") == ("alice", "OVERRIDE")


def test_ad_execution_context_and_provider_sanitization(monkeypatch):
    monkeypatch.setattr(post_tools, "_resolve_ad_creds", lambda *args, **kwargs: (None, "missing"))
    with post_tools._ad_creds_for_execution("host", user="alice") as (creds, error):
        assert creds is None and error == "missing"
    with post_tools._ad_creds_for_execution("host", domain="CORP") as (creds, error):
        assert creds["domain"] == "CORP" and not error
    with post_tools._ad_creds_for_execution("host") as (creds, error):
        assert creds is None and not error

    credential = _ref(user="CORP\\alice", service="ldap", port=0)
    monkeypatch.setattr(post_tools, "_resolve_ad_creds", lambda *args, **kwargs: (credential, ""))
    monkeypatch.setattr(post_tools, "credential_material_for_execution", _material_context("secret"))
    captured = None
    with post_tools._ad_creds_for_execution("host") as (creds, error):
        captured = creds
        assert creds == {
            "user": "alice",
            "username": "alice",
            "password": "secret",
            "domain": "CORP",
            "nthash": "",
            "service": "ldap",
            "port": 389,
        }
        assert not error
    assert captured["password"] == ""

    monkeypatch.setattr(
        post_tools, "sanitize_credential_text", lambda value, plaintext: str(value).replace(plaintext, "X")
    )
    assert post_tools._call_ad_provider({"password": "secret"}, lambda: "ok secret") == "ok X"
    failure = post_tools._call_ad_provider(
        {"password": "secret"},
        lambda: (_ for _ in ()).throw(RuntimeError("bad secret")),
    )
    assert "RuntimeError" in failure and "secret" not in failure


def test_connect_ssh_for_tool_all_resolution_and_transport_paths(monkeypatch):
    root = _ref("root", suffix="root")
    user = _ref("alice", suffix="user")
    wrong_port = _ref("skip", port=2200, suffix="skip")
    monkeypatch.setattr(post_tools, "credential_material_for_execution", _material_context("secret"))
    monkeypatch.setattr(
        post_tools, "sanitize_credential_text", lambda value, plaintext: str(value).replace(plaintext, "X")
    )

    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, "bad handle"))
    assert post_tools._connect_ssh_for_tool("host", "alice", "credential://bad")[3] == "bad handle"

    monkeypatch.setattr(
        post_tools,
        "get_all_credential_refs_for_target",
        lambda host: {"ssh": [user, wrong_port, root]},
    )
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, "missing"))
    calls = []
    good_client = _Client()

    def connect(host, username, password, **kwargs):
        calls.append(username)
        if username == "root":
            return None, "root failed secret"
        return good_client, ""

    _module(monkeypatch, "core.killchain.ssh_helpers", _ssh_connect=connect)
    result = post_tools._connect_ssh_for_tool("host", prefer_privileged=True)
    assert result[:3] == (good_client, "alice", user.handle)
    assert calls == ["root", "alice"]

    monkeypatch.setattr(post_tools, "get_all_credential_refs_for_target", lambda host: {"ssh": []})
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (user, ""))
    assert post_tools._connect_ssh_for_tool("host")[0] is good_client

    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, ""))
    assert "credentials required" in post_tools._connect_ssh_for_tool("host")[3]

    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (user, ""))
    with _blocked_import("core.killchain.ssh_helpers"):
        assert "helpers unavailable" in post_tools._connect_ssh_for_tool("host")[3]

    helpers = _module(
        monkeypatch,
        "core.killchain.ssh_helpers",
        _ssh_connect=lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret exploded")),
    )
    result = post_tools._connect_ssh_for_tool("host", pwd=user.handle)
    assert "RuntimeError" in result[3] and "secret" not in result[3]

    helpers._ssh_connect = lambda *args, **kwargs: (None, "")
    assert "unknown error" in post_tools._connect_ssh_for_tool("host", pwd=user.handle)[3]

    monkeypatch.setattr(post_tools, "get_all_credential_refs_for_target", lambda host: {"ssh": [root, user]})
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, ""))
    assert "SSH connection failed" in post_tools._connect_ssh_for_tool("host", prefer_privileged=True)[3]


def test_controlled_inventory_and_generated_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(
        post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (None, None, None, "connect failed")
    )
    assert post_tools._run_controlled_ssh_inventory("host") == "connect failed"

    client = _Client(close_error=True)
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    counter = iter(range(100))

    def execute(client, command, timeout):
        return "[!] failed" if next(counter) == 0 else "ok"

    _module(monkeypatch, "core.killchain.ssh_helpers", _ssh_exec=execute)
    output = post_tools._run_controlled_ssh_inventory("host")
    assert "[-] Identity" in output and "[+] Whoami" in output
    assert "inventory completed" in output

    fake_source = tmp_path / "core" / "tools" / "post_tools.py"
    monkeypatch.setattr(post_tools, "__file__", str(fake_source))
    path = Path(post_tools._write_generated_artifact("artifact.txt", "content"))
    assert path.read_text() == "content"


def test_hash_candidate_discovery_and_registration(monkeypatch):
    monkeypatch.setattr(post_tools.os.path, "isfile", lambda path: path == "direct")
    assert post_tools._candidate_hash_files_for_target("direct") == ["direct"]

    monkeypatch.setattr(post_tools.os.path, "expanduser", lambda path: "/loot")
    monkeypatch.setattr(post_tools.os.path, "isdir", lambda path: path in {"/loot", "/tmp"})
    monkeypatch.setattr(post_tools.os, "listdir", lambda path: ["tmp.hash", "ignore.txt"])
    monkeypatch.setattr(post_tools.os, "walk", lambda path: [(path, [], ["shadow", "zero.hash", "bad.hash", "ignore"])])

    def size(path):
        if path.endswith("bad.hash"):
            raise OSError("gone")
        return 0 if path.endswith("zero.hash") else 10

    monkeypatch.setattr(post_tools.os.path, "getsize", size)
    monkeypatch.setattr(post_tools.os.path, "getmtime", lambda path: 2 if "tmp" in path else 1)
    candidates = post_tools._candidate_hash_files_for_target("host:1/path")
    assert candidates == ["/tmp/tmp.hash", "/loot/shadow"]
    monkeypatch.setattr(post_tools.os.path, "isdir", lambda path: False)
    assert post_tools._candidate_hash_files_for_target("host") == []

    monkeypatch.setattr(post_tools.os.path, "isfile", lambda path: path == "file")
    assert post_tools._register_cracked_pairs_from_output("+ a:b", "") == 0
    assert post_tools._register_cracked_pairs_from_output("+ a:b", "file") == 0
    registered = []
    monkeypatch.setattr(post_tools, "register_credential", lambda *args: registered.append(args))
    output = "+ alice:password\n+ blank:   \ninvalid"
    assert post_tools._register_cracked_pairs_from_output(output, "host") == 1
    assert len(registered) == 2


def test_scope_and_active_msf_configuration(monkeypatch):
    assert not post_tools._target_in_authorized_scope("host", ["", None])
    assert post_tools._target_in_authorized_scope("host", ["*"])
    assert post_tools._target_in_authorized_scope("app.example.test", ["*.example.test"])
    assert post_tools._target_in_authorized_scope("10.0.0.4:443", ["10.0.0.0/24"])
    assert not post_tools._target_in_authorized_scope("10.0.1.4", ["10.0.0.0/24"])
    assert not post_tools._target_in_authorized_scope("host", ["10.0.0.0/24", "other"])

    import config

    for strategy, expected in (
        ({}, False),
        ({"allow_active_msf": True}, False),
        ({"allow_active_msf": True, "active_authorized": True, "authorized_targets": ["other"]}, False),
        ({"allow_active_msf": True, "active_authorized": True, "authorized_targets": ["host"]}, True),
    ):
        monkeypatch.setattr(config, "CFG", {"strategy": strategy})
        assert post_tools._active_msf_allowed_for_target("host") is expected
    with _blocked_import("config"):
        assert not post_tools._active_msf_allowed_for_target("host")


def test_killchain_exploit_and_msf_wrappers(monkeypatch):
    import core.exploits.selector as selector
    import core.killchain as killchain
    import core.killchain.policy as policy

    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: f"deny:{stage}")
    assert post_tools.ai_vuln_assess("host") == "deny:vuln_assess"
    assert post_tools.ai_auto_exploit("host") == "deny:exploitation"
    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "")
    monkeypatch.setattr(killchain, "vuln_assess", lambda target, recon: f"vuln:{recon}")
    monkeypatch.setattr(killchain, "auto_exploit", lambda target, recon: f"exploit:{recon}")
    assert post_tools.ai_vuln_assess("host", "data") == "vuln:data"
    assert post_tools.ai_auto_exploit("host", "data") == "exploit:data"
    monkeypatch.setattr(selector, "select_exploits", lambda target, recon: f"selected:{target}")
    assert post_tools.ai_exploit_select("host") == "selected:host"

    assert "requires target and module" in post_tools.ai_msf_check("host")
    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("", None, "blocked"))
    assert post_tools.ai_msf_check("host", "module") == "blocked"
    calls = []
    _module(monkeypatch, "msf", run_msf_module=lambda *args, **kwargs: calls.append((args, kwargs)) or "msf ok")
    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("RPORT=1", None, ""))
    assert post_tools.ai_msf_check("host", "module") == "msf ok"
    assert "RHOSTS=host" in calls[-1][0][1]
    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("RHOSTS=other", None, ""))
    post_tools.ai_msf_check("host", "module")
    assert calls[-1][0][1] == "RHOSTS=host"

    credential = _ref()
    monkeypatch.setattr(post_tools, "call_credential_provider", _call_provider)
    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("", credential, ""))
    assert post_tools.ai_msf_check("host", "module") == "msf ok"
    assert calls[-1][1]["credential"].password == "secret"

    for marker, service in (
        ("ssh_login", "ssh"),
        ("postgres_login", "postgresql"),
        ("mysql_login", "mysql"),
        ("ftp_login", "ftp"),
        ("smb_login", "smb"),
        ("mssql_login", "mssql"),
    ):
        assert post_tools._msf_login_service(marker) == service
    assert post_tools._msf_login_service("other") == ""


def test_msf_login_preparation_and_provider_gates(monkeypatch):
    credential = _ref()
    assert post_tools._prepare_msf_login_check("host", "module", "A=1") == ("A=1", None, "")
    assert "prohibited" in post_tools._prepare_msf_login_check("host", "ssh_login", "PASSWORD=x")[2]

    refs = iter([credential, None, credential, None, None])
    monkeypatch.setattr(post_tools, "get_best_credential_ref", lambda *args, **kwargs: next(refs))
    opts, result, error = post_tools._prepare_msf_login_check("host", "ssh_login", "")
    assert result is credential and "STOP_ON_SUCCESS" in opts and not error
    opts, result, error = post_tools._prepare_msf_login_check("host", "ftp_login", "")
    assert result is credential and not error
    assert "requires registered credentials" in post_tools._prepare_msf_login_check("host", "ssh/login", "")[2]

    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("opts", None, ""))
    assert post_tools._scope_msf_login_check("host", "module", "") == "opts"
    monkeypatch.setattr(post_tools, "_prepare_msf_login_check", lambda *args: ("", None, "error"))
    assert post_tools._scope_msf_login_check("host", "module", "") == "error"
    finalized = post_tools._finalize_msf_login_check_options("STOP_ON_SUCCESS=false VERBOSE=true CreateSession=true")
    assert finalized == "STOP_ON_SUCCESS=false VERBOSE=true CreateSession=true"
    finalized = post_tools._finalize_msf_login_check_options("")
    assert all(key in finalized for key in ("STOP_ON_SUCCESS", "VERBOSE", "CreateSession"))

    import core.killchain.policy as policy

    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "denied")
    assert (
        post_tools._run_ssh_credential_provider(
            "host", None, None, lambda *args: "ok", missing_message="missing", killchain_stage="stage"
        )
        == "denied"
    )
    monkeypatch.setattr(policy, "stage_gate_message", lambda stage: "")
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, "bad handle"))
    assert (
        post_tools._run_ssh_credential_provider(
            "host", None, "credential://bad", lambda *args: "ok", missing_message="missing", killchain_stage="stage"
        )
        == "bad handle"
    )
    assert (
        post_tools._run_ssh_credential_provider("host", None, None, lambda *args: "ok", missing_message="missing")
        == "missing"
    )
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (credential, ""))
    monkeypatch.setattr(post_tools, "call_credential_provider", _call_provider)
    assert (
        post_tools._run_ssh_credential_provider(
            "host", None, credential.handle, lambda target, user, pwd: f"{user}:{pwd}", missing_message="missing"
        )
        == "alice:secret"
    )

    monkeypatch.setattr(policy, "master_gate_message", lambda: "master denied")
    assert (
        post_tools._run_full_killchain_credential_provider(
            "host", None, None, lambda *args, **kwargs: "ok", missing_message="missing"
        )
        == "master denied"
    )
    monkeypatch.setattr(policy, "master_gate_message", lambda: "")
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, "bad"))
    assert (
        post_tools._run_full_killchain_credential_provider(
            "host", None, "credential://bad", lambda *args, **kwargs: "ok", missing_message="missing"
        )
        == "bad"
    )
    assert (
        post_tools._run_full_killchain_credential_provider(
            "host", None, None, lambda *args, **kwargs: "ok", missing_message="missing"
        )
        == "missing"
    )
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (credential, ""))
    monkeypatch.setattr(post_tools, "sanitize_credential_result", lambda cred, value: str(value).replace("secret", "X"))
    assert (
        post_tools._run_full_killchain_credential_provider(
            "host",
            None,
            None,
            lambda *args, **kwargs: f"ok secret:{kwargs['callback_host']}",
            missing_message="missing",
            provider_kwargs={"callback_host": "callback"},
        )
        == "ok X:callback"
    )
    failure = post_tools._run_full_killchain_credential_provider(
        "host",
        None,
        None,
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret")),
        missing_message="missing",
    )
    assert "RuntimeError" in failure and "secret" not in failure


def test_active_msf_and_killchain_ai_wrappers(monkeypatch):
    monkeypatch.setattr(post_tools, "_active_msf_allowed_for_target", lambda target: False)
    assert "disabled" in post_tools.ai_msf_run("host", "module")
    monkeypatch.setattr(post_tools, "_active_msf_allowed_for_target", lambda target: True)
    assert "requires target and module" in post_tools.ai_msf_run("host")
    calls = []
    _module(monkeypatch, "msf", run_msf_module=lambda *args, **kwargs: calls.append((args, kwargs)) or "run")
    assert post_tools.ai_msf_run("host", "module", "RPORT=1") == "run"
    assert "RHOSTS=host" in calls[-1][0][1]
    post_tools.ai_msf_run("host", "module", "RHOSTS=other")
    assert calls[-1][0][1] == "RHOSTS=host"

    captured = []
    monkeypatch.setattr(
        post_tools, "_run_ssh_credential_provider", lambda *args, **kwargs: captured.append((args, kwargs)) or "wrapped"
    )
    monkeypatch.setattr(
        post_tools,
        "_run_full_killchain_credential_provider",
        lambda *args, **kwargs: captured.append((args, kwargs)) or "full",
    )
    for wrapper in (
        post_tools.ai_privesc,
        post_tools.ai_persist,
        post_tools.ai_lateral,
        post_tools.ai_exfil,
        post_tools.ai_stealth_cleanup,
        post_tools.ai_deploy_c2_beacon,
    ):
        assert wrapper("host") == "wrapped"
    assert post_tools.ai_full_killchain("host", callback_host="callback") == "full"
    assert captured[-1][1]["provider_kwargs"] == {"callback_host": "callback"}
    assert len(captured) == 7


def test_shodan_browser_and_hash_ai_wrappers(monkeypatch):
    _module(monkeypatch, "shodan_module", run_shodan_smart=lambda query: f"smart:{query}")
    assert post_tools.ai_shodan_smart("query") == "smart:query"
    with _blocked_import("shodan_module"):
        assert "not found" in post_tools.ai_shodan_smart("query")

    monkeypatch.setattr(post_tools, "run_scrapling_fetch", lambda url: f"fetched:{url}")
    context = ExecutionContext.automatic(
        ("host",),
        actor="post-tools-browser-contract",
        origin="tests",
    )
    with bind_execution_context(context):
        output = post_tools.ai_browser_surface_analysis("host")
        assert "Browser Surface Analysis" in output
        assert "fetched:https://host" in output

    _module(monkeypatch, "hash_cracker", run_crack_hashes=lambda path: f"+ alice:secret\n{path}")
    monkeypatch.setattr(post_tools, "_candidate_hash_files_for_target", lambda target: ["hashes"])
    monkeypatch.setattr(post_tools, "_register_cracked_pairs_from_output", lambda output, target: 1)
    assert "Auto-selected" in post_tools.ai_crack_hashes("host")
    monkeypatch.setattr(post_tools, "_candidate_hash_files_for_target", lambda target: [])
    assert "registered: 1" in post_tools.ai_crack_hashes("host")
    with _blocked_import("hash_cracker"):
        assert "not found" in post_tools.ai_crack_hashes("host")


class _Cursor:
    def __init__(self):
        self.fetches = iter([("version",), ("current",)])
        self.closed = False

    def execute(self, query):
        self.query = query

    def fetchone(self):
        return next(self.fetches)

    def fetchall(self):
        return [("db1",), ("db2",)]

    def close(self):
        self.closed = True


class _Connection:
    def __init__(self, *, close_error=False):
        self.cur = _Cursor()
        self.close_error = close_error
        self.session = None

    def set_session(self, **kwargs):
        self.session = kwargs

    def cursor(self):
        return self.cur

    def close(self):
        if self.close_error:
            raise RuntimeError("close")


def test_database_helper_normalization_and_known_refs(monkeypatch):
    assert post_tools._db_clean_host(" https://host:5432/path ") == "host"
    for value in ("postgres", "pgsql", "postgresql"):
        assert post_tools._db_service_name(value, 0) == "postgresql"
    for value in ("mysql", "mariadb"):
        assert post_tools._db_service_name(value, 0) == "mysql"
    assert post_tools._db_service_name("", 5432) == "postgresql"
    assert post_tools._db_service_name("", 3306) == "mysql"
    assert post_tools._db_service_name("oracle", 1521) == "oracle"

    primary = _ref(service="postgresql", port=5432, suffix="db")
    alias = _ref(service="postgres", port=0, suffix="alias")
    wrong = _ref(service="pgsql", port=1111, suffix="wrong")
    monkeypatch.setattr(
        post_tools,
        "get_all_credential_refs_for_target",
        lambda host: {"postgresql": [primary], "postgres": [alias, primary], "pgsql": [wrong]},
    )
    assert set(post_tools._db_known_creds("host", "postgresql", 5432)) == {primary, alias}
    mysql = _ref(service="mariadb", port=3306, suffix="mysql")
    monkeypatch.setattr(post_tools, "get_all_credential_refs_for_target", lambda host: {"mariadb": [mysql]})
    assert post_tools._db_known_creds("host", "mysql", 3306) == [mysql]


def test_postgres_inventory_driver_and_failure_paths(monkeypatch):
    connection = _Connection()
    psycopg2 = _module(monkeypatch, "psycopg2", connect=lambda **kwargs: connection)
    result = post_tools._postgres_inventory("host", 5432, "alice", "secret")
    assert result["databases"] == ["db1", "db2"]
    assert connection.session == {"readonly": True, "autocommit": True}

    fallback_connection = _Connection(close_error=True)
    _module(monkeypatch, "psycopg", connect=lambda **kwargs: fallback_connection)
    with _blocked_import("psycopg2"):
        assert post_tools._postgres_inventory("host", 5432, "alice", "secret")["version"] == "version"

    psycopg2.connect = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("connect error"))
    assert "connect error" in post_tools._postgres_inventory("host", 5432, "alice", "secret")["error"]
    with _blocked_import("psycopg2"), _blocked_import("psycopg"):
        assert "driver unavailable" in post_tools._postgres_inventory("host", 5432, "alice", "secret")["error"]


def test_mysql_inventory_driver_and_failure_paths(monkeypatch):
    connection = _Connection()
    pymysql = _module(monkeypatch, "pymysql", connect=lambda **kwargs: connection)
    result = post_tools._mysql_inventory("host", 3306, "alice", "secret")
    assert result["databases"] == ["db1", "db2"]

    fallback_connection = _Connection(close_error=True)
    mysql_package = _module(monkeypatch, "mysql")
    connector = _module(monkeypatch, "mysql.connector", connect=lambda **kwargs: fallback_connection)
    mysql_package.connector = connector
    with _blocked_import("pymysql"):
        assert post_tools._mysql_inventory("host", 3306, "alice", "secret")["version"] == "version"

    pymysql.connect = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("connect error"))
    assert "connect error" in post_tools._mysql_inventory("host", 3306, "alice", "secret")["error"]
    with _blocked_import("pymysql"), _blocked_import("mysql.connector"):
        assert "driver unavailable" in post_tools._mysql_inventory("host", 3306, "alice", "secret")["error"]


def test_ai_database_inventory_all_outcomes(monkeypatch):
    assert "requires a database service" in post_tools.ai_db_inventory("host", port="bad")
    assert "requires a port" in post_tools.ai_db_inventory("host", service="oracle")
    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [])
    assert "requires known" in post_tools.ai_db_inventory("host", 5432, "postgres")

    skipped = _ref(user="", service="postgresql", port=5432, suffix="skip")
    key_auth = _ref(service="postgresql", port=5432, auth_kind="ssh_key", suffix="key")
    first = _ref(service="postgresql", port=5432, suffix="first")
    second = _ref(user="bob", service="postgresql", port=5432, suffix="second")
    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [skipped, first, second])
    monkeypatch.setattr(post_tools, "credential_material_for_execution", _material_context("secret"))
    results = iter(
        [
            {"error": "failed secret"},
            {"version": "version secret", "current_user": "bob secret", "databases": ["one secret"]},
        ]
    )
    monkeypatch.setattr(post_tools, "_postgres_inventory", lambda *args: next(results))
    monkeypatch.setattr(
        post_tools, "sanitize_credential_text", lambda value, plaintext: str(value).replace(plaintext, "X")
    )
    output = post_tools.ai_db_inventory("https://host/path", 0, "postgres")
    assert "Attempt failed: failed [REDACTED]" in output
    assert "version X" in output and "one X" in output

    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [key_auth])
    assert "DB inventory failed" in post_tools.ai_db_inventory("host", 5432, "postgres")

    mysql_ref = _ref(service="mysql", port=3306, suffix="mysql")
    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [mysql_ref])
    monkeypatch.setattr(post_tools, "_mysql_inventory", lambda *args: {"version": "v", "databases": []})
    output = post_tools.ai_db_inventory("host", 0, "mysql")
    assert "Current user: alice" in output

    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [first])
    monkeypatch.setattr(post_tools, "_postgres_inventory", lambda *args: {"error": "last"})
    output = post_tools.ai_db_inventory("host", 5432, "postgresql")
    assert "DB inventory failed" in output and "Last error: last" in output

    oracle = _ref(service="oracle", port=1521, suffix="oracle")
    monkeypatch.setattr(post_tools, "_db_known_creds", lambda *args: [oracle])
    output = post_tools.ai_db_inventory("host", 1521, "oracle")
    assert "unsupported database service" in output


def test_ssh_ai_wrappers_and_exec_cleanup(monkeypatch):
    credential = _ref()
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, "bad"))
    assert post_tools.ai_ssh_session("host", pwd="credential://bad") == "bad"
    assert "No SSH credentials" in post_tools.ai_ssh_session("host")
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (credential, ""))
    monkeypatch.setattr(post_tools, "call_credential_provider", _call_provider)
    monkeypatch.setattr(post_tools, "_ssh_analyze", lambda *args, **kwargs: "analysis")
    assert post_tools.ai_ssh_session("host") == "analysis"

    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (None, ""))
    assert "requires valid" in post_tools.ai_ssh_inventory("host")
    monkeypatch.setattr(post_tools, "_resolve_ai_creds", lambda *args, **kwargs: (credential, ""))
    monkeypatch.setattr(post_tools, "_run_controlled_ssh_inventory", lambda *args, **kwargs: "inventory")
    assert post_tools.ai_ssh_inventory("host") == "inventory"

    monkeypatch.setattr(post_tools, "_ssh_exec_block_reason", lambda command: "blocked")
    assert "ssh_exec blocked" in post_tools.ai_ssh_exec("host", command='"id"')
    monkeypatch.setattr(post_tools, "_ssh_exec_block_reason", lambda command: "")
    monkeypatch.setattr(
        post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (None, None, None, "connect error")
    )
    assert post_tools.ai_ssh_exec("host", command="id") == "connect error"

    helpers = _module(monkeypatch, "core.killchain.ssh_helpers", _ssh_exec=lambda client, command, timeout: "uid=0")
    client = _Client(close_error=True)
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    assert "uid=0" in post_tools.ai_ssh_exec("host", command="id")
    assert client.closed
    helpers._ssh_exec = lambda client, command, timeout: "other"


def test_ad_ai_wrappers_error_requirements_and_success(monkeypatch):
    import core.killchain.ad.credential as ad_credential
    import core.killchain.ad.enumeration as enumeration
    import core.killchain.ad.kerberos as kerberos
    import core.killchain.ad.lateral as lateral

    @contextmanager
    def context(value):
        yield value

    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((None, "bad creds")))
    for wrapper in (
        post_tools.ai_ad_enum,
        post_tools.ai_bloodhound_ingest,
        post_tools.ai_gpo_review,
        post_tools.ai_asrep_roast,
        post_tools.ai_kerberoast,
        post_tools.ai_dcsync,
        post_tools.ai_psexec,
        post_tools.ai_wmiexec,
    ):
        assert wrapper("host") == "bad creds"

    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((None, "")))
    assert "BloodHound requires" in post_tools.ai_bloodhound_ingest("host")
    assert "GPO review requires" in post_tools.ai_gpo_review("host")
    assert "Kerberoasting requires" in post_tools.ai_kerberoast("host")
    assert "DCSync requires" in post_tools.ai_dcsync("host")
    assert "PsExec requires" in post_tools.ai_psexec("host")
    assert "WMIExec requires" in post_tools.ai_wmiexec("host")

    domain_only = {"user": "", "domain": "CORP", "password": ""}
    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((domain_only, "")))
    monkeypatch.setattr(post_tools, "_call_ad_provider", lambda creds, provider: str(provider()))
    monkeypatch.setattr(enumeration, "run_ad_enum", lambda target, creds=None: "enum")
    monkeypatch.setattr(kerberos, "asrep_roast", lambda target, creds=None: f"asrep:{creds}")
    assert post_tools.ai_ad_enum("host") == "enum"
    assert post_tools.ai_asrep_roast("host") == "asrep:{'user': '', 'domain': 'CORP', 'password': ''}"

    creds = {"user": "alice", "domain": "CORP", "password": "secret"}
    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((creds, "")))
    monkeypatch.setattr(enumeration, "bloodhound_ingest", lambda target, value: "bloodhound")
    monkeypatch.setattr(enumeration, "enumerate_gpo", lambda target, value: "gpo")
    monkeypatch.setattr(kerberos, "kerberoast", lambda target, value: "kerberoast")
    monkeypatch.setattr(ad_credential, "dcsync", lambda target, value: "dcsync")
    monkeypatch.setattr(lateral, "psexec", lambda target, value, command: f"psexec:{command}")
    monkeypatch.setattr(lateral, "wmiexec", lambda target, value, command: f"wmiexec:{command}")
    assert post_tools.ai_bloodhound_ingest("host") == "bloodhound"
    assert "gpo" in post_tools.ai_gpo_review("host")
    assert post_tools.ai_kerberoast("host") == "kerberoast"
    assert post_tools.ai_dcsync("host") == "dcsync"
    assert post_tools.ai_psexec("host", command='"whoami"') == "psexec:whoami"
    assert post_tools.ai_wmiexec("host", command="'hostname'") == "wmiexec:hostname"


def test_adcs_review_binary_credentials_and_provider(monkeypatch):
    @contextmanager
    def context(value):
        yield value

    monkeypatch.setattr(post_tools.shutil, "which", lambda name: None)
    assert "not installed" in post_tools.ai_adcs_review("host")
    monkeypatch.setattr(post_tools.shutil, "which", lambda name: "/bin/certipy" if name == "certipy-ad" else None)
    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((None, "bad")))
    assert post_tools.ai_adcs_review("host") == "bad"
    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((None, "")))
    assert "requires domain credentials" in post_tools.ai_adcs_review("host")
    creds = {"user": "alice", "domain": "CORP", "password": "secret"}
    monkeypatch.setattr(post_tools, "_ad_creds_for_execution", lambda *args, **kwargs: context((creds, "")))
    monkeypatch.setattr(post_tools, "_call_ad_provider", lambda creds, provider: str(provider()))
    calls = []
    monkeypatch.setattr(post_tools, "run_tool", lambda cmd, timeout: calls.append((cmd, timeout)) or "certipy")
    assert "certipy" in post_tools.ai_adcs_review("host")
    assert "alice@CORP" in calls[0][0]


def test_pivot_and_internal_network_wrappers(monkeypatch):
    client = _Client()
    monkeypatch.setattr(
        post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (None, None, None, "connect error")
    )
    for call in (
        lambda: post_tools.ai_socks_proxy("host"),
        lambda: post_tools.ai_port_forward("host"),
        lambda: post_tools.ai_network_recon("host"),
        lambda: post_tools.ai_internal_service_probe("host"),
    ):
        assert call() == "connect error"

    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    import core.killchain.pivot as pivot

    monkeypatch.setattr(pivot, "setup_socks_proxy", lambda client, local_port: f"socks:{local_port}")
    assert post_tools.ai_socks_proxy("host", local_port=1081) == "socks:1081"
    assert client in post_tools._PIVOT_SSH_CLIENTS

    failing = _Client()
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (failing, "alice", "handle", ""))
    monkeypatch.setattr(pivot, "setup_socks_proxy", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("fail")))
    with pytest.raises(RuntimeError):
        post_tools.ai_socks_proxy("host")
    assert failing.closed

    client = _Client()
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    forward_calls = []
    monkeypatch.setattr(
        pivot,
        "setup_local_forward",
        lambda client, local, remote, port: forward_calls.append((local, remote, port)) or "forward",
    )
    assert post_tools.ai_port_forward("host", remote_host="db:5432") == "forward"
    assert forward_calls[-1][1:] == ("db", 5432)
    assert post_tools.ai_port_forward("host", remote_host="db:name") == "forward"
    assert forward_calls[-1][1:] == ("db:name", 80)
    assert post_tools.ai_port_forward("host", remote_host=123) == "forward"

    failing = _Client()
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (failing, "alice", "handle", ""))
    monkeypatch.setattr(pivot, "setup_local_forward", lambda *args: (_ for _ in ()).throw(RuntimeError("fail")))
    with pytest.raises(RuntimeError):
        post_tools.ai_port_forward("host")
    assert failing.closed

    client = _Client()
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    monkeypatch.setattr(pivot, "get_network_info", lambda client: "networks")
    assert post_tools.ai_network_recon("host") == "networks"
    assert client.closed

    client = _Client()
    monkeypatch.setattr(post_tools, "_connect_ssh_for_tool", lambda *args, **kwargs: (client, "alice", "handle", ""))
    helpers = _module(monkeypatch, "core.killchain.ssh_helpers", _ssh_exec=lambda *args, **kwargs: "OPEN 10.0.0.2:22")
    output = post_tools.ai_internal_service_probe("host")
    assert output.startswith("[INTERNAL SERVICE PROBE]")
    helpers._ssh_exec = lambda *args, **kwargs: "[INTERNAL SERVICE PROBE]\nnone"
    assert post_tools.ai_internal_service_probe("host").startswith("[INTERNAL SERVICE PROBE]\nnone")


def test_builders_waf_search_and_plugin_wrappers(monkeypatch, tmp_path):
    import core.c2.builder as builder
    import core.c2.implants.powershell_stager as powershell
    import core.c2.implants.python_implant as python_implant
    import core.tools.exploit_tools as exploit_tools

    monkeypatch.setattr(exploit_tools, "run_bruteforce", lambda service, target: f"brute:{service}:{target}")
    assert post_tools.ai_stealth_brute("ssh", "host") == "brute:ssh:host"
    monkeypatch.setattr(builder, "build_implant", lambda **kwargs: "built")
    assert post_tools.ai_build_go_implant() == "built"
    monkeypatch.setattr(builder, "build_implant", lambda **kwargs: "")
    assert "build finished" in post_tools.ai_build_go_implant()
    monkeypatch.setattr(builder, "build_implant", lambda **kwargs: (_ for _ in ()).throw(SystemExit("stop")))
    assert "build aborted" in post_tools.ai_build_go_implant()

    written = []
    monkeypatch.setattr(
        post_tools, "_write_generated_artifact", lambda name, code: written.append((name, code)) or str(tmp_path / name)
    )
    monkeypatch.setattr(python_implant, "generate_python_implant", lambda **kwargs: "python code")
    assert "Python implant generated" in post_tools.ai_build_python_implant(beacon_interval=5)
    monkeypatch.setattr(powershell, "generate_ps_encoded", lambda url: "encoded")
    monkeypatch.setattr(powershell, "generate_ps_stager", lambda url, method: f"stager:{method}")
    assert "PowerShell stager" in post_tools.ai_build_ps_stager(method="encoded")
    assert "PowerShell stager" in post_tools.ai_build_ps_stager(method="download")

    monkeypatch.setattr(post_tools, "_run_waf_detect", lambda target: "waf")
    assert post_tools.ai_waf_detect("host") == "waf"
    monkeypatch.setattr(post_tools, "run_tool", lambda cmd, timeout: f"tool:{cmd}:{timeout}")
    assert "searchsploit" in post_tools.ai_searchsploit("apache 2")

    with _blocked_import("core.plugins.base"):
        assert "Plugin system unavailable" in post_tools.ai_run_plugin("list")
    with _blocked_import("core.plugins.loader"):
        assert "Plugin system unavailable" in post_tools.ai_plugin_inventory()

    class Context:
        def __init__(self, target):
            self.target = target

    class Manager:
        plugins: ClassVar[dict] = {"demo": object()}
        output = "details"
        calls: ClassVar[list[str]] = []

        def __init__(self, path):
            pass

        def list_plugins(self):
            return ["demo"]

        def list_skipped_plugins(self):
            return []

        def get_plugin(self, name):
            return self.plugins.get(name)

        def check(self, name, target, timeout=60):
            self.calls.append(f"check:{name}:{target}:{timeout}")
            return SimpleNamespace(
                vulnerable=False,
                confidence=0.75,
                details="checked",
                evidence="fixture",
                version="1.0",
            )

        def execute(self, *args, **kwargs):
            self.calls.append(f"run:{args[0]}")
            return SimpleNamespace(
                success=True,
                data={"ok": True},
                artifacts=[],
                credentials=[],
                sessions=[],
                error="",
                output=self.output,
            )

    import core.plugins.base as plugin_base
    import core.plugins.loader as plugin_loader

    monkeypatch.setattr(plugin_base, "PluginContext", Context)
    monkeypatch.setattr(plugin_loader, "PluginManager", Manager)
    inventory = post_tools.ai_plugin_inventory()
    assert '"plugins": [' in inventory and "demo" in inventory
    assert "demo" in post_tools.ai_run_plugin("list")
    assert "demo" in post_tools.ai_run_plugin("summary")
    assert "not found" in post_tools.ai_run_plugin("missing")
    output = post_tools.ai_run_plugin("demo", "host", "scan")
    assert '"action": "check"' in output
    assert Manager.calls == ["check:demo:host:60"]
    assert "not declared" in post_tools.ai_run_plugin("demo", "host", "summary")
    output = post_tools.ai_run_plugin("demo", "host", "run")
    assert "plugin output" in output
    assert Manager.calls[-1] == "run:demo"
    Manager.output = ""
    assert "plugin output" not in post_tools.ai_run_plugin("demo", action="run")
