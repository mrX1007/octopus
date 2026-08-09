"""Hermetic denial, cleanup, and error-path coverage for kill-chain modules."""

from __future__ import annotations

import builtins
import importlib
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

credential = importlib.import_module("core.killchain.ad.credential")
enumeration = importlib.import_module("core.killchain.ad.enumeration")
kerberos = importlib.import_module("core.killchain.ad.kerberos")
lateral = importlib.import_module("core.killchain.ad.lateral")
exfil = importlib.import_module("core.killchain.exfil")
persistence = importlib.import_module("core.killchain.persistence")

pytestmark = [pytest.mark.unit, pytest.mark.security]


class _Client:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def _redirect_exfil_loot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Give exfiltration an isolated filesystem view without patching global ``os``."""

    real_os = exfil.os
    isolated_os = SimpleNamespace(
        path=SimpleNamespace(
            expanduser=lambda _path: str(tmp_path),
            isfile=real_os.path.isfile,
            join=real_os.path.join,
        ),
        makedirs=real_os.makedirs,
    )
    monkeypatch.setattr(exfil, "os", isolated_os)


def _install_report_double(monkeypatch: pytest.MonkeyPatch, calls: list[tuple[object, ...]]) -> None:
    module = ModuleType("core.killchain.orchestrator")

    def generate_report(*args: object) -> None:
        calls.append(args)

    module._generate_target_report = generate_report  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "core.killchain.orchestrator", module)


def test_data_exfil_connection_failure_is_explicit_and_non_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    ssh_exec = Mock(side_effect=AssertionError("execution must not start"))
    monkeypatch.setattr(exfil, "_ssh_connect", lambda *_args: (None, "authentication rejected"))
    monkeypatch.setattr(exfil, "_ssh_exec", ssh_exec)

    output = exfil.data_exfil("host.example", "tester", "")

    assert "SSH connection failed: authentication rejected" in output
    ssh_exec.assert_not_called()


def test_data_exfil_closes_client_when_initial_inventory_raises(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _Client()
    _redirect_exfil_loot(monkeypatch, tmp_path)
    monkeypatch.setattr(exfil, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(exfil, "_ssh_exec", Mock(side_effect=RuntimeError("inventory failed")))

    with pytest.raises(RuntimeError, match="inventory failed"):
        exfil.data_exfil("host.example", "tester", "")

    assert client.close_calls == 1


def test_data_exfil_skips_denied_files_without_sudo_and_reports_zero_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _Client()
    report_calls: list[tuple[object, ...]] = []
    commands: list[str] = []
    _redirect_exfil_loot(monkeypatch, tmp_path)
    _install_report_double(monkeypatch, report_calls)
    monkeypatch.setattr(exfil, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(exfil.shutil, "which", lambda _name: None)

    def ssh_exec(_client: object, command: str, **_kwargs: object) -> str:
        commands.append(command)
        if command == "id":
            return "uid=1000(tester) gid=1000(tester)"
        if command.startswith("sudo -n id"):
            return "sudo: a password is required"
        if command.startswith("find "):
            return ""
        if command == "cat /etc/passwd 2>&1":
            return "Permission denied"
        return "No such file"

    monkeypatch.setattr(exfil, "_ssh_exec", ssh_exec)

    output = exfil.data_exfil("host.example", "tester", "")

    assert "SKIPPED: /etc/passwd — permission denied (non-root, no sudo)" in output
    assert "Files exfiltrated: 0" in output
    assert "Total data: 0 bytes" in output
    assert not any(command.startswith("sudo cat ") for command in commands)
    assert client.close_calls == 1
    assert len(report_calls) == 1
    assert report_calls[0][3] == []


def test_data_exfil_preserves_sudo_denial_as_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _Client()
    report_calls: list[tuple[object, ...]] = []
    _redirect_exfil_loot(monkeypatch, tmp_path)
    _install_report_double(monkeypatch, report_calls)
    monkeypatch.setattr(exfil, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(exfil.shutil, "which", lambda _name: None)

    def ssh_exec(_client: object, command: str, **_kwargs: object) -> str:
        if command == "id":
            return "uid=1000(tester) gid=1000(tester)"
        if command.startswith("sudo -n id"):
            return "uid=0(root) gid=0(root)"
        if command.startswith("find "):
            return ""
        if command.startswith(("cat ", "sudo cat ")):
            return "Permission denied"
        return ""

    monkeypatch.setattr(exfil, "_ssh_exec", ssh_exec)

    output = exfil.data_exfil("host.example", "tester", "")

    assert "SKIPPED: /etc/passwd — permission denied" in output
    assert "Files exfiltrated: 0" in output
    assert report_calls[0][3] == []
    assert client.close_calls == 1


def test_persistence_rejects_missing_or_ambiguous_callback_before_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect = Mock(side_effect=AssertionError("connection must not start"))
    monkeypatch.setattr(persistence, "_ssh_connect", connect)

    missing = persistence.plant_persistence("host.example", "tester", "")
    ambiguous = persistence.plant_persistence(
        "host.example",
        "tester",
        "",
        callback_host="https://callback.example/path",
    )

    assert "explicit callback_host is required" in missing
    assert "callback_host must be one host without URL syntax" in ambiguous
    connect.assert_not_called()


def test_persistence_connection_failure_is_reported_without_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    ssh_exec = Mock(side_effect=AssertionError("execution must not start"))
    monkeypatch.setattr(persistence, "_ssh_connect", lambda *_args: (None, "connection refused"))
    monkeypatch.setattr(persistence, "_ssh_exec", ssh_exec)

    output = persistence.plant_persistence(
        "host.example",
        "tester",
        "",
        callback_host="callback.example",
    )

    assert "SSH connection failed: connection refused" in output
    ssh_exec.assert_not_called()


def test_persistence_closes_client_when_identity_check_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client()
    monkeypatch.setattr(persistence, "_ssh_connect", lambda *_args: (client, ""))
    monkeypatch.setattr(persistence, "_ssh_exec", Mock(side_effect=RuntimeError("identity unavailable")))

    with pytest.raises(RuntimeError, match="identity unavailable"):
        persistence.plant_persistence(
            "host.example",
            "tester",
            "",
            callback_host="callback.example",
        )

    assert client.close_calls == 1


@pytest.mark.parametrize(
    "module",
    [credential, enumeration, kerberos, lateral],
    ids=["credential", "enumeration", "kerberos", "lateral"],
)
def test_ad_cli_boundary_combines_captured_output_without_running_a_tool(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
) -> None:
    run = Mock(return_value=SimpleNamespace(stdout="standard output", stderr="standard error"))
    monkeypatch.setattr(module.subprocess, "run", run)

    assert module._run_cli(["diagnostic-probe"], timeout=7) == "standard outputstandard error"
    run.assert_called_once()
    args, kwargs = run.call_args
    assert args == (["diagnostic-probe"],)
    assert kwargs["shell"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["timeout"] == 7


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (subprocess.TimeoutExpired("diagnostic-probe", 7), "Command timed out after 7s"),
        (FileNotFoundError(), "Command not found"),
        (RuntimeError("boundary failure"), "Command error: RuntimeError"),
    ],
    ids=["timeout", "missing", "unexpected"],
)
@pytest.mark.parametrize(
    "module",
    [credential, enumeration, kerberos, lateral],
    ids=["credential", "enumeration", "kerberos", "lateral"],
)
def test_ad_cli_boundary_maps_failures_to_bounded_messages(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    failure: Exception,
    expected: str,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(module.subprocess, "run", fail)

    assert expected in module._run_cli(["diagnostic-probe"], timeout=7)


@pytest.mark.parametrize(
    "module",
    [credential, enumeration, kerberos, lateral],
    ids=["credential", "enumeration", "kerberos", "lateral"],
)
def test_ad_cli_boundary_rejects_shell_command_strings(
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
) -> None:
    run = Mock(side_effect=AssertionError("string command must not execute"))
    monkeypatch.setattr(module.subprocess, "run", run)

    result = module._run_cli("tool user:password; injected")

    assert "argv sequence is required" in result
    run.assert_not_called()


@pytest.mark.parametrize(
    "module",
    [credential, enumeration, kerberos, lateral],
    ids=["credential", "enumeration", "kerberos", "lateral"],
)
def test_ad_credential_normalizers_default_every_field(module: ModuleType) -> None:
    assert module._normalize_creds(None) == {
        "user": "",
        "password": "",
        "domain": "",
        "nthash": "",
    }


def test_ad_lateral_does_not_copy_or_serialize_provider_secrets() -> None:
    canary = "provider-secret-canary-4d91"
    provider_material = {
        "user": "fixture",
        "password": canary,
        "domain": "EXAMPLE",
        "nthash": "",
    }

    assert lateral._normalize_creds(provider_material) is provider_material
    failure = lateral._provider_failure(RuntimeError(f"failed with {canary}"))
    assert failure == "RuntimeError"
    assert canary not in failure


@pytest.mark.parametrize(
    ("module", "function_name", "expected"),
    [
        (credential, "dcsync", "Domain credentials required"),
        (credential, "dump_lsass", "Credentials required for LSASS dump"),
        (credential, "sam_dump", "Credentials required for SAM dump"),
        (kerberos, "asrep_roast", "Domain name required"),
        (kerberos, "kerberoast", "Authenticated domain credentials required"),
        (kerberos, "extract_tickets", "Domain credentials required"),
        (lateral, "psexec", "Credentials required for PsExec"),
        (lateral, "wmiexec", "Credentials required for WMIExec"),
        (lateral, "smbexec", "Credentials required for SMBExec"),
        (lateral, "winrm_exec", "Credentials required for WinRM"),
        (lateral, "dcom_exec", "Credentials required for DCOM execution"),
    ],
)
def test_ad_actions_fail_closed_when_required_identity_is_missing(
    module: ModuleType,
    function_name: str,
    expected: str,
) -> None:
    output = getattr(module, function_name)("dc.example")

    assert expected in output


def test_ad_credential_artifact_guards_reject_missing_inputs(tmp_path: Path) -> None:
    missing_ticket = str(tmp_path / "missing.ccache")
    raw_hash = "0123456789abcdef0123456789abcdef"

    assert "unsafe_provider_contract_not_mounted" in credential.pass_the_hash("host.example")
    with pytest.raises(TypeError):
        credential.pass_the_hash("host.example", "tester", raw_hash)
    assert "Ticket file not found" in credential.pass_the_ticket("host.example", missing_ticket)
    assert "Ticket file not found" in kerberos.crack_tickets(missing_ticket)


@pytest.mark.parametrize(
    "module",
    [credential, kerberos],
    ids=["credential", "kerberos"],
)
def test_ad_loot_directory_is_scoped_to_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    module: ModuleType,
) -> None:
    monkeypatch.setattr(module, "DEFAULT_LOOT_BASE", str(tmp_path))

    result = module._loot_dir("dc.example")

    assert Path(result).relative_to(tmp_path) == Path("dc_example") / result.rsplit(os.sep, 1)[-1]
    assert Path(result).is_dir()


def test_ldap_backends_fail_closed_when_optional_packages_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ldap3" or name.startswith("impacket.ldap"):
            raise ImportError(f"blocked {name}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    creds = enumeration._normalize_creds(None)

    assert enumeration._ldap_search_impacket("dc.example", "", "(objectClass=*)", [], creds) is None
    assert enumeration._ldap_search_ldap3("dc.example", "", "(objectClass=*)", [], creds) is None


def test_ldap_cli_reports_missing_binary_without_shelling_out(monkeypatch: pytest.MonkeyPatch) -> None:
    run_cli = Mock(side_effect=AssertionError("CLI must not run"))
    monkeypatch.setattr(enumeration.shutil, "which", lambda _name: None)
    monkeypatch.setattr(enumeration, "_run_cli", run_cli)

    output = enumeration._ldap_search_cli(
        "dc.example",
        "DC=EXAMPLE",
        "(objectClass=*)",
        ["displayName"],
        enumeration._normalize_creds(None),
    )

    assert output == "[!] ldapsearch not found in PATH"
    run_cli.assert_not_called()


def test_ldap_formatting_bounds_attributes_and_handles_empty_results() -> None:
    assert enumeration._build_base_dn("") == ""
    assert enumeration._build_base_dn("corp.example") == "DC=CORP,DC=EXAMPLE"
    assert enumeration._format_entries([], "users") == "  No users found.\n"

    output = enumeration._format_entries(
        [
            {
                "dn": "CN=Tester,DC=CORP,DC=EXAMPLE",
                "sAMAccountName": "tester",
                "memberOf": ["one", "two", "three", "four", "five", "six"],
                "description": "bounded",
                "mail": "tester@example.invalid",
                "adminCount": "0",
                "ignored": "fifth detail",
            }
        ],
        "users",
    )

    assert "tester" in output
    assert "one, two, three, four, five" in output
    assert "six" not in output
    assert "ignored=" not in output


@pytest.mark.parametrize(
    ("function_name", "impacket_result", "ldap3_result", "expected"),
    [
        ("enumerate_users", [], None, "via impacket"),
        ("enumerate_groups", None, [], "via ldap3"),
        ("enumerate_computers", None, None, "backend unavailable"),
        ("enumerate_gpo", [{"displayName": "Baseline Policy"}], None, "Baseline Policy"),
    ],
)
def test_ad_enumerators_use_ordered_fallbacks_without_network(
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
    impacket_result: list[dict[str, object]] | None,
    ldap3_result: list[dict[str, object]] | None,
    expected: str,
) -> None:
    impacket_search = Mock(return_value=impacket_result)
    ldap3_search = Mock(return_value=ldap3_result)
    cli_search = Mock(return_value="backend unavailable")
    monkeypatch.setattr(enumeration, "_ldap_search_impacket", impacket_search)
    monkeypatch.setattr(enumeration, "_ldap_search_ldap3", ldap3_search)
    monkeypatch.setattr(enumeration, "_ldap_search_cli", cli_search)

    output = getattr(enumeration, function_name)("dc.example", {"domain": "corp.example"})

    assert expected in output
    assert impacket_search.call_args.args[1] == "DC=CORP,DC=EXAMPLE"
    if impacket_result is not None:
        ldap3_search.assert_not_called()
        cli_search.assert_not_called()
    elif ldap3_result is not None:
        ldap3_search.assert_called_once()
        cli_search.assert_not_called()
    else:
        ldap3_search.assert_called_once()
        cli_search.assert_called_once()


def test_full_ad_enumeration_degrades_when_cli_tools_are_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    run_cli = Mock(side_effect=AssertionError("CLI must not run"))
    monkeypatch.setattr(enumeration.shutil, "which", lambda _name: None)
    monkeypatch.setattr(enumeration, "_run_cli", run_cli)
    monkeypatch.setattr(enumeration, "enumerate_users", lambda *_args: "users\n")
    monkeypatch.setattr(enumeration, "enumerate_groups", lambda *_args: "groups\n")
    monkeypatch.setattr(enumeration, "enumerate_computers", lambda *_args: "computers\n")
    monkeypatch.setattr(enumeration, "enumerate_gpo", lambda *_args: "gpo\n")

    output = enumeration.run_ad_enum("dc.example")

    assert "enum4linux not in PATH" in output
    assert "rpcclient not in PATH" in output
    assert "users\ngroups\ncomputers\ngpo\n" in output
    assert "AD enumeration complete" in output
    run_cli.assert_not_called()


def test_bloodhound_requires_complete_domain_identity_before_filesystem_access() -> None:
    output = enumeration.bloodhound_ingest("dc.example", {"domain": "CORP.EXAMPLE"})

    assert "BloodHound requires domain credentials" in output
