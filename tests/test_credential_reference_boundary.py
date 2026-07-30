"""Canaries for the reference-only credential execution boundary."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from core.credentials import (
    CredentialRef,
    CredentialStore,
    credential_material_for_execution,
    deprecated_plaintext_credential_for_execution,
    get_best_credential_ref,
    register_credential,
)
from core.secrets import SecretStore

pytestmark = [pytest.mark.contract, pytest.mark.security]

CANARY = "credential-canary-must-never-reach-control-plane"
HOST = "198.51.100.73"


@pytest.fixture
def credential_store(monkeypatch):
    secret_store = SecretStore(":memory:", key=b"c" * 32)
    store = CredentialStore(secret_store=secret_store, hydrate=False)
    monkeypatch.setattr(CredentialStore, "_instance", store)
    yield store
    secret_store.close()


def test_store_and_public_lookup_are_reference_only(credential_store):
    assert register_credential("ssh", HOST, "support", CANARY, quiet=True) is True

    credential = get_best_credential_ref(HOST, "ssh")

    assert isinstance(credential, CredentialRef)
    assert credential.handle.startswith("credential://")
    assert not hasattr(credential, "secret_ref")
    assert CANARY not in repr(credential_store._cache)
    assert CANARY not in repr(credential)
    assert "secret://" not in repr(credential.audit_dict())
    assert "secret://" not in repr(credential_store.to_dict())
    assert not hasattr(credential_store, "_kg_available")


def test_plaintext_exists_only_inside_explicit_execution_context(credential_store):
    register_credential("ssh", HOST, "support", CANARY, quiet=True)
    credential = get_best_credential_ref(HOST, "ssh")
    assert credential is not None

    with credential_material_for_execution(credential) as material:
        assert material.username == "support"
        assert material.password == CANARY
        assert CANARY not in repr(material)

    assert material.password == ""

    with pytest.warns(FutureWarning, match="deprecated"), deprecated_plaintext_credential_for_execution(
        credential.handle
    ) as compatibility_material:
        assert compatibility_material.password == CANARY
    assert compatibility_material.password == ""


def test_port_is_part_of_handle_identity_and_execution_scope(credential_store):
    secret_ref = credential_store.secret_store.store(
        CANARY,
        kind="credential:ssh",
    )
    port_22, created_22 = credential_store.register(
        "ssh",
        HOST,
        "support",
        secret_ref,
        port=22,
        quiet=True,
    )
    port_2222, created_2222 = credential_store.register(
        "ssh",
        HOST,
        "support",
        secret_ref,
        port=2222,
        quiet=True,
    )

    assert created_22 is True
    assert created_2222 is True
    assert port_22.handle != port_2222.handle
    assert port_22.port == 22
    assert port_2222.port == 2222
    assert not hasattr(port_22, "secret_ref")


def test_full_orchestrator_reveals_only_to_each_provider_and_sanitizes_results(
    credential_store,
    monkeypatch,
):
    from core.killchain import orchestrator

    secret_ref = credential_store.secret_store.store(
        CANARY,
        kind="credential:ssh",
    )
    credential, _created = credential_store.register(
        "ssh",
        HOST,
        "support",
        secret_ref,
        port=2222,
        quiet=True,
    )
    calls = []

    def provider(name):
        def run(target, username, password, port):
            calls.append((name, target, username, password, port))
            return f"{name}:provider-result:{password}:{secret_ref}"

        return run

    monkeypatch.setattr(orchestrator, "master_gate_message", lambda: "")
    monkeypatch.setattr(orchestrator, "stage_gate_message", lambda _stage: "")
    monkeypatch.setattr(orchestrator, "run_privesc", provider("privesc"))
    monkeypatch.setattr(orchestrator, "plant_persistence", provider("persistence"))
    monkeypatch.setattr(orchestrator, "lateral_move", provider("lateral_movement"))
    monkeypatch.setattr(orchestrator, "data_exfil", provider("data_exfil"))
    monkeypatch.setattr(orchestrator, "stealth_cleanup", provider("cleanup"))
    monkeypatch.setattr(orchestrator.os, "makedirs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orchestrator, "_generate_target_report", lambda *_args: None)

    output = orchestrator.run_full_killchain(
        HOST,
        credential=credential.handle,
        port=2222,
    )

    assert [call[0] for call in calls] == [
        "privesc",
        "persistence",
        "lateral_movement",
        "data_exfil",
        "cleanup",
    ]
    assert all(call[1:] == (HOST, "support", CANARY, 2222) for call in calls)
    assert CANARY not in output
    assert secret_ref not in output
    assert output.count("[REDACTED]") >= len(calls) * 2


@pytest.mark.parametrize(
    (
        "service",
        "registered_target",
        "registered_port",
        "call_target",
        "call_user",
        "call_port",
        "expected_error",
    ),
    [
        ("ldap", HOST, 2222, HOST, None, 2222, "scope mismatch"),
        ("ssh", "198.51.100.74", 2222, HOST, None, 2222, "scope mismatch"),
        ("ssh", HOST, 2222, HOST, "root", 2222, "username mismatch"),
        ("ssh", HOST, 2222, HOST, None, 22, "port mismatch"),
    ],
)
def test_full_orchestrator_rejects_mismatched_credential_scope_before_provider(
    credential_store,
    monkeypatch,
    service,
    registered_target,
    registered_port,
    call_target,
    call_user,
    call_port,
    expected_error,
):
    from core.killchain import orchestrator

    secret_ref = credential_store.secret_store.store(
        CANARY,
        kind=f"credential:{service}",
    )
    credential, _created = credential_store.register(
        service,
        registered_target,
        "support",
        secret_ref,
        port=registered_port,
        quiet=True,
    )
    calls = []
    monkeypatch.setattr(orchestrator, "master_gate_message", lambda: "")
    monkeypatch.setattr(
        orchestrator,
        "run_privesc",
        lambda *_args: calls.append(_args) or "unexpected",
    )

    output = orchestrator.run_full_killchain(
        call_target,
        user=call_user,
        credential=credential,
        port=call_port,
    )

    assert expected_error in output
    assert calls == []
    assert CANARY not in output
    assert secret_ref not in output


def test_registered_killchain_wrapper_sanitizes_provider_error(
    credential_store,
    monkeypatch,
):
    import core.killchain
    from core.killchain import policy
    from core.tools import post_tools

    secret_ref = credential_store.secret_store.store(
        CANARY,
        kind="credential:ssh",
    )
    credential, _created = credential_store.register(
        "ssh",
        HOST,
        "support",
        secret_ref,
        port=22,
        quiet=True,
    )
    seen = []

    def failing_provider(target, username, password):
        seen.append((target, username, password))
        raise RuntimeError(f"provider rejected {password} from {secret_ref}")

    monkeypatch.setattr(policy, "stage_gate_message", lambda _stage: "")
    monkeypatch.setattr(core.killchain, "run_privesc", failing_provider)

    output = post_tools.ai_privesc(
        HOST,
        user="support",
        pwd=credential.handle,
    )

    assert seen == [(HOST, "support", CANARY)]
    assert "RuntimeError" in output
    assert CANARY not in output
    assert secret_ref not in output
    assert output.count("[REDACTED]") == 2


def test_full_wrapper_passes_only_reference_and_sanitizes_provider_result(
    credential_store,
    monkeypatch,
):
    import core.killchain
    from core.killchain import policy
    from core.tools import post_tools

    secret_ref = credential_store.secret_store.store(
        CANARY,
        kind="credential:ssh",
    )
    credential, _created = credential_store.register(
        "ssh",
        HOST,
        "support",
        secret_ref,
        port=22,
        quiet=True,
    )
    seen = []

    def fake_orchestrator(target, *, credential):
        seen.append((target, credential))
        return f"provider-result:{CANARY}:{secret_ref}"

    monkeypatch.setattr(policy, "master_gate_message", lambda: "")
    monkeypatch.setattr(core.killchain, "run_full_killchain", fake_orchestrator)

    output = post_tools.ai_full_killchain(
        HOST,
        user="support",
        pwd=credential.handle,
    )

    assert seen == [(HOST, credential)]
    assert isinstance(seen[0][1], CredentialRef)
    assert not hasattr(seen[0][1], "secret_ref")
    assert CANARY not in output
    assert secret_ref not in output
    assert output == "provider-result:[REDACTED]:[REDACTED]"


def test_ssh_authentication_error_never_echoes_password(monkeypatch):
    from core.killchain import ssh_helpers

    class AuthenticationError(Exception):
        pass

    class Client:
        def set_missing_host_key_policy(self, _policy):
            pass

        def connect(self, **_kwargs):
            raise AuthenticationError(CANARY)

    fake_paramiko = SimpleNamespace(
        AuthenticationException=AuthenticationError,
        AutoAddPolicy=lambda: object(),
        SSHClient=Client,
    )
    monkeypatch.setattr(ssh_helpers, "paramiko", fake_paramiko)

    client, error = ssh_helpers._ssh_connect(HOST, "support", CANARY)

    assert client is None
    assert error == f"Auth failed: support@{HOST}"
    assert CANARY not in error


def test_bruteforce_skip_never_prints_or_returns_secret(credential_store, capsys):
    from core.tools import exploit_tools

    register_credential("ssh", HOST, "support", CANARY, quiet=True)

    output = exploit_tools.run_bruteforce("ssh", HOST)
    terminal = capsys.readouterr().out

    assert "Credentials already known" in output
    assert CANARY not in output + terminal
    assert "secret://" not in output + terminal
    assert "[TOOL: ssh_session" not in output
    assert not hasattr(exploit_tools, "_KNOWN_CREDS")


def test_msf_cached_secret_is_typed_provider_input_not_options(
    credential_store,
    monkeypatch,
):
    from core.tools import post_tools

    register_credential("ssh", HOST, "support", CANARY, quiet=True)
    seen = {}

    def fake_run(module, options, *, mode, credential=None, **_kwargs):
        seen.update(
            module=module,
            options=options,
            mode=mode,
            username=credential.username if credential else "",
            password=credential.password if credential else "",
            credential_repr=repr(credential),
        )
        return "provider-called"

    monkeypatch.setitem(
        sys.modules,
        "msf",
        SimpleNamespace(run_msf_module=fake_run),
    )

    output = post_tools.ai_msf_check(
        HOST,
        "auxiliary/scanner/ssh/ssh_login",
        f"RHOSTS={HOST} RPORT=22",
    )

    assert output == "provider-called"
    assert seen["username"] == "support"
    assert seen["password"] == CANARY
    assert CANARY not in seen["options"]
    assert "secret://" not in seen["options"]
    assert "credential://" not in seen["options"]
    assert CANARY not in seen["credential_repr"]


def test_msf_plaintext_options_fail_closed_before_provider(
    credential_store,
    monkeypatch,
):
    from core.tools import post_tools

    called = []
    monkeypatch.setitem(
        sys.modules,
        "msf",
        SimpleNamespace(run_msf_module=lambda *args, **kwargs: called.append((args, kwargs))),
    )

    output = post_tools.ai_msf_check(
        HOST,
        "auxiliary/scanner/ssh/ssh_login",
        f"RHOSTS={HOST} USERNAME=support PASSWORD={CANARY}",
    )

    assert "credential options are prohibited" in output
    assert CANARY not in output
    assert called == []


def test_ad_resolver_returns_only_scoped_reference(credential_store):
    from core.tools import post_tools

    register_credential(
        "ldap",
        HOST,
        r"CORP.LOCAL\svc-roast",
        CANARY,
        quiet=True,
    )
    credential = get_best_credential_ref(HOST, "ldap")
    assert credential is not None

    resolved, error = post_tools._resolve_ad_creds(
        HOST,
        pwd=credential.handle,
        domain="CORP.LOCAL",
    )

    assert error == ""
    assert resolved == credential
    assert isinstance(resolved, CredentialRef)
    assert CANARY not in repr((resolved, error))


def test_ad_wrapper_reveals_only_during_provider_call_and_clears_legacy_shape(
    credential_store,
    monkeypatch,
):
    from core.killchain.ad import kerberos
    from core.tools import post_tools

    register_credential(
        "ldap",
        HOST,
        r"CORP.LOCAL\svc-roast",
        CANARY,
        quiet=True,
    )
    credential = get_best_credential_ref(HOST, "ldap")
    assert credential is not None
    seen = {}

    def fake_kerberoast(target, creds):
        seen["target"] = target
        seen["during"] = dict(creds)
        seen["retained"] = creds
        return "provider-called"

    monkeypatch.setattr(kerberos, "kerberoast", fake_kerberoast)

    output = post_tools.ai_kerberoast(HOST, pwd=credential.handle)

    assert output == "provider-called"
    assert seen["target"] == HOST
    assert seen["during"]["user"] == "svc-roast"
    assert seen["during"]["domain"] == "CORP.LOCAL"
    assert seen["during"]["password"] == CANARY
    assert seen["retained"]["password"] == ""


def test_ad_plaintext_argument_fails_closed_before_provider(
    credential_store,
    monkeypatch,
):
    from core.killchain.ad import credential as ad_credential
    from core.tools import post_tools

    called = []
    monkeypatch.setattr(
        ad_credential,
        "dcsync",
        lambda *_args, **_kwargs: called.append((_args, _kwargs)),
    )

    output = post_tools.ai_dcsync(
        HOST,
        user="svc-sync",
        pwd=CANARY,
        domain="CORP.LOCAL",
    )

    assert "Plaintext credential arguments are prohibited" in output
    assert CANARY not in output
    assert called == []


def test_ad_enum_preserves_domain_only_anonymous_mode(
    credential_store,
    monkeypatch,
):
    from core.killchain.ad import enumeration
    from core.tools import post_tools

    seen = {}

    def fake_run_ad_enum(target, *, creds=None):
        seen["target"] = target
        seen["creds"] = dict(creds or {})
        return "anonymous-provider-called"

    monkeypatch.setattr(enumeration, "run_ad_enum", fake_run_ad_enum)

    output = post_tools.ai_ad_enum(HOST, domain="CORP.LOCAL")

    assert output == "anonymous-provider-called"
    assert seen == {
        "target": HOST,
        "creds": {
            "user": "",
            "username": "",
            "password": "",
            "domain": "CORP.LOCAL",
            "nthash": "",
            "service": "",
            "port": 0,
        },
    }
