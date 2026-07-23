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
    assert credential.secret_ref.startswith("secret://")
    assert CANARY not in repr(credential_store._cache)
    assert CANARY not in repr(credential)
    assert credential.secret_ref not in repr(credential.audit_dict())
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
