#!/usr/bin/env python3
"""Credential synchronization, access, and post-access gate contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_evidence_verifier_accepts_ssh_access_aliases_from_real_facts():
    import uuid

    from core.ai.evidence import EvidenceVerifier
    from core.ai.fact_store import FactStore

    db_path = f"/tmp/octopus_evidence_verifier_alias_{uuid.uuid4().hex}.db"
    scan_id = "scan"
    host = "10.0.0.5"
    store = FactStore(db_path)
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "ssh_inventory")
    store.add_fact(scan_id, host, "service_status", "ssh_authenticated", "ssh_inventory")
    store.add_fact(scan_id, host, "system_access", "uid=0", "ssh_inventory")

    verifier = EvidenceVerifier(store)
    result = verifier.verify_claim(
        scan_id,
        host,
        "root_access_confirmed",
        ["surface_states[ssh_access]: confirmed_present", "ssh_access_confirmed"],
    )

    assert result["status"] == "accepted"
    assert result["assessment_status"] == "verified"


def test_pipeline_runs_controlled_ssh_inventory_after_ssh_auth():
    import uuid

    import config
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    old_strategy = dict(config.CFG.get("strategy", {}))
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("ssh_session"):
            return """
[*] SSH Post-Exploitation Analysis: support@10.0.0.5:22
[+] SSH connected as support@10.0.0.5
"""
        if cmd.startswith("ssh_inventory"):
            return """
[*] SSH Controlled Inventory: support@10.0.0.5:22
[+] SSH connected as support@10.0.0.5:22

[+] Hostname
$ hostname
web01

[+] Kernel
$ uname -a
Linux web01 5.15.0 x86_64 GNU/Linux

[+] Network addresses
$ ip -o addr show 2>/dev/null || ip addr show 2>/dev/null
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0

[+] SSH inventory completed
"""
        return ""

    config.CFG.setdefault("strategy", {}).update({
        "active_authorized": True,
        "authorized_targets": ["10.0.0.0/24"],
    })
    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_ssh_inventory_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        result = pipeline._run_task_commands(
            "scan-ssh-inventory",
            "10.0.0.5",
            ["ssh_session 10.0.0.5"],
            fact_label="Fact",
        )
        facts = pipeline.fact_store.get_facts("scan-ssh-inventory", "10.0.0.5")
    finally:
        config.CFG["strategy"] = old_strategy
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert calls[:2] == ["ssh_session 10.0.0.5", "ssh_inventory 10.0.0.5"]
    assert any(cmd.startswith("exploit_select 10.0.0.5") for cmd in calls)
    assert ("post_exploit_stage", "post_access_inventory_completed") in pairs
    assert ("hostname", "web01") in pairs
    assert ("internal_host", "10.0.0.5") in pairs
    assert result["parsed_facts"] >= 7


def test_pipeline_marks_missing_credential_stage_as_blocked_not_completed():
    import uuid

    import config
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    old_strategy = dict(config.CFG.get("strategy", {}))

    def fake_runner(cmd):
        return "[!] Persistence requires valid SSH credentials for 10.0.0.5."

    config.CFG.setdefault("strategy", {}).update({
        "active_authorized": True,
        "authorized_targets": ["10.0.0.0/24"],
    })
    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_blocked_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        result = pipeline._run_task_commands(
            "scan-blocked",
            "10.0.0.5",
            ["killchain_persist 10.0.0.5"],
            fact_label="Fact",
        )
        status = pipeline._classify_task_result(result)
    finally:
        config.CFG["strategy"] = old_strategy
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert status == "blocked"
    assert result["reason"] == "missing_credentials_or_manual_gate"


def test_root_access_requests_inventory_before_persistence():
    import uuid

    import config
    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    old_strategy = dict(config.CFG.get("strategy", {}))
    config.CFG.setdefault("strategy", {}).update({"auto_persistence": True})
    db_path = f"/tmp/octopus_context_root_inventory_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    try:
        scan_id = "scan-root-inventory"
        host = "10.0.0.5"
        store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
        store.add_fact(scan_id, host, "credential", f"ssh_login_success:support@{host}", "test")
        store.add_fact(scan_id, host, "system_access", "root_access_confirmed", "test")

        context = ContextBuilder(store, resolver).build_context(scan_id, host)
        goal = DirectorLLM()._fallback_logic(context, []).get("goal")

        assert context["state"] == "root_access_confirmed"
        assert "post_access_inventory_needed" in context["open_questions"]
        assert context["next_required_capability"] == "post_access_inventory"
        assert goal == "post_access_inventory"

        store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "test")
        context = ContextBuilder(store, resolver).build_context(scan_id, host)
        goal = DirectorLLM()._fallback_logic(context, []).get("goal")
    finally:
        config.CFG["strategy"] = old_strategy

    assert "post_access_inventory_needed" not in context["open_questions"]
    assert "persistence_needed" in context["open_questions"]
    assert goal == "persistence"


def test_cpanel_app_session_does_not_trigger_ssh_post_access_chain():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_cpanel_app_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-cpanel-app"
    host = "67.215.12.67"
    store.add_fact(scan_id, host, "port_open", "2087/tcp (cpanel) [cPanel/WHM]", "test")
    store.add_fact(scan_id, host, "vulnerability", "CVE-2026-41940", "test")
    store.add_fact(scan_id, host, "exploit_success", "CVE-2026-41940 - cPanel/WHM Auth Bypass", "test")
    store.add_fact(scan_id, host, "credential", "whm_session:nllWuSD9KpP7C1kL", "test")
    store.add_fact(scan_id, host, "application_access", "cpanel_whm_authenticated", "test")

    state = resolver.resolve_state(scan_id, host)
    context = ContextBuilder(store, resolver).build_context(scan_id, host)
    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert state["credentials_found"]
    assert state["vulnerabilities_found"]
    assert not state["root_access_confirmed"]
    assert context["state"] == "credentials_found"
    assert "cpanel" in context["services"]
    assert context["next_required_capability"] == "vulnerability_assessment"
    assert goal == "vulnerability_assessment"


def test_cpanel_session_on_ssh_host_is_not_treated_as_ssh_access():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_cpanel_with_ssh_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-cpanel-with-ssh"
    host = "67.215.12.67"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh) [OpenSSH]", "test")
    store.add_fact(scan_id, host, "port_open", "2087/tcp (cpanel) [cPanel/WHM]", "test")
    store.add_fact(scan_id, host, "credential", "whm_session:nllWuSD9KpP7C1kL", "test")
    store.add_fact(scan_id, host, "application_access", "cpanel_whm_authenticated", "test")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)
    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert context["state"] == "credentials_found"
    assert "ssh" in context["services"]
    assert "cpanel_authenticated_session_present" in context["open_questions"]
    assert "privilege_escalation_path_unknown" not in context["open_questions"]
    assert context["next_required_capability"] == "vulnerability_assessment"
    assert goal == "vulnerability_assessment"


def test_post_exploit_task_templates_do_not_force_root_without_password():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()

    assert registry.task_map["exploit_privesc"] == [("killchain_privesc {target}", "killchain_privesc")]
    assert registry.task_map["establish_persistence"] == [("killchain_persist {target}", "killchain_persist")]
    assert registry.task_map["exfiltrate_data"] == [("killchain_exfil {target}", "killchain_exfil")]


@pytest.fixture
def reference_credential_store(monkeypatch):
    """Install an isolated reference-only store for compatibility callers."""
    from core.credentials import CredentialStore
    from core.secrets import SecretStore

    secret_store = SecretStore(":memory:", key=b"a" * 32)
    store = CredentialStore(secret_store=secret_store, hydrate=False)
    monkeypatch.setattr(CredentialStore, "_instance", store)
    yield store
    secret_store.close()


def test_credential_ranking_prefers_password_login_over_root_key_marker(
    reference_credential_store,
):
    import uuid
    from dataclasses import replace

    from core.credential_ranking import KEY_AUTH_MARKER
    from core.credentials import CredentialRef

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    password = "fixture-password-123"
    reference_credential_store.add("ssh", host, "root", KEY_AUTH_MARKER, quiet=True)
    reference_credential_store.add("ssh", host, "support", password, quiet=True)

    selected = reference_credential_store.best_ref(host, "ssh")

    assert isinstance(selected, CredentialRef)
    assert selected.username == "support"
    assert selected.auth_kind == "password"
    assert password not in repr(reference_credential_store._cache)
    assert password not in repr(selected)
    with reference_credential_store.material_for_execution(selected) as material:
        assert material.username == "support"
        assert material.target == host
        assert material.password == password
        assert password not in repr(material)
    assert material.password == ""
    with pytest.raises(
        KeyError, match="unknown credential handle"
    ), reference_credential_store.material_for_execution(
        replace(selected, target="192.0.2.254")
    ):
        pass


def test_credential_lookup_is_reference_only_without_legacy_cache(
    reference_credential_store,
):
    import uuid

    from core.credentials import CredentialRef
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    password = "fixture-password-123"
    reference_credential_store.add("ssh", host, "support", password, quiet=True)

    with pytest.warns(FutureWarning, match="no longer reveals plaintext"):
        credentials = exploit_tools.get_known_creds("ssh", host)
    with pytest.warns(FutureWarning, match="now returns CredentialRef"):
        selected = exploit_tools.get_best_creds_for_target(host, "ssh")

    assert credentials == (selected,)
    assert all(isinstance(item, CredentialRef) for item in credentials)
    assert password not in repr(credentials)
    assert not hasattr(exploit_tools, "_KNOWN_CREDS")


def test_unified_credential_store_compatibility_getter_returns_reference(
    reference_credential_store,
):
    import uuid

    from core.credential_ranking import KEY_AUTH_MARKER
    from core.credentials import CredentialRef

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    password = "fixture-password-123"
    reference_credential_store.add("ssh", host, "root", KEY_AUTH_MARKER, quiet=True)
    reference_credential_store.add("ssh", host, "support", password, quiet=True)

    with pytest.warns(FutureWarning, match="now returns CredentialRef"):
        selected = reference_credential_store.get_best(host, "ssh")

    assert isinstance(selected, CredentialRef)
    assert selected.username == "support"
    assert password not in repr(reference_credential_store._cache)
    assert password not in repr(selected)


def test_pipeline_syncs_root_key_fact_into_reference_only_credential_store(
    reference_credential_store,
):
    import uuid

    from core.ai.pipeline import AIPipeline
    from core.credentials import CredentialRef, get_credential_refs
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    canary = "session-plaintext-must-not-be-cached"
    pipeline = AIPipeline(f"/tmp/octopus_pipeline_root_key_{uuid.uuid4().hex}.db")

    pipeline._sync_runtime_credentials_from_facts(
        host,
        [
            {"type": "credential", "value": f"ssh_key_available:root@{host}"},
            {"type": "credential", "value": f"whm_session:{canary}"},
        ],
    )

    credentials = get_credential_refs("ssh", host)
    assert len(credentials) == 1
    assert isinstance(credentials[0], CredentialRef)
    assert credentials[0].username == "root"
    assert credentials[0].auth_kind == "ssh_key"
    assert canary not in repr(reference_credential_store._cache)
    assert canary not in repr(pipeline.fact_store.get_facts("scan-root-key", host))
    assert not hasattr(exploit_tools, "_KNOWN_CREDS")


def test_get_all_known_creds_returns_grouped_references_only(
    reference_credential_store,
):
    import uuid

    from core.credential_ranking import KEY_AUTH_MARKER
    from core.credentials import CredentialRef
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    ssh_password = "fixture-password-123"
    db_password = "dbpass"
    reference_credential_store.add("ssh", host, "support", ssh_password, quiet=True)
    reference_credential_store.add("ssh", host, "root", KEY_AUTH_MARKER, quiet=True)
    reference_credential_store.add("postgres", host, "app", db_password, quiet=True)

    with pytest.warns(FutureWarning, match="now returns CredentialRef objects"):
        credentials = exploit_tools.get_all_known_creds_for_target(host)

    assert [item.username for item in credentials["ssh"]] == ["support", "root"]
    assert [item.username for item in credentials["postgres"]] == ["app"]
    assert all(
        isinstance(item, CredentialRef)
        for grouped in credentials.values()
        for item in grouped
    )
    assert ssh_password not in repr(credentials)
    assert db_password not in repr(credentials)
    assert not hasattr(exploit_tools, "_KNOWN_CREDS")


def test_pipeline_seeds_reference_only_ssh_credential_and_verifies_instead_of_bruteforce(
    reference_credential_store,
):
    import uuid

    from core.ai.pipeline import AIPipeline
    from core.credentials import credential_material_for_execution
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    password = "fixture-password-123"
    credential, created = reference_credential_store.register(
        "ssh",
        host,
        "support",
        password,
        quiet=True,
    )
    assert created is True
    pipeline = AIPipeline(f"/tmp/octopus_pipeline_cached_creds_{uuid.uuid4().hex}.db")

    seeded = pipeline._seed_known_credentials("scan-cached-creds", host)
    facts = pipeline.fact_store.get_facts("scan-cached-creds", host)
    expanded = pipeline._expand_command_with_context(
        f"bruteforce ssh {host}",
        "scan-cached-creds",
        host,
    )

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert seeded == 1
    availability_values = [
        value
        for fact_type, value in pairs
        if fact_type == "credential" and value.startswith("ssh_credential_available:")
    ]
    assert len(availability_values) == 1
    assert availability_values[0].startswith("ssh_credential_available:secret://")
    assert "support" not in availability_values[0]
    assert password not in repr(facts)
    assert password not in repr(reference_credential_store._cache)
    assert not hasattr(exploit_tools, "_KNOWN_CREDS")
    with credential_material_for_execution(credential) as material:
        assert material.password == password
        assert password not in repr(material)
    assert material.password == ""
    assert expanded == [f"ssh_session {host}"]
