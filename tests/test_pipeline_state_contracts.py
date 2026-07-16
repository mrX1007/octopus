#!/usr/bin/env python3
"""State, context, coverage-gap, and stage-transition contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_evidence_verifier_accepts_indexed_context_evidence_aliases():
    import uuid

    from core.ai.evidence import EvidenceVerifier
    from core.ai.fact_store import FactStore

    db_path = f"/tmp/octopus_evidence_verifier_indexed_{uuid.uuid4().hex}.db"
    scan_id = "scan"
    host = "10.0.0.5"
    store = FactStore(db_path)
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh) [OpenSSH 7.4 (protocol 2.0)]", "nmap")
    store.add_fact(scan_id, host, "service_version", "ssh:22:OpenSSH 7.4 (protocol 2.0)", "nmap")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "ssh_inventory")
    store.add_fact(scan_id, host, "service_status", "ssh_authenticated", "ssh_inventory")
    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "ssh_inventory")

    verifier = EvidenceVerifier(store)
    result = verifier.verify_claim(
        scan_id,
        host,
        "ssh_service_needs_exploit_selection",
        [
            "typed_coverage_gaps[0].status == 'pending'",
            "services[0].banner == 'OpenSSH 7.4 (protocol 2.0)'",
        ],
    )

    assert result["status"] == "accepted"
    assert result["assessment_status"] == "inferred"


def test_exploit_select_context_excludes_json_web_endpoint_facts():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    host = "10.0.0.5"
    pipeline = AIPipeline(f"/tmp/octopus_exploit_context_{uuid.uuid4().hex}.db")
    scan_id = "scan-exploit-context"
    pipeline.fact_store.add_fact(scan_id, host, "port_open", "22/tcp (ssh) [OpenSSH 7.4]", "test")
    pipeline.fact_store.add_fact(
        scan_id,
        host,
        "web_endpoint",
        json.dumps({"host": host, "url": f"http://{host}/"}, sort_keys=True),
        "test",
    )

    command = pipeline._augment_command_with_context(f"exploit_select {host}", scan_id, host)

    assert "port_open -> 22/tcp (ssh)" in command
    assert "web_endpoint" not in command
    assert '{"host"' not in command


def test_pipeline_exploit_context_excludes_local_inventory_but_keeps_external_web_surface():
    import uuid

    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_surface_context_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-surface-context"
    host = "10.0.0.5"
    for fact_type, value in [
        ("service_version", "nginx:local:nginx/1.14.0"),
        ("local_listening_port", "8080"),
        ("web_server", "nginx/1.14.0"),
        ("app_stack", "nodejs"),
        ("app_manifest", "/var/www/app/package.json"),
        ("config_candidate", "/var/www/app/.env"),
    ]:
        pipeline.fact_store.add_fact(scan_id, host, fact_type, value, "test")

    cmd = pipeline._augment_command_with_context(f"exploit_select {host}", scan_id, host)

    assert "service_version -> nginx:local:nginx/1.14.0" not in cmd
    assert "local_listening_port -> 8080" not in cmd
    assert "web_server -> nginx/1.14.0" in cmd
    assert "app_stack -> nodejs" not in cmd
    assert "app_manifest -> /var/www/app/package.json" not in cmd
    assert "config_candidate -> /var/www/app/.env" not in cmd


def test_context_keeps_vulnerabilities_without_recon_from_concluding():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_vuln_no_recon_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-vuln-no-recon"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "potential_vulnerability", "CVE-2099-0001", "test")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)
    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert context["state"] == "vulnerabilities_found"
    assert "service_discovery_needed" in context["open_questions"]
    assert context["next_required_capability"] == "service_discovery"
    assert goal == "service_discovery"


def test_exploit_select_context_filters_offscope_web_urls():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_exploit_context_scope_{uuid.uuid4().hex}.db")
    scan_id = "scan-context-scope"
    target = "83.166.242.55"
    facts = [
        ("web_endpoint", {"url": "http://83.166.242.55/", "scheme": "http", "host": "83.166.242.55", "port": "80", "path": "/"}),
        ("web_endpoint", {"url": "http://nginx.org/", "scheme": "http", "host": "nginx.org", "port": "80", "path": "/"}),
        ("web_link", "/admin"),
        ("web_link", "http://nginx.com/"),
        ("browser_rendered", "http://83.166.242.55"),
        ("browser_rendered", "http://nginx.org"),
        ("web_server", "nginx/1.14.0"),
    ]
    for fact_type, value in facts:
        stored_value = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
        pipeline.fact_store.add_fact(scan_id, target, fact_type, stored_value, "test")

    command = pipeline._augment_command_with_context(f"exploit_select {target}", scan_id, target)

    assert "83.166.242.55" in command
    assert "/admin" not in command
    assert "nginx/1.14.0" in command
    assert "nginx.org" not in command
    assert "nginx.com" not in command


def test_context_builder_detects_web_login_and_cpanel_capabilities():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_web_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-web"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "2087/tcp (https) [WHM cPanel]", "test")
    store.add_fact(scan_id, host, "web_surface", "login_form_detected", "test")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert "cpanel" in context["services"]
    assert "cpanel_auth_bypass_unknown" in context["open_questions"]
    assert "web_credentials_unknown" in context["open_questions"]


def test_internal_hosts_from_ssh_inventory_do_not_complete_network_recon():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_internal_recon_gate_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-internal-gate"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
    store.add_fact(scan_id, host, "system_access", "root_access_confirmed", "test")
    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "test")
    store.add_fact(scan_id, host, "persistence", "ssh_key_injected", "test")
    store.add_fact(scan_id, host, "internal_host", "172.25.0.1", "ssh_inventory")
    store.add_fact(scan_id, host, "internal_subnet", "172.25.0.1/16", "ssh_inventory")

    state = resolver.resolve_state(scan_id, host)
    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert not state["internal_recon_completed"]
    assert context["state"] == "persistence_established"
    assert "internal_network_recon_pending" in context["open_questions"]

    store.add_fact(scan_id, host, "internal_network", "hosts_discovered:3", "network_recon")

    state = resolver.resolve_state(scan_id, host)

    assert state["internal_recon_completed"]


def test_network_recon_with_internal_hosts_opens_internal_service_gap():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_internal_service_gap_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-internal-service-gap"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "test")
    store.add_fact(scan_id, host, "system_access", "uid=0", "test")
    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "test")
    store.add_fact(scan_id, host, "service_status", "network_recon_completed", "network_recon")
    store.add_fact(scan_id, host, "internal_host", "172.24.108.2", "network_recon")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)
    goal = DirectorLLM()._validate_goal(
        "internal_reconnaissance",
        context,
        ["internal_reconnaissance"],
    )

    assert "internal_service_assessment_pending" in context["coverage_gaps"]
    assert context["next_required_capability"] == "internal_reconnaissance"
    assert goal == "internal_reconnaissance"

    store.add_fact(scan_id, host, "service_status", "internal_service_probe_completed:0", "internal_service_probe")
    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert "internal_service_assessment_pending" not in context["coverage_gaps"]


def test_internal_service_gap_forces_probe_task():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task == "internal_service_discovery"
    context = {
        "state": "root_access_confirmed",
        "services": ["ssh"],
        "open_questions": ["internal_service_assessment_pending"],
        "coverage_gaps": ["internal_service_assessment_pending"],
        "automation_policy": {"auto_internal_recon": True},
    }

    optimized = pipeline._optimize_plan(
        [{"agent": "VerificationAgent", "task": "internal_network_recon"}],
        "internal_reconnaissance",
        context,
    )

    assert optimized == [{"agent": "VerificationAgent", "task": "internal_service_discovery"}]


def test_internal_vulnerability_gap_is_separate_from_external_gap():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_internal_vuln_gap_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-internal-vuln-gap"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "nmap")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "ssh_inventory")
    store.add_fact(scan_id, host, "system_access", "uid=0", "ssh_inventory")
    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "ssh_inventory")
    store.add_fact(scan_id, host, "service_status", "network_recon_completed", "network_recon")
    store.add_fact(scan_id, host, "internal_host", "172.24.108.2", "network_recon")
    store.add_fact(scan_id, host, "internal_service", "172.24.108.2:53/tcp (dns)", "internal_service_probe")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert "internal_service_assessment_pending" not in context["coverage_gaps"]
    assert "internal_vulnerability_assessment_pending" in context["coverage_gaps"]
    assert "external_vulnerability_assessment_pending" in context["coverage_gaps"]


def test_internal_vulnerability_gap_closes_with_internal_service_check_result():
    import json
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_internal_vuln_gap_closed_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-internal-vuln-gap-closed"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "nmap")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "ssh_inventory")
    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "ssh_inventory")
    store.add_fact(scan_id, host, "service_status", "network_recon_completed", "network_recon")
    store.add_fact(scan_id, host, "internal_host", "172.24.108.2", "network_recon")
    store.add_fact(scan_id, host, "internal_service", "172.24.108.2:53/tcp (dns)", "internal_service_probe")
    store.add_fact(
        scan_id,
        host,
        "check_result",
        json.dumps({
            "tool": "exploit_select",
            "kind": "internal_vulnerability_assessment",
            "mode": "check_only",
            "scope": {"type": "internal_service", "value": "172.24.108.2:53/tcp"},
            "status": "completed",
        }, sort_keys=True),
        "exploit_select",
    )

    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert "internal_vulnerability_assessment_pending" not in context["coverage_gaps"]


def test_external_vulnerability_gap_keeps_external_task_ahead_of_internal_followup():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_external_internal_vuln_gap.db")
    available = {"vulnerability_assessment", "exploit_selection", "internal_service_discovery"}
    pipeline.tool_registry.task_has_available_tools = lambda task: task in available
    context = {
        "host": "10.0.0.5",
        "state": "root_access_confirmed",
        "services": ["ssh"],
        "coverage_gaps": [
            "external_vulnerability_assessment_pending",
            "internal_vulnerability_assessment_pending",
        ],
        "open_questions": [
            "external_vulnerability_assessment_pending",
            "internal_vulnerability_assessment_pending",
        ],
        "target_model": {"internal_services": [{"host": "172.24.108.2", "port": 53, "service": "dns"}]},
    }

    optimized = pipeline._optimize_plan(
        [{"agent": "DiscoveryAgent", "task": "internal_service_discovery"}],
        "vulnerability_assessment",
        context,
    )
    tasks = [step["task"] for step in optimized]

    assert tasks[0] == "vulnerability_assessment"
    assert "internal_service_discovery" in tasks


def test_context_builder_detects_ad_surface_from_ports():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_ad_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-ad"
    host = "10.10.10.5"
    store.add_fact(scan_id, host, "port_open", "389/tcp (ldap) [Microsoft Windows Active Directory LDAP]", "test")
    store.add_fact(scan_id, host, "port_open", "88/tcp (kerberos-sec)", "test")

    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert "ldap" in context["services"]
    assert "kerberos" in context["services"]
    assert "active_directory_exposure_unknown" in context["open_questions"]


def test_shadow_harvest_does_not_skip_to_exfiltration_completed():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_shadow_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-shadow"
    host = "83.166.241.164"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:support@{host}", "test")
    store.add_fact(scan_id, host, "system_access", "root_access_confirmed", "test")
    store.add_fact(scan_id, host, "persistence", "ssh_key_injected", "test")
    store.add_fact(scan_id, host, "credential_material", "shadow_file_extracted", "test")

    state = resolver.resolve_state(scan_id, host)
    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert state["root_access_confirmed"]
    assert state["persistence_established"]
    assert not state["exfiltration_completed"]
    assert context["state"] == "persistence_established"
    assert context["stage_gates"]["exfiltration"] is False
    assert context["next_required_capability"] == "post_access_inventory"
    assert "post_access_inventory_needed" in context["open_questions"]

    store.add_fact(scan_id, host, "post_exploit_stage", "post_access_inventory_completed", "test")
    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert context["next_required_capability"] == "internal_reconnaissance"
    assert "internal_network_recon_pending" in context["open_questions"]


def test_root_ssh_login_confirms_root_access_without_separate_uid_fact():
    import uuid

    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_root_ssh_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    scan_id = "scan-root-ssh"
    host = "83.166.241.164"
    store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
    store.add_fact(scan_id, host, "credential", f"ssh_login_success:root@{host}", "msf_check")
    store.add_fact(scan_id, host, "service_status", "ssh_authenticated", "msf_check")

    state = resolver.resolve_state(scan_id, host)
    context = ContextBuilder(store, resolver).build_context(scan_id, host)

    assert state["root_access_confirmed"]
    assert context["stage_gates"]["root"] is True
    assert context["target_model"]["access"]["root_confirmed"] is True


def test_explicit_exfil_stage_completion_opens_cleanup_gate():
    import uuid

    import config
    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    old_strategy = dict(config.CFG.get("strategy", {}))
    config.CFG.setdefault("strategy", {}).update({"auto_cleanup": True})
    db_path = f"/tmp/octopus_context_exfil_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
    try:
        scan_id = "scan-exfil"
        host = "83.166.241.164"
        store.add_fact(scan_id, host, "port_open", "22/tcp (ssh)", "test")
        store.add_fact(scan_id, host, "system_access", "root_access_confirmed", "test")
        store.add_fact(scan_id, host, "persistence", "ssh_key_injected", "test")
        store.add_fact(scan_id, host, "internal_network", "hosts_discovered:1", "test")
        store.add_fact(scan_id, host, "data_exfiltration", "files_exfiltrated:1", "test")
        store.add_fact(scan_id, host, "post_exploit_stage", "data_exfiltration_completed", "test")

        state = resolver.resolve_state(scan_id, host)
        context = ContextBuilder(store, resolver).build_context(scan_id, host)
    finally:
        config.CFG["strategy"] = old_strategy

    assert state["exfiltration_completed"]
    assert context["state"] == "exfiltration_completed"
    assert context["stage_gates"]["exfiltration"] is True
    assert context["next_required_capability"] == "cleanup"
    assert "cleanup_needed" in context["open_questions"]


def test_internal_services_keep_reachability_and_typed_coverage():
    import uuid

    from core.ai.fact_store import FactStore
    from core.ai.target_model import TargetModel

    store = FactStore(f"/tmp/octopus_internal_service_coverage_{uuid.uuid4().hex}.db")
    scan_id = "scan-internal"
    target = "83.166.241.164"
    store.add_fact(
        scan_id,
        target,
        "internal_service",
        "172.24.108.2:5432/tcp (postgresql)",
        "internal_service_probe 83.166.241.164",
    )

    model = TargetModel.from_facts(scan_id, target, store.get_facts(scan_id, target)).to_dict()
    service = model["internal_services"][0]

    assert service["reachable_via"] == "ssh"
    assert model["typed_facts"]["InternalService"][0]["host"] == "172.24.108.2"
    assert model["coverage"]["internal_services"][0]["port"] == 5432
