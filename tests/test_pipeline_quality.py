#!/usr/bin/env python3
"""Regression tests for AI pipeline planning quality gates."""


def test_post_exploit_goal_forces_verification_plan():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    context = {
        "state": "root_access_confirmed",
        "services": ["ssh", "http"],
        "open_questions": ["persistence_needed"],
    }
    noisy_plan = [
        {"agent": "DiscoveryAgent", "task": "directory_bruteforce"},
        {"agent": "AnalysisAgent", "task": "analyze_services"},
    ]

    optimized = pipeline._optimize_plan(noisy_plan, "data_exfiltration", context)

    assert optimized == [{"agent": "VerificationAgent", "task": "exfiltrate_data"}]


def test_vulnerability_plan_gets_context_web_enrichment():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task == "web_application_mapping"
    context = {
        "state": "recon_completed",
        "services": ["http"],
        "open_questions": ["web_vulnerabilities_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert tasks == [
        "vulnerability_assessment",
        "web_application_mapping",
        "analyze_vulnerabilities",
    ]


def test_tooldef_python_dependency_gate():
    from core.tools.registry import ToolDef

    assert ToolDef(name="ok", requires=["python:sys"]).is_available()
    assert not ToolDef(name="missing", requires=["python:octopus_missing_module"]).is_available()
    assert ToolDef(name="any-ok", requires=["any:python:octopus_missing_module,python:sys"]).is_available()
    assert not ToolDef(name="any-missing", requires=["any:python:octopus_missing_a,python:octopus_missing_b"]).is_available()


def test_persistence_state_requests_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert goal == "internal_reconnaissance"


def test_director_validation_inserts_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._validate_goal("data_exfiltration", context, [])

    assert goal == "internal_reconnaissance"


def test_director_does_not_advance_to_persistence_without_root():
    from core.ai.director import DirectorLLM

    context = {
        "state": "credentials_found",
        "services": ["ssh"],
        "open_questions": ["privilege_escalation_path_unknown"],
    }

    goal = DirectorLLM()._validate_goal(
        "privilege_escalation",
        context,
        ["service_discovery", "vulnerability_assessment", "credential_harvesting", "privilege_escalation"],
    )

    assert goal == "conclude"


def test_director_rejects_post_exploit_goal_without_root():
    from core.ai.director import DirectorLLM

    context = {
        "state": "credentials_found",
        "services": ["ssh"],
        "open_questions": ["privilege_escalation_path_unknown"],
    }

    goal = DirectorLLM()._validate_goal("data_exfiltration", context, [])

    assert goal == "privilege_escalation"


def test_internal_recon_goal_forces_single_network_task():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    noisy_plan = [
        {"agent": "DiscoveryAgent", "task": "service_discovery"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]
    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    optimized = pipeline._optimize_plan(noisy_plan, "internal_reconnaissance", context)

    assert optimized == [{"agent": "VerificationAgent", "task": "internal_network_recon"}]


def test_registry_canonicalizes_ad_hash_tasks():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()

    assert registry.canonical_task("ad_enum") == "active_directory_enumeration"
    assert registry.canonical_task("asrep_roast") == "kerberos_assessment"
    assert registry.canonical_task("dcsync") == "domain_credential_extraction"
    assert registry.canonical_task("psexec") == "ad_remote_execution"
    assert registry.canonical_task("crack_hashes") == "hash_cracking"
    assert registry.has_task("active_directory_enumeration")
    assert registry.has_task("hash_cracking")


def test_registry_exposes_exploit_selection_and_msf_verification():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()

    assert registry.canonical_task("payload_plan") == "exploit_selection"
    assert registry.canonical_task("msf_check") == "metasploit_verification"
    assert registry.has_task("exploit_selection")
    assert registry.has_task("metasploit_verification")
    assert ("exploit_select {target}", "exploit_select") in registry.task_map["vulnerability_assessment"]


def test_registry_expands_nested_web_and_plugin_capabilities():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()
    available = {
        "nmap", "nikto", "exploit_select", "wpscan", "sqlmap",
        "jmx2rce_scan", "plugin", "cpanel_exploit",
    }
    registry._is_tool_available = lambda name: name in available or name in registry.task_map

    vuln_cmds = registry.get_commands_for_task("vulnerability_assessment", "10.0.0.5")
    cpanel_cmds = registry.get_commands_for_task("cpanel_assessment", "10.0.0.5")

    assert "exploit_select 10.0.0.5" in vuln_cmds
    assert "wpscan 10.0.0.5" in vuln_cmds
    assert "sqlmap 10.0.0.5" in vuln_cmds
    assert "jmx2rce_scan 10.0.0.5" in vuln_cmds
    assert registry.get_available_tools_for_task("vulnerability_assessment") == [
        "nmap",
        "nikto",
        "exploit_select",
        "wpscan",
        "sqlmap",
        "jmx2rce_scan",
    ]
    assert "plugin cpanel_auth_bypass 10.0.0.5 scan" in cpanel_cmds


def test_registry_coverage_classifies_gated_and_legacy_tools():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()
    registered = [
        "bruteforce", "exploit_select", "jmx2rce_cleanup", "jmx2rce_rce",
        "jmx2rce_read", "jmx2rce_scan", "msf_check", "msf_run",
        "stealth_brute", "web_login_brute", "deploy_c2_beacon",
        "killchain_exploit", "killchain_full", "killchain_vuln_assess",
        "ssh_exec", "ssh_inventory", "ssh_session", "plugin",
        "ftp_anonymous_check", "smtp_probe", "db_inventory",
    ]

    report = registry.get_coverage_report(registered)

    assert report["registered"] == len(registered)
    assert report["covered"] == len(registered)
    assert report["unknown"] == []
    assert "msf_check" in report["followup"]
    assert "msf_run" in report["manual_gated"]
    assert "ssh_exec" in report["manual_gated"]
    assert "ssh_session" in report["manual_gated"]
    assert "ssh_inventory" in report["followup"]
    assert "deploy_c2_beacon" in report["manual_gated"]
    assert "jmx2rce_rce" in report["manual_gated"]
    assert "killchain_full" in report["legacy_wrappers"]
    assert "stealth_brute" in report["legacy_wrappers"]
    assert "ftp_anonymous_check" in report["auto"]
    assert "smtp_probe" in report["auto"]
    assert "db_inventory" in report["auto"]


def test_exploit_base_normalizes_legacy_tuple_results():
    from core.killchain.exploits.base import ExploitBase, ExploitResult

    class DemoExploit(ExploitBase):
        name = "Demo"
        cve = "CVE-2099-0001"

        def check_vulnerable(self, client):
            return True, "demo vulnerable"

        def run(self, client):
            return True, "uid=0(root)"

    exploit = DemoExploit()

    check = exploit.normalize_check_result(exploit.check_vulnerable(None))
    run = exploit.normalize_run_result(exploit.run(None))

    assert isinstance(check, ExploitResult)
    assert check.success
    assert check.status == "vulnerable"
    assert ("vulnerability", "CVE-2099-0001") in {
        (fact["type"], fact["value"]) for fact in check.facts
    }
    assert run.as_tuple() == (True, "uid=0(root)")
    assert ("exploit_success", "CVE-2099-0001:Demo") in {
        (fact["type"], fact["value"]) for fact in run.facts
    }


def test_exploit_selector_maps_service_banner_to_msf_payload_plan():
    from core.exploits.selector import select_exploits

    output = select_exploits(
        "10.0.0.5",
        "80/tcp open http Apache httpd 2.4.49",
        run_probe=False,
    )

    assert "exploit/multi/http/apache_normalize_path_rce" in output
    assert "Payload recommendation:" in output
    assert "MSF check: msf_check 10.0.0.5" in output
    assert "RPORT=80" in output


def test_pipeline_feeds_known_recon_facts_into_exploit_selector():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_exploit_select_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-exploit-select"
    host = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, host, "port_open", "80/tcp (http) [Apache httpd 2.4.49]", "test")

    cmd = pipeline._augment_command_with_context(f"exploit_select {host}", scan_id, host)

    assert cmd.startswith(f"exploit_select {host} ")
    assert "port_open -> 80/tcp (http) [Apache httpd 2.4.49]" in cmd


def test_pipeline_runs_safe_verification_followups_from_facts():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("exploit_select"):
            return """
[EXPLOIT SELECTION - 10.0.0.5]
Services analyzed: 1
[EXPLOIT CANDIDATE 1] http:80 Apache httpd 2.4.49 -> exploit/multi/http/apache_normalize_path_rce (version_map; matched 'apache 2.4.49')
  Payload recommendation: generic/shell_reverse_tcp
  MSF check: msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
"""
        if cmd.startswith("msf_check"):
            return "[+] The target appears to be vulnerable."
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_followup_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        result = pipeline._run_task_commands(
            "scan-followup",
            "10.0.0.5",
            ["exploit_select 10.0.0.5"],
            fact_label="Fact",
        )
        facts = pipeline.fact_store.get_facts("scan-followup", "10.0.0.5")
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert any(cmd.startswith("msf_check 10.0.0.5") for cmd in calls)
    assert ("vulnerability", "msf_check_positive:exploit/multi/http/apache_normalize_path_rce") in pairs
    assert result["parsed_facts"] >= 4


def test_pipeline_runs_controlled_ssh_inventory_after_ssh_auth():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
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
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert calls == ["ssh_session 10.0.0.5", "ssh_inventory 10.0.0.5"]
    assert ("post_exploit_stage", "post_access_inventory_completed") in pairs
    assert ("hostname", "web01") in pairs
    assert ("internal_host", "10.0.0.5") in pairs
    assert result["parsed_facts"] >= 7


def test_pipeline_promotes_msf_run_only_after_positive_check_and_scope():
    import uuid
    import config
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    old_strategy = dict(config.CFG.get("strategy", {}))
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("exploit_select"):
            return """
[EXPLOIT CANDIDATE 1] http:80 Apache httpd 2.4.49 -> exploit/multi/http/apache_normalize_path_rce (version_map; matched 'apache 2.4.49')
  Payload recommendation: generic/shell_reverse_tcp
  MSF check: msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
  MSF run gated: msf_run 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
"""
        if cmd.startswith("msf_check"):
            return "[+] The target appears to be vulnerable."
        if cmd.startswith("msf_run"):
            return "[+] Command shell session 1 opened"
        return ""

    config.CFG.setdefault("strategy", {}).update({
        "allow_active_msf": True,
        "active_authorized": True,
        "authorized_targets": ["10.0.0.0/24"],
        "max_active_msf_runs_per_scan": 1,
    })
    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_active_msf_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        result = pipeline._run_task_commands(
            "scan-active-msf",
            "10.0.0.5",
            ["exploit_select 10.0.0.5"],
            fact_label="Fact",
        )
        facts = pipeline.fact_store.get_facts("scan-active-msf", "10.0.0.5")
    finally:
        config.CFG["strategy"] = old_strategy
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert any(cmd.startswith("msf_check 10.0.0.5") for cmd in calls)
    assert any(cmd.startswith("msf_run 10.0.0.5") for cmd in calls)
    assert ("exploit_success", "msf_session_opened:exploit/multi/http/apache_normalize_path_rce") in pairs
    assert result["parsed_facts"] >= 6


def test_pipeline_does_not_promote_msf_run_outside_authorized_scope():
    import uuid
    import config
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    old_strategy = dict(config.CFG.get("strategy", {}))
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("exploit_select"):
            return """
[EXPLOIT CANDIDATE 1] http:80 Apache httpd 2.4.49 -> exploit/multi/http/apache_normalize_path_rce (version_map; matched 'apache 2.4.49')
  Payload recommendation: generic/shell_reverse_tcp
  MSF check: msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
  MSF run gated: msf_run 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
"""
        if cmd.startswith("msf_check"):
            return "[+] The target appears to be vulnerable."
        return ""

    config.CFG.setdefault("strategy", {}).update({
        "allow_active_msf": True,
        "active_authorized": True,
        "authorized_targets": ["192.0.2.0/24"],
        "max_active_msf_runs_per_scan": 1,
    })
    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_active_scope_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline._run_task_commands(
            "scan-active-scope",
            "10.0.0.5",
            ["exploit_select 10.0.0.5"],
            fact_label="Fact",
        )
    finally:
        config.CFG["strategy"] = old_strategy
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert any(cmd.startswith("msf_check 10.0.0.5") for cmd in calls)
    assert not any(cmd.startswith("msf_run 10.0.0.5") for cmd in calls)


def test_pipeline_marks_missing_credential_stage_as_blocked_not_completed():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd

    def fake_runner(cmd):
        return "[!] Persistence requires valid SSH credentials for 10.0.0.5."

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
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert status == "blocked"
    assert result["reason"] == "missing_credentials_or_manual_gate"


def test_context_keeps_vulnerabilities_without_recon_from_concluding():
    import uuid
    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver
    from core.ai.director import DirectorLLM

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


def test_root_access_requests_inventory_before_persistence():
    import uuid
    from core.ai.context_builder import ContextBuilder
    from core.ai.director import DirectorLLM
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_root_inventory_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
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

    assert "post_access_inventory_needed" not in context["open_questions"]
    assert "persistence_needed" in context["open_questions"]
    assert goal == "persistence"


def test_cpanel_commands_use_discovered_panel_port():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_cpanel_port_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-cpanel-port"
    host = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, host, "port_open", "2083/tcp (ssl/http) [cPanel]", "test")

    plugin_cmd = pipeline._augment_command_with_context(
        "plugin cpanel_auth_bypass 10.0.0.5 scan", scan_id, host
    )
    direct_cmd = pipeline._augment_command_with_context(
        "cpanel_exploit 10.0.0.5 scan", scan_id, host
    )

    assert plugin_cmd == "plugin cpanel_auth_bypass 10.0.0.5:2083 scan"
    assert direct_cmd == "cpanel_exploit 10.0.0.5:2083 scan"


def test_web_mapping_commands_expand_across_discovered_http_endpoints():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_web_endpoints_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-web-endpoints"
    host = "10.0.0.5"
    for value in [
        "80/tcp (http) [Golang net/http server]",
        "443/tcp (ssl/http) [nginx]",
        "3000/tcp (http) [Node.js Express]",
        "3030/tcp (http-alt) [Golang net/http server]",
        "5432/tcp (postgresql) [PostgreSQL DB]",
        "2087/tcp (ssl/http) [cPanel WHM]",
    ]:
        pipeline.fact_store.add_fact(scan_id, host, "port_open", value, "test")

    endpoints = pipeline._web_endpoints_from_facts(scan_id, host)
    expanded = pipeline._expand_command_with_context(f"whatweb {host}", scan_id, host)
    explicit = pipeline._expand_command_with_context(f"whatweb http://{host}:9000", scan_id, host)

    assert endpoints == [
        "http://10.0.0.5",
        "https://10.0.0.5",
        "http://10.0.0.5:3000",
        "http://10.0.0.5:3030",
        "https://10.0.0.5:2087",
    ]
    assert f"http://{host}:5432" not in endpoints
    assert expanded == [f"whatweb {endpoint}" for endpoint in endpoints]
    assert explicit == [f"whatweb http://{host}:9000"]


def test_fact_driven_actions_map_evidence_to_next_commands():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_fact_actions_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-fact-actions"
    host = "10.0.0.5"
    facts = [
        {"type": "credential", "value": "support:qweqwe123 (cached)"},
        {"type": "port_open", "value": "2087/tcp (cpanel) [cPanel/WHM]"},
        {"type": "web_path", "value": "/_reports:301"},
    ]
    for fact in facts:
        pipeline.fact_store.add_fact(scan_id, host, fact["type"], fact["value"], "test")

    commands = pipeline._fact_driven_action_commands(scan_id, host, facts)

    assert f"ssh_session {host}" in commands
    assert f"plugin cpanel_auth_bypass {host}:2087 scan" in commands
    assert f"curl_headers https://{host}:2087/_reports" in commands
    assert f"scrapling https://{host}:2087/_reports" in commands


def test_fact_driven_actions_add_protocol_and_db_probes():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_service_actions_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    pipeline._known_credentials_for_target = lambda target: {
        "postgresql": [("postgres", "secret")]
    }
    scan_id = "scan-service-actions"
    host = "10.0.0.5"
    facts = [
        {"type": "port_open", "value": "21/tcp (ftp) [Pure-FTPd]"},
        {"type": "port_open", "value": "587/tcp (smtp) [Postfix smtpd]"},
        {"type": "port_open", "value": "5432/tcp (postgresql) [PostgreSQL DB]"},
        {"type": "port_open", "value": "3306/tcp (mysql) [MariaDB]"},
    ]
    for fact in facts:
        pipeline.fact_store.add_fact(scan_id, host, fact["type"], fact["value"], "test")

    commands = pipeline._fact_driven_action_commands(scan_id, host, facts)

    assert f"ftp_anonymous_check {host} 21" in commands
    assert f"smtp_probe {host} 587" in commands
    assert f"db_inventory {host} 5432 postgresql" in commands
    assert f"db_inventory {host} 3306 mysql" not in commands


def test_pipeline_runs_protocol_fact_actions_after_service_discovery():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("nmap "):
            return """
21/tcp open ftp Pure-FTPd
587/tcp open smtp Postfix smtpd
5432/tcp open postgresql PostgreSQL DB
"""
        if cmd.startswith("ftp_anonymous_check "):
            return "[FTP Anonymous Check - 10.0.0.5:21]\nAnonymous login: allowed"
        if cmd.startswith("smtp_probe "):
            return "[SMTP Probe - 10.0.0.5:587]\nSTARTTLS: supported\nAUTH mechanisms: PLAIN LOGIN"
        if cmd.startswith("db_inventory "):
            return """
[DB Inventory - postgresql 10.0.0.5:5432]
DB inventory completed: postgresql
Version: PostgreSQL 15.4
Current user: postgres
Databases (1):
  postgres
"""
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_protocol_actions_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline._known_credentials_for_target = lambda target: {
            "postgresql": [("postgres", "secret")]
        }
        scan_id = "scan-protocol-actions"
        host = "10.0.0.5"
        result = pipeline._run_task_commands(scan_id, host, [f"nmap -Pn -sV {host}"], fact_label="Fact")
        facts = pipeline.fact_store.get_facts(scan_id, host)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert f"ftp_anonymous_check {host} 21" in calls
    assert f"smtp_probe {host} 587" in calls
    assert f"db_inventory {host} 5432 postgresql" in calls
    assert ("vulnerability", "ftp_anonymous_login_allowed:10.0.0.5:21") in pairs
    assert ("service_status", "smtp_starttls_supported:587") in pairs
    assert ("service_status", "db_inventory_completed:postgresql:5432") in pairs
    assert result["new_facts"] >= 6


def test_pipeline_runs_web_path_fact_actions_after_ffuf():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("ffuf "):
            return "_reports                [Status: 301, Size: 17, Words: 2, Lines: 1]"
        if cmd.startswith("curl_headers "):
            return "Server: nginx\nLocation: /_reports/"
        if cmd.startswith("scrapling "):
            return "[REQUESTS+BS4 RESULT - http://10.0.0.5/_reports]\nTitle: Reports"
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_web_path_actions_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        scan_id = "scan-web-path-actions"
        host = "10.0.0.5"
        pipeline.fact_store.add_fact(scan_id, host, "port_open", "80/tcp (http)", "test")
        result = pipeline._run_task_commands(scan_id, host, [f"ffuf {host}"], fact_label="Fact")
        facts = pipeline.fact_store.get_facts(scan_id, host)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert f"curl_headers http://{host}/_reports" in calls
    assert f"scrapling http://{host}/_reports" in calls
    assert ("web_path", "/_reports:301") in pairs
    assert ("web_server", "nginx") in pairs
    assert ("web_title", "Reports") in pairs
    assert result["new_facts"] >= 3


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


def test_cpanel_enrichment_takes_priority_in_short_vuln_plan():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_cpanel.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task in {
        "cpanel_assessment",
        "web_application_mapping",
        "web_vulnerability_testing",
    }
    context = {
        "state": "recon_completed",
        "services": ["http", "https", "cpanel"],
        "open_questions": ["web_vulnerabilities_unknown", "cpanel_auth_bypass_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "DiscoveryAgent", "task": "web_application_mapping"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert "cpanel_assessment" in tasks
    assert len(tasks) == 3


def test_post_exploit_task_templates_do_not_force_root_without_password():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()

    assert registry.task_map["exploit_privesc"] == [("killchain_privesc {target}", "killchain_privesc")]
    assert registry.task_map["establish_persistence"] == [("killchain_persist {target}", "killchain_persist")]
    assert registry.task_map["exfiltrate_data"] == [("killchain_exfil {target}", "killchain_exfil")]


def test_credential_ranking_prefers_password_login_over_root_key_marker():
    import uuid
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    exploit_tools._KNOWN_CREDS[("ssh", host)] = [
        ("root", "__KEY_AUTH__"),
        ("support", "qweqwe123"),
    ]

    assert exploit_tools.get_best_creds_for_target(host, "ssh") == ("support", "qweqwe123")


def test_ssh_exec_blocks_arbitrary_commands_by_default():
    from core.tools.post_tools import ai_ssh_exec

    output = ai_ssh_exec("10.0.0.5", "support", "secret", "cat /etc/passwd")

    assert "ssh_exec blocked" in output
    assert "outside controlled ssh_exec inventory allowlist" in output


def test_pipeline_syncs_root_key_fact_into_ssh_credential_cache():
    import uuid
    from core.ai.pipeline import AIPipeline
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    exploit_tools._KNOWN_CREDS.pop(("ssh", host), None)
    pipeline = AIPipeline(f"/tmp/octopus_pipeline_root_key_{uuid.uuid4().hex}.db")

    pipeline._sync_runtime_credentials_from_facts(host, [
        {"type": "credential", "value": f"ssh_key_available:root@{host}"},
        {"type": "credential", "value": "whm_session:nllWuSD9KpP7C1kL"},
    ])

    creds = exploit_tools.get_known_creds("ssh", host)
    assert ("root", "__KEY_AUTH__") in creds
    assert all(user != "whm_session" for user, _pwd in creds)


def test_get_all_known_creds_reads_unified_store_and_legacy_cache():
    import uuid
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    old_get_store = exploit_tools._get_cred_store
    old_legacy = dict(exploit_tools._KNOWN_CREDS)

    class FakeStore:
        def get_all(self, target):
            if target == host:
                return {
                    "ssh": [("support", "qweqwe123")],
                    "postgres": [("app", "dbpass")],
                }
            return {}

    try:
        exploit_tools._get_cred_store = lambda: FakeStore()
        exploit_tools._KNOWN_CREDS[("ssh", host)] = [("root", "__KEY_AUTH__")]
        creds = exploit_tools.get_all_known_creds_for_target(host)
    finally:
        exploit_tools._get_cred_store = old_get_store
        exploit_tools._KNOWN_CREDS.clear()
        exploit_tools._KNOWN_CREDS.update(old_legacy)

    assert creds["ssh"] == [("support", "qweqwe123"), ("root", "__KEY_AUTH__")]
    assert creds["postgres"] == [("app", "dbpass")]


def test_pipeline_seeds_cached_ssh_creds_and_verifies_instead_of_bruteforce():
    import uuid
    from core.ai.pipeline import AIPipeline
    from core.tools import exploit_tools

    host = f"192.0.2.{uuid.uuid4().int % 200 + 1}"
    old_get_store = exploit_tools._get_cred_store
    old_legacy = dict(exploit_tools._KNOWN_CREDS)
    exploit_tools._get_cred_store = lambda: None
    exploit_tools._KNOWN_CREDS[("ssh", host)] = [("support", "qweqwe123")]
    try:
        pipeline = AIPipeline(f"/tmp/octopus_pipeline_cached_creds_{uuid.uuid4().hex}.db")
        seeded = pipeline._seed_known_credentials("scan-cached-creds", host)
        facts = pipeline.fact_store.get_facts("scan-cached-creds", host)
        expanded = pipeline._expand_command_with_context(f"bruteforce ssh {host}", "scan-cached-creds", host)
    finally:
        exploit_tools._get_cred_store = old_get_store
        exploit_tools._KNOWN_CREDS.clear()
        exploit_tools._KNOWN_CREDS.update(old_legacy)

    pairs = {(fact["type"], fact["value"]) for fact in facts}
    assert seeded == 1
    assert ("credential", "support:qweqwe123 (cached)") in pairs
    assert expanded == [f"ssh_session {host}"]


def test_runner_detects_all_http_like_ports_from_nmap_lines():
    from core.tools.runner import _detect_web_ports_from_nmap

    output = """
80/tcp   open  http       Golang net/http server
443/tcp  open  ssl/http   Golang net/http server
2087/tcp open  ssl/eli?
3000/tcp open  http       Node.js Express framework
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
8080/tcp open  http       (PHP 8.4.22)
9000/tcp open  http       Golang net/http server
"""

    ports = _detect_web_ports_from_nmap(output)

    assert ports == ["80", "443", "2087", "3000", "8080", "9000"]
    assert "5432" not in ports


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


def test_explicit_exfil_stage_completion_opens_cleanup_gate():
    import uuid
    from core.ai.context_builder import ContextBuilder
    from core.ai.fact_store import FactStore
    from core.ai.state_resolver import StateResolver

    db_path = f"/tmp/octopus_context_exfil_{uuid.uuid4().hex}.db"
    store = FactStore(db_path)
    resolver = StateResolver(store)
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

    assert state["exfiltration_completed"]
    assert context["state"] == "exfiltration_completed"
    assert context["stage_gates"]["exfiltration"] is True
    assert context["next_required_capability"] == "cleanup"
    assert "cleanup_needed" in context["open_questions"]


def test_vulnerability_plan_gets_ad_enrichment_for_ldap_surface():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    pipeline.tool_registry.task_has_available_tools = lambda task: task == "active_directory_enumeration"
    context = {
        "state": "recon_completed",
        "services": ["ldap", "kerberos"],
        "open_questions": ["active_directory_exposure_unknown"],
    }
    base_plan = [
        {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
        {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"},
    ]

    optimized = pipeline._optimize_plan(base_plan, "vulnerability_assessment", context)
    tasks = [step["task"] for step in optimized]

    assert tasks == [
        "vulnerability_assessment",
        "active_directory_enumeration",
        "analyze_vulnerabilities",
    ]
