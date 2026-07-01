#!/usr/bin/env python3
"""Regression tests for AI pipeline planning quality gates."""


def test_post_exploit_goal_forces_verification_plan():
    import config
    from core.ai.pipeline import AIPipeline

    old_strategy = dict(config.CFG.get("strategy", {}))
    config.CFG.setdefault("strategy", {}).update({"auto_data_exfil": True})
    pipeline = AIPipeline("/tmp/octopus_test_pipeline_quality.db")
    try:
        context = {
            "state": "root_access_confirmed",
            "services": ["ssh", "http"],
            "open_questions": ["data_exfiltration_pending"],
            "automation_policy": {"auto_data_exfil": True},
        }
        noisy_plan = [
            {"agent": "DiscoveryAgent", "task": "directory_bruteforce"},
            {"agent": "AnalysisAgent", "task": "analyze_services"},
        ]

        optimized = pipeline._optimize_plan(noisy_plan, "data_exfiltration", context)
    finally:
        config.CFG["strategy"] = old_strategy

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


def test_fact_store_preserves_duplicate_fact_observations():
    import uuid
    from core.ai.fact_store import FactStore

    store = FactStore(f"/tmp/octopus_fact_provenance_{uuid.uuid4().hex}.db")
    scan_id = "scan-provenance"
    host = "10.0.0.5"

    first_id, first_created = store.add_fact_with_status(
        scan_id, host, "web_server", "nginx/1.24.0", "curl_headers http://10.0.0.5"
    )
    second_id, second_created = store.add_fact_with_status(
        scan_id, host, "web_server", "nginx/1.24.0", "scrapling http://10.0.0.5"
    )
    facts = store.get_facts(scan_id, host, fact_type="web_server")

    assert first_created
    assert not second_created
    assert first_id == second_id
    assert len(facts) == 1
    assert len(facts[0]["observations"]) == 2
    assert facts[0]["sources"] == [
        "curl_headers http://10.0.0.5",
        "scrapling http://10.0.0.5",
    ]


def test_pipeline_derives_normalized_endpoint_and_network_graph_facts():
    import json
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_pipeline_derived_{uuid.uuid4().hex}.db")
    scan_id = "scan-derived"
    host = "10.0.0.5"

    pipeline._store_fact(
        scan_id,
        host,
        {"type": "port_open", "value": "43117/tcp (ssl/http) [Golang net/http server]", "confidence": 100},
        "test",
    )
    pipeline._store_fact(
        scan_id,
        host,
        {"type": "internal_subnet", "value": "172.25.0.1/16", "confidence": 90},
        "ssh_inventory",
    )
    facts = pipeline.fact_store.get_facts(scan_id, host)
    pairs = {(fact["type"], fact["value"]) for fact in facts}
    endpoint_values = [json.loads(value) for ftype, value in pairs if ftype == "web_endpoint"]
    edge_values = [json.loads(value) for ftype, value in pairs if ftype == "network_edge"]

    assert any(endpoint["url"] == "https://10.0.0.5:43117/" for endpoint in endpoint_values)
    assert any(edge["type"] == "attached_subnet" and edge["to"] == "172.25.0.1/16" for edge in edge_values)


def test_pipeline_runtime_zero_means_unlimited():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_runtime_limit.db")

    assert pipeline._runtime_limit(0) is None
    assert pipeline._runtime_limit("unlimited") is None
    assert pipeline._runtime_limit(7) == 7


def test_runner_preserves_discovered_web_page_urls_for_browser_analysis():
    import core.tools.post_tools  # noqa: F401 - registers browser_surface_analysis
    import core.tools.recon_tools  # noqa: F401 - registers URL-aware web tools
    from core.tools.registry import get_tool
    from core.tools.runner import run_tool_by_command

    commands = {
        "browser_surface_analysis": "browser_surface_analysis http://10.0.0.5/_reports?id=7",
        "security_headers_check": "security_headers_check https://app.example.com/admin?x=1",
        "cors_check": "cors_check https://app.example.com/admin?x=1",
        "nuclei_safe": "nuclei_safe https://app.example.com/admin?x=1",
        "openapi_import": "openapi_import https://app.example.com/openapi.json",
        "graphql_check": "graphql_check https://app.example.com/graphql",
        "api_auth_check": "api_auth_check https://app.example.com/api/users",
    }
    captured = []
    old_funcs = {}

    def fake_url_tool(target, *args, **kwargs):
        captured.append(target)
        return "ok"

    try:
        for tool_name, command in commands.items():
            tool_def = get_tool(tool_name)
            old_funcs[tool_name] = tool_def.func
            tool_def.func = fake_url_tool
            result = run_tool_by_command(command)
            assert result == "ok"
    finally:
        for tool_name, old_func in old_funcs.items():
            get_tool(tool_name).func = old_func

    assert captured == [
        "http://10.0.0.5/_reports?id=7",
        "https://app.example.com/admin?x=1",
        "https://app.example.com/admin?x=1",
        "https://app.example.com/admin?x=1",
        "https://app.example.com/openapi.json",
        "https://app.example.com/graphql",
        "https://app.example.com/api/users",
    ]


def test_n_mode_uses_registry_safe_deep_coverage_without_real_tools():
    import builtins
    import sys
    import types
    import core.tools.runner as runner
    import core.tools.recon_tools  # noqa: F401 - registers safe/deep tools
    from core.tools.registry import get_tool

    old_input = builtins.input
    old_default_recon = runner.run_default_recon
    old_killchain = sys.modules.get("core.killchain")
    old_web_funcs = {
        "wpscan": runner.run_wpscan,
        "sqlmap": runner.run_sqlmap,
        "nikto": runner.run_nikto,
        "web_login": runner.run_web_login_bruteforce,
        "scrapling": runner.run_scrapling_fetch,
        "ssh_enum": runner.run_ssh_user_enum,
        "bruteforce": runner.run_bruteforce,
    }
    patched_tools = {}
    calls = []

    def fake_default_recon(_target):
        return {
            "nmap": "80/tcp open http nginx\n22/tcp open ssh OpenSSH\n",
            "curl_headers": "HTTP/1.1 200 OK\nServer: nginx\n",
            "whatweb": "nginx",
        }

    def fake_tool(name):
        def _run(target, *args, **kwargs):
            calls.append((name, target))
            return f"{name} ok {target}"
        return _run

    try:
        builtins.input = lambda _prompt="": "n"
        runner.run_default_recon = fake_default_recon
        fake_killchain = types.ModuleType("core.killchain")
        fake_killchain.vuln_assess = lambda target, recon_blob: f"vuln_assess ok {target}"
        sys.modules["core.killchain"] = fake_killchain
        runner.run_wpscan = fake_tool("wpscan")
        runner.run_sqlmap = fake_tool("sqlmap")
        runner.run_nikto = fake_tool("nikto")
        runner.run_web_login_bruteforce = fake_tool("web_login_brute")
        runner.run_scrapling_fetch = fake_tool("scrapling")
        runner.run_ssh_user_enum = fake_tool("ssh_user_enum")
        runner.run_bruteforce = fake_tool("bruteforce")

        for tool_name in (
            "httpx_probe", "naabu", "tlsx", "security_headers_check",
            "cors_check", "nuclei_safe", "katana_crawl", "openapi_import",
            "graphql_check",
        ):
            tool_def = get_tool(tool_name)
            patched_tools[tool_name] = (tool_def.func, list(tool_def.requires))
            tool_def.requires = []
            tool_def.func = fake_tool(tool_name)

        output = runner.interactive_tool_run("10.0.0.5")
    finally:
        builtins.input = old_input
        runner.run_default_recon = old_default_recon
        if old_killchain is None:
            sys.modules.pop("core.killchain", None)
        else:
            sys.modules["core.killchain"] = old_killchain
        runner.run_wpscan = old_web_funcs["wpscan"]
        runner.run_sqlmap = old_web_funcs["sqlmap"]
        runner.run_nikto = old_web_funcs["nikto"]
        runner.run_web_login_bruteforce = old_web_funcs["web_login"]
        runner.run_scrapling_fetch = old_web_funcs["scrapling"]
        runner.run_ssh_user_enum = old_web_funcs["ssh_enum"]
        runner.run_bruteforce = old_web_funcs["bruteforce"]
        for tool_name, (old_func, old_requires) in patched_tools.items():
            tool_def = get_tool(tool_name)
            tool_def.func = old_func
            tool_def.requires = old_requires

    called_tools = {name for name, _target in calls}

    assert "[N MODE PLAN]" in output
    assert "asm_domain_discovery: not_applicable:target_is_ip" in output
    assert "secrets/code/cloud: not_applicable" in output
    assert "vuln_assess ok 10.0.0.5" in output
    assert {"httpx_probe", "naabu", "tlsx", "security_headers_check", "cors_check", "nuclei_safe", "katana_crawl", "openapi_import", "graphql_check"}.issubset(called_tools)
    assert ("security_headers_check", "http://10.0.0.5") in calls
    assert ("openapi_import", "http://10.0.0.5/openapi.json") in calls


def test_x_mode_runs_exhaustive_applicable_coverage_without_real_tools():
    import builtins
    import sys
    import types
    import core.tools.runner as runner
    import core.tools.post_tools  # noqa: F401 - registers browser_surface_analysis
    import core.tools.recon_tools  # noqa: F401 - registers recon/deep tools
    from core.tools.registry import get_tool

    old_input = builtins.input
    old_default_recon = runner.run_default_recon
    old_killchain = sys.modules.get("core.killchain")
    patched_tools = {}
    calls = []

    def fake_default_recon(_target):
        return {
            "nmap": "80/tcp open http nginx\n",
            "curl_headers": "HTTP/1.1 200 OK\nServer: nginx\n",
            "whatweb": "nginx",
        }

    def fake_tool(name):
        def _run(target, *args, **kwargs):
            calls.append((name, target))
            return f"{name} ok {target}"
        return _run

    try:
        builtins.input = lambda _prompt="": "x"
        runner.run_default_recon = fake_default_recon
        fake_killchain = types.ModuleType("core.killchain")
        fake_killchain.vuln_assess = lambda target, recon_blob: f"vuln_assess ok {target}"
        sys.modules["core.killchain"] = fake_killchain

        for tool_name in (
            "httpx_probe", "naabu", "tlsx", "whatweb", "curl_headers",
            "security_headers_check", "cors_check", "scrapling",
            "scrapling_crawl", "browser_surface_analysis", "nuclei_safe",
            "katana_crawl", "wpscan", "sqlmap", "nikto", "openapi_import",
            "graphql_check", "api_auth_check",
        ):
            tool_def = get_tool(tool_name)
            patched_tools[tool_name] = (tool_def.func, list(tool_def.requires))
            tool_def.requires = []
            tool_def.func = fake_tool(tool_name)

        output = runner.interactive_tool_run("10.0.0.5")
    finally:
        builtins.input = old_input
        runner.run_default_recon = old_default_recon
        if old_killchain is None:
            sys.modules.pop("core.killchain", None)
        else:
            sys.modules["core.killchain"] = old_killchain
        for tool_name, (old_func, old_requires) in patched_tools.items():
            tool_def = get_tool(tool_name)
            tool_def.func = old_func
            tool_def.requires = old_requires

    called_tools = {name for name, _target in calls}

    assert "[X MODE PLAN]" in output
    assert "gated killchain_exfil" in output
    assert "vuln_assess ok 10.0.0.5" in output
    assert {"httpx_probe", "naabu", "tlsx", "nuclei_safe", "katana_crawl", "wpscan", "sqlmap", "nikto", "api_auth_check"}.issubset(called_tools)
    assert ("security_headers_check", "http://10.0.0.5") in calls
    assert ("api_auth_check", "http://10.0.0.5/api") in calls


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


def test_director_does_not_drift_from_vuln_assessment_to_post_exploit_without_creds():
    from core.ai.director import DirectorLLM

    context = {
        "state": "vulnerabilities_found",
        "services": ["http", "https"],
        "open_questions": ["vulnerability_verification_needed", "jmx_exposure_unknown"],
    }

    goal = DirectorLLM()._validate_goal(
        "vulnerability_assessment",
        context,
        ["vulnerability_assessment", "credential_harvesting"],
    )

    assert goal == "conclude"


def test_evidence_verifier_does_not_treat_unknown_question_as_exposure_proof():
    import uuid
    from core.ai.evidence import EvidenceVerifier
    from core.ai.fact_store import FactStore

    db_path = f"/tmp/octopus_evidence_verifier_{uuid.uuid4().hex}.db"
    scan_id = "scan"
    host = "10.0.0.5"
    store = FactStore(db_path)
    store.add_fact(scan_id, host, "port_open", "80/tcp (http) [Angie]", "test")
    store.add_fact(scan_id, host, "open_question", "jmx_exposure_unknown", "test")

    verifier = EvidenceVerifier(store)
    rejected = verifier.verify_claim(
        scan_id,
        host,
        "jmx_service_exposed_on_port",
        ["open_questions: jmx_exposure_unknown", "services_include_http"],
    )
    accepted = verifier.verify_claim(
        scan_id,
        host,
        "http_service_active",
        ["http_service_active", "services_include_http"],
    )

    assert rejected["status"] == "rejected"
    assert accepted["status"] == "accepted"


def test_vulnerability_metadata_uses_endpoint_facts_for_confirmed_findings():
    import sys
    import types

    fake_export = types.ModuleType("export")
    fake_export.export_menu = lambda *args, **kwargs: None
    fake_db = types.ModuleType("db")
    for name in [
        "get_connection", "create_session", "update_session_status",
        "save_vulnerability", "save_fix", "save_exploit", "save_summary",
        "get_all_history", "get_session", "get_vulnerabilities", "get_fixes",
        "get_exploits", "edit_vulnerability", "edit_fix", "edit_exploit",
        "edit_summary_risk", "delete_vulnerability", "delete_exploit",
        "delete_fix", "delete_full_session", "print_history", "print_session",
    ]:
        setattr(fake_db, name, lambda *args, **kwargs: None)
    old_export = sys.modules.get("export")
    old_db = sys.modules.get("db")
    old_octopus = sys.modules.get("octopus")
    sys.modules["export"] = fake_export
    sys.modules["db"] = fake_db
    try:
        from octopus import _vulnerability_metadata
    finally:
        if old_octopus is not None:
            sys.modules["octopus"] = old_octopus
        else:
            sys.modules.pop("octopus", None)
        if old_export is not None:
            sys.modules["export"] = old_export
        else:
            sys.modules.pop("export", None)
        if old_db is not None:
            sys.modules["db"] = old_db
        else:
            sys.modules.pop("db", None)

    msf_fact = {
        "type": "vulnerability",
        "value": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec",
        "source": "msf_check 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RPORT=49153",
    }
    facts = [
        msf_fact,
        {"type": "port_open", "value": "49153/tcp (redis) [Redis key-value store]"},
        {
            "type": "vulnerability_endpoint",
            "value": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec:49153",
        },
    ]

    meta = _vulnerability_metadata(msf_fact, facts, {})

    assert meta["port"] == "49153"
    assert meta["service"] == "redis"


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


def test_legacy_agents_module_imports_current_ai_and_tool_facades(monkeypatch):
    import agents
    from core.ai.legacy_agents import DirectorAgent

    monkeypatch.setattr(
        agents,
        "get_all_known_creds_for_target",
        lambda target: {"ssh": [("root", "toor")]} if target == "10.0.0.5" else {},
    )

    assert callable(agents.ask_ollama)
    assert callable(agents.extract_tags)
    assert callable(agents.extract_facts_from_output)
    assert callable(agents.run_tool_by_command)
    assert callable(agents.run_arbitrary_cmd)
    assert DirectorAgent is agents.DirectorAgent
    assert "ssh" in agents._build_creds_context("10.0.0.5").lower()


def test_plugin_manager_skips_optional_import_failures_without_warning(tmp_path, caplog):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    plugin_dir.mkdir()
    plugin_file = plugin_dir / "optional_plugin.py"
    plugin_file.write_text(
        "\n".join([
            "import octopus_missing_optional_dep",
            "from core.plugins.base import OctopusPlugin, PluginType, PluginResult",
            "class OptionalPlugin(OctopusPlugin):",
            "    name = 'optional_plugin'",
            "    version = '1.0.0'",
            "    plugin_type = PluginType.AUXILIARY",
            "    def run(self, **kwargs):",
            "        return PluginResult(success=True)",
        ])
    )

    with caplog.at_level("WARNING"):
        manager = PluginManager(str(plugin_dir))

    assert manager.plugins == {}
    assert manager.list_skipped_plugins() == [
        {"module": "optional_plugin", "reason": "No module named 'octopus_missing_optional_dep'"}
    ]
    assert not [record for record in caplog.records if record.levelname == "WARNING"]


def test_privesc_exploit_registry_autoloads_existing_adapters():
    from core.killchain.exploits import get_privesc_exploits
    from core.killchain.exploits.base import ExploitBase

    exploits = get_privesc_exploits()
    names = {exploit.name for exploit in exploits}

    assert exploits
    assert all(isinstance(exploit, ExploitBase) for exploit in exploits)
    assert {"Baron Samedit", "DirtyPipe", "DirtyCow"}.issubset(names)


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


def test_exploit_selector_handles_local_inventory_without_msf_run():
    from core.exploits.selector import select_exploits

    output = select_exploits(
        "10.0.0.5",
        "service_version -> apache:local:Apache/2.4.49\napp_stack -> nginx",
        run_probe=False,
    )

    assert "Services analyzed:" in output
    assert "apache_normalize_path_rce" in output
    assert "MSF check:" not in output
    assert "MSF run gated:" not in output


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


def test_pipeline_feeds_internal_and_web_surface_facts_into_exploit_selector():
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

    assert "service_version -> nginx:local:nginx/1.14.0" in cmd
    assert "local_listening_port -> 8080" in cmd
    assert "web_server -> nginx/1.14.0" in cmd
    assert "app_manifest -> /var/www/app/package.json" in cmd
    assert "config_candidate -> /var/www/app/.env" in cmd


def test_fact_driven_actions_enrich_internal_and_web_surfaces():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_all_surface_actions_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    pipeline.tool_registry._is_tool_available = lambda name: name != "msf_check"
    scan_id = "scan-all-surfaces"
    host = "10.0.0.5"
    facts = [
        {"type": "service_version", "value": "nginx:local:nginx/1.14.0"},
        {"type": "local_listening_port", "value": "8080"},
        {"type": "web_server", "value": "nginx/1.14.0"},
        {"type": "web_title", "value": "Welcome to nginx!"},
        {"type": "app_manifest", "value": "/var/www/app/package.json"},
        {"type": "config_candidate", "value": "/var/www/app/.env"},
    ]
    for fact in facts:
        pipeline.fact_store.add_fact(scan_id, host, fact["type"], fact["value"], "test")

    commands = pipeline._fact_driven_action_commands(scan_id, host, facts)

    assert any(cmd.startswith(f"exploit_select {host}") for cmd in commands)
    assert "searchsploit nginx nginx/1.14.0" in commands
    assert "searchsploit http" in commands
    assert "searchsploit nodejs" in commands
    assert f"browser_surface_analysis http://{host}" in commands
    assert f"scrapling_crawl http://{host}" in commands


def test_fact_driven_service_intelligence_runs_exploit_select_searchsploit_and_msf_check():
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
        if cmd.startswith("searchsploit"):
            return "Apache 2.4.49 Path Traversal | multiple/webapps/50383.py"
        if cmd.startswith("msf_check"):
            return "[+] The target appears to be vulnerable."
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_service_intel_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline.tool_registry._is_tool_available = lambda name: True
        facts = [
            {
                "type": "port_open",
                "value": "80/tcp (http) [Apache httpd 2.4.49]",
                "confidence": 100,
                "session_id": "test",
            }
        ]
        result = pipeline._run_fact_driven_actions("scan-service-intel", "10.0.0.5", facts)
        stored = pipeline.fact_store.get_facts("scan-service-intel", "10.0.0.5")
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in stored}
    assert any(cmd.startswith("exploit_select 10.0.0.5") for cmd in calls)
    assert any(cmd.startswith("searchsploit http Apache httpd 2.4.49") for cmd in calls)
    assert any(cmd.startswith("msf_check 10.0.0.5") for cmd in calls)
    assert ("vulnerability", "msf_check_positive:exploit/multi/http/apache_normalize_path_rce") in pairs
    assert ("exploit_reference", "Apache 2.4.49 Path Traversal -> multiple/webapps/50383.py") in pairs
    assert result["new_facts"] >= 4


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
        pipeline.tool_registry._is_tool_available = lambda name: True
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


def test_pipeline_does_not_truncate_verification_followup_fanout_to_three():
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
            lines = ["[EXPLOIT SELECTION - 10.0.0.5]", "Services analyzed: 6"]
            for idx, port in enumerate(["49153", "49154", "49155", "49156", "49157", "49158"], 1):
                lines.extend([
                    f"[EXPLOIT CANDIDATE {idx}] redis:{port} Redis key-value store -> exploit/linux/redis/redis_replication_cmd_exec (version_map; matched 'redis')",
                    "  Payload recommendation: cmd/unix/reverse_python",
                    f"  MSF check: msf_check 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RHOSTS=10.0.0.5 RPORT={port}",
                ])
            return "\n".join(lines)
        if cmd.startswith("msf_check"):
            return "[-] The target does not appear to be vulnerable."
        return ""

    config.CFG.setdefault("strategy", {}).update({"verification_followup_commands": 10})
    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_followup_fanout_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline.tool_registry._is_tool_available = lambda name: True
        pipeline._run_task_commands(
            "scan-followup-fanout",
            "10.0.0.5",
            ["exploit_select 10.0.0.5"],
            fact_label="Fact",
        )
    finally:
        config.CFG["strategy"] = old_strategy
        pipeline_mod.run_arbitrary_cmd = old_runner

    msf_calls = [cmd for cmd in calls if cmd.startswith("msf_check ")]

    assert len(msf_calls) == 6
    assert any("RPORT=49158" in cmd for cmd in msf_calls)


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
    assert calls[:2] == ["ssh_session 10.0.0.5", "ssh_inventory 10.0.0.5"]
    assert any(cmd.startswith("exploit_select 10.0.0.5") for cmd in calls)
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
        pipeline.tool_registry._is_tool_available = lambda name: True
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
        pipeline.tool_registry._is_tool_available = lambda name: True
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
        "43117/tcp (ssl/http) [Golang net/http server]",
        "51234/tcp (http) [Cowboy httpd]",
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
        "https://10.0.0.5:43117",
        "http://10.0.0.5:51234",
        "http://10.0.0.5:3000",
        "http://10.0.0.5:3030",
        "https://10.0.0.5:2087",
    ]
    assert f"http://{host}:5432" not in endpoints
    assert expanded == [f"whatweb {endpoint}" for endpoint in endpoints]
    assert explicit == [f"whatweb http://{host}:9000"]


def test_web_endpoint_followups_stay_in_target_scope():
    import json
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_scope_endpoints_{uuid.uuid4().hex}.db")
    scan_id = "scan-scope-endpoints"
    target = "83.166.242.55"
    for endpoint in (
        {"url": "http://83.166.242.55/", "scheme": "http", "host": "83.166.242.55", "port": "80", "path": "/"},
        {"url": "http://nginx.org/", "scheme": "http", "host": "nginx.org", "port": "80", "path": "/"},
        {"url": "https://octopus.invalid/", "scheme": "https", "host": "octopus.invalid", "port": "443", "path": "/"},
    ):
        pipeline.fact_store.add_fact(scan_id, target, "web_endpoint", json.dumps(endpoint, sort_keys=True), "test")

    endpoints = pipeline._web_endpoints_from_facts(scan_id, target)

    assert endpoints == ["http://83.166.242.55"]


def test_pipeline_stores_offscope_browser_urls_as_external_not_web_endpoint():
    import json
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_store_scope_{uuid.uuid4().hex}.db")
    scan_id = "scan-store-scope"
    target = "83.166.242.55"

    pipeline._store_fact(
        scan_id,
        target,
        {
            "type": "web_endpoint",
            "value": json.dumps({
                "url": "http://nginx.org/",
                "scheme": "http",
                "host": "nginx.org",
                "port": "80",
                "path": "/",
            }, sort_keys=True),
            "confidence": 90,
        },
        "browser_surface_analysis",
    )
    pipeline._store_fact(
        scan_id,
        target,
        {
            "type": "web_endpoint",
            "value": json.dumps({
                "url": "http://83.166.242.55/",
                "scheme": "http",
                "host": "83.166.242.55",
                "port": "80",
                "path": "/",
            }, sort_keys=True),
            "confidence": 90,
        },
        "browser_surface_analysis",
    )

    facts = pipeline.fact_store.get_facts(scan_id, target)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("external_url", "http://nginx.org/") in pairs
    assert not any(ftype == "web_endpoint" and "nginx.org" in value for ftype, value in pairs)
    assert pipeline._web_endpoints_from_facts(scan_id, target) == ["http://83.166.242.55"]


def test_domain_target_allows_subdomain_but_not_external_endpoint_followups():
    import json
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_scope_domain_{uuid.uuid4().hex}.db")
    scan_id = "scan-scope-domain"
    target = "example.com"
    for endpoint in (
        {"url": "https://app.example.com/admin", "scheme": "https", "host": "app.example.com", "port": "443", "path": "/admin"},
        {"url": "https://cdn.other.net/app.js", "scheme": "https", "host": "cdn.other.net", "port": "443", "path": "/app.js"},
    ):
        pipeline.fact_store.add_fact(scan_id, target, "web_endpoint", json.dumps(endpoint, sort_keys=True), "test")

    endpoints = pipeline._web_endpoints_from_facts(scan_id, target)

    assert endpoints == ["https://app.example.com/admin"]


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
    assert "/admin" in command
    assert "nginx/1.14.0" in command
    assert "nginx.org" not in command
    assert "nginx.com" not in command


def test_web_content_discovery_probes_unknown_web_surface_once():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_pipeline_no_web_ffuf_{uuid.uuid4().hex}.db")
    scan_id = "scan-no-web-ffuf"
    host = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, host, "port_open", "22/tcp (ssh) [OpenSSH]", "test")

    ffuf_expanded = pipeline._expand_command_with_context(f"ffuf {host}", scan_id, host)
    crawl_expanded = pipeline._expand_command_with_context(f"scrapling_crawl {host}", scan_id, host)
    explicit_url = pipeline._expand_command_with_context(
        f"ffuf http://{host}:43117",
        scan_id,
        host,
    )

    assert ffuf_expanded == [f"ffuf {host}"]
    assert crawl_expanded == [f"scrapling_crawl {host}"]
    assert explicit_url == [f"ffuf http://{host}:43117"]


def test_web_content_discovery_negative_probe_becomes_fact_not_loop():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("ffuf "):
            return "[!] ffuf skipped: no HTTP(S) response during preflight."
        if cmd.startswith("scrapling_crawl "):
            return "[!] no HTTP(S) response"
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        pipeline = AIPipeline(f"/tmp/octopus_pipeline_no_web_task_{uuid.uuid4().hex}.db")
        scan_id = "scan-no-web-task"
        host = "10.0.0.5"
        pipeline.fact_store.add_fact(scan_id, host, "port_open", "22/tcp (ssh) [OpenSSH]", "test")
        result = pipeline._run_task_commands(
            scan_id,
            host,
            [f"ffuf {host}", f"scrapling_crawl {host}"],
            fact_label="Fact",
        )
        status = pipeline._classify_task_result(result)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {
        (fact["type"], fact["value"])
        for fact in pipeline.fact_store.get_facts("scan-no-web-task", "10.0.0.5")
    }

    assert calls == ["ffuf 10.0.0.5", "scrapling_crawl 10.0.0.5"]
    assert ("service_status", "web_content_discovery_skipped:no_http_response") in pairs
    assert result["reason"].endswith("_new_facts")
    assert status == "completed"


def test_fact_driven_actions_map_evidence_to_next_commands():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_fact_actions_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    pipeline.tool_registry._is_tool_available = lambda name: name != "searchsploit"
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

    assert f"ssh_inventory {host}" in commands
    assert any(cmd.startswith(f"exploit_select {host}") for cmd in commands)
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


def test_fact_driven_actions_recurse_from_crawl_links_to_pages():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("browser_surface_analysis "):
            return """
URL: http://10.0.0.5
Page title: Root
Content size: 1200 bytes
link: /login
"""
        if cmd.startswith("scrapling_crawl "):
            return """
[REQUESTS+BS4 RESULT - http://10.0.0.5]
Status: 200
Title: Root
Links (1):
  Login -> /login
"""
        if cmd == "curl_headers http://10.0.0.5/login":
            return "Server: nginx\nLocation: /login"
        if cmd == "scrapling http://10.0.0.5/login":
            return """
[REQUESTS+BS4 RESULT - http://10.0.0.5/login]
Status: 200
Title: Login
Forms (1):
  POST -> /login
"""
        if cmd.startswith("searchsploit "):
            return "No Results"
        if cmd.startswith("exploit_select "):
            return "[EXPLOIT SELECTION - 10.0.0.5]\nServices analyzed: 1"
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_deep_web_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline.tool_registry._is_tool_available = lambda name: True
        scan_id = "scan-deep-web"
        host = "10.0.0.5"
        facts = [{"type": "port_open", "value": "80/tcp (http) [nginx]"}]
        pipeline.fact_store.add_fact(scan_id, host, "port_open", "80/tcp (http) [nginx]", "test")
        result = pipeline._run_fact_driven_actions(scan_id, host, facts)
        stored = pipeline.fact_store.get_facts(scan_id, host)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in stored}
    assert f"browser_surface_analysis http://{host}" in calls
    assert f"scrapling_crawl http://{host}" in calls
    assert f"curl_headers http://{host}/login" in calls
    assert f"scrapling http://{host}/login" in calls
    assert ("web_link", "/login") in pairs
    assert ("web_title", "Login") in pairs
    assert result["new_facts"] >= 5


def test_post_access_inventory_facts_reenter_fact_driven_depth():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        if cmd.startswith("ssh_inventory "):
            return """
[*] SSH Controlled Inventory: support@10.0.0.5:22
[+] SSH connected as support@10.0.0.5:22

[+] Hostname
$ hostname
web01

[+] Listening Ports (1 internal services)
tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*

nginx version: nginx/1.14.0
/var/www/app/package.json

[+] SSH inventory completed
"""
        if cmd.startswith("exploit_select "):
            return "[EXPLOIT SELECTION - 10.0.0.5]\nServices analyzed: 2"
        if cmd.startswith("searchsploit "):
            return "nginx 1.14.0 local info"
        return ""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        db_path = f"/tmp/octopus_pipeline_inventory_depth_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline.tool_registry._is_tool_available = lambda name: True
        scan_id = "scan-inventory-depth"
        host = "10.0.0.5"
        facts = [{"type": "credential", "value": f"ssh_login_success:support@{host}"}]
        pipeline.fact_store.add_fact(scan_id, host, "credential", f"ssh_login_success:support@{host}", "test")
        result = pipeline._run_fact_driven_actions(scan_id, host, facts)
        stored = pipeline.fact_store.get_facts(scan_id, host)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in stored}
    assert f"ssh_inventory {host}" in calls
    assert any(
        cmd.startswith(f"exploit_select {host}") and "service_version -> nginx:local:nginx/1.14.0" in cmd
        for cmd in calls
    )
    assert "searchsploit nginx nginx/1.14.0" in calls
    assert ("service_version", "nginx:local:nginx/1.14.0") in pairs
    assert ("local_listening_port", "8080") in pairs
    assert ("app_manifest", "/var/www/app/package.json") in pairs
    assert result["new_facts"] >= 6


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
[159s] 443/tcp  open  ssl/http   Golang net/http server
2087/tcp open  ssl/eli?
3000/tcp open  http       Node.js Express framework
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
8080/tcp open  http       (PHP 8.4.22)
9000/tcp open  http       Golang net/http server
[159s] 43117/tcp open  ssl/http   Golang net/http server
[159s] 51234/tcp open  http       Cowboy httpd
"""

    ports = _detect_web_ports_from_nmap(output)

    assert ports == ["80", "443", "3000", "8080", "9000", "43117", "51234"]
    assert "5432" not in ports
    assert "2087" not in ports


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


def test_exploit_selector_splits_pipe_delimited_fact_context():
    from core.exploits.selector import select_exploits

    context = (
        "port_open -> 43117/tcp (ssl/http) [Golang net/http server] | "
        "service_version -> ssl/http:43117:Golang net/http server | "
        "port_open -> 10002/tcp (nagios-nsca) [Nagios NSCA] | "
        "service_version -> nagios-nsca:10002:Nagios NSCA | "
        "port_open -> 49153/tcp (redis) [Redis key-value store] | "
        "service_version -> redis:49153:Redis key-value store"
    )

    output = select_exploits("10.0.0.5", context, run_probe=False)

    assert "exploit/linux/redis/redis_replication_cmd_exec" in output
    assert "RPORT=49153" in output
    assert "RPORT=43117" not in output
    assert "10002/tcp on ssl/http:43117" not in output


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


def test_replay_outputs_builds_target_model_and_snapshot_actions():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_replay_target_model_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-replay"
    target = "10.0.0.5"

    result = pipeline.replay_outputs(scan_id, target, [
        {
            "tool": "nmap",
            "output": """
Nmap scan report for 10.0.0.5
PORT      STATE SERVICE VERSION
43117/tcp open  ssl/http Golang net/http server
49153/tcp open  redis    Redis key-value store 6.2
""",
        },
        {
            "tool": "scrapling https://10.0.0.5:43117/",
            "output": """
URL: https://10.0.0.5:43117/
Status: 200
Title: Admin
Forms: 1
Links:
  /login
""",
        },
    ])

    model = result["context"]["target_model"]
    actions = [item["command"] for item in result["snapshot_actions"]]

    assert result["parsed_facts"] > 0
    assert any(service["port"] == 43117 and "http" in service["service"] for service in model["services"])
    assert any(endpoint["url"] == "https://10.0.0.5:43117/" for endpoint in model["endpoints"])
    assert model["unknowns"]["web_surface"] == "confirmed_present"
    assert any(command.startswith("scrapling https://10.0.0.5:43117/login") for command in actions)
    assert any(command.startswith("exploit_select 10.0.0.5") for command in actions)


def test_command_scheduler_skips_duplicate_and_negative_http_surface():
    import uuid
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_scheduler_negative_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-negative"
    target = "10.0.0.5"

    pipeline._store_fact(
        scan_id,
        target,
        {
            "type": "service_status",
            "value": "web_content_discovery_skipped:no_http_response:http://10.0.0.5/",
            "confidence": 90,
        },
        "ffuf http://10.0.0.5",
    )

    facts = pipeline.fact_store.get_facts(scan_id, target)
    first = pipeline.command_scheduler.decide("ffuf http://10.0.0.5", facts, pipeline.executed_command_keys)
    pipeline.executed_command_keys.add(pipeline.command_scheduler.command_key("curl_headers http://10.0.0.5"))
    second = pipeline.command_scheduler.decide("curl_headers http://10.0.0.5/", facts, pipeline.executed_command_keys)

    assert first.action == "skip"
    assert first.reason == "confirmed_absent:no_http_response"
    assert second.action == "skip"
    assert second.reason == "duplicate_command_key"


def test_execute_pipeline_command_records_trace_and_blocks_repeat(monkeypatch=None):
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_command_trace_{uuid.uuid4().hex}.db"
    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        return "Nmap scan report for 10.0.0.5\n80/tcp open http nginx"

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        pipeline = AIPipeline(db_path)
        first = pipeline._execute_pipeline_command("scan-trace", "10.0.0.5", "nmap 10.0.0.5", "Fact", "[Running]")
        second = pipeline._execute_pipeline_command("scan-trace", "10.0.0.5", "nmap   10.0.0.5", "Fact", "[Running]")
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert len(calls) == 1
    assert first["parsed_facts"] > 0
    assert second["command_result"]["skipped"] is True
    assert second["command_result"]["skip_reason"] == "duplicate_command_key"
    assert any(item["action"] == "execute" and item["new_facts"] > 0 for item in pipeline.command_trace)
    assert any(item["action"] == "skip" and item["reason"] == "duplicate_command_key" for item in pipeline.command_trace)


def test_director_next_required_capability_overrides_llm_suggestion():
    from core.ai.director import DirectorLLM

    context = {
        "state": "recon_completed",
        "services": ["http"],
        "open_questions": ["web_vulnerabilities_unknown"],
        "next_required_capability": "vulnerability_assessment",
        "automation_policy": {},
    }

    assert DirectorLLM()._validate_goal("credential_harvesting", context, []) == "vulnerability_assessment"


def test_real_app_replay_ssh_only_log_builds_state_without_web_or_msf_noise():
    import pathlib
    import uuid
    from core.ai.pipeline import AIPipeline

    fixture = pathlib.Path(__file__).parent / "fixtures" / "replay_ssh_only_real_app.log"
    raw_log = fixture.read_text()
    db_path = f"/tmp/octopus_real_replay_ssh_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-real-ssh"
    target = "83.166.241.164"

    result = pipeline.replay_outputs(scan_id, target, [{"tool": "manual_recon", "output": raw_log}])
    facts = pipeline.fact_store.get_facts(scan_id, target)
    pairs = {(fact["type"], fact["value"]) for fact in facts}
    context = result["context"]
    model = context["target_model"]

    assert ("port_open", "22/tcp (ssh) [OpenSSH 7.4 (protocol 2.0)]") in pairs
    assert ("credential", "support:qweqwe123 (cached)") in pairs
    assert ("service_status", "ssh_user_enum_unreliable_or_patched") in pairs
    assert ("service_status", "msf_check_invalid_options:auxiliary/scanner/ssh/ssh_login") in pairs
    assert not any(ftype == "web_endpoint" for ftype, _value in pairs)
    assert not any(ftype == "module_name" for ftype, _value in pairs)
    assert context["state"] == "credentials_found"
    assert context["next_required_capability"] == "credential_harvesting"
    assert model["unknowns"]["web_surface"] == "unknown"
    assert any(service["service"] == "ssh" and service["port"] == 22 for service in model["services"])


def test_registry_exposes_asm_api_secret_code_cloud_categories():
    from core.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()

    for task in (
        "asm_discovery",
        "template_verification",
        "api_security_testing",
        "secrets_scanning",
        "code_security_assessment",
        "cloud_security_assessment",
        "ad_security_review",
        "bloodhound_ingest",
        "password_policy_review",
        "delegation_analysis",
        "gpo_review",
        "adcs_review",
    ):
        assert registry.has_task(task)

    assert registry.canonical_task("asset_inventory") == "asm_discovery"
    assert registry.canonical_task("nuclei") == "template_verification"
    assert registry.canonical_task("gitleaks") == "secrets_scanning"
    assert registry.canonical_task("sharphound") == "bloodhound_ingest"
    assert registry.canonical_task("adcs") == "adcs_review"
    assert "nuclei_safe" in registry._tool_names_for_task("template_verification")
    assert "openapi_import" in registry._tool_names_for_task("api_security_testing")
    assert "bloodhound_ingest" in registry._tool_names_for_task("ad_security_review")


def test_target_model_exposes_assets_api_and_security_findings():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_target_model_asm_{uuid.uuid4().hex}.db")
    scan_id = "scan-asm"
    target = "example.com"
    for fact_type, value in (
        ("asset_domain", "app.example.com"),
        ("asset_ip", "203.0.113.10"),
        ("asset_url", "https://app.example.com"),
        ("technology", "nginx,React"),
        ("api_endpoint", "GET:/users:auth=unknown_or_none"),
        ("api_security_note", "auth_unknown_or_none:GET:/users"),
        ("nuclei_finding", "medium:exposed-panel:https://app.example.com/admin"),
        ("secret_finding", "generic-api-key:app/.env:unvalidated:rotation_required"),
        ("code_finding", "high:CVE-2024-0001:requirements.txt"),
        ("cloud_finding", "high:s3_bucket_public_access:bucket-1"),
        ("ad_domain", "CORP.LOCAL"),
        ("ad_attack_path", "domain_admin_paths:3"),
        ("ad_adcs_issue", "ESC1:vulnerable template"),
        ("ad_password_policy", "lockout_threshold:0"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]

    assert "app.example.com" in model["assets"]["domains"]
    assert "203.0.113.10" in model["assets"]["ips"]
    assert model["api"]["endpoints"][0]["method"] == "GET"
    assert model["unknowns"]["api_surface"] == "confirmed_present"
    assert model["unknowns"]["secrets"] == "confirmed_present"
    assert model["security_findings"]["nuclei"]
    assert model["security_findings"]["secrets"]
    assert model["security_findings"]["secrets"][0]["secret_type"] == "generic-api-key"
    assert model["security_findings"]["secrets"][0]["rotation_required"] == "yes"
    assert model["security_findings"]["code"]
    assert model["security_findings"]["cloud"]
    assert model["security_findings"]["cloud"][0]["provider"] == "aws"
    assert model["active_directory"]["domains"][0]["value"] == "CORP.LOCAL"
    assert model["active_directory"]["attack_paths"][0]["value"] == "domain_admin_paths:3"
    assert model["active_directory"]["adcs_issues"][0]["value"] == "ESC1:vulnerable template"
    assert model["unknowns"]["active_directory"] == "confirmed_present"
    assert model["unknowns"]["cloud"] == "confirmed_present"
    assert model["unknowns"]["code_security"] == "confirmed_present"


def test_web_surface_actions_include_safe_nuclei_katana_and_api_imports():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_pipeline_safe_web_{uuid.uuid4().hex}.db")
    pipeline.tool_registry._is_tool_available = lambda name: name in {
        "nuclei_safe", "katana_crawl", "security_headers_check", "cors_check",
    }
    scan_id = "scan-safe-web"
    target = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, target, "web_endpoint", "https://10.0.0.5:8443/", "test")

    commands = pipeline._web_surface_action_commands(
        scan_id,
        target,
        [{"type": "web_endpoint", "value": "https://10.0.0.5:8443/"}],
        set(),
    )
    link_commands = pipeline._web_link_action_commands(
        scan_id,
        target,
        [
            {"type": "web_link", "value": "/openapi.json"},
            {"type": "web_link", "value": "/graphql"},
            {"type": "web_link", "value": "/static/app.js"},
        ],
    )

    assert "security_headers_check https://10.0.0.5:8443" in commands
    assert "cors_check https://10.0.0.5:8443" in commands
    assert "nuclei_safe https://10.0.0.5:8443" in commands
    assert "katana_crawl https://10.0.0.5:8443" in commands
    assert "openapi_import https://10.0.0.5:8443/openapi.json" in link_commands
    assert "graphql_check https://10.0.0.5:8443/graphql" in link_commands
    assert "js_route_extract https://10.0.0.5:8443/static/app.js" in link_commands


def test_target_model_exposes_web_app_security_layer():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_target_model_webapp_{uuid.uuid4().hex}.db")
    scan_id = "scan-webapp"
    target = "app.example.com"
    for fact_type, value in (
        ("web_security_note", "missing_hsts"),
        ("web_security_note", "cors_credentials_allowed"),
        ("js_route", "/api/users/{id}"),
        ("proxy_finding", "Medium Cookie No HttpOnly Flag"),
        ("jwt_metadata", "alg:none"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]

    assert model["unknowns"]["web_security_notes"] == "confirmed_present"
    assert any(item["value"] == "missing_hsts" for item in model["web_app"]["security_notes"])
    assert any(item["value"] == "/api/users/{id}" for item in model["web_app"]["js_routes"])
    assert any("Cookie No HttpOnly" in item["value"] for item in model["web_app"]["proxy_findings"])
    assert any(item["value"] == "alg:none" for item in model["web_app"]["jwt"])


def test_parser_families_extract_without_legacy_dependency():
    from core.ai.parsers import ParserFamilyPipeline

    raw = """
80/tcp open http nginx
[API AUTH CHECK - https://app.example.com/api/users]
Anonymous status: 200
NOTE anonymous_accessible
Domain Name: CORP.LOCAL
ESC1: vulnerable template
"""

    facts = ParserFamilyPipeline().parse("nmap api_auth_check adcs_review", raw, "sess")
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "80/tcp (http) [nginx]") in pairs
    assert ("api_security_note", "anonymous_accessible") in pairs
    assert ("ad_domain", "CORP.LOCAL") in pairs
    assert ("ad_adcs_issue", "ESC1:vulnerable template") in pairs


def test_asset_graph_models_interface_subnet_endpoint_and_secret():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_asset_graph_{uuid.uuid4().hex}.db")
    scan_id = "scan-graph"
    host = "10.0.0.5"
    for fact_type, value in (
        ("internal_subnet", "172.25.0.5/16"),
        ("internal_host", "172.25.0.23"),
        ("web_endpoint", "https://10.0.0.5:8443/admin"),
        ("secret_finding", "aws-access-key:app/.env:validated:rotation_required"),
    ):
        pipeline._store_fact(scan_id, host, {"type": fact_type, "value": value, "confidence": 90}, "test")

    graph = pipeline.context_builder.build_context(scan_id, host)["asset_graph"]
    kinds = {node["kind"] for node in graph["nodes"]}
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert {"host", "interface", "subnet", "endpoint", "service", "secret"}.issubset(kinds)
    assert "has_interface" in edge_types
    assert "attached_to_subnet" in edge_types
    assert "member_of_subnet" in edge_types
    assert "exposes_endpoint" in edge_types


def test_surface_state_and_policy_filter_confirmed_absent_tasks():
    from core.ai.policy import DeterministicPolicy
    from core.ai.surface_state import SurfaceState

    facts = [{"type": "service_status", "value": "web_content_discovery_skipped:no_http_response:https://10.0.0.5/"}]
    states = SurfaceState(facts).to_dict()
    context = {
        "state": "recon_completed",
        "automation_policy": {},
        "target_model": {"surface_states": states},
    }
    plan = [
        {"agent": "DiscoveryAgent", "task": "web_application_mapping"},
        {"agent": "DiscoveryAgent", "task": "api_security_testing"},
    ]

    filtered = DeterministicPolicy().validate_plan(plan, context)

    assert states["web"] == "confirmed_absent"
    assert [step["task"] for step in filtered] == ["api_security_testing"]


def test_command_result_fingerprint_records_duplicate_outputs():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    calls = []

    def fake_runner(cmd):
        calls.append(cmd)
        return "80/tcp open http nginx"

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        pipeline = AIPipeline(f"/tmp/octopus_result_fp_{uuid.uuid4().hex}.db")
        pipeline._execute_pipeline_command("scan-fp", "10.0.0.5", "nmap 10.0.0.5", "Fact", "[Running]")
        pipeline._execute_pipeline_command("scan-fp", "10.0.0.5", "curl_headers http://10.0.0.5", "Fact", "[Running]")
        results = pipeline.fact_store.get_command_results("scan-fp", "10.0.0.5")
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert len(calls) == 2
    assert len(results) == 2
    assert results[0]["output_hash"] == results[1]["output_hash"]
    assert any(item.get("duplicate_output") for item in pipeline.command_trace)


def test_target_model_risk_analysis_correlates_ad_cloud_secret_and_code():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_risk_analysis_{uuid.uuid4().hex}.db")
    scan_id = "scan-risk"
    target = "app.example.com"
    for fact_type, value in (
        ("web_endpoint", "https://app.example.com/"),
        ("ad_attack_path", "domain_admin_paths:2"),
        ("ad_adcs_issue", "ESC1:vulnerable template"),
        ("cloud_finding", "high:s3_bucket_public_access:bucket-1"),
        ("secret_finding", "aws-access-key:app/.env:validated:rotation_required"),
        ("code_finding", "critical:CVE-2025-0001:requirements.txt"),
    ):
        pipeline.fact_store.add_fact(scan_id, target, fact_type, value, "test")

    model = pipeline.context_builder.build_context(scan_id, target)["target_model"]
    risk = model["risk_analysis"]

    assert any(item["kind"] == "adcs" and item["severity"] == "critical" for item in risk["ad_attack_paths"])
    assert "aws" in risk["cloud_posture"]
    assert risk["secret_rotation"][0]["priority"] == "urgent"
    assert risk["code_reachability"][0]["exposed_surface_present"] is True


def test_authenticated_web_and_api_facts_are_normalized():
    from core.ai.evidence import OutputParser

    output = """
[SESSION PROFILE IMPORT - session.json]
Headers: 2
Cookies: 1
[AUTHENTICATED CRAWL - https://app.example.com/dashboard]
Status: 200
Title: Dashboard
Forms: 1
CSRF token observed: no
LINK https://app.example.com/api/users
[API AUTH CHECK - https://app.example.com/api/users]
Anonymous status: 200
NOTE anonymous_accessible
"""

    facts = OutputParser().parse_tool_output("session_profile_import authenticated_crawl api_auth_check", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("web_session", "profile_imported:headers=2:cookies=1") in pairs
    assert ("web_session", "authenticated_crawl_status:200") in pairs
    assert ("web_security_note", "csrf_token_not_observed_authenticated") in pairs
    assert ("web_link", "https://app.example.com/api/users") in pairs
    assert ("api_security_note", "anonymous_accessible") in pairs


def test_trace_report_summarizes_commands_facts_and_duplicates():
    import uuid
    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd

    def fake_runner(cmd):
        return "80/tcp open http nginx"

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        pipeline = AIPipeline(f"/tmp/octopus_trace_report_{uuid.uuid4().hex}.db")
        scan_id = "scan-trace-report"
        target = "10.0.0.5"
        pipeline._execute_pipeline_command(scan_id, target, "nmap 10.0.0.5", "Fact", "[Running]")
        pipeline._execute_pipeline_command(scan_id, target, "curl_headers http://10.0.0.5", "Fact", "[Running]")
        report = pipeline.trace_report(scan_id, target)
        text = pipeline.trace_report_text(scan_id, target)
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    assert report["summary"]["commands"] == 2
    assert report["summary"]["duplicate_outputs"] == 1
    assert report["fact_flow"]
    assert "duplicate_output" in text
    assert "fact_flow" in text


def test_asm_parser_normalizes_dns_records_services_and_graph_edges():
    import uuid
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_asm_graph_{uuid.uuid4().hex}.db")
    scan_id = "scan-asm-graph"
    target = "example.com"
    result = pipeline.replay_outputs(scan_id, target, [{
        "tool": "httpx_probe dnsx tlsx naabu",
        "output": """
https://app.example.com [200] [Admin] [nginx,React]
app.example.com CNAME edge.example.net
app.example.com:443
SAN app.example.com api.example.com
""",
    }])

    model = result["context"]["target_model"]
    graph = result["context"]["asset_graph"]
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert "app.example.com" in model["assets"]["domains"]
    assert any(value.startswith("cname:edge.example.net") for value in model["assets"]["dns_records"])
    assert "app.example.com:443/tcp" in model["assets"]["services"]
    assert "owns_service" in edge_types
    assert "has_dns_record" in edge_types or "has_tls_san" in edge_types


def test_family_parsers_cover_template_web_api_ad_code_cloud_secrets():
    from core.ai.parsers import ParserFamilyPipeline

    raw = """
{"template-id":"exposed-panel","info":{"severity":"medium","name":"Panel"},"matched-at":"https://app.example.com/admin"}
Content-Security-Policy: default-src * 'unsafe-inline'
Set-Cookie: sid=abc
alg: none
/api/users/{id}
GET /users/{id} auth=unknown_or_none
PATCH /users/{id} auth=unknown_or_none
Minimum password length: 8
Lockout threshold: 0
Unconstrained delegation: WEB01$
GenericAll -> CORP\\Helpdesk
{"RuleID":"generic-api-key","File":"app/.env","Verified":true}
{"results":[{"check_id":"python.lang.security.audit","path":"app.py","extra":{"severity":"HIGH"}}]}
{"Results":[{"Target":"requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2025-0001","Severity":"CRITICAL"}]}]}
{"Status":"FAIL","Severity":"HIGH","CheckID":"s3_bucket_public_access","ResourceId":"bucket-1"}
"""

    facts = ParserFamilyPipeline().parse(
        "nuclei_safe security_headers_check jwt_analyze js_route_extract openapi_import ad_security_review gitleaks_scan semgrep_scan trivy_scan prowler_scan",
        raw,
        "sess",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert any(ftype == "nuclei_finding" and value.startswith("medium:exposed-panel") for ftype, value in pairs)
    assert ("web_security_note", "weak_csp_policy") in pairs
    assert ("web_security_note", "cookie_missing_httponly:sid") in pairs
    assert ("jwt_metadata", "alg:none") in pairs
    assert ("api_security_note", "idor_candidate:GET:/users/{id}") in pairs
    assert ("api_security_note", "mass_assignment_candidate:PATCH:/users/{id}") in pairs
    assert ("ad_password_policy", "min_length:8") in pairs
    assert ("ad_gpo_issue", "account_lockout_disabled") in pairs
    assert ("ad_delegation", "WEB01$") in pairs
    assert ("ad_acl_issue", "GenericAll:CORP\\Helpdesk") in pairs
    assert ("secret_finding", "generic-api-key:app/.env:validated:rotation_required") in pairs
    assert ("code_finding", "high:python.lang.security.audit:app.py") in pairs
    assert ("code_finding", "critical:CVE-2025-0001:requirements.txt") in pairs
    assert ("cloud_finding", "high:s3_bucket_public_access:bucket-1") in pairs


def test_output_parser_skips_legacy_regex_for_family_owned_tools():
    from core.ai.evidence import OutputParser

    parser = OutputParser()

    def fail_legacy(*_args, **_kwargs):
        raise AssertionError("legacy RegexParser should not run for family-owned tools")

    parser.regex_parser.parse = fail_legacy
    facts = parser.parse_tool_output(
        "httpx_probe nuclei_safe security_headers_check openapi_import gitleaks_scan semgrep_scan prowler_scan ad_security_review",
        """
https://app.example.com [200] [Admin] [nginx]
{"template-id":"exposed-panel","info":{"severity":"medium"},"matched-at":"https://app.example.com/admin"}
Server: nginx
GET /users/{id} auth=unknown_or_none
{"RuleID":"generic-api-key","File":"app/.env","Verified":true}
{"results":[{"check_id":"python.lang.security.audit","path":"app.py","extra":{"severity":"HIGH"}}]}
{"Status":"FAIL","Severity":"HIGH","CheckID":"s3_bucket_public_access","ResourceId":"bucket-1"}
Shortest paths to Domain Admins: 1
""",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("asset_url", "https://app.example.com") in pairs
    assert any(ftype == "nuclei_finding" for ftype, _value in pairs)
    assert ("web_server", "nginx") in pairs
    assert ("api_security_note", "idor_candidate:GET:/users/{id}") in pairs
    assert ("secret_finding", "generic-api-key:app/.env:validated:rotation_required") in pairs
    assert ("code_finding", "high:python.lang.security.audit:app.py") in pairs
    assert ("cloud_finding", "high:s3_bucket_public_access:bucket-1") in pairs
    assert ("ad_attack_path", "domain_admin_paths:1") in pairs


def test_output_parser_keeps_legacy_regex_for_legacy_killchain_outputs():
    from core.ai.evidence import OutputParser

    parser = OutputParser()
    facts = parser.parse_tool_output(
        "killchain_vuln_assess 10.0.0.5",
        "Total exploitable findings: 2",
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("stage_status", "vulnerability_assessment:findings:2") in pairs


def test_replay_snapshot_asserts_facts_actions_and_surface_states():
    import uuid
    from core.ai.replay_snapshot import ReplaySnapshot

    snapshot = ReplaySnapshot(f"/tmp/octopus_replay_snapshot_{uuid.uuid4().hex}.db")
    result = snapshot.assert_ok({
        "scan_id": "scan-snapshot",
        "target": "10.0.0.5",
        "outputs": [
            {
                "tool": "nmap",
                "output": "80/tcp open http nginx",
            },
            {
                "tool": "scrapling http://10.0.0.5",
                "output": "URL: http://10.0.0.5/\nTitle: Home\nLinks:\n  /api/users\n",
            },
        ],
        "expected_facts": [
            ("port_open", "80/tcp (http) [nginx]"),
            ("web_title", "Home"),
        ],
        "expected_fact_prefixes": [
            ("web_endpoint", "{\"host\": \"10.0.0.5\""),
        ],
        "expected_actions": [
            "scrapling http://10.0.0.5/api/users",
            "exploit_select 10.0.0.5",
        ],
        "expected_surface_states": {
            "web": "confirmed_present",
        },
    })

    assert result["ok"]
    assert any(action.startswith("exploit_select 10.0.0.5") for action in result["actions"])


def test_replay_snapshot_fixture_file_web_api():
    import pathlib
    import uuid
    from core.ai.replay_snapshot import ReplaySnapshot

    fixture = pathlib.Path(__file__).parent / "fixtures" / "replay_snapshot_web_api.json"
    snapshot = ReplaySnapshot(f"/tmp/octopus_replay_snapshot_file_{uuid.uuid4().hex}.db")
    result = snapshot.assert_file_ok(str(fixture))

    assert result["surface_states"]["web"] == "confirmed_present"
    assert result["surface_states"]["api"] == "confirmed_present"


def test_vulnerability_plan_enriches_safe_categories_from_surface_state():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_plan_surface_enrichment.db")
    available = {
        "asm_discovery",
        "web_application_mapping",
        "web_app_deep_testing",
        "template_verification",
        "api_security_testing",
        "active_directory_enumeration",
        "ad_security_review",
    }
    pipeline.tool_registry.task_has_available_tools = lambda task: task in available
    context = {
        "host": "app.example.com",
        "state": "recon_completed",
        "services": ["http", "https", "ldap"],
        "open_questions": ["web_vulnerabilities_unknown", "active_directory_exposure_unknown"],
        "automation_policy": {},
        "surface_states": {"asm": "unknown", "api": "unknown", "web": "confirmed_present"},
        "target_model": {
            "surface_states": {"asm": "unknown", "api": "unknown", "web": "confirmed_present"},
            "assets": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
        },
    }

    optimized = pipeline._optimize_plan(
        [{"agent": "DiscoveryAgent", "task": "vulnerability_assessment"}],
        "vulnerability_assessment",
        context,
    )
    tasks = [step["task"] for step in optimized]

    assert "asm_discovery" in tasks
    assert "web_app_deep_testing" in tasks
    assert "template_verification" in tasks
    assert "api_security_testing" in tasks
    assert "ad_security_review" in tasks
