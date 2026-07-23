#!/usr/bin/env python3
"""Action registry, adapter, provider, and follow-up contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_n_mode_uses_registry_safe_deep_coverage_without_real_tools():
    import builtins
    import sys
    import types

    import core.tools.recon_tools  # noqa: F401 - registers safe/deep tools
    import core.tools.runner as runner
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
    assert "compact_state ->" in cmd


def test_pipeline_feeds_compact_state_to_exploit_selector_without_raw_recon_bits():
    import uuid

    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_exploit_select_compact_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    scan_id = "scan-exploit-select-compact"
    host = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, host, "os_version", "CentOS Linux 7 (Core)", "ssh_inventory")
    pipeline.fact_store.add_fact(scan_id, host, "kernel_version", "3.10.0-1160.el7.x86_64", "ssh_inventory")
    pipeline.fact_store.add_fact(scan_id, host, "system_access", "uid=0", "ssh_inventory")
    pipeline.fact_store.add_fact(scan_id, host, "internal_service", "172.24.108.2:53/tcp (dns)", "internal_service_probe")

    cmd = pipeline._augment_command_with_context(f"exploit_select {host}", scan_id, host)

    assert cmd.startswith(f"exploit_select {host} ")
    assert "compact_state ->" in cmd
    assert '"os": "CentOS Linux 7 (Core)"' in cmd
    assert '"internal_services":' in cmd


def test_exploit_selector_strips_compact_state_before_regex_parsing():
    from core.exploits.selector import _extract_services

    services = _extract_services(
        'service_version -> ssh:22:OpenSSH 7.4 | '
        'compact_state -> {"open_ports":[{"port":22,"service":"ssh","banner":"OpenSSH 7.4"}]}'
    )

    assert {"port": "22", "service": "ssh", "version": "OpenSSH 7.4"} in services
    assert not any("compact_state" in svc["version"] or "{" in svc["service"] for svc in services)


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
        {"type": "potential_vulnerability", "value": "CVE-2023-48795"},
    ]
    for fact in facts:
        pipeline.fact_store.add_fact(scan_id, host, fact["type"], fact["value"], "test")

    commands = pipeline._fact_driven_action_commands(scan_id, host, facts)

    assert any(cmd.startswith(f"exploit_select {host}") for cmd in commands)
    assert "searchsploit http" in commands
    assert "searchsploit CVE-2023-48795" in commands
    assert "searchsploit nginx nginx/1.14.0" not in commands
    assert "searchsploit nodejs" not in commands
    assert f"browser_surface_analysis http://{host}" in commands
    assert f"scrapling_crawl http://{host}" in commands


def test_msf_ssh_login_success_drives_controlled_internal_inventory():
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
[EXPLOIT CANDIDATE 1] ssh:22 OpenSSH 7.4 -> auxiliary/scanner/ssh/ssh_login (credential verification)
  Payload recommendation: none/check-only
  MSF check: msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RHOSTS=10.0.0.5 RPORT=22
"""
        if cmd.startswith("searchsploit"):
            return ""
        if cmd.startswith("msf_check"):
            return """
[*] MSF Module: auxiliary/scanner/ssh/ssh_login
[+] 10.0.0.5:22     - Success: 'support:qweqwe123' ''
[+] MSF login check stopped after first success (CreateSession=false)
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
        db_path = f"/tmp/octopus_pipeline_msf_login_inventory_{uuid.uuid4().hex}.db"
        pipeline = AIPipeline(db_path)
        pipeline.tool_registry._is_tool_available = lambda name: True
        facts = [
            {
                "type": "port_open",
                "value": "22/tcp (ssh) [OpenSSH 7.4]",
                "confidence": 100,
                "session_id": "test",
            }
        ]
        result = pipeline._run_fact_driven_actions("scan-msf-login", "10.0.0.5", facts)
        stored = pipeline.fact_store.get_facts("scan-msf-login", "10.0.0.5")
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    pairs = {(fact["type"], fact["value"]) for fact in stored}
    assert any(cmd.startswith("msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login") for cmd in calls)
    assert any(cmd == "ssh_inventory 10.0.0.5" for cmd in calls)
    assert ("credential", "ssh_login_success:support@10.0.0.5") in pairs
    assert ("service_status", "ssh_authenticated") in pairs
    assert ("post_exploit_stage", "post_access_inventory_completed") in pairs
    assert ("hostname", "web01") in pairs
    assert result["new_facts"] >= 6


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


def test_fact_driven_actions_map_evidence_to_next_commands():
    import uuid

    from core.ai.pipeline import AIPipeline

    db_path = f"/tmp/octopus_pipeline_fact_actions_{uuid.uuid4().hex}.db"
    pipeline = AIPipeline(db_path)
    pipeline.tool_registry._is_tool_available = lambda name: name != "searchsploit"
    scan_id = "scan-fact-actions"
    host = "10.0.0.5"
    facts = [
        {"type": "credential", "value": "support:fixture-password-123 (cached)"},
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


def test_msf_login_check_without_creds_is_short_skip():
    from core.tools.post_tools import ai_msf_check

    output = ai_msf_check(
        "198.51.100.77",
        "auxiliary/scanner/ssh/ssh_login",
        "RHOSTS=198.51.100.77 RPORT=22",
    )

    assert "MSF login check skipped" in output
    assert "Short check not run" in output


def test_msf_login_check_options_use_typed_credential_reference(monkeypatch):
    from core.credentials import CredentialStore, register_credential
    from core.secrets import SecretStore
    from core.tools.post_tools import _prepare_msf_login_check

    host = "10.0.0.5"
    canary = "msf-password-must-not-enter-options"
    secret_store = SecretStore(":memory:", key=b"m" * 32)
    store = CredentialStore(secret_store=secret_store, hydrate=False)
    monkeypatch.setattr(CredentialStore, "_instance", store)
    try:
        register_credential("ssh", host, "support", canary, quiet=True)

        options, credential, error = _prepare_msf_login_check(
            host,
            "auxiliary/scanner/ssh/ssh_login",
            f"RHOSTS={host} RPORT=22",
        )
    finally:
        secret_store.close()

    assert error == ""
    assert credential is not None
    assert credential.username == "support"
    assert credential.handle.startswith("credential://")
    assert canary not in options
    assert "secret://" not in options
    assert "credential://" not in options
    assert "STOP_ON_SUCCESS=true" in options
    assert "VERBOSE=false" in options
    assert "CreateSession=false" in options


def test_run_msf_login_check_script_disables_session_creation_and_exits(monkeypatch):
    import msf

    scripts = []

    class FakeStdout:
        def __iter__(self):
            yield "[+] 10.0.0.5:22     - Success: 'support:qweqwe123' ''\n"

        def close(self):
            pass

    class FakeProc:
        def __init__(self, args, **kwargs):
            scripts.append(args[-1])
            self.stdout = FakeStdout()

        def terminate(self):
            pass

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(msf.shutil, "which", lambda _name: "/usr/bin/msfconsole")
    monkeypatch.setattr(msf.subprocess, "Popen", FakeProc)

    output = msf.run_msf_module(
        "auxiliary/scanner/ssh/ssh_login",
        "RHOSTS=10.0.0.5 RPORT=22 USERNAME=support PASSWORD=qweqwe123",
        timeout=30,
        mode="check",
    )

    assert "set CreateSession false" in scripts[0]
    assert "set STOP_ON_SUCCESS true" in scripts[0]
    assert scripts[0].endswith("run; exit -y")
    assert "Success: 'support:qweqwe123'" in output


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


def test_msf_check_results_separate_login_check_and_active_run_modes():
    import json

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_msf_modes.db")
    login_fact = pipeline._command_check_result_fact(
        "msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RPORT=22 USERNAME=root PASSWORD=toor",
        "10.0.0.5",
        "msf-login",
        "completed",
    )
    active_fact = pipeline._command_check_result_fact(
        "msf_run 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RPORT=6379",
        "10.0.0.5",
        "msf-run",
        "completed",
    )

    login = json.loads(login_fact["value"])
    active = json.loads(active_fact["value"])

    assert login["kind"] == "msf_login_check"
    assert login["mode"] == "login_check_with_known_creds"
    assert login["scope"] == {"type": "service", "value": "10.0.0.5:22/tcp"}
    assert active["kind"] == "active_exploitation"
    assert active["mode"] == "active_run"
