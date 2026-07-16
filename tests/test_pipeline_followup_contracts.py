#!/usr/bin/env python3
"""Fact-driven follow-up and bounded depth contracts."""

import pytest

pytestmark = pytest.mark.contract

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


def test_jmx2rce_generic_scan_only_expands_with_tomcat_or_jmx_evidence():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_pipeline_jmx_context_{uuid.uuid4().hex}.db")
    scan_id = "scan-jmx-context"
    host = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, host, "port_open", "80/tcp (http) [nginx]", "test")

    assert pipeline._expand_command_with_context(f"jmx2rce_scan {host}", scan_id, host) == []

    pipeline.fact_store.add_fact(scan_id, host, "port_open", "8080/tcp (http) [Apache Tomcat]", "test")

    expanded = pipeline._expand_command_with_context(f"jmx2rce_scan {host}", scan_id, host)

    assert expanded == ["jmx2rce_scan http://10.0.0.5:8080"]


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
    assert not any(cmd.startswith(f"exploit_select {host}") for cmd in calls)
    assert "searchsploit nginx nginx/1.14.0" not in calls
    assert ("service_version", "nginx:local:nginx/1.14.0") in pairs
    assert ("local_listening_port", "8080") in pairs
    assert ("app_manifest", "/var/www/app/package.json") in pairs
    assert result["new_facts"] >= 6


def test_pipeline_records_internal_vulnerability_check_results_from_compact_state():
    import json

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_internal_vuln_check_results.db")
    cmd = (
        'exploit_select 10.0.0.5 port_open -> 22/tcp (ssh) | '
        'compact_state -> {"internal_services":[{"host":"172.24.108.2","port":53,"proto":"tcp","service":"dns"}]}'
    )

    results = pipeline._command_end_check_results(
        cmd=cmd,
        target="10.0.0.5",
        command_key=cmd,
        status="completed",
        output_str="Services analyzed: 1",
        parsed_facts=[],
    )
    payloads = [json.loads(item["value"]) for item in results if item["type"] == "check_result"]

    assert any(
        payload["kind"] == "internal_vulnerability_assessment"
        and payload["scope"] == {"type": "internal_service", "value": "172.24.108.2:53/tcp"}
        for payload in payloads
    )


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
