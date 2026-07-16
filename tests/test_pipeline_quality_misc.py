#!/usr/bin/env python3
"""Remaining focused pipeline compatibility contracts."""

import pytest

pytestmark = pytest.mark.contract

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


def test_runner_preserves_discovered_web_page_urls_for_browser_analysis():
    import core.tools.post_tools
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


def test_persistence_state_requests_internal_recon_before_exfil():
    from core.ai.director import DirectorLLM

    context = {
        "state": "persistence_established",
        "services": ["ssh"],
        "open_questions": ["internal_network_recon_pending"],
    }

    goal = DirectorLLM()._fallback_logic(context, []).get("goal")

    assert goal == "internal_reconnaissance"


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
    assert meta["exploit_executed"] is False
    assert meta["impact_confirmed"] is False


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


def test_scrapling_crawl_uses_requests_fallback_when_scrapling_missing(monkeypatch):
    import core.tools.recon_tools as recon_tools
    from core.tools.registry import get_tool

    class FakeResponse:
        status_code = 200
        text = "<html><title>Home</title><a href='/next'>next</a></html>"

    monkeypatch.setattr(recon_tools, "_SCRAPLING_OK", False)
    monkeypatch.setattr(recon_tools, "_StealthyFetcher", None)
    monkeypatch.setattr(recon_tools, "_req_get_seen", [], raising=False)

    def fake_get(url, **_kwargs):
        recon_tools._req_get_seen.append(url)
        return FakeResponse()

    import requests
    monkeypatch.setattr(requests, "get", fake_get)

    tool_def = get_tool("scrapling_crawl")
    output = recon_tools.run_scrapling_crawl("http://10.0.0.5", max_pages=2)

    assert tool_def.requires == []
    assert "Mode: requests+bs4 fallback" in output
    assert "http://10.0.0.5/next" in recon_tools._req_get_seen


def test_pipeline_llm_dead_uses_fallback_without_new_llm_calls():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_llm_dead_fallback_{uuid.uuid4().hex}.db")
    original_reset = pipeline._reset_runtime_state

    def reset_with_dead_llm():
        original_reset()
        pipeline.consecutive_llm_failures = pipeline.MAX_CONSECUTIVE_LLM_FAILURES

    def forbidden_call(*_args, **_kwargs):
        raise AssertionError("LLM-backed path should not be called after LLM is dead")

    pipeline._reset_runtime_state = reset_with_dead_llm
    pipeline.director.decide_goal = forbidden_call
    pipeline.planner.create_plan = forbidden_call
    pipeline.analysis_agent.analyze = forbidden_call
    pipeline._director_fallback_result = lambda _context: {
        "goal": "vulnerability_assessment",
        "thought": "fallback test",
        "llm_status": "skipped",
        "llm_error": "llm_dead_fallback_only",
        "fallback": True,
    }
    pipeline.tool_registry.get_commands_for_task = lambda _task, _target: []

    pipeline.run_scan("scan-llm-dead", "10.0.0.5", max_iterations=1)

    analysis_outcomes = [
        item for item in pipeline.task_outcomes
        if item["agent"] == "AnalysisAgent"
    ]
    llm_health = pipeline.fact_store.get_facts("scan-llm-dead", "10.0.0.5", fact_type="llm_health")

    assert analysis_outcomes[0]["status"] == "no_new_facts"
    assert analysis_outcomes[0]["reason"] == "llm_unavailable_fallback_mode"
    assert any('"status": "skipped"' in fact["value"] for fact in llm_health)
