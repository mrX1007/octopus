#!/usr/bin/env python3
"""Legacy and canonical reporting compatibility contracts."""

import pytest

pytestmark = pytest.mark.contract

def test_reporting_groups_repeated_msf_checks_without_marking_exploited():
    from core.ai.reporting import build_finding_groups

    facts = [
        {"id": 1, "type": "port_open", "value": "49153/tcp (redis) [Redis key-value store]"},
        {"id": 2, "type": "port_open", "value": "49154/tcp (redis) [Redis key-value store]"},
        {
            "id": 3,
            "type": "vulnerability",
            "value": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec",
        },
        {
            "id": 4,
            "type": "vulnerability_endpoint",
            "value": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec:49153",
        },
        {
            "id": 5,
            "type": "vulnerability_endpoint",
            "value": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec:49154",
        },
        {
            "id": 6,
            "type": "active_command",
            "value": "msf_run 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RPORT=49153",
        },
    ]

    groups = build_finding_groups(facts, {})

    assert len(groups) == 1
    group = groups[0]
    assert group["module"] == "exploit/linux/redis/redis_replication_cmd_exec"
    assert group["service"] == "redis"
    assert group["ports"] == ["49153", "49154"]
    assert group["verified"] is True
    assert group["exploited"] is False
    assert group["impact_confirmed"] is False
    assert group["severity"] == "HIGH"


def test_reporting_evidence_index_and_coverage_summarize_traceability():
    from core.ai.reporting import build_coverage_summary, build_evidence_index

    facts = [
        {
            "id": 42,
            "type": "service_status",
            "value": "tool_timeout:nuclei_safe",
            "confidence": 80,
            "source": "nuclei_safe http://10.0.0.5",
            "evidence_hash": "abc123def456",
            "observations": [{"source": "nuclei_safe http://10.0.0.5"}],
        },
        {
            "id": 43,
            "type": "service_status",
            "value": "sqlmap_no_get_parameters_found",
            "confidence": 85,
            "source": "sqlmap http://10.0.0.5",
            "evidence_hash": "def456abc123",
        },
    ]

    evidence = build_evidence_index(facts)
    coverage = build_coverage_summary(facts)

    assert evidence[0]["evidence_id"] == "E-001"
    assert evidence[0]["fact_id"] == 42
    assert evidence[0]["command"] == "nuclei_safe http://10.0.0.5"
    assert coverage["confidence"] == "partial"
    assert coverage["degraded"][0]["tool"] == "nuclei_safe"
    assert coverage["checked_but_not_confirmed"][0]["status"] == "sqlmap_no_get_parameters_found"


def test_coverage_summary_dedupes_repeated_timeout_signals():
    import json

    from core.ai.reporting import build_coverage_summary

    facts = [
        {
            "id": 1,
            "type": "check_result",
            "value": json.dumps({
                "tool": "nikto",
                "kind": "web_vulnerability",
                "status": "timeout",
                "scope": {"type": "endpoint", "value": "http://10.0.0.5"},
            }),
        },
        {
            "id": 2,
            "type": "check_result",
            "value": json.dumps({
                "tool": "nikto",
                "kind": "web_vulnerability",
                "status": "timeout",
                "scope": {"type": "endpoint", "value": "http://10.0.0.5:8080"},
            }),
        },
        {"id": 3, "type": "service_status", "value": "tool_timeout:nikto"},
    ]

    coverage = build_coverage_summary(facts)

    assert len(coverage["degraded"]) == 1
    assert coverage["degraded"][0]["tool"] == "nikto"
    assert coverage["degraded"][0]["kind"] == "web_vulnerability"
    assert len(coverage["degraded"][0]["scopes"]) == 2


def test_trace_report_records_deterministic_llm_status():
    from core.ai.fact_store import FactStore
    from core.ai.trace_report import TraceReporter

    reporter = TraceReporter(FactStore("/tmp/octopus_trace_llm_status.db"))
    report = reporter.build(
        "scan-llm-status",
        "10.0.0.5",
        goal_trace=[{"loop": 1, "thought": "LLM suggested X but policy forced Y"}],
        task_outcomes=[
            {
                "agent": "AnalysisAgent",
                "task": "analyze_vulnerabilities",
                "status": "failed",
                "reason": "analysis_returned_no_hypotheses",
            }
        ],
    )

    assert report["llm_status"]["primary_response"] == "empty"
    assert report["llm_status"]["empty_response_events"] == 1
    assert report["llm_status"]["fallback_policy_used"] is True


def test_trace_report_text_includes_evidence_attack_path_and_remediation():
    import uuid

    from core.ai.fact_store import FactStore
    from core.ai.trace_report import TraceReporter

    store = FactStore(f"/tmp/octopus_trace_reporting_{uuid.uuid4().hex}.db")
    scan_id = "scan-reporting-text"
    host = "10.0.0.5"
    store.add_fact(scan_id, host, "port_open", "49153/tcp (redis) [Redis key-value store]", "nmap")
    store.add_fact(
        scan_id,
        host,
        "vulnerability",
        "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec",
        "msf_check 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RPORT=49153",
    )
    store.add_fact(
        scan_id,
        host,
        "vulnerability_endpoint",
        "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec:49153",
        "msf_check 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RPORT=49153",
    )

    reporter = TraceReporter(store)
    text = reporter.to_text(reporter.build(scan_id, host))

    assert "evidence_index:" in text
    assert "E-001 port_open" in text
    assert "finding_groups:" in text
    assert "exploit/linux/redis/redis_replication_cmd_exec" in text
    assert "attack_path:" in text
    assert "remediations:" in text
    assert "Restrict Redis" in text


def test_cli_results_table_prints_reporting_sections(monkeypatch, capsys):
    import core.cli as cli

    monkeypatch.setattr(cli, "RICH_AVAILABLE", False)
    cli.print_results_table({
        "risk_level": "HIGH",
        "vulnerabilities": [],
        "confirmed_facts": [],
        "outcome_summary": ["Exploit check positive; execution not performed"],
        "finding_groups": [{
            "module": "exploit/linux/redis/redis_replication_cmd_exec",
            "service": "redis",
            "ports": [49153, 49154],
            "candidate": True,
            "verified": True,
            "exploited": False,
            "impact_confirmed": False,
        }],
        "coverage": {
            "confidence": "partial",
            "degraded": [{"tool": "nuclei_safe", "status": "timeout", "impact": "coverage incomplete"}],
            "checked_but_not_confirmed": [{"status": "sqlmap_no_get_parameters_found"}],
        },
        "attack_path": [{"stage": "Verification", "status": "positive", "detail": "msf check positive"}],
        "remediations": [{"service": "redis", "recommendation": "Restrict Redis to trusted networks."}],
    })

    output = capsys.readouterr().out

    assert "[ FINDING STATUS ]" in output
    assert "ports=49153,49154" in output
    assert "[ COVERAGE ]" in output
    assert "[ ATTACK PATH ]" in output
    assert "[ REMEDIATION ]" in output


def test_cli_results_table_explains_critical_access_without_vulnerabilities(monkeypatch, capsys):
    import core.cli as cli

    monkeypatch.setattr(cli, "RICH_AVAILABLE", False)
    cli.print_results_table({
        "risk_level": "CRITICAL",
        "vulnerabilities": [],
        "confirmed_facts": [],
        "access_findings": [{
            "severity": "CRITICAL",
            "name": "Root access confirmed on target",
            "evidence": ["credential: ssh_login_success:root@10.0.0.5", "system_access: uid=0"],
        }],
        "risk_explanation": "Risk is CRITICAL because root-level access was verified, even if no CVE-style vulnerability was parsed.",
    })

    output = capsys.readouterr().out

    assert "[ No vulnerabilities parsed ]" in output
    assert "[ ACCESS FINDINGS ]" in output
    assert "Root access confirmed" in output
    assert "[ RISK EXPLANATION ]" in output


def test_reporting_keeps_root_access_out_of_vulnerability_finding_groups():
    from core.ai.reporting import enrich_result_with_reporting

    result = {"risk_level": "CRITICAL", "vulnerabilities": []}
    facts = [
        {"id": 1, "type": "credential", "value": "ssh_login_success:root@10.0.0.5", "source": "ssh_inventory"},
        {"id": 2, "type": "service_status", "value": "ssh_authenticated", "source": "ssh_inventory"},
        {"id": 3, "type": "system_access", "value": "uid=0", "source": "ssh_inventory"},
    ]

    enriched = enrich_result_with_reporting(result, facts, {"root_access_confirmed": True})

    assert enriched["finding_groups"] == []
    assert enriched["access_findings"][0]["severity"] == "CRITICAL"
    assert "root-level access was verified" in enriched["risk_explanation"]


def test_save_results_persists_deterministic_remediation_when_fix_missing(monkeypatch):
    import importlib
    import sys
    import types

    saved_fixes = []
    fake_export = types.ModuleType("export")
    fake_export.export_menu = lambda *args, **kwargs: None
    fake_db = types.ModuleType("db")

    def save_vulnerability(*args, **kwargs):
        return 701

    def save_fix(sl_no, vuln_id, fix_text, source="ai"):
        saved_fixes.append((sl_no, vuln_id, fix_text, source))

    fake_db.save_vulnerability = save_vulnerability
    fake_db.save_fix = save_fix
    fake_db.save_exploit = lambda *args, **kwargs: None
    fake_db.save_summary = lambda *args, **kwargs: None
    fake_db.get_session = lambda sl_no: {
        "history": [sl_no, "target", "", "complete"],
        "vulns": [],
        "fixes": [],
        "exploits": [],
        "summary": None,
    }
    fake_db.print_session = lambda data: None
    for name in [
        "get_connection", "create_session", "update_session_status",
        "get_all_history", "get_vulnerabilities", "get_fixes", "get_exploits",
        "edit_vulnerability", "edit_fix", "edit_exploit", "edit_summary_risk",
        "delete_vulnerability", "delete_exploit", "delete_fix", "delete_full_session",
        "print_history",
    ]:
        setattr(fake_db, name, lambda *args, **kwargs: None)

    tools_stub = types.ModuleType("tools")
    tools_stub.interactive_tool_run = lambda *args, **kwargs: ""
    tools_stub.format_recon_for_llm = lambda data: str(data)
    tools_stub.run_default_recon = lambda target: {}

    old_octopus = sys.modules.pop("octopus", None)
    old_export = sys.modules.get("export")
    old_db = sys.modules.get("db")
    old_tools = sys.modules.get("tools")
    sys.modules["export"] = fake_export
    sys.modules["db"] = fake_db
    sys.modules["tools"] = tools_stub
    try:
        octopus = importlib.import_module("octopus")
        monkeypatch.setattr(octopus, "confirm", lambda _question: False)
        monkeypatch.setattr(octopus, "print_results_table", lambda _result: None)
        octopus._save_and_show_results(99, {
            "vulnerabilities": [{
                "vuln_name": "CVE-2099-0001 fixture vulnerability",
                "severity": "HIGH",
                "port": "443",
                "service": "https",
                "description": "Fixture vulnerability with an AI-provided fix.",
                "confidence": "CONFIRMED",
                "evidence_tool": "fixture",
                "fix": "Apply the vendor patch.",
            }, {
                "vuln_name": "msf_check_positive:exploit/linux/redis/redis_replication_cmd_exec",
                "severity": "HIGH",
                "port": "49153",
                "service": "redis",
                "description": "Metasploit check positive; exploit execution not confirmed.",
                "confidence": "VERIFIED",
                "evidence_tool": "msf_check",
            }],
            "exploits": [],
            "risk_level": "HIGH",
            "raw_scan": "",
            "full_response": "",
            "confirmed_facts": [],
            "remediations": [{
                "finding": "exploit/linux/redis/redis_replication_cmd_exec",
                "service": "redis",
                "recommendation": "Restrict Redis to trusted networks.",
            }],
        })
    finally:
        sys.modules.pop("octopus", None)
        if old_octopus is not None:
            sys.modules["octopus"] = old_octopus
        if old_export is not None:
            sys.modules["export"] = old_export
        else:
            sys.modules.pop("export", None)
        if old_db is not None:
            sys.modules["db"] = old_db
        else:
            sys.modules.pop("db", None)
        if old_tools is not None:
            sys.modules["tools"] = old_tools
        else:
            sys.modules.pop("tools", None)

    assert saved_fixes == [
        (99, 701, "Apply the vendor patch.", "ai"),
        (99, 701, "Restrict Redis to trusted networks.", "deterministic"),
    ]


def test_llm_health_facts_are_visible_in_trace_report():
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_llm_health_{uuid.uuid4().hex}.db")
    scan_id = "scan-llm"
    target = "10.0.0.5"
    pipeline._record_llm_health(
        scan_id,
        target,
        "director",
        {"llm_status": "failed", "llm_error": "No JSON found in LLM response", "fallback": True, "goal": "service_discovery"},
        1,
    )

    facts = pipeline.fact_store.get_facts(scan_id, target, fact_type="llm_health")
    report = pipeline.trace_report(scan_id, target)

    assert len(facts) == 1
    assert report["llm_status"]["primary_response"] == "failed"
    assert report["llm_status"]["empty_response_events"] == 1
    assert report["llm_events"][0]["role"] == "director"


def test_trace_report_text_hides_machine_facts_but_keeps_human_facts():
    import json
    import uuid

    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline(f"/tmp/octopus_trace_human_{uuid.uuid4().hex}.db")
    scan_id = "scan-human-trace"
    target = "10.0.0.5"
    pipeline.fact_store.add_fact(scan_id, target, "port_open", "22/tcp (ssh)", "test")
    pipeline.fact_store.add_fact(
        scan_id,
        target,
        "check_result",
        json.dumps({"tool": "nuclei_safe", "kind": "template_verification", "status": "running"}),
        "test",
    )
    pipeline.fact_store.add_fact(
        scan_id,
        target,
        "llm_health",
        json.dumps({"role": "director", "status": "failed", "loop": 1}),
        "test",
    )
    pipeline.fact_store.add_fact(
        scan_id,
        target,
        "network_edge",
        json.dumps({"from": target, "to": "172.17.0.2", "type": "observed_internal_host"}),
        "test",
    )

    text = pipeline.trace_report_text(scan_id, target)

    assert "port_open" in text
    assert "check_result" not in text
    assert "llm_health" not in text
    assert "network_edge" not in text


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
