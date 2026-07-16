#!/usr/bin/env python3
"""Scheduler, command-result, and command-trace contracts."""

import pytest

pytestmark = pytest.mark.contract

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


def test_command_scheduler_blocks_web_checks_after_fetch_failed():
    from core.ai.command_scheduler import CommandScheduler

    facts = [
        {
            "type": "service_status",
            "value": "web_fetch_failed:http://10.0.0.5",
            "confidence": 80,
        }
    ]
    scheduler = CommandScheduler()

    for command in (
        "security_headers_check http://10.0.0.5",
        "cors_check http://10.0.0.5",
        "nuclei_safe http://10.0.0.5",
        "nuclei -u http://10.0.0.5 -severity high",
        "katana_crawl http://10.0.0.5",
        "graphql_check http://10.0.0.5/graphql",
    ):
        decision = scheduler.decide(command, facts, set())
        assert decision.action == "skip", command
        assert decision.reason == "confirmed_absent:no_http_response"


def test_nuclei_completion_fact_blocks_repeat_command():
    from core.ai.command_scheduler import CommandScheduler
    from core.ai.evidence import OutputParser

    facts = OutputParser().parse_tool_output(
        "nuclei_safe http://10.0.0.5",
        "[NUCLEI SAFE - http://10.0.0.5]\nNo nuclei findings detected.\n[NUCLEI COMPLETE - http://10.0.0.5]",
    )

    decision = CommandScheduler().decide("nuclei -u http://10.0.0.5/", facts, set())

    assert decision.action == "skip"
    assert decision.reason == "already_completed:nuclei_scan"


def test_nuclei_completion_fact_blocks_bare_host_repeat_command():
    from core.ai.command_scheduler import CommandScheduler

    facts = [
        {
            "type": "service_status",
            "value": "nuclei_scan_completed:http://10.0.0.5",
            "confidence": 85,
        }
    ]

    decision = CommandScheduler().decide("nuclei_safe 10.0.0.5", facts, set())

    assert decision.key == "nuclei_safe http://10.0.0.5"
    assert decision.action == "skip"
    assert decision.reason == "already_completed:nuclei_scan"


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


def test_task_result_with_only_skipped_commands_is_skipped_not_no_fact():
    from core.ai.pipeline import AIPipeline

    pipeline = AIPipeline("/tmp/octopus_skipped_task_result.db")
    task_result = {
        "commands": [
            {"command": "nuclei_safe 10.0.0.5", "failed": False, "skipped": True, "skip_reason": "already_completed:nuclei_scan"},
            {"command": "sqlmap http://10.0.0.5", "failed": False, "skipped": True, "skip_reason": "duplicate_command_key"},
        ],
        "parsed_facts": 0,
        "new_facts": 0,
    }

    assert pipeline._classify_task_result(task_result) == "skipped"
    assert pipeline._command_result_reason(task_result["commands"], 0, 0).startswith("all_commands_skipped:")


def test_execute_pipeline_command_stores_running_and_timeout_check_results():
    import json
    import uuid

    import core.ai.pipeline as pipeline_mod
    from core.ai.pipeline import AIPipeline

    old_runner = pipeline_mod.run_arbitrary_cmd
    db_path = f"/tmp/octopus_command_check_state_{uuid.uuid4().hex}.db"

    def fake_runner(cmd):
        return """
[PARTIAL OUTPUT - nuclei_safe - 1 lines captured before timeout]
[TIMEOUT] nuclei_safe killed after 1200s
"""

    pipeline_mod.run_arbitrary_cmd = fake_runner
    try:
        pipeline = AIPipeline(db_path)
        result = pipeline._execute_pipeline_command(
            "scan-check-state",
            "10.0.0.5",
            "nuclei_safe http://10.0.0.5",
            "Fact",
            "[Running]",
        )
    finally:
        pipeline_mod.run_arbitrary_cmd = old_runner

    facts = pipeline.fact_store.get_facts("scan-check-state", "10.0.0.5", fact_type="check_result")
    payloads = [json.loads(fact["value"]) for fact in facts]
    statuses = {payload["status"] for payload in payloads if payload["tool"] == "nuclei_safe"}

    assert result["command_result"]["check_status"] == "timeout"
    assert {"running", "timeout"}.issubset(statuses)
    assert any(payload["scope"] == {"type": "endpoint", "value": "http://10.0.0.5"} for payload in payloads)


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
