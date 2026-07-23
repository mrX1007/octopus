"""Complete deterministic branch coverage for command scheduling helpers."""

import pytest

from core.ai.command_scheduler import CommandScheduler

pytestmark = pytest.mark.unit


def test_scheduler_empty_and_command_key_canonicalization_branches():
    scheduler = CommandScheduler()

    assert scheduler.command_key("") == ""
    assert scheduler._negative_fact_block("", []) == ""
    assert scheduler.command_key("curl_headers HTTP://Example.COM:80/") == (
        "curl_headers http://example.com"
    )
    assert scheduler._canonical_url("ftp://example.com/file") == "ftp://example.com/file"
    assert scheduler._canonical_url("https://EXAMPLE.com:8443/a?q=1") == (
        "https://example.com:8443/a?q=1"
    )


def test_scheduler_nuclei_timeout_fact_uses_observation_provenance():
    scheduler = CommandScheduler()
    facts = [
        {
            "type": "service_status",
            "value": "tool_timeout:nuclei_safe",
            "source": "other",
            "observations": [{"source": "nuclei_safe http://10.0.0.5"}],
        }
    ]

    assert scheduler._negative_fact_block("nuclei -u http://10.0.0.5", facts) == (
        "already_degraded:nuclei_timeout"
    )


def test_scheduler_nikto_completion_and_timeout_facts():
    scheduler = CommandScheduler()
    completed = [
        {"type": "port_open", "value": "80/tcp"},
        {"type": "service_status", "value": "unrelated"},
        {
            "type": "service_status",
            "value": "nikto_scan_completed:http://10.0.0.5",
        }
    ]
    timed_out = [
        {
            "type": "service_status",
            "value": "tool_timeout:nikto",
            "observations": [{"source": "nikto -h http://10.0.0.5"}],
        }
    ]

    assert scheduler._negative_fact_block("nikto -h http://10.0.0.5", completed) == (
        "already_completed:nikto_scan"
    )
    assert scheduler._negative_fact_block("nikto http://10.0.0.5", timed_out) == (
        "already_degraded:nikto_timeout"
    )


def test_scheduler_sqlmap_negative_fact_with_observation_provenance():
    scheduler = CommandScheduler()
    facts = [
        {"type": "port_open", "value": "80/tcp"},
        {"type": "service_status", "value": "unrelated"},
        {
            "type": "service_status",
            "value": "sqlmap_no_get_parameters_found",
            "source": "other",
            "observations": [{"source": "sqlmap --url=http://10.0.0.5"}],
        }
    ]

    assert scheduler._negative_fact_block("sqlmap --url=http://10.0.0.5", facts) == (
        "already_checked:sqlmap_no_input_surface"
    )


def test_scheduler_command_url_extractors_cover_flag_and_fallback_forms():
    scheduler = CommandScheduler()

    assert scheduler._command_url([]) == ""
    assert scheduler._command_url(["nikto", "-h", "http://a.example"]) == "http://a.example"
    assert scheduler._command_url(["nikto", "http://b.example"]) == "http://b.example"
    assert scheduler._command_url(["nikto", "--plugins"]) == ""
    assert scheduler._command_url(["sqlmap", "-u", "http://c.example?id=1"]) == (
        "http://c.example?id=1"
    )
    assert scheduler._command_url(["sqlmap", "--url=http://d.example?id=1"]) == (
        "http://d.example?id=1"
    )
    assert scheduler._command_url(["sqlmap", "--batch"]) == ""
    assert scheduler._command_url(["wpscan", "--url", "http://e.example"]) == (
        "http://e.example"
    )
    assert scheduler._command_url(["wpscan", "--url=http://f.example"]) == (
        "http://f.example"
    )
    assert scheduler._command_url(["wpscan", "--no-update"]) == ""
    assert scheduler._command_url(["tool", "flag", "https://g.example"]) == (
        "https://g.example"
    )
    assert scheduler._command_url(["tool", "bare-target"]) == "bare-target"


def test_scheduler_nuclei_target_extractor_covers_all_syntaxes():
    scheduler = CommandScheduler()

    assert scheduler._extract_nuclei_target(["nuclei", "-u=http://a.example"]) == (
        "http://a.example"
    )
    assert scheduler._extract_nuclei_target(["nuclei", "-url", "http://b.example"]) == (
        "http://b.example"
    )
    assert scheduler._extract_nuclei_target(
        ["nuclei", "-severity", "high", "--silent", "https://c.example"]
    ) == "https://c.example"
    assert scheduler._extract_nuclei_target(["nuclei", "bare.example"]) == "bare.example"
    assert scheduler._extract_nuclei_target(["nuclei", "--silent"]) == ""


def test_scheduler_negative_url_matcher_rejects_unrelated_statuses():
    scheduler = CommandScheduler()

    assert not scheduler._negative_status_matches_url("no url", "http://example.com")
    assert not scheduler._negative_status_matches_url(
        "failed:http://example.com", "not-a-url"
    )
    assert not scheduler._negative_status_matches_url(
        "failed:https://example.com", "http://example.com"
    )
    assert not scheduler._negative_status_matches_url(
        "failed:http://other.example", "http://example.com"
    )
    assert not scheduler._negative_status_matches_url(
        "failed:http://example.com/admin", "http://example.com/public"
    )
    assert scheduler._negative_status_matches_url(
        "failed:http://example.com/base", "http://example.com/base/child"
    )
