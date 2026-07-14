#!/usr/bin/env python3
"""Characterization tests for the Phase 2A pure extraction seams."""

from types import SimpleNamespace

import pytest

from core.execution.normalization import (
    command_check_status,
    command_failed,
    command_tool_name,
    normalized_check_status,
    output_text,
)
from core.execution.results import ExecutionResult, ExecutionStatus
from core.tools.targeting import (
    canonical_check_url,
    canonical_endpoint_value,
    display_endpoint_url,
    endpoint_in_target_scope,
    endpoint_url_from_value,
    internal_service_scope_value,
    internal_service_scopes_from_compact_state,
    nmap_service_looks_web,
    service_fact_looks_tls,
    target_in_authorized_scope,
)


class _LegacyTextResult:
    def __str__(self) -> str:
        return "legacy text"


def test_canonical_check_url_preserves_pipeline_identity_rules() -> None:
    assert canonical_check_url(
        " HTTPS://User:Pass@EXAMPLE.COM:443/admin/?b=2#ignored "
    ) == "https://example.com/admin/?b=2"
    assert canonical_check_url("http://EXAMPLE.COM:8080/") == "http://example.com:8080"
    assert canonical_check_url(" Example.COM/path/ ") == "Example.COM/path"


def test_canonical_check_url_keeps_invalid_port_failure_behavior() -> None:
    with pytest.raises(ValueError, match="Port could not be cast"):
        canonical_check_url("http://example.com:not-a-port/")


def test_canonical_endpoint_value_has_exact_legacy_json_shape() -> None:
    assert canonical_endpoint_value(
        "EXAMPLE.COM:8080/api?q=1",
        service="http-alt",
    ) == (
        '{"host": "example.com", "path": "/api", "port": "8080", '
        '"scheme": "http", "service": "http-alt", "status": "", '
        '"title": "", "url": "http://example.com:8080/api?q=1"}'
    )
    assert canonical_endpoint_value("https://EXAMPLE.COM:443", port="8443") == (
        '{"host": "example.com", "path": "/", "port": "8443", '
        '"scheme": "https", "service": "", "status": "", "title": "", '
        '"url": "https://example.com/"}'
    )
    assert canonical_endpoint_value("") == ""


def test_endpoint_url_value_supports_canonical_and_legacy_forms() -> None:
    canonical = canonical_endpoint_value("https://example.com/api")
    assert endpoint_url_from_value(canonical) == "https://example.com/api"
    assert endpoint_url_from_value("HTTP://EXAMPLE.COM/path") == "HTTP://EXAMPLE.COM/path"
    assert endpoint_url_from_value("not an endpoint") == ""
    assert endpoint_url_from_value('{"url": "ftp://example.com/file"}') == ""


def test_endpoint_url_value_keeps_non_mapping_json_failure_behavior() -> None:
    with pytest.raises(AttributeError):
        endpoint_url_from_value('"https://example.com/from-json-string"')


def test_display_endpoint_url_preserves_root_and_path_formatting() -> None:
    assert display_endpoint_url("HTTPS://EXAMPLE.COM:443/") == "https://example.com:443"
    assert display_endpoint_url("HTTP://EXAMPLE.COM/A/?Q=1#fragment") == "http://example.com/A/?Q=1"
    assert display_endpoint_url("ftp://example.com/file") == ""
    assert display_endpoint_url("example.com/path") == ""


@pytest.mark.parametrize(
    ("endpoint", "target", "expected"),
    [
        ("https://example.com", "https://EXAMPLE.COM:443/root", True),
        ("https://api.example.com/v1", "example.com", True),
        ("https://notexample.com", "example.com", False),
        ("https://10.0.0.1", "10.0.0.1", True),
        ("https://10.0.0.2", "10.0.0.1", False),
        ("not-a-url", "example.com", False),
        ("https://example.com", "", False),
    ],
)
def test_endpoint_in_target_scope_matches_existing_target_semantics(
    endpoint: str,
    target: str,
    expected: bool,
) -> None:
    assert endpoint_in_target_scope(endpoint, target) is expected


def test_endpoint_scope_retains_legacy_ip_suffix_behavior() -> None:
    assert endpoint_in_target_scope("https://name.10.0.0.1", "10.0.0.1") is True


def test_internal_service_scope_value_keeps_permissive_prefix_parser() -> None:
    assert internal_service_scope_value("10.0.0.2:00443/TCP") == "10.0.0.2:443/tcp"
    assert (
        internal_service_scope_value("999.999.999.999:00080/UDP trailing")
        == "999.999.999.999:80/udp"
    )
    assert internal_service_scope_value("host.example:443/tcp") == ""


def test_internal_service_scopes_keep_order_defaults_and_deduplication() -> None:
    command = (
        'exploit_select target compact_state -> {"internal_services": ['
        '{"host": "10.0.0.2", "port": "0443", "proto": "TCP"}, '
        '{"host": "10.0.0.2", "port": 443, "proto": "tcp"}, '
        '{"host": "10.0.0.3", "port": 22}, '
        '{"host": "", "port": 80}, '
        '{"host": "10.0.0.9", "port": "bad"}]}; '
        'compact_state: {"internal_services": ['
        '{"host": "10.0.0.4", "port": 53, "proto": "UDP"}]}'
    )
    assert internal_service_scopes_from_compact_state(command) == [
        "10.0.0.2:443/tcp",
        "10.0.0.3:22/tcp",
        "10.0.0.4:53/udp",
    ]
    assert internal_service_scopes_from_compact_state("compact_state -> not-json") == []


@pytest.mark.parametrize(
    ("target", "scopes", "expected"),
    [
        ("https://10.0.0.7:443/path", ["10.0.0.0/24"], True),
        ("10.0.1.7", ["10.0.0.0/24"], False),
        ("api.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], False),
        ("anything.example", ["all"], True),
        ("anything.example", ["*"], True),
        ("anything.example", [], False),
        ("anything.example", ["", "ALL"], False),
    ],
)
def test_target_authorization_scope_preserves_glob_cidr_and_sentinel_rules(
    target: str,
    scopes: list[str],
    expected: bool,
) -> None:
    assert target_in_authorized_scope(target, scopes) is expected


@pytest.mark.parametrize(
    "value",
    [
        "443/tcp (ssl/http)",
        "HTTPS service",
        "TLSv1.3",
        "OpenSSL 3",
        "cPanel admin",
        "WHM panel",
    ],
)
def test_service_tls_markers_match_pipeline_rules(value: str) -> None:
    assert service_fact_looks_tls(value) is True


def test_existing_web_service_helper_is_the_exact_pipeline_rule() -> None:
    assert nmap_service_looks_web("unknown", "Cowboy server") is True
    assert nmap_service_looks_web("ssh", "OpenSSH 9.0") is False
    assert service_fact_looks_tls("ssh OpenSSH") is False


def test_output_text_preserves_combined_and_legacy_projections() -> None:
    assert output_text(SimpleNamespace(stdout="out", stderr="err")) == "out\nerr"
    assert output_text(SimpleNamespace(stdout="", stderr="err")) == "err"
    assert output_text(SimpleNamespace(stdout=0, stderr="")) == "0"
    assert output_text(_LegacyTextResult()) == "legacy text"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("  MSF_CHECK exploit/linux/http/test  ", "msf_check"),
        ("nuclei_safe https://example.com", "nuclei_safe"),
        ("", "tool"),
        ("   ", "tool"),
    ],
)
def test_command_tool_name_preserves_legacy_fallback(command: str, expected: str) -> None:
    assert command_tool_name(command) == expected


@pytest.mark.parametrize(
    ("command", "status", "output", "expected"),
    [
        ("msf_check module", "failed", "Success: target appears safe", "completed"),
        ("msf_check module", "failed", "Target appears to be vulnerable", "completed"),
        ("msf_check module", "failed", "Target is vulnerable", "completed"),
        ("other", "completed_empty", "MSF login check skipped: no creds", "skipped"),
        ("other", "completed_empty", "[TIMEOUT] provider", "timeout"),
        ("other", "completed_empty", "Killed after 30 seconds", "timeout"),
        ("other", "completed_empty", "timed out after 5s", "timeout"),
        ("other", "completed_empty", "[PARTIAL OUTPUT: limit]", "partial"),
        ("other", "failed", "[PARTIAL OUTPUT: limit]", "failed"),
        ("other", "completed_empty", "ordinary empty result", "completed_empty"),
    ],
)
def test_normalized_check_status_keeps_exact_legacy_strings(
    command: str,
    status: str,
    output: str,
    expected: str,
) -> None:
    assert normalized_check_status(command, status, output) == expected


@pytest.mark.parametrize(
    ("canonical_status", "expected"),
    [
        (ExecutionStatus.FAILED, "failed"),
        (ExecutionStatus.TIMEOUT, "timeout"),
        (ExecutionStatus.BLOCKED, "blocked"),
        (ExecutionStatus.PARTIAL, "partial"),
        (ExecutionStatus.UNAVAILABLE, "unavailable"),
        (ExecutionStatus.CANCELLED, "cancelled"),
    ],
)
def test_command_check_status_projects_canonical_status_to_legacy_string(
    canonical_status: ExecutionStatus,
    expected: str,
) -> None:
    result = ExecutionResult(status=canonical_status)
    assert command_check_status("tool", "", False, 0, result) == expected


def test_command_check_status_preserves_succeeded_and_legacy_fallbacks() -> None:
    succeeded = ExecutionResult(status=ExecutionStatus.SUCCEEDED)
    assert command_check_status("tool", "", False, 1, succeeded) == "completed"
    assert command_check_status("tool", "", False, 0, succeeded) == "completed_empty"
    assert command_check_status("tool", "", True, 0, succeeded) == "failed"
    assert command_check_status("tool", "[PARTIAL OUTPUT]", False, 0) == "partial"


@pytest.mark.parametrize(
    "status",
    [
        ExecutionStatus.FAILED,
        ExecutionStatus.TIMEOUT,
        ExecutionStatus.UNAVAILABLE,
        ExecutionStatus.CANCELLED,
    ],
)
def test_command_failed_recognizes_canonical_failures(status: ExecutionStatus) -> None:
    result = ExecutionResult(status=status)
    assert command_failed(result, output_text(result)) is True


def test_command_failed_preserves_blocked_and_exit_code_precedence() -> None:
    blocked = ExecutionResult(
        status=ExecutionStatus.BLOCKED,
        stdout="[!] error: denied",
    )
    assert command_failed(blocked, output_text(blocked)) is False

    blocked_nonzero = ExecutionResult(
        status=ExecutionStatus.BLOCKED,
        stdout="denied",
        exit_code=1,
    )
    assert command_failed(blocked_nonzero, output_text(blocked_nonzero)) is True
    assert command_failed(SimpleNamespace(exit_code=True), "") is True


@pytest.mark.parametrize(
    "legacy_output",
    [
        "[!] tool not found: scanner",
        "[!] error while running scanner",
        "Traceback (most recent call last)",
        "operation timed out",
        "returned no output",
        "requires credentials",
        "connection failed",
        "permission denied",
        "unknown tool",
        "missing dependency",
        "no such file or directory",
        "Psych/Syntax_Error",
        "Bundler/Errors.rb",
        "RubyGems/Errors.rb",
    ],
)
def test_command_failed_keeps_exact_legacy_failure_markers(legacy_output: str) -> None:
    assert command_failed(legacy_output, legacy_output) is True


def test_command_failed_keeps_legacy_success_marker_precedence() -> None:
    mixed = "permission denied, but port is open"
    assert command_failed(mixed, mixed) is False
    assert command_failed("neutral", "neutral output") is False
