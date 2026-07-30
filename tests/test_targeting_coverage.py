"""Pure boundary coverage for shared target normalization helpers."""

import pytest

from core.tools.targeting import (
    as_url,
    canonical_endpoint_value,
    coerce_port,
    detect_web_ports_from_nmap,
    ensure_url,
    internal_service_scopes_from_compact_state,
    nmap_has_any_open_port,
    split_host_port,
    target_looks_domain,
    url_candidates,
    web_urls_from_ports,
)

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_url_prefix_helpers_preserve_existing_schemes_and_build_defaults() -> None:
    assert ensure_url(" HTTPS://example.com/// ") == "http://HTTPS://example.com"
    assert ensure_url(" https://example.com/// ") == "https://example.com"
    assert ensure_url(" example.com/ ", scheme="https") == "https://example.com"

    assert url_candidates(" HTTP://example.com/// ") == [
        "http://HTTP://example.com",
        "https://HTTP://example.com",
    ]
    assert url_candidates(" http://example.com/// ") == ["http://example.com"]
    assert url_candidates(" example.com/ ") == [
        "http://example.com",
        "https://example.com",
    ]

    assert as_url("https://example.com///") == "https://example.com"
    assert as_url(" example.com///") == "http://example.com"


def test_host_port_and_domain_helpers_cover_all_parser_decisions() -> None:
    assert split_host_port("https://Example.com:8443/path", 80) == (
        "Example.com",
        8443,
    )
    assert split_host_port("host:service/path", "8080") == (
        "host:service",
        8080,
    )
    assert split_host_port("[2001:db8::1]/path", 443) == (
        "[2001:db8::1]",
        443,
    )

    assert coerce_port("443", 80) == 443
    assert coerce_port("not-a-port", "8080") == 8080
    assert coerce_port(None, 80) == 80

    assert target_looks_domain("https://api.example.com:443/path") is True
    assert target_looks_domain("localhost") is False
    assert target_looks_domain("10.0.0.1") is False


def test_nmap_web_port_detection_preserves_order_and_deduplicates() -> None:
    output = """
unparseable status line
80/tcp open http Apache httpd
80/tcp open http duplicate banner
22/tcp open ssh OpenSSH
[10.0.0.1] 8443/tcp OPEN ssl/http nginx
"""

    assert detect_web_ports_from_nmap(output) == ["80", "8443"]
    assert detect_web_ports_from_nmap("") == []


def test_open_port_detection_handles_nonmatches_misses_and_early_success() -> None:
    assert nmap_has_any_open_port(
        "noise\n80/tcp open http\n443/tcp closed https",
        {"443"},
    ) is False
    assert nmap_has_any_open_port(
        "[10.0.0.1] 443/tcp OPEN https",
        {"443"},
    ) is True


def test_web_url_projection_covers_default_tls_custom_and_duplicate_ports() -> None:
    assert web_urls_from_ports("example.com", []) == ["http://example.com"]
    assert web_urls_from_ports(
        "example.com",
        ["443", "8443", "80", "8080", "8080"],
    ) == [
        "https://example.com",
        "https://example.com:8443",
        "http://example.com",
        "http://example.com:8080",
    ]


def test_invalid_endpoint_and_compact_state_shapes_are_ignored() -> None:
    assert canonical_endpoint_value("http:///missing-host") == ""

    command = (
        'compact_state: [] compact_state: {"internal_services": ['
        '"legacy-string", {"host": "", "port": 80}, '
        '{"host": "10.0.0.5", "port": null}, '
        '{"host": "10.0.0.6", "port": 53, "proto": "UDP"}]}'
    )
    assert internal_service_scopes_from_compact_state(command) == [
        "10.0.0.6:53/udp"
    ]
