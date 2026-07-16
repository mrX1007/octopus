"""Canonical entity identity contract tests."""

import pytest

from core.knowledge.identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_credential,
    canonical_endpoint,
    canonical_identity,
    canonical_service,
    canonical_session,
    canonical_vulnerability,
    normalize_endpoint_url,
)

pytestmark = pytest.mark.contract


def test_asset_identity_normalizes_dns_ip_and_url_forms():
    assert canonical_asset("Example.COM.").entity_id == canonical_asset("https://example.com/a").entity_id
    assert canonical_asset("[2001:0db8::1]").entity_id == canonical_asset("2001:db8::1").entity_id
    assert canonical_asset("example.com").entity_id != canonical_asset("www.example.com").entity_id
    assert canonical_asset("example.com").normalization_version == ENTITY_NORMALIZATION_VERSION


def test_service_identity_includes_transport_and_effective_host_identity():
    tcp = canonical_service("EXAMPLE.com.", "53", "tcp")
    udp = canonical_service("example.com", 53, "udp")

    assert tcp.entity_id != udp.entity_id
    assert tcp.component("host") == "example.com"
    assert tcp.component("port") == "53"
    assert "svc:example.com:53" in tcp.aliases
    with pytest.raises(ValueError, match="port"):
        canonical_service("example.com", 70000)


def test_endpoint_identity_normalizes_default_port_dot_segments_and_percent_encoding():
    first = canonical_endpoint("HTTPS://Example.com:443/a/../b?name=%7euser#fragment")
    second = canonical_endpoint("https://example.com/b?name=~user")

    assert first.entity_id == second.entity_id
    assert first.component("effective_port") == "443"
    assert first.component("url") == "https://example.com/b?name=~user"
    assert normalize_endpoint_url("http://[2001:db8::1]:80/")[0] == "http://[2001:db8::1]/"
    assert canonical_endpoint("https://example.com/?a=1&b=2").entity_id != canonical_endpoint(
        "https://example.com/?b=2&a=1"
    ).entity_id
    with pytest.raises(ValueError, match="userinfo"):
        canonical_endpoint("https://user:password@example.com/")


def test_identity_scope_prevents_local_account_collisions():
    host_one = canonical_identity("root", host="10.0.0.1")
    host_two = canonical_identity("root", host="10.0.0.2")
    domain_one = canonical_identity("Admin", domain="CORP.EXAMPLE", identity_type="domain")
    domain_two = canonical_identity("admin", domain="corp.example", identity_type="domain")

    assert host_one.entity_id != host_two.entity_id
    assert domain_one.entity_id == domain_two.entity_id
    assert host_one.entity_id != domain_one.entity_id


def test_credential_identity_requires_secret_ref_and_includes_scope():
    secret_ref = "secret://0123456789abcdef0123456789abcdef"
    ssh = canonical_credential(
        "root",
        secret_ref,
        service="ssh",
        host="10.0.0.1",
    )
    mysql = canonical_credential(
        "root",
        secret_ref,
        service="mysql",
        host="10.0.0.1",
    )

    assert ssh.entity_id != mysql.entity_id
    assert secret_ref not in ssh.entity_id
    assert ssh.component("secret_ref") == secret_ref
    with pytest.raises(ValueError, match="opaque secret reference"):
        canonical_credential("root", "plaintext-password", service="ssh", host="10.0.0.1")


def test_session_and_vulnerability_identities_are_namespaced():
    ssh = canonical_session("42", session_type="ssh", host="10.0.0.1", username="root")
    web = canonical_session("42", session_type="web", host="10.0.0.1", username="root")
    cve_lower = canonical_vulnerability("cve-2026-12345")
    cve_text = canonical_vulnerability("finding CVE-2026-12345 on target")

    assert ssh.entity_id != web.entity_id
    assert cve_lower.entity_id == cve_text.entity_id
    assert cve_lower.component("namespace") == "cve"
    assert cve_lower.component("key") == "CVE-2026-12345"
