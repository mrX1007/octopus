"""Hermetic branch contracts for the normalized target model."""

from __future__ import annotations

from typing import Any

import pytest

import core.ai.target_model as target_model_module
from core.ai.target_model import TargetModel

pytestmark = pytest.mark.unit


def _fact(fact_type: str, value: str, **overrides: Any) -> dict[str, Any]:
    fact: dict[str, Any] = {
        "type": fact_type,
        "value": value,
        "confidence": 90,
        "source": "fixture",
    }
    fact.update(overrides)
    return fact


def test_collectors_handle_empty_duplicate_and_malformed_facts() -> None:
    facts = [
        _fact("asset_domain", ""),
        _fact("asset_domain", "app.example.com"),
        _fact("asset_domain", "app.example.com"),
        _fact("port_open", "malformed"),
        _fact("port_open", "443/tcp (https)"),
        _fact("port_open", "443/tcp (https)"),
        _fact("web_endpoint", "not-a-url"),
        _fact("credential", "user:password"),
        _fact("credential_material", "ticket"),
        _fact("hash_material", "hash"),
        _fact("api_endpoint", ""),
        _fact("api_endpoint", "/health"),
        _fact("web_security_note", ""),
        _fact("negative_fact", "explicitly absent"),
        _fact("service_status", "ssh_auth_failed:denied"),
    ]
    model = TargetModel("scan", "https://example.com:443/path", facts)

    assert model._assets()["domains"] == ["app.example.com"]
    assert len(model._services()) == 1
    assert model._endpoints() == []
    assert [item["kind"] for item in model._credentials()] == [
        "credential",
        "material",
        "hash",
    ]
    assert model._api()["endpoints"] == [{"method": "", "path": "/health", "metadata": ""}]
    assert model._web_app()["security_notes"] == []
    assert len(model._negative_facts()) == 2
    assert model._presence_state("ssh_authenticated", "ssh_auth_failed:") == ("confirmed_absent")


def test_active_directory_network_and_internal_service_edge_cases() -> None:
    node = '{"host":"10.0.0.2"}'
    edge = '{"from":"10.0.0.2","to":"10.0.0.3"}'
    facts = [
        _fact("ad_domain", ""),
        _fact("ad_users", "count:3"),
        _fact("ad_groups", "inventory unavailable"),
        _fact("ad_domain", "CORP.EXAMPLE"),
        _fact("ad_domain", "CORP.EXAMPLE"),
        _fact("network_node", "not-json"),
        _fact("network_node", node),
        _fact("network_node", node),
        _fact("network_edge", edge),
        _fact("network_edge", edge),
        _fact("internal_service", "malformed"),
        _fact("internal_service", "10.0.0.2:22/tcp (ssh)", source="network_recon"),
        _fact("internal_service", "10.0.0.2:22/tcp (ssh)", source="duplicate"),
        _fact("internal_service", "10.0.0.3:8080/tcp (http)", source="socks-pivot"),
        _fact("internal_service", "10.0.0.4:53/udp (dns)", source="inventory"),
        _fact("internal_service", "10.0.0.5:99999/tcp (invalid)"),
    ]
    model = TargetModel("scan", "example.com", facts)

    active_directory = model._active_directory()
    assert active_directory["counts"] == {
        "users": 3,
        "groups": "inventory unavailable",
    }
    assert len(active_directory["domains"]) == 1
    assert model._network_graph() == {
        "nodes": [{"host": "10.0.0.2"}],
        "edges": [{"from": "10.0.0.2", "to": "10.0.0.3"}],
    }
    services = model._internal_services()
    assert [service["reachable_via"] for service in services] == [
        "ssh",
        "pivot",
        "unknown",
    ]


def test_check_results_and_coverage_choose_latest_valid_scope() -> None:
    facts = [
        _fact("check_result", ""),
        _fact("check_result", "not-json"),
        _fact("check_result", "[]"),
        _fact("check_result", "[]"),
    ]
    model = TargetModel("scan", "example.com", facts)

    results = model._check_results()
    assert [result["raw"] for result in results] == ["not-json", "[]"]
    assert all("fact_id" not in result for result in results)

    coverage = model._coverage(
        [],
        [],
        [],
        [
            {},
            {
                "scope_type": "service",
                "scope_value": "EXAMPLE.COM:22/TCP",
                "kind": "banner",
                "status": "succeeded",
                "timestamp": 2,
            },
            {
                "scope_type": "service",
                "scope_value": "example.com:22/tcp",
                "kind": "banner",
                "status": "failed",
                "timestamp": 1,
            },
        ],
    )
    assert coverage == {
        "external_services": [],
        "web_endpoints": [],
        "internal_services": [],
        "gaps": [],
    }


def test_url_and_identity_parsers_reject_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = TargetModel("scan", "example.com", [])

    assert model._canonical_url("") == ""
    assert model._canonical_url('{"url":"HTTPS://EXAMPLE.COM:443/path"}') == ("https://example.com/path")
    assert model._canonical_url('"relative/path/"') == '"relative/path/"'
    assert model._canonical_url("relative/path/") == "relative/path"
    assert model._canonical_url("http:///missing-host") == "http:///missing-host"
    assert model._parse_port_fact("invalid") == {}
    assert TargetModel("scan", "", [])._parse_port_fact("80/tcp (http)") == {}
    assert model._parse_endpoint_fact("relative/path") == {}
    assert model._parse_endpoint_fact("http:///missing-host") == {}

    with monkeypatch.context() as patch:
        patch.setattr(
            target_model_module,
            "canonical_endpoint",
            lambda _url: (_ for _ in ()).throw(ValueError("invalid endpoint")),
        )
        assert model._parse_endpoint_fact("https://example.com/") == {}


def test_finding_parsers_cover_short_locations_and_cloud_providers() -> None:
    model = TargetModel(
        "scan",
        "example.com",
        [
            _fact("secret_finding", "token:app/.env:key:rotation_required"),
            _fact("cloud_finding", "high:aws_iam:resource"),
            _fact("code_finding", "high:check:src/main.py"),
            _fact("nuclei_finding", "high:template:https://example.com:name"),
        ],
    )

    assert model._parse_secret_finding("token")["location"] == ""
    assert model._parse_secret_finding("token:https://public.example:key:rotate")["exposure_scope"] == "public_url"
    assert model._parse_secret_finding("token:src/main.py:key:rotate")["exposure_scope"] == "source_code"
    assert model._parse_secret_finding("token:app/.env:key:rotate")["exposure_scope"] == "configuration"
    assert all(model._security_findings().values())
    assert model._parse_cloud_finding("high:azure_storage:resource")["provider"] == ("azure")
    assert model._parse_cloud_finding("high:gcp_bucket:resource")["provider"] == "gcp"
    assert model._parse_cloud_finding("high:k8s_rbac:resource")["provider"] == ("kubernetes")
    assert model._parse_cloud_finding("high:other:resource")["provider"] == "unknown"
