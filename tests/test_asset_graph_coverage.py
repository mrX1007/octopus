"""Focused branch coverage for normalized asset graph construction."""

from __future__ import annotations

import pytest

from core.ai.asset_graph import AssetGraph

pytestmark = pytest.mark.unit


def test_build_skips_contradicted_empty_and_off_target_facts():
    graph = AssetGraph.from_facts(
        "",
        [
            {"assessment_status": "contradicted", "type": "asset_ip", "value": "192.0.2.1"},
            {"type": "asset_ip", "value": ""},
            {"type": "asset_domain", "value": "Example.TEST"},
            {"type": "internal_host", "value": "10.0.0.1"},
        ],
    )

    assert graph.host == ""
    assert len(graph.nodes) == 2
    assert graph.edges == {}


def test_build_covers_local_services_and_subnet_membership_variants():
    graph = AssetGraph.from_facts(
        "192.0.2.10",
        [
            {"type": "local_listening_port", "value": "8080"},
            {"type": "internal_subnet", "value": "10.0.0.0/24"},
            {"type": "internal_subnet", "value": "invalid"},
            {"type": "internal_host", "value": "10.0.0.5"},
            {"type": "internal_host", "value": "10.1.0.5"},
        ],
    )

    edge_types = {edge["type"] for edge in graph.edges.values()}
    assert "reachable_service" in edge_types
    assert "member_of_subnet" in edge_types


def test_add_helpers_reject_malformed_values_and_accept_valid_values():
    graph = AssetGraph("", [])

    graph._add_endpoint("not-a-url")
    graph._add_service("", "22/tcp (ssh)", "external")
    graph._add_service("host", "bad", "external")
    graph._add_asset_service("bad")
    graph._add_dns_record("missing-value")
    graph._add_dns_record("a:example.test")
    graph._add_reachable_service("", "22", "local")
    graph._add_reachable_service("host", "bad", "local")
    graph._add_subnet("10.0.0.0/24")
    graph._add_cloud_resource("too:short")
    graph._add_secret("missing")

    assert graph.nodes
    assert graph.edges == {}

    graph._add_reachable_service("host", "22", "local")
    assert any(edge["type"] == "reachable_service" for edge in graph.edges.values())


def test_empty_nodes_edges_and_invalid_canonical_ids_are_safe():
    graph = AssetGraph("host", [])

    assert graph._node("host", "") == ""
    graph._edge("", "host", "invalid")
    graph._edge("host", "", "invalid")
    fallback = graph._canonical_node_id(
        "service",
        "invalid-service",
        {"host": "host", "port": None},
    )

    assert fallback.startswith("view-service:v1:")
    assert graph.edges == {}


def test_endpoint_parser_rejects_bad_scheme_and_hostname():
    graph = AssetGraph("host", [])

    assert graph._parse_endpoint('{"url":"ftp://host/file"}') == {}
    assert graph._parse_endpoint("http:///missing-host") == {}
    parsed = graph._parse_endpoint('{"url":"https://Example.TEST/path","status":200}')
    assert parsed["host"] == "example.test"
    assert parsed["port"] == 443


def test_invalid_subnets_and_all_cloud_provider_prefixes():
    graph = AssetGraph("host", [])

    assert graph._host_in_subnet("bad", "also-bad") is False
    assert graph._provider_from_check("aws_public") == "aws"
    assert graph._provider_from_check("azure_public") == "azure"
    assert graph._provider_from_check("gcp_public") == "gcp"
    assert graph._provider_from_check("k8s_public") == "kubernetes"
    assert graph._provider_from_check("other") == "unknown"
