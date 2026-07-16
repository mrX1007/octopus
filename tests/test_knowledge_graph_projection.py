"""Canonical semantic-graph migration, projection, and path contracts."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from core.ai.asset_graph import AssetGraph
from core.ai.fact_assessment import AssessmentStatus
from core.ai.fact_store import FactStore
from core.ai.target_model import TargetModel
from core.knowledge import GraphProjectionService, KnowledgeGraph
from core.knowledge.identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_endpoint,
    canonical_service,
)
from core.knowledge.models import EdgeType, NodeType


def stores(tmp_path: Path) -> tuple[FactStore, KnowledgeGraph, GraphProjectionService]:
    facts = FactStore(str(tmp_path / "facts.db"))
    graph = KnowledgeGraph(str(tmp_path / "knowledge.db"))
    return facts, graph, GraphProjectionService(facts, graph)


def assess(
    store: FactStore,
    fact_id: int,
    status: AssessmentStatus,
    *,
    evidence_fact_ids: list[int] | None = None,
):
    return store.assessments.assess_fact(
        fact_id,
        status,
        confidence=95 if status is AssessmentStatus.VERIFIED else 75,
        reason=f"test transition to {status.value}",
        assessor="graph-contract-test",
        evidence_fact_ids=evidence_fact_ids or [fact_id],
        source_execution_ids=[f"execution-{fact_id}"],
    )[0]


def test_projection_is_idempotent_and_carries_complete_provenance(tmp_path: Path):
    facts, graph, projector = stores(tmp_path)
    fact_id = facts.add_fact(
        "scan-1",
        "Example.COM.",
        "port_open",
        "443/tcp (https) [nginx]",
        "nmap",
        source_execution_ids=["execution-1"],
    )
    assessment = assess(facts, fact_id, AssessmentStatus.VERIFIED)

    first = projector.project_fact_ids([fact_id])[0]
    before = graph.stats()
    second = projector.project_fact_ids([fact_id])[0]

    asset_id = canonical_asset("example.com").entity_id
    service_id = canonical_service("example.com", 443, "tcp").entity_id
    edges = graph.get_edges_from(asset_id, EdgeType.RUNS_SERVICE)
    assert first.status == "projected"
    assert second.status == "unchanged"
    assert graph.stats() == before
    assert len(edges) == 1
    metadata = edges[0]["properties"]
    assert metadata["fact_ids"] == [fact_id]
    assert assessment.assessment_id in metadata["assessment_refs"]
    assert metadata["assessment_status"] == "verified"
    assert metadata["confidence"] == 95
    assert metadata["current_evidence_fact_ids"] == [fact_id]
    assert metadata["current_source_execution_ids"] == ["execution-1"]
    assert metadata["scans"] == ["scan-1"]
    assert metadata["scopes"] == ["Example.COM."]
    assert metadata["contradiction_state"] == "none"
    assert metadata["normalization_version"] == ENTITY_NORMALIZATION_VERSION
    assert graph.get_node("asset:example.com")["id"] == asset_id
    assert graph.get_node("svc:example.com:443")["id"] == service_id


def test_verified_path_modes_and_missing_link_explanation(tmp_path: Path):
    facts, graph, projector = stores(tmp_path)
    fact_id = facts.add_fact(
        "scan-1",
        "10.0.0.5",
        "web_endpoint",
        json.dumps({"url": "HTTPS://10.0.0.5:443/a/../admin", "status": 200}),
        "httpx",
        source_execution_ids=["execution-web"],
    )
    assess(facts, fact_id, AssessmentStatus.INFERRED)
    projector.project_fact_ids([fact_id])

    asset_id = canonical_asset("10.0.0.5").entity_id
    endpoint_id = canonical_endpoint("https://10.0.0.5/admin").entity_id
    verified_only = graph.find_verified_paths(asset_id, endpoint_id)
    inferred = graph.find_verified_paths(
        asset_id,
        endpoint_id,
        include_inferred=True,
    )

    assert verified_only["paths"] == []
    assert verified_only["missing_link"]["reason"] == "excluded_edges"
    assert all(
        step["reason"] == "assessment_status:inferred"
        for step in verified_only["missing_link"]["excluded_steps"]
    )
    assert len(inferred["paths"]) == 1
    assert [step["edge_type"] for step in inferred["paths"][0]["steps"]] == [
        "runs_service",
        "exposes_endpoint",
    ]
    assert all(step["evidence_chain"] for step in inferred["paths"][0]["steps"])

    assess(facts, fact_id, AssessmentStatus.VERIFIED)
    projector.project_fact_ids([fact_id])
    verified = graph.find_verified_paths(asset_id, endpoint_id)
    assert len(verified["paths"]) == 1
    assert all(
        chain["assessment_status"] == "verified"
        for step in verified["paths"][0]["steps"]
        for chain in step["evidence_chain"]
    )

    contradiction = facts.add_fact(
        "scan-1",
        "10.0.0.5",
        "check_result",
        "endpoint disproved",
        "manual-review",
    )
    assess(
        facts,
        fact_id,
        AssessmentStatus.CONTRADICTED,
        evidence_fact_ids=[contradiction],
    )
    projector.project_fact_ids([fact_id])
    contradicted = graph.find_verified_paths(asset_id, endpoint_id, include_inferred=True)
    assert contradicted["paths"] == []
    assert contradicted["missing_link"]["reason"] == "excluded_edges"
    assert {
        step["reason"] for step in contradicted["missing_link"]["excluded_steps"]
    } == {"assessment_status:contradicted"}


def test_one_contradicted_fact_does_not_erase_independent_verified_support(tmp_path: Path):
    facts, graph, projector = stores(tmp_path)
    first_id = facts.add_fact(
        "scan",
        "10.0.0.9",
        "port_open",
        "22/tcp (ssh) [OpenSSH]",
        "nmap",
    )
    second_id = facts.add_fact(
        "scan",
        "10.0.0.9",
        "port_open",
        "22/tcp (ssh) [independent probe]",
        "socket-check",
    )
    assess(facts, first_id, AssessmentStatus.VERIFIED)
    assess(facts, second_id, AssessmentStatus.VERIFIED)
    projector.project_fact_ids([first_id, second_id])
    assess(facts, first_id, AssessmentStatus.CONTRADICTED, evidence_fact_ids=[second_id])
    projector.project_fact_ids([first_id])

    asset_id = canonical_asset("10.0.0.9").entity_id
    service_id = canonical_service("10.0.0.9", 22).entity_id
    edge = graph.get_edges_from(asset_id, EdgeType.RUNS_SERVICE)[0]
    assert edge["properties"]["assessment_status"] == "verified"
    assert edge["properties"]["contradiction_state"] == "mixed"
    path = graph.find_verified_paths(asset_id, service_id)
    assert len(path["paths"]) == 1
    evidence = path["paths"][0]["steps"][0]["evidence_chain"]
    assert [item["fact_id"] for item in evidence] == [second_id]


def test_legacy_graph_migration_rekeys_nodes_edges_and_preserves_timestamps(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                properties TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                properties TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(src, dst, edge_type)
            );
            """
        )
        conn.execute(
            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
            (
                "asset:Example.COM",
                "asset",
                json.dumps({"ip": "Example.COM", "tags": {"legacy": "yes"}}),
                10.0,
                20.0,
            ),
        )
        conn.execute(
            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
            (
                "svc:Example.COM:53",
                "service",
                json.dumps({"host": "Example.COM", "port": 53, "protocol": "tcp"}),
                11.0,
                21.0,
            ),
        )
        conn.execute(
            "INSERT INTO edges(src, dst, edge_type, properties, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "asset:Example.COM",
                "svc:Example.COM:53",
                "runs_service",
                json.dumps({"source": "legacy"}),
                12.0,
            ),
        )

    graph = KnowledgeGraph(str(db_path))
    asset_id = canonical_asset("example.com").entity_id
    service_id = canonical_service("example.com", 53, "tcp").entity_id
    asset = graph.get_node("asset:Example.COM")
    service = graph.get_node("svc:Example.COM:53")

    assert asset["id"] == asset_id
    assert asset["created_at"] == 10.0
    assert asset["updated_at"] == 20.0
    assert asset["properties"]["tags"] == {"legacy": "yes"}
    assert service["id"] == service_id
    assert graph.find_paths("asset:Example.COM", "svc:Example.COM:53") == [
        [asset_id, "-[runs_service]->", service_id]
    ]
    assert graph.stats()["schema_version"] == "2.0"

    reopened = KnowledgeGraph(str(db_path))
    assert reopened.stats()["total_nodes"] == 2
    assert reopened.stats()["total_edges"] == 1


def test_protocol_is_part_of_service_identity_without_ambiguous_legacy_alias():
    graph = KnowledgeGraph(":memory:")
    tcp = graph.add_service("example.com", 53, protocol="tcp")
    udp = graph.add_service("example.com", 53, protocol="udp")

    assert tcp.node_id != udp.node_id
    assert graph.get_node("svc:example.com:53")["id"] == tcp.node_id
    assert graph.get_node("example.com:53/udp")["id"] == udp.node_id
    assert len(graph.get_nodes_by_type(NodeType.SERVICE)) == 2


def test_per_scan_read_models_reuse_canonical_entity_ids(tmp_path: Path):
    facts, graph, projector = stores(tmp_path)
    fact_id = facts.add_fact(
        "scan",
        "10.0.0.20",
        "port_open",
        "8443/tcp (https) [nginx]",
        "nmap",
    )
    assess(facts, fact_id, AssessmentStatus.VERIFIED)
    stored = facts.get_facts("scan", "10.0.0.20")
    projector.project_fact_ids([fact_id])

    expected_asset = canonical_asset("10.0.0.20").entity_id
    expected_service = canonical_service("10.0.0.20", 8443).entity_id
    target_model = TargetModel.from_facts("scan", "10.0.0.20", stored).to_dict()
    asset_graph = AssetGraph.from_facts("10.0.0.20", stored).to_dict()

    assert target_model["asset_id"] == expected_asset
    assert target_model["services"][0]["canonical_id"] == expected_service
    assert {node["id"] for node in asset_graph["nodes"]}.issuperset(
        {expected_asset, expected_service}
    )
    assert all(
        edge["from"].startswith(("asset:", "service:", "view-"))
        and edge["to"].startswith(("asset:", "service:", "view-"))
        for edge in asset_graph["edges"]
    )
    assert graph.get_node(expected_service) is not None
