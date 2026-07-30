"""Targeted hermetic coverage for the SQLite knowledge-graph boundary."""

from __future__ import annotations

import json
import os
import sqlite3
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.knowledge import graph as graph_module
from core.knowledge.graph import KnowledgeGraph
from core.knowledge.identity import canonical_asset, canonical_session
from core.knowledge.models import EdgeType, NodeType

pytestmark = pytest.mark.unit


SECRET_REF = "secret://0123456789abcdef0123456789abcdef"


def _insert_node(graph: KnowledgeGraph, node_id: str, node_type: NodeType = NodeType.ASSET, **properties):
    graph.upsert_projected_node(node_id, node_type, properties)
    return node_id


def _evidence(status: str = "verified", fact_id: int = 1) -> dict:
    assessment_id = f"assessment-{fact_id}"
    return {
        "assessment_status": status,
        "assessment_refs": [assessment_id],
        "current_assessment_refs": [assessment_id],
        "evidence_fact_ids": [fact_id],
        "current_evidence_fact_ids": [fact_id],
        "source_execution_ids": [f"execution-{fact_id}"],
        "current_source_execution_ids": [f"execution-{fact_id}"],
        "confidence": 90,
        "provenance": {
            str(fact_id): {
                "fact_id": fact_id,
                "assessment_id": assessment_id,
                "assessment_status": status,
                "assessment_refs": [assessment_id],
                "evidence_fact_ids": [fact_id],
                "source_execution_ids": [f"execution-{fact_id}"],
                "confidence": 90,
            }
        },
    }


def test_constructor_paths_connection_rollback_and_close(monkeypatch: pytest.MonkeyPatch) -> None:
    init_db = MagicMock()
    makedirs = MagicMock()
    isolated_os = SimpleNamespace(path=os.path, makedirs=makedirs)
    monkeypatch.setattr(graph_module, "os", isolated_os)
    monkeypatch.setattr(KnowledgeGraph, "_init_db", init_db)

    default_graph = KnowledgeGraph()
    assert default_graph.db_path.endswith("data/knowledge.db")
    no_directory_graph = KnowledgeGraph("knowledge.db")
    assert no_directory_graph.db_path == "knowledge.db"
    assert makedirs.call_count == 1
    assert init_db.call_count == 2

    monkeypatch.undo()
    memory_graph = KnowledgeGraph(":memory:")
    with pytest.raises(RuntimeError, match="rollback sentinel"), memory_graph._connect() as conn:
        conn.execute("INSERT INTO nodes VALUES ('temporary', 'asset', '{}', 1, 1)")
        raise RuntimeError("rollback sentinel")
    assert memory_graph.get_node("temporary") is None
    persistent = memory_graph._persistent_conn
    assert memory_graph._get_conn() is persistent
    memory_graph._close_conn(persistent)
    assert memory_graph._persistent_conn is persistent
    memory_graph.close()
    assert memory_graph._persistent_conn is None
    memory_graph.close()


def test_schema_rejects_unknown_versions_and_repairs_corrupt_properties(tmp_path) -> None:
    unsupported_path = tmp_path / "unsupported.db"
    graph = KnowledgeGraph(str(unsupported_path))
    graph.close()
    with sqlite3.connect(unsupported_path) as conn:
        conn.execute(
            "INSERT INTO knowledge_graph_schema VALUES (?, ?, ?)",
            ("99.0", "99.0", 1.0),
        )
    with pytest.raises(RuntimeError, match="Unsupported knowledge-graph schema"):
        KnowledgeGraph(str(unsupported_path))

    repair_path = tmp_path / "repair.db"
    graph = KnowledgeGraph(str(repair_path))
    first = graph.add_asset("10.0.0.1")
    second = graph.add_asset("10.0.0.2")
    assert graph.link(first.node_id, second.node_id, EdgeType.TRUSTS, source="unit")
    graph.close()
    with sqlite3.connect(repair_path) as conn:
        conn.execute("UPDATE nodes SET properties = 'not-json'")
        conn.execute("UPDATE edges SET properties = 'not-json'")

    repaired = KnowledgeGraph(str(repair_path))
    with sqlite3.connect(repair_path) as conn:
        node_values = {row[0] for row in conn.execute("SELECT properties FROM nodes")}
        edge_values = {row[0] for row in conn.execute("SELECT properties FROM edges")}
    assert node_values == {"{}"}
    assert edge_values == {"{}"}
    repaired.close()


def test_legacy_migration_merges_duplicate_nodes_edges_and_filters_bad_aliases(tmp_path) -> None:
    path = tmp_path / "legacy-duplicates.db"
    canonical_existing = canonical_asset("already.example").entity_id
    with sqlite3.connect(path) as conn:
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
                updated_at REAL NOT NULL DEFAULT 0,
                UNIQUE(src, dst, edge_type)
            );
            CREATE TABLE node_aliases (
                alias_id TEXT PRIMARY KEY,
                canonical_id TEXT NOT NULL,
                normalization_version TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )
        rows = [
            (
                "asset:Example.COM",
                "asset",
                json.dumps({"ip": "Example.COM", "sources": ["first"], "first_seen": 5}),
                5.0,
                6.0,
            ),
            (
                "asset:example.com",
                "asset",
                json.dumps({"ip": "example.com", "sources": "second", "first_seen": 2}),
                2.0,
                8.0,
            ),
            (
                canonical_existing,
                "asset",
                json.dumps({"ip": "already.example"}),
                3.0,
                3.0,
            ),
            ("campaign:legacy", "campaign", json.dumps({"name": "legacy"}), 1.0, 1.0),
        ]
        conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?)", rows)
        conn.executemany(
            "INSERT INTO edges(src, dst, edge_type, properties, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("asset:Example.COM", "campaign:legacy", "trusts", '{"sources":["one"]}', 4, 0),
                ("asset:example.com", "campaign:legacy", "trusts", '{"sources":"two"}', 5, 7),
            ],
        )
        conn.executemany(
            "INSERT INTO node_aliases VALUES (?, ?, ?, ?)",
            [
                (canonical_existing, canonical_existing, "legacy", 1),
                ("prior-alias", "asset:Example.COM", "legacy", 1),
                ("orphan-alias", "missing-node", "legacy", 1),
            ],
        )

    graph = KnowledgeGraph(str(path))
    example = graph.get_node("prior-alias")
    assert example is not None
    assert example["properties"]["sources"] == ["first", "second"]
    assert example["created_at"] == 2.0
    assert example["updated_at"] == 8.0
    assert graph.get_node(canonical_existing) is not None
    assert graph.get_node("campaign:legacy") is not None
    assert len(graph.get_edges_from(example["id"], EdgeType.TRUSTS)) == 1
    assert graph.resolve_node_id("orphan-alias") == "orphan-alias"


def test_property_loading_merging_metadata_and_alias_helpers() -> None:
    assert KnowledgeGraph._load_properties("not-json") == {}
    assert KnowledgeGraph._load_properties("[]") == {}
    assert KnowledgeGraph._load_properties(None) == {}

    merged = KnowledgeGraph._merge_properties(
        {
            "fact_ids": "old",
            "first_seen": 5,
            "last_seen": 5,
            "provenance": "legacy",
            "nested": {"left": 1},
            "current_status": "old",
            "items": [1],
        },
        {
            "ignored": None,
            "fact_ids": ["old", "new"],
            "first_seen": 2,
            "last_seen": 9,
            "provenance": {"1": {"assessment_status": "verified"}},
            "nested": {"right": 2},
            "current_status": "new",
            "items": [1, 2],
            "plain": "value",
        },
    )
    assert merged["fact_ids"] == ["old", "new"]
    assert merged["first_seen"] == 2.0
    assert merged["last_seen"] == 9.0
    assert merged["provenance"] == {"1": {"assessment_status": "verified"}}
    assert merged["nested"] == {"left": 1, "right": 2}
    assert merged["current_status"] == "new"
    assert merged["items"] == [1, 2]
    assert "ignored" not in merged

    contradicted = KnowledgeGraph._normalize_assessment_metadata({"assessment_status": "contradicted"})
    assert contradicted["contradiction_state"] == "contradicted"
    verified = KnowledgeGraph._normalize_assessment_metadata({"assessment_status": "verified"})
    assert verified["contradiction_state"] == "none"
    assert KnowledgeGraph._normalize_assessment_metadata({}) == {}
    without_confidence = KnowledgeGraph._normalize_assessment_metadata(
        {
            "provenance": {
                "1": {
                    "assessment_status": "verified",
                    "assessment_refs": "assessment-1",
                    "evidence_fact_ids": 1,
                    "source_execution_ids": "execution-1",
                    "confidence": "",
                }
            }
        }
    )
    assert "confidence" not in without_confidence
    assert without_confidence["current_assessment_refs"] == ["assessment-1"]

    graph = KnowledgeGraph(":memory:")
    asset = graph.add_asset("alias.example")
    with graph._connect() as conn:
        graph._register_aliases_in_conn(
            conn,
            asset.node_id,
            [asset.node_id, "custom-alias", "custom-alias", ""],
        )
    assert graph.resolve_node_id("custom-alias") == asset.node_id
    assert graph.resolve_node_id("unknown-alias") == "unknown-alias"


def test_typed_node_apis_relationship_wrappers_and_query_modes() -> None:
    graph = KnowledgeGraph(":memory:")
    asset = graph.add_asset("10.0.0.1", hostname="primary", os="Linux", rooted=True)
    identity = graph.add_identity("alice", host="10.0.0.1", uid=1000)
    credential = graph.add_credential(
        "alice",
        SECRET_REF,
        source="unit",
        service="ssh",
        verified=True,
        host="10.0.0.1",
    )
    service = graph.add_service(
        "10.0.0.1",
        443,
        service_name="https",
        version="nginx",
        web_app="portal",
    )
    endpoint = graph.add_endpoint("https://10.0.0.1/admin", service="https", status="200")
    full_session = graph.add_session("session-1", username="alice", host="10.0.0.1")
    empty_session = graph.add_session("session-2")
    vulnerability = graph.add_vulnerability("CVE-2026-12345", confirmed=True)
    empty_campaign = graph.add_campaign("empty")
    campaign = graph.add_campaign("scoped", targets=["10.0.0.1", "10.0.0.2"])

    assert all(
        item.node_id
        for item in (
            asset,
            identity,
            credential,
            service,
            endpoint,
            full_session,
            empty_session,
            vulnerability,
            empty_campaign,
            campaign,
        )
    )
    graph.link_credential_to_asset(credential.node_id, asset.node_id, method="ssh")
    graph.link_service_to_asset(service.node_id, asset.node_id)
    graph.link_vuln_to_service(vulnerability.node_id, service.node_id)
    assert graph.get_node("missing") is None
    assert graph.get_nodes_by_type(NodeType.ENDPOINT)[0]["id"] == endpoint.node_id
    assert graph.get_edges_from(asset.node_id)
    assert graph.get_edges_from(asset.node_id, EdgeType.RUNS_SERVICE)
    assert graph.get_edges_to(service.node_id)
    assert graph.get_edges_to(service.node_id, EdgeType.RUNS_SERVICE)
    assert graph.link(asset.node_id, service.node_id, object()) is False  # type: ignore[arg-type]


def _populated_surface_graph() -> tuple[KnowledgeGraph, str]:
    graph = KnowledgeGraph(":memory:")
    host = "10.10.0.1"
    asset = graph.add_asset(host, hostname="gateway", os="Linux", rooted=True)
    service = graph.add_service(
        host,
        443,
        service_name="https",
        version="nginx/1.0",
        web_app="portal",
    )
    graph.add_service(host, 22, service_name="ssh")
    graph.add_asset(host, hostname="gateway", os="Linux", rooted=True)
    confirmed = graph.add_vulnerability(
        "CVE-2026-12345",
        name="Confirmed issue",
        severity="high",
        confirmed=True,
    )
    possible = graph.add_vulnerability("CWE-79", name="Possible issue", confirmed=False)
    graph.link_vuln_to_service(confirmed.node_id, service.node_id)
    graph.link_vuln_to_service(possible.node_id, service.node_id)
    credential = graph.add_credential(
        "alice",
        SECRET_REF,
        source="unit",
        service="ssh",
        verified=True,
        host=host,
    )
    second_credential = graph.add_credential(
        "bob",
        "secret://abcdef0123456789abcdef0123456789",
        service="https",
        verified=False,
        host=host,
    )
    graph.link_credential_to_asset(credential.node_id, asset.node_id)
    graph.link_credential_to_asset(second_credential.node_id, asset.node_id, method="https")

    outbound = graph.add_asset("10.10.0.2")
    inbound = graph.add_asset("10.10.0.3")
    graph.link(asset.node_id, outbound.node_id, EdgeType.TRUSTS)
    graph.link(inbound.node_id, asset.node_id, EdgeType.TRUSTS)
    graph.add_session("active-session", username="alice", host=host)
    inactive_id = canonical_session("inactive-session", host=host).entity_id
    graph.upsert_projected_node(
        inactive_id,
        NodeType.SESSION,
        {"session_id": "inactive-session", "session_type": "web", "host": host, "active": False},
    )
    graph.link(inactive_id, asset.node_id, EdgeType.SESSION_TO)

    graph.link(asset.node_id, "service:v1:missing", EdgeType.RUNS_SERVICE)
    graph.link(service.node_id, "vulnerability:v1:missing", EdgeType.VULNERABLE_TO)
    graph.link("credential:v1:missing", asset.node_id, EdgeType.CAN_ACCESS)
    graph.link("session:v1:missing", asset.node_id, EdgeType.SESSION_TO)
    graph.add_asset(host, hostname="gateway", os="Linux", rooted=True)
    return graph, host


def test_attack_surface_credentials_and_llm_context_cover_present_missing_and_empty_nodes() -> None:
    graph, host = _populated_surface_graph()
    surface = graph.get_attack_surface(host)
    assert len(surface["services"]) == 2
    assert len(surface["vulnerabilities"]) == 2
    assert len(surface["credentials"]) == 2
    assert {item["direction"] for item in surface["trusts"]} == {"outbound", "inbound"}
    assert len(surface["sessions"]) == 2

    credentials = graph.get_credentials_for_host(host)
    assert {item["access_method"] for item in credentials} == {"ssh", "https"}
    context = graph.to_llm_context(host)
    for text in (
        "CAMPAIGN INTEL",
        "OS: Linux",
        "Hostname: gateway",
        "ROOT ACCESS ACHIEVED",
        "Port 443/tcp",
        "nginx/1.0",
        "portal",
        "CONFIRMED",
        "possible",
        "ACTIVE CREDENTIALS",
        "Trusts:",
        "Trusted by:",
        "active",
        "inactive",
    ):
        assert text in context

    bare = graph.add_asset("10.10.0.9")
    bare_context = graph.to_llm_context(bare.ip)
    assert "CAMPAIGN INTEL" in bare_context
    assert "OS:" not in bare_context
    assert graph.to_llm_context("10.10.0.99") == "No prior campaign context for this target."


def test_find_paths_edge_support_and_edge_path_boundaries() -> None:
    graph = KnowledgeGraph(":memory:")
    for node in ("a", "b", "c", "d"):
        _insert_node(graph, node)
    graph.link("a", "b", EdgeType.TRUSTS)
    graph.link("a", "b", EdgeType.PIVOTS_TO)
    graph.link("b", "a", EdgeType.TRUSTS)
    graph.link("b", "c", EdgeType.TRUSTS)
    assert graph.find_paths("a", "c")
    assert graph.find_paths("a", "c", max_depth=0) == []
    assert graph.find_paths("a", "a") == [["a"]]

    unsupported = KnowledgeGraph._edge_support(
        {"provenance": [], "assessment_status": "observed"},
        include_inferred=False,
    )
    assert unsupported[0] is False
    scalar_support = KnowledgeGraph._edge_support(
        {
            "assessment_status": "verified",
            "assessment_refs": "assessment-1",
            "evidence_fact_ids": 1,
            "source_execution_ids": "execution-1",
            "confidence": 80,
        },
        include_inferred=False,
    )
    assert scalar_support[0] is True
    assert scalar_support[2][0]["evidence_fact_ids"] == [1]
    missing_chain = KnowledgeGraph._edge_support(
        {"assessment_status": "verified", "assessment_refs": []},
        include_inferred=False,
    )
    assert missing_chain == (False, "missing_evidence_chain", [])
    inferred = KnowledgeGraph._edge_support(
        {
            "provenance": {
                "ignored": "not-a-record",
                "1": {
                    "assessment_status": "inferred",
                    "assessment_refs": ["assessment-1"],
                    "evidence_fact_ids": [1],
                },
            }
        },
        include_inferred=True,
    )
    assert inferred[0] is True

    verified_edge = {"dst": "b", "properties": scalar_support[2][0] | _evidence()}
    cycle_edge = {"dst": "a", "properties": _evidence()}
    observed_edge = {"dst": "c", "properties": {"assessment_status": "observed"}}
    adjacency = {"a": [cycle_edge, verified_edge], "b": [cycle_edge, observed_edge]}
    assert (
        KnowledgeGraph._edge_paths(
            adjacency,
            "a",
            "c",
            max_depth=0,
            max_paths=2,
            include_inferred=None,
        )
        == []
    )
    assert (
        KnowledgeGraph._edge_paths(
            adjacency,
            "a",
            "c",
            max_depth=3,
            max_paths=2,
            include_inferred=False,
        )
        == []
    )


def test_evidence_paths_explain_unknown_disconnected_and_partially_supported_routes() -> None:
    graph = KnowledgeGraph(":memory:")
    for node in ("a", "b", "c", "d"):
        _insert_node(graph, node)

    unknown = graph.find_evidence_paths("missing", "also-missing")
    assert unknown["missing_link"] == {
        "reason": "unknown_node",
        "missing": ["source", "destination"],
    }
    disconnected = graph.find_evidence_paths("a", "d", max_depth=99, max_paths=0)
    assert disconnected["missing_link"]["reason"] == "no_structural_path"
    assert disconnected["missing_link"]["max_depth"] == 32

    graph.link("a", "b", EdgeType.TRUSTS, **_evidence("verified", 1))
    graph.link("b", "c", EdgeType.TRUSTS, assessment_status="observed")
    excluded = graph.find_verified_paths("a", "c")
    assert excluded["missing_link"]["reason"] == "excluded_edges"
    assert len(excluded["missing_link"]["excluded_steps"]) == 1
    assert excluded["missing_link"]["excluded_steps"][0]["reason"] == ("assessment_status:observed")


def test_pivot_targets_deduplicate_trust_credential_and_explicit_routes() -> None:
    graph = KnowledgeGraph(":memory:")
    compromised = graph.add_asset("192.0.2.1")
    trusted = graph.add_asset("192.0.2.2")
    shared = graph.add_asset("192.0.2.3")
    explicit = graph.add_asset("192.0.2.4")
    credential = graph.add_credential("pivot", SECRET_REF, host=compromised.ip)
    graph.link(compromised.node_id, trusted.node_id, EdgeType.TRUSTS)
    graph.link(compromised.node_id, "asset:v1:missing", EdgeType.TRUSTS)
    graph.link(credential.node_id, compromised.node_id, EdgeType.CAN_ACCESS)
    graph.link(credential.node_id, shared.node_id, EdgeType.CAN_ACCESS)
    graph.link(credential.node_id, trusted.node_id, EdgeType.CAN_ACCESS)
    graph.link(compromised.node_id, explicit.node_id, EdgeType.PIVOTS_TO)
    graph.link(compromised.node_id, trusted.node_id, EdgeType.PIVOTS_TO)

    targets = graph.get_pivot_targets(compromised.ip)
    methods = {item["target"]: item["method"] for item in targets}
    assert methods[trusted.node_id] == "trust"
    assert methods[shared.node_id] == "shared_credential"
    assert methods[explicit.node_id] == "pivot"
    assert methods["asset:v1:missing"] == "trust"
    assert next(item for item in targets if item["target"] == "asset:v1:missing")["details"] == {}


def test_projection_records_stats_and_clear_are_idempotent() -> None:
    graph = KnowledgeGraph(":memory:")
    assert graph.projection_record(1, "assessment") is None
    graph.add_asset("203.0.113.1")
    graph.record_projection(
        fact_id=1,
        assessment_id="assessment",
        fingerprint="first",
        node_ids=["node", "node"],
        edge_keys=["edge", "edge"],
    )
    graph.record_projection(
        fact_id=1,
        assessment_id="assessment",
        fingerprint="second",
        node_ids=["node"],
        edge_keys=["edge"],
    )
    record = graph.projection_record(1, "assessment")
    assert record is not None
    assert record["fingerprint"] == "second"
    assert record["node_ids"] == ["node"]
    stats = graph.stats()
    assert stats["total_nodes"] == 1
    assert stats["projected_assessments"] == 1
    graph.clear()
    cleared = graph.stats()
    assert cleared["total_nodes"] == 0
    assert cleared["total_edges"] == 0
    assert cleared["projected_assessments"] == 0
