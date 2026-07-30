"""Hermetic normalization, model, and graph-projection boundary coverage."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.knowledge import identity as identity_module
from core.knowledge import models
from core.knowledge.identity import (
    EntityKind,
    canonical_asset,
    canonical_credential,
    canonical_from_legacy,
    canonical_identity,
    canonical_service,
    canonical_session,
    canonical_vulnerability,
    canonicalize_scope_value,
    canonicalize_scope_values,
    normalize_endpoint_url,
    normalize_host,
    normalize_protocol,
    validate_canonical_entity_id,
)
from core.knowledge.models import EdgeType, NodeType
from core.knowledge.projection import GraphProjectionService, ProjectionResult

pytestmark = pytest.mark.unit


SECRET_REF = "secret://0123456789abcdef0123456789abcdef"


class GraphDouble:
    def __init__(self) -> None:
        self.previous: dict[str, Any] | None = None
        self.link_ok = True
        self.nodes: list[tuple[str, NodeType, dict[str, Any], tuple[str, ...]]] = []
        self.edges: list[tuple[str, str, EdgeType, dict[str, Any]]] = []
        self.records: list[dict[str, Any]] = []

    def projection_record(self, _fact_id: int, _assessment_id: str):
        return self.previous

    def upsert_projected_node(
        self,
        entity_id: str,
        node_type: NodeType,
        properties: dict[str, Any],
        *,
        aliases: tuple[str, ...],
    ) -> None:
        self.nodes.append((entity_id, node_type, properties, aliases))

    def link(self, source: str, destination: str, edge_type: EdgeType, **properties) -> bool:
        self.edges.append((source, destination, edge_type, properties))
        return self.link_ok

    def record_projection(self, **record: Any) -> None:
        self.records.append(record)


class FactStoreDouble:
    def __init__(self, facts: list[dict[str, Any]]) -> None:
        self.facts = facts
        self.scan_calls: list[tuple[str, str | None]] = []
        self.id_calls: list[tuple[int, ...]] = []

    def get_facts(self, scan_id: str, host: str | None):
        self.scan_calls.append((scan_id, host))
        return list(self.facts)

    def get_facts_by_ids(self, fact_ids):
        self.id_calls.append(tuple(fact_ids))
        return list(self.facts)


def _fact(
    fact_type: str = "observation",
    value: str = "value",
    *,
    fact_id: Any = 1,
    host: str = "10.0.0.1",
    status: str = "verified",
    assessment: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    current_assessment = (
        {
            "assessment_id": f"assessment-{fact_id}",
            "status": status,
            "confidence": 91,
            "reason": "unit assessment",
            "evidence_fact_ids": [fact_id],
            "source_execution_ids": [f"execution-{fact_id}"],
        }
        if assessment is None
        else assessment
    )
    return {
        "id": fact_id,
        "scan_id": "scan-unit",
        "host": host,
        "type": fact_type,
        "value": value,
        "confidence": 80,
        "timestamp": 10.0,
        "source": "unit-source",
        "assessment": current_assessment,
        **extra,
    }


def _project(fact: dict[str, Any]) -> tuple[ProjectionResult, GraphDouble, GraphProjectionService]:
    graph = GraphDouble()
    service = GraphProjectionService(FactStoreDouble([]), graph)  # type: ignore[arg-type]
    return service.project_fact(fact), graph, service


def test_canonical_identity_value_object_and_scope_adapters() -> None:
    asset = canonical_asset("Example.COM.")
    rendered = asset.to_dict()

    assert rendered["entity_id"] == asset.entity_id
    assert rendered["kind"] == "asset"
    assert rendered["components"]["address"] == "example.com"
    assert rendered["aliases"] == list(asset.aliases)
    assert asset.component("missing", "fallback") == "fallback"
    assert validate_canonical_entity_id(f"  {asset.entity_id}  ") == asset.entity_id
    with pytest.raises(ValueError, match="Invalid canonical entity id"):
        validate_canonical_entity_id("asset:example.com")

    assert canonicalize_scope_value(asset.entity_id) == asset.entity_id
    assert canonicalize_scope_value("asset:Example.COM.") == "example.com"
    assert canonicalize_scope_value("endpoint:HTTPS://Example.COM:443/a/../b") == "https://example.com/b"
    assert canonicalize_scope_value("https://Example.COM:443/") == "https://example.com/"
    assert canonicalize_scope_value("[2001:0db8::1]") == "2001:db8::1"
    with pytest.raises(ValueError, match="must not be empty"):
        canonicalize_scope_value("  ")

    assert canonicalize_scope_values("Example.COM") == ("example.com",)
    assert canonicalize_scope_values(["Example.COM", "", "example.com", "10.0.0.2"]) == (
        "10.0.0.2",
        "example.com",
    )


def test_host_protocol_service_and_endpoint_validation_edges() -> None:
    assert normalize_host("https://Example.COM:8443/path") == ("dns", "example.com")
    assert normalize_host("[2001:0db8::1]") == ("ip", "2001:db8::1")
    assert normalize_host("münich.example") == ("dns", "xn--mnich-kva.example")
    with pytest.raises(ValueError, match="must not be empty"):
        normalize_host("https:///missing-host")
    with pytest.raises(ValueError, match="Invalid DNS host"):
        normalize_host("bad..example")
    with pytest.raises(ValueError, match="Invalid DNS host"):
        normalize_host("a" * 64 + ".example")
    with pytest.raises(ValueError, match="Invalid DNS host"):
        normalize_host(".".join(["a" * 63] * 4))
    with pytest.raises(ValueError, match="Invalid DNS host"):
        normalize_host("\ud800")

    assert normalize_protocol("TCP6") == "tcp"
    assert normalize_protocol("udp6") == "udp"
    assert normalize_protocol("") == "tcp"
    with pytest.raises(ValueError, match="Unsupported service protocol"):
        normalize_protocol("icmp")

    tcp = canonical_service("example.com", "443", "tcp")
    udp = canonical_service("example.com", 443, "udp")
    assert "svc:example.com:443" in tcp.aliases
    assert "svc:example.com:443" not in udp.aliases
    with pytest.raises(ValueError, match="Invalid service port"):
        canonical_service("example.com", object())
    with pytest.raises(ValueError, match="Invalid service port"):
        canonical_service("example.com", 0)

    assert normalize_endpoint_url("http://example.com:8080/a")[0] == "http://example.com:8080/a"
    assert normalize_endpoint_url("https://[2001:db8::1]/")[0] == "https://[2001:db8::1]/"
    with pytest.raises(ValueError, match="absolute HTTP"):
        normalize_endpoint_url("ftp://example.com/file")
    with pytest.raises(ValueError, match="userinfo"):
        normalize_endpoint_url("https://user@example.com/")
    with pytest.raises(ValueError, match="Invalid endpoint port"):
        normalize_endpoint_url("https://example.com:not-a-port/")
    with pytest.raises(ValueError, match="Invalid endpoint port"):
        normalize_endpoint_url("https://example.com:0/")


def test_identity_credential_session_and_vulnerability_variants() -> None:
    local = canonical_identity("CaseSensitive", identity_type="!!!")
    scoped = canonical_identity("Admin", domain="Example.COM.", identity_type="domain")
    hosted = canonical_identity("root", host="10.0.0.5")
    assert local.component("username") == "CaseSensitive"
    assert local.component("identity_type") == "local"
    assert local.component("scope") == "global"
    assert scoped.component("username") == "admin"
    assert scoped.component("scope") == "example.com"
    assert hosted.component("scope").startswith("asset:v1:")
    with pytest.raises(ValueError, match="username must not be empty"):
        canonical_identity("")

    credential = canonical_credential(
        "Admin",
        SECRET_REF,
        domain="example.com",
        host="10.0.0.5",
        service=" SSH ",
        secret_type="",
    )
    assert credential.component("service") == "ssh"
    assert credential.component("secret_type") == "password"
    assert credential.component("asset_id").startswith("asset:v1:")
    no_host_credential = canonical_credential("local", SECRET_REF)
    assert no_host_credential.component("asset_id") == ""
    with pytest.raises(ValueError, match="opaque secret reference"):
        canonical_credential("local", "plaintext")

    anonymous = canonical_session("session-1", session_type="", host="")
    domain_session = canonical_session(
        "session-2",
        host="10.0.0.5",
        username="Admin",
        domain="example.com",
    )
    assert anonymous.component("session_type") == "session"
    assert anonymous.component("identity_id") == ""
    assert domain_session.component("asset_id").startswith("asset:v1:")
    assert domain_session.component("identity_id").startswith("identity:v1:")
    with pytest.raises(ValueError, match="identifier must not be empty"):
        canonical_session("")

    assert canonical_vulnerability("CWE-79").component("namespace") == "cwe"
    assert canonical_vulnerability("exploit/windows/example").component("namespace") == "module"
    custom = canonical_vulnerability("  Custom   Finding  ")
    assert custom.component("namespace") == "custom"
    assert custom.component("key") == "custom finding"
    with pytest.raises(ValueError, match="identifier must not be empty"):
        canonical_vulnerability("")


@pytest.mark.parametrize(
    ("node_type", "properties", "expected_kind"),
    (
        ("asset", {"host": "example.com"}, EntityKind.ASSET),
        ("service", {"host": "example.com", "port": 53, "proto": "udp"}, EntityKind.SERVICE),
        ("endpoint", {"url": "https://example.com/"}, EntityKind.ENDPOINT),
        (
            "identity",
            {"username": "alice", "domain": "example.com", "identity_type": "domain", "host": "10.0.0.1"},
            EntityKind.IDENTITY,
        ),
        (
            "credential",
            {
                "username": "alice",
                "secret": SECRET_REF,
                "service": "ssh",
                "host": "10.0.0.1",
                "domain": "example.com",
                "secret_type": "password",
            },
            EntityKind.CREDENTIAL,
        ),
        (
            "session",
            {"session_id": "7", "session_type": "ssh", "host": "10.0.0.1", "username": "alice"},
            EntityKind.SESSION,
        ),
        ("vulnerability", {"name": "CVE-2026-12345"}, EntityKind.VULNERABILITY),
    ),
)
def test_legacy_identity_adapter_covers_every_supported_kind(
    node_type: str,
    properties: dict[str, Any],
    expected_kind: EntityKind,
) -> None:
    converted = canonical_from_legacy(node_type, properties)
    assert converted is not None
    assert converted.kind is expected_kind


def test_legacy_identity_adapter_is_best_effort() -> None:
    assert canonical_from_legacy("asset", {}) is None
    assert canonical_from_legacy("campaign", {"name": "test"}) is None


def test_private_identity_normalizers_cover_realm_percent_and_path_edges() -> None:
    assert identity_module._normalize_realm("") == ""
    assert identity_module._normalize_realm("Münich.Example.") == "xn--mnich-kva.example"
    assert identity_module._normalize_realm("\ud800") == "\ud800"
    assert identity_module._normalize_percent_encoding("%7e%2f%zz") == "~%2F%zz"
    assert identity_module._normalize_path("/../a/./b/../c/") == "/a/c/"
    assert identity_module._normalize_path("..") == "/"
    assert identity_module._normalize_path("a") == "a"
    assert identity_module._normalize_path(".") == "/"

    identity = identity_module._identity(
        EntityKind.ASSET,
        (("address", "example.com"),),
        ("", "alias", "alias"),
    )
    assert identity.aliases == ("alias",)


def test_host_normalization_defensively_rejects_invalid_codec_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EncodedHost:
        def decode(self, _encoding: str) -> str:
            return "bad..host"

    class NormalizedHost:
        def __contains__(self, _item: object) -> bool:
            return False

        def __bool__(self) -> bool:
            return True

        def strip(self, _characters: str | None = None):
            return self

        def rstrip(self, _characters: str | None = None):
            return self

        def encode(self, _encoding: str) -> EncodedHost:
            return EncodedHost()

    monkeypatch.setattr(
        identity_module,
        "unicodedata",
        SimpleNamespace(normalize=lambda *_args: NormalizedHost()),
    )
    monkeypatch.setattr(
        identity_module,
        "ipaddress",
        SimpleNamespace(ip_address=MagicMock(side_effect=ValueError("not an IP"))),
    )

    with pytest.raises(ValueError, match="Invalid DNS host"):
        normalize_host("codec-boundary")


def test_all_graph_models_expose_canonical_and_serializable_views(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redactor = SimpleNamespace(protect=MagicMock(return_value=SECRET_REF))
    monkeypatch.setattr(models, "get_redactor", lambda: redactor)

    asset = models.Asset("Example.COM", hostname="web", first_seen=1.0)
    identity = models.Identity("Admin", domain="example.com", identity_type="domain", host="10.0.0.1")
    plaintext_credential = models.Credential(
        "alice",
        "plaintext",
        secret_type="",
        service="ssh",
        host="10.0.0.1",
    )
    referenced_credential = models.Credential("alice", SECRET_REF)
    empty_credential = models.Credential("alice", "")
    service = models.Service("example.com", 443, service_name="https")
    endpoint = models.Endpoint("https://example.com/admin", service="https", status="200", title="Admin")
    session = models.Session("session-1", username="alice", host="10.0.0.1", opened_at=2.0)
    vulnerability = models.Vulnerability("CVE-2026-12345", confirmed=True)
    campaign = models.Campaign("unit", objective="verification", started_at=3.0)

    redactor.protect.assert_called_once_with("plaintext", kind="credential")
    assert plaintext_credential.secret == SECRET_REF
    assert referenced_credential.secret == SECRET_REF
    assert empty_credential.secret == ""

    for model in (asset, identity, plaintext_credential, service, endpoint, session, vulnerability):
        assert model.node_id.startswith(
            (
                "asset:v1:",
                "identity:v1:",
                "credential:v1:",
                "service:v1:",
                "endpoint:v1:",
                "session:v1:",
                "vulnerability:v1:",
            )
        )
        assert model.legacy_node_ids
        rendered = model.to_dict()
        assert rendered["canonical_id"] == model.node_id
        assert rendered["normalization_version"] == identity_module.ENTITY_NORMALIZATION_VERSION

    assert campaign.node_id == "campaign:unit"
    assert campaign.to_dict() == {
        "name": "unit",
        "objective": "verification",
        "started_at": 3.0,
        "targets": [],
        "status": "active",
    }


def test_projection_result_collections_and_skip_paths() -> None:
    result = ProjectionResult(
        fact_id=7,
        assessment_id="assessment-7",
        status="projected",
        node_ids=("node-1",),
        edge_keys=("edge-1",),
        reason="done",
    )
    assert result.to_dict()["node_ids"] == ["node-1"]

    fact = _fact()
    store = FactStoreDouble([fact])
    graph = GraphDouble()
    projector = GraphProjectionService(store, graph)  # type: ignore[arg-type]
    assert projector.project_scan("scan-unit", "10.0.0.1")[0].status == "projected"
    assert store.scan_calls == [("scan-unit", "10.0.0.1")]

    graph = GraphDouble()
    projector = GraphProjectionService(store, graph)  # type: ignore[arg-type]
    assert projector.project_fact_ids([1])[0].status == "projected"
    assert store.id_calls == [(1,)]

    missing_id, _graph, _projector = _project(_fact(fact_id=0))
    assert missing_id.status == "skipped"
    missing_assessment, _graph, _projector = _project(_fact(assessment={}, assessment_id=""))
    assert missing_assessment.status == "skipped"
    invalid_host, _graph, _projector = _project(_fact(host=""))
    assert invalid_host.status == "skipped"
    assert "must not be empty" in invalid_host.reason

    non_mapping = _fact(assessment="legacy", assessment_id="assessment-legacy")
    projected, _graph, _projector = _project(non_mapping)
    assert projected.status == "projected"


def test_projection_detects_unchanged_fingerprints() -> None:
    fact = _fact("port_open", "443/tcp (https) [nginx]")
    graph = GraphDouble()
    projector = GraphProjectionService(FactStoreDouble([]), graph)  # type: ignore[arg-type]
    fingerprint = projector._fingerprint(fact, fact["assessment"])
    graph.previous = {
        "fingerprint": fingerprint,
        "node_ids": ["node-a"],
        "edge_keys": ["edge-a"],
    }

    result = projector.project_fact(fact)
    assert result.status == "unchanged"
    assert result.node_ids == ("node-a",)
    assert result.edge_keys == ("edge-a",)
    assert graph.nodes == []


def test_projection_covers_service_endpoint_asset_and_vulnerability_families() -> None:
    remote_service, remote_graph, _service = _project(_fact("asset_service", "10.0.0.2:22/tcp (ssh) [OpenSSH]"))
    assert remote_service.status == "projected"
    assert {edge[2] for edge in remote_graph.edges} == {
        EdgeType.RUNS_SERVICE,
        EdgeType.DISCOVERED_ASSET,
    }

    same_service, same_graph, _service = _project(_fact("port_open", "443/tcp (https) [nginx]"))
    assert same_service.status == "projected"
    assert [edge[2] for edge in same_graph.edges] == [EdgeType.RUNS_SERVICE]
    no_service, no_service_graph, _service = _project(_fact("port_open", "not a port"))
    assert no_service.status == "projected"
    assert no_service_graph.edges == []

    endpoint, endpoint_graph, _service = _project(
        _fact("web_endpoint", json.dumps({"url": "/admin", "status": 200, "title": "Admin"}))
    )
    assert endpoint.status == "projected"
    assert {edge[2] for edge in endpoint_graph.edges} == {
        EdgeType.RUNS_SERVICE,
        EdgeType.EXPOSES_ENDPOINT,
    }
    no_endpoint, no_endpoint_graph, _service = _project(_fact("web_endpoint", "not-an-endpoint"))
    assert no_endpoint.status == "projected"
    assert no_endpoint_graph.edges == []

    discovered, discovered_graph, _service = _project(_fact("asset_ip", "A:10.0.0.2/32"))
    assert discovered.status == "projected"
    assert [edge[2] for edge in discovered_graph.edges] == [EdgeType.DISCOVERED_ASSET]
    same_asset, same_asset_graph, _service = _project(_fact("domain", "10.0.0.1"))
    assert same_asset.status == "projected"
    assert same_asset_graph.edges == []
    invalid_asset, invalid_asset_graph, _service = _project(_fact("subdomain", "bad..host"))
    assert invalid_asset.status == "projected"
    assert invalid_asset_graph.edges == []
    empty_asset, empty_asset_graph, _service = _project(_fact("subdomain", ""))
    assert empty_asset.status == "projected"
    assert empty_asset_graph.edges == []

    vulnerability, vulnerability_graph, _service = _project(_fact("vulnerability", "finding CVE-2026-12345"))
    assert vulnerability.status == "projected"
    assert [edge[2] for edge in vulnerability_graph.edges] == [EdgeType.HAS_VULNERABILITY]
    no_vulnerability, no_vulnerability_graph, _service = _project(_fact("vulnerability", "x" * 513))
    assert no_vulnerability.status == "projected"
    assert no_vulnerability_graph.edges == []


def test_access_projection_covers_credentials_sessions_and_non_access_returns() -> None:
    full_access, full_graph, _service = _project(
        _fact(
            "credential",
            f"ssh_login_success:alice@10.0.0.1 {SECRET_REF}",
            secret_refs=[SECRET_REF, ""],
            session_id="session-explicit",
        )
    )
    assert full_access.status == "projected"
    assert {
        EdgeType.HAS_IDENTITY,
        EdgeType.HAS_CREDENTIAL,
        EdgeType.CAN_ACCESS,
        EdgeType.ACTIVE_SESSION,
        EdgeType.SESSION_TO,
    }.issubset({edge[2] for edge in full_graph.edges})

    extracted_secret, extracted_graph, _service = _project(
        _fact("application_access", f"user=bob authenticated {SECRET_REF}")
    )
    assert extracted_secret.status == "projected"
    assert EdgeType.HAS_CREDENTIAL in {edge[2] for edge in extracted_graph.edges}

    identity_only, identity_graph, _service = _project(_fact("service_status", "user=carol access"))
    assert identity_only.status == "projected"
    assert EdgeType.HAS_IDENTITY in {edge[2] for edge in identity_graph.edges}
    assert EdgeType.HAS_CREDENTIAL not in {edge[2] for edge in identity_graph.edges}

    no_access, no_access_graph, _service = _project(_fact("credential", "***"))
    assert no_access.status == "projected"
    assert no_access_graph.edges == []

    anonymous_session, anonymous_graph, _service = _project(
        _fact("session", "***", session_id="none", status="contradicted")
    )
    assert anonymous_session.status == "projected"
    assert [edge[2] for edge in anonymous_graph.edges] == [EdgeType.SESSION_TO]
    session_node = next(node for node in anonymous_graph.nodes if node[1] is NodeType.SESSION)
    assert session_node[2]["session_id"] == "fact-1"
    assert session_node[2]["active"] is False


def test_projection_node_edge_provenance_and_fingerprint_helpers() -> None:
    graph = GraphDouble()
    projector = GraphProjectionService(FactStoreDouble([]), graph)  # type: ignore[arg-type]
    node_ids: list[str] = []
    identity = canonical_asset("10.0.0.1")
    projector._node(identity, NodeType.ASSET, {"ip": "10.0.0.1"}, node_ids)
    assert node_ids == [identity.entity_id]

    graph.link_ok = False
    with pytest.raises(RuntimeError, match="Unable to project edge"):
        projector._edge(identity.entity_id, "destination", EdgeType.TRUSTS, {}, [])

    contradicted = projector._provenance(
        {
            "id": 4,
            "assessment_id": "assessment-4",
            "assessment_status": "contradicted",
            "confidence": 12,
            "timestamp": 2,
            "observations": [{"timestamp": 9}, "ignored"],
            "sources": [],
            "source": "fallback-source",
            "scan_id": "scan",
            "host": "host",
        },
        {"evidence_fact_ids": [], "source_execution_ids": ["execution", ""], "reason": "no"},
    )
    assert contradicted["last_seen"] == 9.0
    assert contradicted["sources"] == ["fallback-source"]
    assert contradicted["contradiction_state"] == "contradicted"
    assert contradicted["evidence_fact_ids"] == [4]

    observed = projector._provenance(
        {
            "id": 5,
            "assessment_id": "assessment-5",
            "timestamp": 1,
            "sources": ["primary", ""],
        },
        {},
    )
    assert observed["assessment_status"] == "observed"
    assert observed["sources"] == ["primary"]
    assert observed["contradiction_state"] == "none"

    fingerprint = projector._fingerprint(_fact(), {"value": object()})
    assert len(fingerprint) == 64


@pytest.mark.parametrize(
    ("fact_type", "value", "expected"),
    (
        ("asset_service", "10.0.0.2:22/tcp (SSH) [OpenSSH]", ("10.0.0.2", 22, "tcp")),
        ("local_listening_port", "53/udp", ("10.0.0.1", 53, "udp")),
        ("service_version", "HTTP:8080:Apache", ("10.0.0.1", 8080, "tcp")),
        ("port_open", "443/tcp (HTTPS) [nginx]", ("10.0.0.1", 443, "tcp")),
    ),
)
def test_service_parser_supports_each_fact_shape(fact_type: str, value: str, expected) -> None:
    parsed = GraphProjectionService._parse_service(fact_type, value, "10.0.0.1")
    assert parsed is not None
    _identity, properties = parsed
    assert (properties["host"], properties["port"], properties["protocol"]) == expected


def test_projection_parsing_helpers_cover_invalid_and_fallback_shapes() -> None:
    assert GraphProjectionService._parse_service("port_open", "missing", "10.0.0.1") is None
    assert GraphProjectionService._parse_service("local_listening_port", "99999/tcp", "10.0.0.1") is None

    assert GraphProjectionService._endpoint_details("not-json") == {}
    assert GraphProjectionService._endpoint_details("[]") == {}
    assert GraphProjectionService._endpoint_details('{"status": 200, "title": "", "extra": 1}') == {"status": 200}

    assert GraphProjectionService._endpoint_url('{"endpoint": "https://example.com/a"}', "host") == (
        "https://example.com/a"
    )
    assert GraphProjectionService._endpoint_url("see https://example.com/a], next", "host") == ("https://example.com/a")
    assert GraphProjectionService._endpoint_url("/relative", "example.com") == "http://example.com/relative"
    assert GraphProjectionService._endpoint_url("[]", "example.com") == ""
    assert GraphProjectionService._endpoint_url("relative", "") == ""

    assert GraphProjectionService._asset_value("AAAA: [2001:db8::1]/64") == "2001:db8::1"
    assert GraphProjectionService._asset_value("example.com/24") == "example.com"

    assert GraphProjectionService._vulnerability_key("finding cve-2026-12345") == "cve-2026-12345"
    assert GraphProjectionService._vulnerability_key('{"template_id": "template-1"}') == "template-1"
    assert GraphProjectionService._vulnerability_key("[]") == "[]"
    assert GraphProjectionService._vulnerability_key("plain finding") == "plain finding"
    assert GraphProjectionService._vulnerability_key("x" * 513) == ""
    assert GraphProjectionService._vulnerability_key("") == ""

    assert GraphProjectionService._access_identity("ssh_login_success:alice@host") == ("alice", "ssh")
    assert GraphProjectionService._access_identity("username=bob") == ("bob", "access")
    assert GraphProjectionService._access_identity("***") == ("", "access")

    assert GraphProjectionService._positive_int("7") == 7
    assert GraphProjectionService._positive_int(-2) == 0
    assert GraphProjectionService._positive_int("bad") == 0
