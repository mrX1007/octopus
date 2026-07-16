#!/usr/bin/env python3
"""Idempotent projection from canonical facts into the semantic graph."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .graph import KnowledgeGraph
from .identity import (
    ENTITY_NORMALIZATION_VERSION,
    CanonicalEntityIdentity,
    canonical_asset,
    canonical_credential,
    canonical_endpoint,
    canonical_identity,
    canonical_service,
    canonical_session,
    canonical_vulnerability,
)
from .models import EdgeType, NodeType

GRAPH_PROJECTION_SCHEMA_VERSION = "1.0"
_SERVICE_FACT_TYPES = {
    "asset_service",
    "internal_service",
    "local_listening_port",
    "port_open",
    "service_version",
}
_ENDPOINT_FACT_TYPES = {"api_endpoint", "asset_url", "browser_rendered", "web_endpoint"}
_ASSET_FACT_TYPES = {
    "asset_domain",
    "asset_ip",
    "domain",
    "internal_host",
    "subdomain",
}
_VULNERABILITY_FACT_TYPES = {
    "candidate_vulnerability",
    "exploit_success",
    "nuclei_finding",
    "potential_vulnerability",
    "verified_claim",
    "vulnerability",
}
_ACCESS_FACT_TYPES = {
    "application_access",
    "credential",
    "service_status",
    "session",
    "system_access",
}


@dataclass(frozen=True)
class ProjectionResult:
    fact_id: int
    assessment_id: str
    status: str
    node_ids: tuple[str, ...] = ()
    edge_keys: tuple[str, ...] = ()
    reason: str = ""
    schema_version: str = GRAPH_PROJECTION_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "fact_id": self.fact_id,
            "assessment_id": self.assessment_id,
            "status": self.status,
            "node_ids": list(self.node_ids),
            "edge_keys": list(self.edge_keys),
            "reason": self.reason,
        }


class GraphProjectionService:
    """Translate facts to typed graph entities without becoming a fact writer."""

    def __init__(self, fact_store: Any, graph: KnowledgeGraph):
        self.fact_store = fact_store
        self.graph = graph

    def project_scan(self, scan_id: str, host: str | None = None) -> list[ProjectionResult]:
        return [self.project_fact(fact) for fact in self.fact_store.get_facts(scan_id, host)]

    def project_fact_ids(self, fact_ids: Sequence[int]) -> list[ProjectionResult]:
        return [
            self.project_fact(fact)
            for fact in self.fact_store.get_facts_by_ids(fact_ids)
        ]

    def project_fact(self, fact: Mapping[str, Any]) -> ProjectionResult:
        fact_id = self._positive_int(fact.get("id"))
        assessment = fact.get("assessment")
        assessment = dict(assessment) if isinstance(assessment, Mapping) else {}
        assessment_id = str(
            assessment.get("assessment_id") or fact.get("assessment_id") or ""
        )
        if not fact_id or not assessment_id:
            return ProjectionResult(
                fact_id=fact_id,
                assessment_id=assessment_id,
                status="skipped",
                reason="Fact and current assessment identifiers are required.",
            )

        fingerprint = self._fingerprint(fact, assessment)
        previous = self.graph.projection_record(fact_id, assessment_id)
        if previous and previous.get("fingerprint") == fingerprint:
            return ProjectionResult(
                fact_id=fact_id,
                assessment_id=assessment_id,
                status="unchanged",
                node_ids=tuple(previous.get("node_ids") or ()),
                edge_keys=tuple(previous.get("edge_keys") or ()),
            )

        metadata = self._provenance(fact, assessment)
        host = str(fact.get("host") or "").strip()
        try:
            subject = canonical_asset(host)
        except ValueError as exc:
            return ProjectionResult(
                fact_id=fact_id,
                assessment_id=assessment_id,
                status="skipped",
                reason=str(exc),
            )

        node_ids: list[str] = []
        edge_keys: list[str] = []
        self._node(
            subject,
            NodeType.ASSET,
            {"ip": subject.component("address"), **metadata},
            node_ids,
        )
        fact_type = str(fact.get("type") or "").strip().lower()
        value = str(fact.get("value") or "").strip()

        if fact_type in _SERVICE_FACT_TYPES:
            parsed_service = self._parse_service(fact_type, value, host)
            if parsed_service:
                service, properties = parsed_service
                service_asset = canonical_asset(service.component("host"))
                self._node(
                    service_asset,
                    NodeType.ASSET,
                    {"ip": service.component("host"), **metadata},
                    node_ids,
                )
                self._node(service, NodeType.SERVICE, {**properties, **metadata}, node_ids)
                self._edge(
                    service_asset.entity_id,
                    service.entity_id,
                    EdgeType.RUNS_SERVICE,
                    metadata,
                    edge_keys,
                )
                if service_asset.entity_id != subject.entity_id:
                    self._edge(
                        subject.entity_id,
                        service_asset.entity_id,
                        EdgeType.DISCOVERED_ASSET,
                        metadata,
                        edge_keys,
                    )
        elif fact_type in _ENDPOINT_FACT_TYPES:
            endpoint_url = self._endpoint_url(value, host)
            if endpoint_url:
                endpoint = canonical_endpoint(endpoint_url)
                scheme = endpoint.component("scheme")
                service = canonical_service(
                    endpoint.component("host"),
                    endpoint.component("effective_port"),
                    "tcp",
                )
                endpoint_asset = canonical_asset(endpoint.component("host"))
                self._node(
                    endpoint_asset,
                    NodeType.ASSET,
                    {"ip": endpoint.component("host"), **metadata},
                    node_ids,
                )
                self._node(
                    service,
                    NodeType.SERVICE,
                    {
                        "host": endpoint.component("host"),
                        "port": int(endpoint.component("effective_port")),
                        "protocol": "tcp",
                        "service_name": scheme,
                        **metadata,
                    },
                    node_ids,
                )
                self._node(
                    endpoint,
                    NodeType.ENDPOINT,
                    {**dict(endpoint.components), **self._endpoint_details(value), **metadata},
                    node_ids,
                )
                self._edge(
                    endpoint_asset.entity_id,
                    service.entity_id,
                    EdgeType.RUNS_SERVICE,
                    metadata,
                    edge_keys,
                )
                self._edge(
                    service.entity_id,
                    endpoint.entity_id,
                    EdgeType.EXPOSES_ENDPOINT,
                    metadata,
                    edge_keys,
                )
        elif fact_type in _ASSET_FACT_TYPES:
            discovered_value = self._asset_value(value)
            if discovered_value:
                try:
                    discovered = canonical_asset(discovered_value)
                except ValueError:
                    discovered = None
                if discovered is not None:
                    self._node(
                        discovered,
                        NodeType.ASSET,
                        {"ip": discovered.component("address"), **metadata},
                        node_ids,
                    )
                    if discovered.entity_id != subject.entity_id:
                        self._edge(
                            subject.entity_id,
                            discovered.entity_id,
                            EdgeType.DISCOVERED_ASSET,
                            metadata,
                            edge_keys,
                        )
        elif fact_type in _VULNERABILITY_FACT_TYPES:
            vulnerability_key = self._vulnerability_key(value)
            if vulnerability_key:
                vulnerability = canonical_vulnerability(vulnerability_key)
                self._node(
                    vulnerability,
                    NodeType.VULNERABILITY,
                    {
                        "vuln_id": vulnerability.component("key"),
                        "candidate_value": value,
                        "confirmed": metadata["assessment_status"] == "verified",
                        **metadata,
                    },
                    node_ids,
                )
                self._edge(
                    subject.entity_id,
                    vulnerability.entity_id,
                    EdgeType.HAS_VULNERABILITY,
                    metadata,
                    edge_keys,
                )
        elif fact_type in _ACCESS_FACT_TYPES:
            self._project_access_fact(
                fact,
                value,
                subject,
                metadata,
                node_ids,
                edge_keys,
            )

        self.graph.record_projection(
            fact_id=fact_id,
            assessment_id=assessment_id,
            fingerprint=fingerprint,
            node_ids=node_ids,
            edge_keys=edge_keys,
        )
        return ProjectionResult(
            fact_id=fact_id,
            assessment_id=assessment_id,
            status="projected",
            node_ids=tuple(dict.fromkeys(node_ids)),
            edge_keys=tuple(dict.fromkeys(edge_keys)),
        )

    def _project_access_fact(
        self,
        fact: Mapping[str, Any],
        value: str,
        subject: CanonicalEntityIdentity,
        metadata: dict[str, Any],
        node_ids: list[str],
        edge_keys: list[str],
    ) -> None:
        username, service = self._access_identity(value)
        fact_id = self._positive_int(fact.get("id"))
        secret_refs = [str(item) for item in fact.get("secret_refs") or () if item]
        if not secret_refs:
            secret_refs = re.findall(r"secret://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", value)

        identity = None
        if username:
            identity = canonical_identity(username, host=subject.component("address"))
            self._node(
                identity,
                NodeType.IDENTITY,
                {"username": username, "host": subject.component("address"), **metadata},
                node_ids,
            )
            self._edge(
                subject.entity_id,
                identity.entity_id,
                EdgeType.HAS_IDENTITY,
                metadata,
                edge_keys,
            )

        if identity is not None and secret_refs:
            credential = canonical_credential(
                username,
                secret_refs[0],
                service=service,
                host=subject.component("address"),
            )
            self._node(
                credential,
                NodeType.CREDENTIAL,
                {
                    "username": username,
                    "secret": secret_refs[0],
                    "service": service,
                    "host": subject.component("address"),
                    "verified": metadata["assessment_status"] == "verified",
                    **metadata,
                },
                node_ids,
            )
            self._edge(
                identity.entity_id,
                credential.entity_id,
                EdgeType.HAS_CREDENTIAL,
                metadata,
                edge_keys,
            )
            self._edge(
                credential.entity_id,
                subject.entity_id,
                EdgeType.CAN_ACCESS,
                {"method": service, **metadata},
                edge_keys,
            )

        access_marker = any(
            marker in value.lower()
            for marker in ("access", "authenticated", "login_success", "session", "uid=")
        )
        if not access_marker and str(fact.get("type") or "") != "session":
            return
        raw_session_id = str(fact.get("session_id") or "").strip()
        session_id = raw_session_id if raw_session_id.lower() not in {"", "none"} else f"fact-{fact_id}"
        session = canonical_session(
            session_id,
            session_type=service or "access",
            host=subject.component("address"),
            username=username,
        )
        self._node(
            session,
            NodeType.SESSION,
            {
                "session_id": session_id,
                "session_type": service or "access",
                "username": username,
                "host": subject.component("address"),
                "active": metadata["assessment_status"] != "contradicted",
                **metadata,
            },
            node_ids,
        )
        if identity is not None:
            self._edge(
                identity.entity_id,
                session.entity_id,
                EdgeType.ACTIVE_SESSION,
                metadata,
                edge_keys,
            )
        self._edge(
            session.entity_id,
            subject.entity_id,
            EdgeType.SESSION_TO,
            metadata,
            edge_keys,
        )

    def _node(
        self,
        identity: CanonicalEntityIdentity,
        node_type: NodeType,
        properties: dict[str, Any],
        node_ids: list[str],
    ) -> None:
        self.graph.upsert_projected_node(
            identity.entity_id,
            node_type,
            properties,
            aliases=identity.aliases,
        )
        node_ids.append(identity.entity_id)

    def _edge(
        self,
        source: str,
        destination: str,
        edge_type: EdgeType,
        properties: dict[str, Any],
        edge_keys: list[str],
    ) -> None:
        if not self.graph.link(source, destination, edge_type, **properties):
            raise RuntimeError(
                f"Unable to project edge {source} -[{edge_type.value}]-> {destination}"
            )
        edge_keys.append(f"{source}|{edge_type.value}|{destination}")

    @staticmethod
    def _provenance(
        fact: Mapping[str, Any],
        assessment: Mapping[str, Any],
    ) -> dict[str, Any]:
        fact_id = int(fact["id"])
        assessment_id = str(assessment.get("assessment_id") or fact.get("assessment_id"))
        status = str(assessment.get("status") or fact.get("assessment_status") or "observed")
        evidence_fact_ids = [int(item) for item in assessment.get("evidence_fact_ids") or [fact_id]]
        execution_ids = [str(item) for item in assessment.get("source_execution_ids") or () if item]
        timestamp = float(fact.get("timestamp", 0.0) or 0.0)
        observations = [item for item in fact.get("observations") or () if isinstance(item, Mapping)]
        last_seen = max(
            [timestamp, *(float(item.get("timestamp", 0.0) or 0.0) for item in observations)]
        )
        sources = [str(item) for item in fact.get("sources") or () if item]
        if not sources and fact.get("source"):
            sources = [str(fact["source"])]
        record = {
            "fact_id": fact_id,
            "assessment_id": assessment_id,
            "assessment_refs": [assessment_id],
            "current_assessment_refs": [assessment_id],
            "assessment_status": status,
            "confidence": int(assessment.get("confidence", fact.get("confidence", 0)) or 0),
            "evidence_fact_ids": evidence_fact_ids,
            "current_evidence_fact_ids": evidence_fact_ids,
            "source_execution_ids": execution_ids,
            "current_source_execution_ids": execution_ids,
            "reason": str(assessment.get("reason") or ""),
        }
        return {
            "fact_ids": [fact_id],
            "assessment_refs": [assessment_id],
            "assessment_status": status,
            "confidence": record["confidence"],
            "evidence_fact_ids": evidence_fact_ids,
            "source_execution_ids": execution_ids,
            "first_seen": timestamp,
            "last_seen": last_seen,
            "scans": [str(fact.get("scan_id") or "")],
            "scopes": [str(fact.get("host") or "")],
            "sources": sources,
            "contradiction_state": "contradicted" if status == "contradicted" else "none",
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "projection_schema_version": GRAPH_PROJECTION_SCHEMA_VERSION,
            "provenance": {str(fact_id): record},
        }

    @staticmethod
    def _fingerprint(fact: Mapping[str, Any], assessment: Mapping[str, Any]) -> str:
        payload = {
            "schema_version": GRAPH_PROJECTION_SCHEMA_VERSION,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "fact": {
                "id": fact.get("id"),
                "scan_id": fact.get("scan_id"),
                "host": fact.get("host"),
                "type": fact.get("type"),
                "value": fact.get("value"),
                "confidence": fact.get("confidence"),
                "timestamp": fact.get("timestamp"),
                "secret_refs": fact.get("secret_refs") or [],
            },
            "assessment": dict(assessment),
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8", "replace")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _parse_service(
        fact_type: str,
        value: str,
        default_host: str,
    ) -> tuple[CanonicalEntityIdentity, dict[str, Any]] | None:
        host = default_host
        port = ""
        protocol = "tcp"
        service_name = ""
        banner = ""
        if fact_type in {"asset_service", "internal_service"}:
            match = re.search(
                r"(?P<host>[^\s:]+):(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)"
                r"(?:\s+\((?P<service>[^)]*)\))?(?:\s+\[(?P<banner>.*?)\])?",
                value,
                re.IGNORECASE,
            )
        elif fact_type == "local_listening_port":
            match = re.search(r"(?P<port>\d{1,5})(?:/(?P<proto>tcp|udp|sctp))?", value)
        elif fact_type == "service_version":
            match = re.match(
                r"(?P<service>[^:]+):(?P<port>\d{1,5}):(?P<banner>.+)",
                value,
            )
        else:
            match = re.search(
                r"(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)"
                r"(?:\s+\((?P<service>[^)]*)\))?(?:\s+\[(?P<banner>.*?)\])?",
                value,
                re.IGNORECASE,
            )
        if not match:
            return None
        groups = match.groupdict()
        host = str(groups.get("host") or host)
        port = str(groups.get("port") or "")
        protocol = str(groups.get("proto") or protocol).lower()
        service_name = str(groups.get("service") or "").strip().lower()
        banner = str(groups.get("banner") or "").strip()
        try:
            identity = canonical_service(host, port, protocol)
        except ValueError:
            return None
        return identity, {
            "host": identity.component("host"),
            "port": int(identity.component("port")),
            "protocol": identity.component("protocol"),
            "service_name": service_name,
            "version": banner,
            "banner": banner,
            "state": "open",
        }

    @staticmethod
    def _endpoint_details(value: str) -> dict[str, Any]:
        try:
            loaded = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        return {
            key: loaded[key]
            for key in ("status", "title")
            if loaded.get(key) not in (None, "")
        }

    @staticmethod
    def _endpoint_url(value: str, host: str) -> str:
        try:
            loaded = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            loaded = {}
        raw = (
            str(loaded.get("url") or loaded.get("endpoint") or "").strip()
            if isinstance(loaded, dict)
            else ""
        )
        raw = raw or value.strip()
        match = re.search(r"https?://[^\s'\"<>]+", raw, re.IGNORECASE)
        if match:
            return match.group(0).rstrip("],);")
        if raw.startswith("/") and host:
            return f"http://{host}{raw}"
        return ""

    @staticmethod
    def _asset_value(value: str) -> str:
        raw = value.strip()
        if ":" in raw and raw.split(":", 1)[0].lower() in {"a", "aaaa", "cname", "tls_san"}:
            raw = raw.split(":", 1)[1]
        return raw.split("/", 1)[0].strip().strip("[]")

    @staticmethod
    def _vulnerability_key(value: str) -> str:
        match = re.search(r"\b(?:CVE-\d{4}-\d{4,7}|CWE-\d{1,5})\b", value, re.IGNORECASE)
        if match:
            return match.group(0)
        try:
            loaded = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, dict):
            for key in ("template", "template_id", "id", "name"):
                if loaded.get(key):
                    return str(loaded[key])
        if value and len(value) <= 512:
            return value
        return ""

    @staticmethod
    def _access_identity(value: str) -> tuple[str, str]:
        lowered = value.lower()
        service_match = re.match(r"([a-z0-9_.-]+?)(?:_login_success|_authenticated|_session):", lowered)
        service = service_match.group(1) if service_match else "access"
        user_match = re.search(r"(?:login_success:)?([^:@/\s]+)@[^\s]+", value, re.IGNORECASE)
        if not user_match:
            user_match = re.search(r"(?:user(?:name)?[=:]|^)([A-Za-z0-9_.@-]+)", value)
        username = user_match.group(1).strip() if user_match else ""
        return username, service

    @staticmethod
    def _positive_int(value: Any) -> int:
        try:
            parsed = int(value or 0)
        except (TypeError, ValueError):
            return 0
        return parsed if parsed > 0 else 0


__all__ = [
    "GRAPH_PROJECTION_SCHEMA_VERSION",
    "GraphProjectionService",
    "ProjectionResult",
]
