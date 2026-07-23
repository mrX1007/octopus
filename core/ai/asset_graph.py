#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Union, cast
from urllib.parse import urlparse

from core.knowledge.identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_endpoint,
    canonical_service,
)


class AssetGraph:
    """Normalize facts into an asset/network graph for deterministic planning."""

    def __init__(self, target: str, facts: list[dict[str, Any]]):
        self.target = target
        self.host = self._target_host(target)
        self.facts = facts or []
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = {}
        self._current_fact: dict[str, Any] | None = None

    @classmethod
    def from_facts(cls, target: str, facts: list[dict[str, Any]]) -> AssetGraph:
        graph = cls(target, facts)
        graph._build()
        return graph

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "nodes": sorted(self.nodes.values(), key=lambda n: (n.get("kind", ""), n.get("id", ""))),
            "edges": sorted(self.edges.values(), key=lambda e: (e.get("type", ""), e.get("from", ""), e.get("to", ""))),
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            kind = node.get("kind", "unknown")
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def _build(self) -> None:
        if self.host:
            self._node("host", self.host, state="confirmed_present", source="target")

        subnets = []
        internal_hosts = []
        for fact in self.facts:
            if str(fact.get("assessment_status") or "observed") == "contradicted":
                continue
            self._current_fact = fact
            ftype = fact.get("type")
            value = str(fact.get("value", "")).strip()
            if not value:
                continue
            if ftype == "asset_domain":
                self._node("domain", value.lower(), state="confirmed_present")
                if self.host:
                    self._edge(value.lower(), self.host, "resolves_or_related_to")
            elif ftype == "asset_ip":
                self._node("host", value, state="confirmed_present")
            elif ftype == "asset_url":
                self._add_endpoint(value)
            elif ftype == "asset_dns_record":
                self._add_dns_record(value)
            elif ftype == "asset_service":
                self._add_asset_service(value)
            elif ftype == "web_endpoint":
                self._add_endpoint(value)
            elif ftype == "port_open":
                self._add_service(self.host, value, "external")
            elif ftype == "local_listening_port":
                self._add_reachable_service(self.host, value, "local")
            elif ftype == "internal_subnet":
                subnets.append(value)
                self._add_subnet(value)
            elif ftype == "internal_host":
                internal_hosts.append(value)
                self._node("host", value, state="confirmed_present", scope="internal")
                if self.host:
                    self._edge(self.host, value, "discovered_host")
            elif ftype == "cloud_finding":
                self._add_cloud_resource(value)
            elif ftype == "secret_finding":
                self._add_secret(value)

        self._current_fact = None

        for internal_host in internal_hosts:
            for subnet in subnets:
                if self._host_in_subnet(internal_host, subnet):
                    self._edge(internal_host, subnet, "member_of_subnet")

    def _add_endpoint(self, value: str) -> None:
        endpoint = self._parse_endpoint(value)
        if not endpoint:
            return
        endpoint_id = endpoint["url"].rstrip("/")
        host = endpoint["host"]
        self._node("host", host, state="confirmed_present")
        self._node("endpoint", endpoint_id, **endpoint, state="confirmed_present")
        self._edge(host, endpoint_id, "serves_endpoint")
        service_id = f"{host}:{endpoint['port']}/tcp"
        self._node("service", service_id, host=host, port=endpoint["port"], proto="tcp", service=endpoint["scheme"])
        self._edge(host, service_id, "listens_on")
        self._edge(service_id, endpoint_id, "exposes_endpoint")

    def _add_service(self, host: str, value: str, scope: str) -> None:
        match = re.match(r"(\d+)/(tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value, re.IGNORECASE)
        if not match or not host:
            return
        port, proto, service, banner = match.groups()
        service_id = f"{host}:{port}/{proto.lower()}"
        self._node("host", host, state="confirmed_present")
        self._node("service", service_id, host=host, port=int(port), proto=proto.lower(), service=service.lower(), banner=banner or "", scope=scope)
        self._edge(host, service_id, "listens_on")

    def _add_asset_service(self, value: str) -> None:
        match = re.match(r"([^:\s]+):(\d{1,5})/(tcp|udp)", value, re.IGNORECASE)
        if not match:
            return
        host, port, proto = match.groups()
        service_id = f"{host}:{port}/{proto.lower()}"
        self._node("host", host, state="confirmed_present")
        self._node("service", service_id, host=host, port=int(port), proto=proto.lower(), service="unknown", scope="asset_inventory")
        self._edge(host, service_id, "owns_service")

    def _add_dns_record(self, value: str) -> None:
        kind, _, record_value = value.partition(":")
        if not record_value:
            return
        self._node("domain", record_value, state="confirmed_present")
        if self.host:
            edge_type = "has_tls_san" if kind == "tls_san" else "has_dns_record"
            self._edge(self.host, record_value, edge_type)

    def _add_reachable_service(self, host: str, port: str, scope: str) -> None:
        if not host or not str(port).isdigit():
            return
        service_id = f"{host}:{port}/tcp"
        self._node("service", service_id, host=host, port=int(port), proto="tcp", service="unknown", scope=scope)
        self._edge(host, service_id, "reachable_service")

    def _add_subnet(self, value: str) -> None:
        self._node("subnet", value, state="confirmed_present")
        if not self.host:
            return
        interface_id = f"{self.host}:iface:{value.split('/', 1)[0]}"
        self._node("interface", interface_id, host=self.host, address=value.split("/", 1)[0], subnet=value)
        self._edge(self.host, interface_id, "has_interface")
        self._edge(interface_id, value, "attached_to_subnet")

    def _add_cloud_resource(self, value: str) -> None:
        parts = value.split(":", 2)
        if len(parts) < 3:
            return
        severity, check_id, resource = parts
        provider = self._provider_from_check(check_id)
        resource_id = resource or check_id
        self._node("cloud_resource", resource_id, provider=provider, check_id=check_id, severity=severity)

    def _add_secret(self, value: str) -> None:
        parts = value.split(":", 3)
        if len(parts) < 2:
            return
        secret_type, location = parts[0], parts[1]
        secret_id = f"{secret_type}:{location}"
        self._node("secret", secret_id, secret_type=secret_type, location=location)

    def _node(self, kind: str, node_id: str, **attrs: Any) -> str:
        if not node_id:
            return ""
        canonical_id = self._canonical_node_id(kind, node_id, attrs)
        self.aliases.setdefault(str(node_id), canonical_id)
        existing = self.nodes.get(
            canonical_id,
            {
                "kind": kind,
                "id": canonical_id,
                "canonical_id": canonical_id,
                "display_id": node_id,
                "normalization_version": ENTITY_NORMALIZATION_VERSION,
            },
        )
        incoming = {
            **attrs,
            **self._fact_metadata(),
        }
        self.nodes[canonical_id] = self._merge(existing, incoming)
        return canonical_id

    def _edge(self, src: str, dst: str, edge_type: str, **attrs: Any) -> None:
        if not src or not dst:
            return
        canonical_src = self.aliases.get(str(src), str(src))
        canonical_dst = self.aliases.get(str(dst), str(dst))
        key = json.dumps(
            {"from": canonical_src, "to": canonical_dst, "type": edge_type},
            sort_keys=True,
        )
        edge = self.edges.get(
            key,
            {"from": canonical_src, "to": canonical_dst, "type": edge_type},
        )
        self.edges[key] = self._merge(edge, {**attrs, **self._fact_metadata()})

    def _canonical_node_id(
        self,
        kind: str,
        node_id: str,
        attrs: dict[str, Any],
    ) -> str:
        try:
            if kind in {"host", "domain"}:
                return canonical_asset(node_id).entity_id
            if kind == "service":
                return canonical_service(
                    str(attrs.get("host") or str(node_id).split(":", 1)[0]),
                    cast(Union[int, str], attrs.get("port")),
                    str(attrs.get("proto") or attrs.get("protocol") or "tcp"),
                ).entity_id
            if kind == "endpoint":
                return canonical_endpoint(str(attrs.get("url") or node_id)).entity_id
        except (TypeError, ValueError):
            pass
        payload = json.dumps(
            {
                "kind": kind,
                "value": str(node_id).strip(),
                "normalization_version": ENTITY_NORMALIZATION_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:32]
        return f"view-{kind}:v1:{digest}"

    def _fact_metadata(self) -> dict[str, Any]:
        fact = self._current_fact
        if not fact:
            return {}
        assessment = fact.get("assessment")
        assessment = assessment if isinstance(assessment, dict) else {}
        fact_id = fact.get("id")
        assessment_id = assessment.get("assessment_id") or fact.get("assessment_id")
        return {
            "fact_ids": [int(fact_id)] if fact_id is not None else [],
            "assessment_refs": [str(assessment_id)] if assessment_id else [],
            "assessment_status": str(
                assessment.get("status") or fact.get("assessment_status") or "observed"
            ),
            "evidence_fact_ids": list(assessment.get("evidence_fact_ids") or []),
            "source_execution_ids": list(assessment.get("source_execution_ids") or []),
        }

    @staticmethod
    def _merge(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
        merged = dict(existing)
        union_keys = {
            "assessment_refs",
            "evidence_fact_ids",
            "fact_ids",
            "source_execution_ids",
        }
        for key, value in incoming.items():
            if value in (None, ""):
                continue
            if key in union_keys:
                previous = merged.get(key) or []
                merged[key] = list(dict.fromkeys([*previous, *(value or [])]))
            else:
                merged[key] = value
        return merged

    def _parse_endpoint(self, value: str) -> dict[str, Any]:
        try:
            data = json.loads(value)
            url = str(data.get("url", "")).strip()
        except Exception:
            data = {}
            url = value.strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            return {}
        parsed = urlparse(url)
        if not parsed.hostname:
            return {}
        port = int(data.get("port") or parsed.port or (443 if parsed.scheme == "https" else 80))
        return {
            "url": url,
            "scheme": parsed.scheme.lower(),
            "host": parsed.hostname.lower(),
            "port": port,
            "path": parsed.path or "/",
            "status": data.get("status", ""),
            "title": data.get("title", ""),
        }

    def _target_host(self, target: str) -> str:
        return (target or "").strip().split("://")[-1].split("/", 1)[0].split(":", 1)[0]

    def _host_in_subnet(self, host: str, subnet: str) -> bool:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            return False

    def _provider_from_check(self, check_id: str) -> str:
        value = (check_id or "").lower()
        if value.startswith(("aws", "s3", "iam", "ec2", "lambda", "ecr")):
            return "aws"
        if value.startswith(("azure", "entra", "storage")):
            return "azure"
        if value.startswith(("gcp", "gcs", "google")):
            return "gcp"
        if value.startswith(("k8s", "kubernetes")):
            return "kubernetes"
        return "unknown"
