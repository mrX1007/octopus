#!/usr/bin/env python3

import json
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from core.ai.asset_graph import AssetGraph
from core.ai.risk_analysis import RiskAnalyzer
from core.ai.surface_state import SurfaceState
from core.knowledge.identity import (
    ENTITY_NORMALIZATION_VERSION,
    canonical_asset,
    canonical_endpoint,
    canonical_service,
)


class TargetModel:
    """Build a normalized target object from stored facts.

    The pipeline still stores simple facts for compatibility, but planning code
    should reason over this object: host -> services -> endpoints -> credentials
    -> access -> internal graph -> negative observations.
    """

    NEGATIVE_PREFIXES = (
        "web_content_discovery_skipped:",
        "web_fetch_failed:",
        "ssh_auth_failed:",
        "ftp_anonymous_denied:",
        "ftp_probe_failed:",
        "smtp_probe_failed:",
        "db_inventory_failed:",
        "msf_check_not_vulnerable:",
        "msf_module_invalid:",
        "sqlmap_no_injection_found",
        "jmx2rce_not_vulnerable",
        "tool_unavailable:",
    )

    def __init__(self, scan_id: str, target: str, facts: list[dict[str, Any]]):
        self.scan_id = scan_id
        self.target = target
        self.host = self._target_host(target)
        self.facts = [
            fact
            for fact in (facts or [])
            if str(fact.get("assessment_status") or "observed") != "contradicted"
        ]

    @classmethod
    def from_facts(cls, scan_id: str, target: str, facts: list[dict[str, Any]]) -> "TargetModel":
        return cls(scan_id, target, facts)

    def to_dict(self) -> dict[str, Any]:
        services = self._services()
        endpoints = self._endpoints()
        internal_services = self._internal_services()
        check_results = self._check_results()
        model: dict[str, Any] = {
            "target": self.target,
            "host": self.host,
            "asset_id": canonical_asset(self.host).entity_id if self.host else "",
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "assets": self._assets(),
            "services": services,
            "endpoints": endpoints,
            "web_app": self._web_app(),
            "api": self._api(),
            "active_directory": self._active_directory(),
            "credentials": self._credentials(),
            "access": self._access(),
            "internal_graph": self._network_graph(),
            "internal_services": internal_services,
            "asset_graph": AssetGraph.from_facts(self.target, self.facts).to_dict(),
            "security_findings": self._security_findings(),
            "check_results": check_results,
            "negative_facts": self._negative_facts(),
            "surface_states": SurfaceState(self.facts).to_dict(),
            "unknowns": self._unknowns(services, endpoints),
        }
        model["typed_facts"] = self._typed_facts(
            services, endpoints, internal_services, check_results, model["security_findings"]
        )
        model["coverage"] = self._coverage(services, endpoints, internal_services, check_results)
        model["risk_analysis"] = RiskAnalyzer(model).to_dict()
        return model

    def _assets(self) -> dict[str, list[str]]:
        buckets: dict[str, list[str]] = {
            "domains": [],
            "ips": [],
            "urls": [],
            "technologies": [],
            "services": [],
            "dns_records": [],
        }
        mapping: dict[str, str] = {
            "asset_domain": "domains",
            "asset_ip": "ips",
            "asset_url": "urls",
            "technology": "technologies",
            "asset_service": "services",
            "asset_dns_record": "dns_records",
        }
        seen: dict[str, set[str]] = {key: set() for key in buckets}
        for fact in self.facts:
            bucket = mapping.get(str(fact.get("type") or ""))
            if not bucket:
                continue
            value = str(fact.get("value", "")).strip()
            if not value or value in seen[bucket]:
                continue
            seen[bucket].add(value)
            buckets[bucket].append(value)
        return buckets

    def _services(self) -> list[dict[str, Any]]:
        services = []
        seen = set()
        for fact in self.facts:
            if fact.get("type") != "port_open":
                continue
            parsed = self._parse_port_fact(str(fact.get("value", "")))
            if not parsed:
                continue
            key = (parsed["host"], parsed["port"], parsed["proto"])
            if key in seen:
                continue
            seen.add(key)
            parsed.update(self._fact_identity_metadata(fact))
            services.append(parsed)
        return services

    def _endpoints(self) -> list[dict[str, Any]]:
        endpoints = []
        seen = set()
        for fact in self.facts:
            if fact.get("type") != "web_endpoint":
                continue
            endpoint = self._parse_endpoint_fact(str(fact.get("value", "")))
            if not endpoint:
                continue
            key = endpoint["url"].rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            endpoint.update(self._fact_identity_metadata(fact))
            endpoints.append(endpoint)
        return endpoints

    def _credentials(self) -> list[dict[str, Any]]:
        credentials = []
        for fact in self.facts:
            if fact.get("type") not in {"credential", "credential_material", "hash_material"}:
                continue
            value = str(fact.get("value", ""))
            kind = "credential"
            if fact.get("type") == "credential_material":
                kind = "material"
            elif fact.get("type") == "hash_material":
                kind = "hash"
            credentials.append({
                "kind": kind,
                "value": value,
                "confidence": fact.get("confidence", 100),
                "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
            })
        return credentials

    def _api(self) -> dict[str, list[dict[str, Any]]]:
        endpoints = []
        notes = []
        for fact in self.facts:
            ftype = fact.get("type")
            value = str(fact.get("value", "")).strip()
            if not value:
                continue
            if ftype == "api_endpoint":
                parts = value.split(":", 2)
                if len(parts) == 3:
                    method, path, rest = parts
                    endpoints.append({"method": method, "path": path, "metadata": rest})
                else:
                    endpoints.append({"method": "", "path": value, "metadata": ""})
            elif ftype == "api_security_note":
                notes.append({"value": value, "confidence": fact.get("confidence", 100)})
        return {"endpoints": endpoints, "security_notes": notes}

    def _web_app(self) -> dict[str, list[dict[str, Any]]]:
        notes = []
        js_routes = []
        proxy_findings = []
        jwt = []
        for fact in self.facts:
            ftype = fact.get("type")
            value = str(fact.get("value", "")).strip()
            if not value:
                continue
            item = {"value": value, "confidence": fact.get("confidence", 100)}
            if ftype == "web_security_note":
                notes.append(item)
            elif ftype == "js_route":
                js_routes.append(item)
            elif ftype == "proxy_finding":
                proxy_findings.append(item)
            elif ftype == "jwt_metadata":
                jwt.append(item)
        return {
            "security_notes": notes,
            "js_routes": js_routes,
            "proxy_findings": proxy_findings,
            "jwt": jwt,
        }

    def _security_findings(self) -> dict[str, list[dict[str, Any]]]:
        buckets: dict[str, list[dict[str, Any]]] = {
            "nuclei": [],
            "secrets": [],
            "code": [],
            "cloud": [],
        }
        mapping: dict[str, str] = {
            "nuclei_finding": "nuclei",
            "secret_finding": "secrets",
            "code_finding": "code",
            "cloud_finding": "cloud",
        }
        for fact in self.facts:
            bucket = mapping.get(str(fact.get("type") or ""))
            if not bucket:
                continue
            item: dict[str, Any] = {
                "value": str(fact.get("value", "")),
                "confidence": fact.get("confidence", 100),
                "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
            }
            if bucket == "secrets":
                item.update(self._parse_secret_finding(item["value"]))
            elif bucket == "cloud":
                item.update(self._parse_cloud_finding(item["value"]))
            elif bucket == "code":
                item.update(self._parse_severity_finding(item["value"], ("severity", "check_id", "location")))
            elif bucket == "nuclei":
                item.update(self._parse_severity_finding(item["value"], ("severity", "template", "matched_at", "name")))
            buckets[bucket].append(item)
        return buckets

    def _active_directory(self) -> dict[str, Any]:
        buckets: dict[str, Any] = {
            "domains": [],
            "objects": [],
            "counts": {},
            "high_value_objects": [],
            "graph_data": [],
            "attack_paths": [],
            "local_admin_paths": [],
            "delegation": [],
            "gpo_issues": [],
            "adcs_issues": [],
            "acl_issues": [],
            "password_policy": [],
            "kerberos": [],
            "credential_material": [],
            "domain_hash_dumps": [],
        }
        count_types: dict[str, str] = {
            "ad_users": "users",
            "ad_groups": "groups",
            "ad_computers": "computers",
            "ad_gpos": "gpos",
        }
        list_mapping: dict[str, str] = {
            "ad_domain": "domains",
            "ad_object": "objects",
            "ad_high_value_object": "high_value_objects",
            "ad_graph_data": "graph_data",
            "ad_attack_path": "attack_paths",
            "ad_local_admin_path": "local_admin_paths",
            "ad_delegation": "delegation",
            "ad_gpo_issue": "gpo_issues",
            "ad_adcs_issue": "adcs_issues",
            "ad_acl_issue": "acl_issues",
            "ad_password_policy": "password_policy",
            "kerberos_hashes": "kerberos",
            "credential_material": "credential_material",
            "domain_hash_dump": "domain_hash_dumps",
        }
        seen: dict[str, set[str]] = {
            name: set() for name in buckets if isinstance(buckets[name], list)
        }
        for fact in self.facts:
            ftype = str(fact.get("type") or "")
            value = str(fact.get("value", "")).strip()
            if not value:
                continue
            if ftype in count_types:
                match = re.match(r"count:(\d+)", value)
                buckets["counts"][count_types[ftype]] = int(match.group(1)) if match else value
                continue
            bucket = list_mapping.get(ftype)
            if not bucket:
                continue
            item = {
                "value": value,
                "confidence": fact.get("confidence", 100),
                "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
            }
            key = json.dumps(item, sort_keys=True)
            if key in seen[bucket]:
                continue
            seen[bucket].add(key)
            buckets[bucket].append(item)
        return buckets

    def _access(self) -> dict[str, Any]:
        values = [str(f.get("value", "")).lower() for f in self.facts]
        return {
            "ssh_authenticated": any(v.startswith("ssh_login_success:") or v == "ssh_authenticated" for v in values),
            "root_confirmed": any(
                v in {"uid=0", "root_access_confirmed"}
                or v.startswith("ssh_login_success:root@")
                or "root access" in v
                for v in values
            ),
            "application_sessions": [
                str(f.get("value", ""))
                for f in self.facts
                if f.get("type") == "application_access" or (
                    f.get("type") == "credential"
                    and str(f.get("value", "")).startswith(("whm_session:", "cpanel_session:"))
                )
            ],
        }

    def _network_graph(self) -> dict[str, Any]:
        nodes = []
        edges = []
        seen_nodes = set()
        seen_edges = set()
        for fact in self.facts:
            ftype = fact.get("type")
            if ftype not in {"network_node", "network_edge"}:
                continue
            try:
                parsed = json.loads(str(fact.get("value", "")))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            key = json.dumps(parsed, sort_keys=True)
            if ftype == "network_node" and key not in seen_nodes:
                seen_nodes.add(key)
                nodes.append(parsed)
            elif ftype == "network_edge" and key not in seen_edges:
                seen_edges.add(key)
                edges.append(parsed)
        return {"nodes": nodes, "edges": edges}

    def _internal_services(self) -> list[dict[str, Any]]:
        services = []
        seen = set()
        for fact in self.facts:
            if fact.get("type") != "internal_service":
                continue
            value = str(fact.get("value", "")).strip()
            match = re.match(r"((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})/(tcp|udp)\s+\(([^)]*)\)", value, re.IGNORECASE)
            if not match:
                continue
            host, port, proto, service = match.groups()
            key = (host, port, proto.lower())
            if key in seen:
                continue
            seen.add(key)
            try:
                canonical_id = canonical_service(host, port, proto).entity_id
            except ValueError:
                continue
            services.append({
                "canonical_id": canonical_id,
                "normalization_version": ENTITY_NORMALIZATION_VERSION,
                "host": host,
                "port": int(port),
                "proto": proto.lower(),
                "service": (service or "unknown").lower(),
                "state": "confirmed_present",
                "reachable_via": self._internal_service_reachability(fact),
                "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
                **self._fact_identity_metadata(fact),
            })
        return services

    def _internal_service_reachability(self, fact: dict[str, Any]) -> str:
        sources = [str(fact.get("source", ""))]
        sources.extend(str(source) for source in fact.get("sources", []) or [])
        source_text = " ".join(sources).lower()
        if "ssh" in source_text or "network_recon" in source_text or "internal_service_probe" in source_text:
            return "ssh"
        if "socks" in source_text or "pivot" in source_text or "port_forward" in source_text:
            return "pivot"
        return "unknown"

    def _check_results(self) -> list[dict[str, Any]]:
        results = []
        seen = set()
        for fact in self.facts:
            if fact.get("type") != "check_result":
                continue
            value = str(fact.get("value", "")).strip()
            if not value:
                continue
            try:
                parsed = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                parsed = {"raw": value}
            if not isinstance(parsed, dict):
                parsed = {"raw": value}
            parsed = dict(parsed)
            parsed.setdefault("confidence", fact.get("confidence", 100))
            parsed.setdefault("sources", fact.get("sources") or ([fact.get("source")] if fact.get("source") else []))
            parsed.setdefault("timestamp", fact.get("timestamp"))
            if fact.get("id") is not None:
                parsed.setdefault("fact_id", fact.get("id"))
            key = json.dumps(parsed, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            results.append(parsed)
        return results

    def _typed_facts(
        self,
        services: list[dict[str, Any]],
        endpoints: list[dict[str, Any]],
        internal_services: list[dict[str, Any]],
        check_results: list[dict[str, Any]],
        security_findings: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        findings = []
        for bucket, items in (security_findings or {}).items():
            for item in items or []:
                typed = dict(item)
                typed.setdefault("kind", bucket)
                findings.append(typed)
        return {
            "Service": services,
            "Endpoint": endpoints,
            "InternalService": internal_services,
            "Finding": findings,
            "Credential": self._credentials(),
            "Access": self._access(),
            "CheckResult": check_results,
        }

    def _coverage(
        self,
        services: list[dict[str, Any]],
        endpoints: list[dict[str, Any]],
        internal_services: list[dict[str, Any]],
        check_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        checks_by_scope: dict[tuple, dict[str, dict[str, Any]]] = {}
        for result in check_results:
            scope: dict[str, Any] = (
                result["scope"] if isinstance(result.get("scope"), dict) else {}
            )
            scope_type = str(scope.get("type") or result.get("scope_type") or "").strip().lower()
            scope_value = str(scope.get("value") or result.get("scope_value") or "").strip()
            if not scope_type or not scope_value:
                continue
            scope_key = (scope_type, self._normalize_scope_value(scope_type, scope_value))
            kind = str(result.get("kind") or result.get("check") or result.get("tool") or "unknown").strip().lower()
            current = checks_by_scope.setdefault(scope_key, {}).get(kind)
            if not current or float(result.get("timestamp") or 0) >= float(current.get("timestamp") or 0):
                checks_by_scope.setdefault(scope_key, {})[kind] = result

        endpoint_items = []
        service_items = []
        internal_items = []
        gaps = []

        endpoint_expected = ("web_mapping", "web_headers", "template_verification")
        for endpoint in endpoints:
            url = self._canonical_url(str(endpoint.get("url", "")))
            checks = checks_by_scope.get(("endpoint", url), {})
            item = dict(endpoint)
            item["checks"] = self._coverage_checks(checks)
            endpoint_items.append(item)
            gaps.extend(self._coverage_gaps_for("endpoint", url, endpoint_expected, checks))

        for service in services:
            service_id = self._service_scope_value(service)
            checks = checks_by_scope.get(("service", service_id), {})
            item = dict(service)
            item["checks"] = self._coverage_checks(checks)
            service_items.append(item)
            service_text = f"{service.get('service', '')} {service.get('banner', '')}".lower()
            if not any(marker in service_text for marker in ("http", "web", "nginx", "apache", "tomcat")):
                gaps.extend(self._coverage_gaps_for("service", service_id, ("exploit_selection",), checks))

        for service in internal_services:
            service_id = self._service_scope_value(service)
            checks = checks_by_scope.get(("internal_service", service_id), {})
            item = dict(service)
            item["checks"] = self._coverage_checks(checks)
            internal_items.append(item)
            gaps.extend(self._coverage_gaps_for("internal_service", service_id, ("internal_vulnerability_assessment",), checks))

        return {
            "external_services": service_items,
            "web_endpoints": endpoint_items,
            "internal_services": internal_items,
            "gaps": gaps,
        }

    def _coverage_checks(self, checks: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        covered = {}
        for kind, result in sorted((checks or {}).items()):
            covered[kind] = {
                "status": result.get("status", "unknown"),
                "tool": result.get("tool", ""),
                "duration_seconds": result.get("duration_seconds"),
                "timestamp": result.get("timestamp"),
            }
        return covered

    def _coverage_gaps_for(
        self,
        surface_type: str,
        surface_id: str,
        expected: tuple,
        checks: dict[str, dict[str, Any]],
    ) -> list[dict[str, str]]:
        gaps = []
        degraded = {"timeout", "partial", "failed", "completed_empty", "skipped"}
        for check in expected:
            result = checks.get(check)
            if not result:
                gaps.append({
                    "surface": surface_type,
                    "id": surface_id,
                    "check": check,
                    "status": "pending",
                })
                continue
            status = str(result.get("status", "unknown")).lower()
            if status in degraded:
                gaps.append({
                    "surface": surface_type,
                    "id": surface_id,
                    "check": check,
                    "status": status,
                })
        return gaps

    def _normalize_scope_value(self, scope_type: str, value: str) -> str:
        if scope_type == "endpoint":
            return self._canonical_url(value)
        return value.strip().lower()

    def _service_scope_value(self, service: dict[str, Any]) -> str:
        host = str(service.get("host") or self.host).lower()
        proto = str(service.get("proto") or "tcp").lower()
        return f"{host}:{int(service.get('port') or 0)}/{proto}"

    def _canonical_url(self, value: str) -> str:
        if not value:
            return ""
        url = value.strip()
        try:
            parsed_json = json.loads(url)
            if isinstance(parsed_json, dict) and parsed_json.get("url"):
                url = str(parsed_json.get("url"))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        if not re.match(r"^https?://", url, re.IGNORECASE):
            return url.lower().rstrip("/")
        parsed = urlparse(url)
        if not parsed.hostname:
            return url.lower().rstrip("/")
        port = parsed.port
        netloc = parsed.hostname.lower()
        if port and not ((parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)):
            netloc = f"{netloc}:{port}"
        return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, "")).rstrip("/")

    def _negative_facts(self) -> list[dict[str, Any]]:
        negatives = []
        for fact in self.facts:
            ftype = str(fact.get("type", ""))
            value = str(fact.get("value", ""))
            if ftype in {"negative_fact", "tool_unavailable"} or any(value.startswith(p) for p in self.NEGATIVE_PREFIXES):
                negatives.append({
                    "type": ftype,
                    "value": value,
                    "confidence": fact.get("confidence", 100),
                    "sources": fact.get("sources") or ([fact.get("source")] if fact.get("source") else []),
                })
        return negatives

    def _unknowns(self, services: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> dict[str, str]:
        service_names = " ".join(s.get("service", "") for s in services).lower()
        web_known = bool(endpoints) or any(marker in service_names for marker in ("http", "nginx", "apache", "tomcat"))
        return {
            "web_surface": "confirmed_present" if web_known else "unknown",
            "ssh_access": self._presence_state("ssh_authenticated", "ssh_auth_failed:"),
            "internal_graph": "confirmed_present" if self._network_graph().get("nodes") else "unknown",
            "api_surface": "confirmed_present" if self._api().get("endpoints") else "unknown",
            "secrets": "confirmed_present" if self._security_findings().get("secrets") else "unknown",
            "cloud": "confirmed_present" if self._security_findings().get("cloud") else "unknown",
            "code_security": "confirmed_present" if self._security_findings().get("code") else "unknown",
            "web_security_notes": "confirmed_present" if self._web_app().get("security_notes") else "unknown",
            "active_directory": "confirmed_present" if self._active_directory().get("domains") or self._active_directory().get("counts") else (
                "confirmed_absent" if not any(marker in service_names for marker in ("ldap", "kerberos", "microsoft-ds", "smb")) else "unknown"
            ),
        }

    def _presence_state(self, positive_marker: str, negative_prefix: str) -> str:
        positives = []
        negatives = []
        for fact in self.facts:
            value = str(fact.get("value", "")).lower()
            positives.append(value == positive_marker or value.startswith(f"{positive_marker}:"))
            negatives.append(value.startswith(negative_prefix))
        if any(positives):
            return "confirmed_present"
        if any(negatives):
            return "confirmed_absent"
        return "unknown"

    def _parse_port_fact(self, value: str) -> dict[str, Any]:
        match = re.match(r"(\d+)/(tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value.strip(), re.IGNORECASE)
        if not match:
            return {}
        port, proto, service, banner = match.groups()
        try:
            identity = canonical_service(self.host, port, proto)
        except ValueError:
            return {}
        return {
            "canonical_id": identity.entity_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "host": self.host,
            "port": int(port),
            "proto": proto.lower(),
            "service": (service or "").lower(),
            "banner": banner or "",
            "state": "confirmed_present",
        }

    def _parse_endpoint_fact(self, value: str) -> dict[str, Any]:
        try:
            parsed = json.loads(value)
            url = str(parsed.get("url", "")).strip()
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed = {}
            url = value.strip()
        if not re.match(r"^https?://", url, re.IGNORECASE):
            return {}
        url_parts = urlparse(url)
        if not url_parts.hostname:
            return {}
        port = parsed.get("port") or url_parts.port or (443 if url_parts.scheme == "https" else 80)
        canonical_url = urlunparse((
            url_parts.scheme.lower(),
            url_parts.netloc.lower(),
            url_parts.path or "/",
            "",
            url_parts.query,
            "",
        ))
        try:
            identity = canonical_endpoint(canonical_url)
        except ValueError:
            return {}
        return {
            "canonical_id": identity.entity_id,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "url": canonical_url,
            "scheme": url_parts.scheme.lower(),
            "host": url_parts.hostname.lower(),
            "port": int(port),
            "path": url_parts.path or "/",
            "service": parsed.get("service", ""),
            "status": parsed.get("status", ""),
            "title": parsed.get("title", ""),
            "state": "confirmed_present",
        }

    def _fact_identity_metadata(self, fact: dict[str, Any]) -> dict[str, Any]:
        assessment = fact.get("assessment")
        assessment = assessment if isinstance(assessment, dict) else {}
        return {
            "fact_ids": [int(fact["id"])] if fact.get("id") is not None else [],
            "assessment_refs": (
                [str(assessment.get("assessment_id"))]
                if assessment.get("assessment_id")
                else []
            ),
            "assessment_status": str(
                assessment.get("status") or fact.get("assessment_status") or "observed"
            ),
            "evidence_fact_ids": list(assessment.get("evidence_fact_ids") or []),
            "source_execution_ids": list(assessment.get("source_execution_ids") or []),
        }

    def _parse_secret_finding(self, value: str) -> dict[str, Any]:
        parts = value.split(":", 3)
        if len(parts) < 4:
            return {
                "secret_type": parts[0] if parts else "unknown",
                "location": parts[1] if len(parts) > 1 else "",
                "validated_or_not": "unknown",
                "rotation_required": "unknown",
                "exposure_scope": "unknown",
            }
        secret_type, location, validated, rotation = parts
        scope = "source_code"
        if location.startswith(("http://", "https://")):
            scope = "public_url"
        elif any(marker in location.lower() for marker in (".env", "config", "settings", "secret")):
            scope = "configuration"
        return {
            "secret_type": secret_type or "unknown",
            "location": location,
            "validated_or_not": validated or "unknown",
            "rotation_required": "yes" if "rotation_required" in rotation else "unknown",
            "exposure_scope": scope,
        }

    def _parse_cloud_finding(self, value: str) -> dict[str, Any]:
        item = self._parse_severity_finding(value, ("severity", "check_id", "resource"))
        check_id = item.get("check_id", "").lower()
        provider = "unknown"
        if check_id.startswith(("aws", "s3", "iam", "ec2", "lambda", "ecr")):
            provider = "aws"
        elif check_id.startswith(("azure", "entra", "storage_account")):
            provider = "azure"
        elif check_id.startswith(("gcp", "google", "gcs")):
            provider = "gcp"
        elif check_id.startswith(("k8s", "kubernetes")):
            provider = "kubernetes"
        item["provider"] = provider
        return item

    def _parse_severity_finding(self, value: str, fields: tuple) -> dict[str, Any]:
        parts = value.split(":", len(fields) - 1)
        parsed = {}
        for idx, field in enumerate(fields):
            parsed[field] = parts[idx] if idx < len(parts) else ""
        return parsed

    def _target_host(self, target: str) -> str:
        return (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
