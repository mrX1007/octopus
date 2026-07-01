#!/usr/bin/env python3

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse
from core.ai.asset_graph import AssetGraph
from core.ai.surface_state import SurfaceState
from core.ai.risk_analysis import RiskAnalyzer


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

    def __init__(self, scan_id: str, target: str, facts: List[Dict[str, Any]]):
        self.scan_id = scan_id
        self.target = target
        self.host = self._target_host(target)
        self.facts = facts or []

    @classmethod
    def from_facts(cls, scan_id: str, target: str, facts: List[Dict[str, Any]]) -> "TargetModel":
        return cls(scan_id, target, facts)

    def to_dict(self) -> Dict[str, Any]:
        services = self._services()
        endpoints = self._endpoints()
        model = {
            "target": self.target,
            "host": self.host,
            "assets": self._assets(),
            "services": services,
            "endpoints": endpoints,
            "web_app": self._web_app(),
            "api": self._api(),
            "active_directory": self._active_directory(),
            "credentials": self._credentials(),
            "access": self._access(),
            "internal_graph": self._network_graph(),
            "asset_graph": AssetGraph.from_facts(self.target, self.facts).to_dict(),
            "security_findings": self._security_findings(),
            "negative_facts": self._negative_facts(),
            "surface_states": SurfaceState(self.facts).to_dict(),
            "unknowns": self._unknowns(services, endpoints),
        }
        model["risk_analysis"] = RiskAnalyzer(model).to_dict()
        return model

    def _assets(self) -> Dict[str, List[str]]:
        buckets = {
            "domains": [],
            "ips": [],
            "urls": [],
            "technologies": [],
            "services": [],
            "dns_records": [],
        }
        mapping = {
            "asset_domain": "domains",
            "asset_ip": "ips",
            "asset_url": "urls",
            "technology": "technologies",
            "asset_service": "services",
            "asset_dns_record": "dns_records",
        }
        seen = {key: set() for key in buckets}
        for fact in self.facts:
            bucket = mapping.get(fact.get("type"))
            if not bucket:
                continue
            value = str(fact.get("value", "")).strip()
            if not value or value in seen[bucket]:
                continue
            seen[bucket].add(value)
            buckets[bucket].append(value)
        return buckets

    def _services(self) -> List[Dict[str, Any]]:
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
            services.append(parsed)
        return services

    def _endpoints(self) -> List[Dict[str, Any]]:
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
            endpoints.append(endpoint)
        return endpoints

    def _credentials(self) -> List[Dict[str, Any]]:
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

    def _api(self) -> Dict[str, List[Dict[str, Any]]]:
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

    def _web_app(self) -> Dict[str, List[Dict[str, Any]]]:
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

    def _security_findings(self) -> Dict[str, List[Dict[str, Any]]]:
        buckets = {
            "nuclei": [],
            "secrets": [],
            "code": [],
            "cloud": [],
        }
        mapping = {
            "nuclei_finding": "nuclei",
            "secret_finding": "secrets",
            "code_finding": "code",
            "cloud_finding": "cloud",
        }
        for fact in self.facts:
            bucket = mapping.get(fact.get("type"))
            if not bucket:
                continue
            item = {
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

    def _active_directory(self) -> Dict[str, Any]:
        buckets = {
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
        count_types = {
            "ad_users": "users",
            "ad_groups": "groups",
            "ad_computers": "computers",
            "ad_gpos": "gpos",
        }
        list_mapping = {
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
        seen = {name: set() for name in buckets if isinstance(buckets[name], list)}
        for fact in self.facts:
            ftype = fact.get("type")
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

    def _access(self) -> Dict[str, Any]:
        values = [str(f.get("value", "")).lower() for f in self.facts]
        return {
            "ssh_authenticated": any(v.startswith("ssh_login_success:") or v == "ssh_authenticated" for v in values),
            "root_confirmed": any(v in {"uid=0", "root_access_confirmed"} or "root access" in v for v in values),
            "application_sessions": [
                str(f.get("value", ""))
                for f in self.facts
                if f.get("type") == "application_access" or (
                    f.get("type") == "credential"
                    and str(f.get("value", "")).startswith(("whm_session:", "cpanel_session:"))
                )
            ],
        }

    def _network_graph(self) -> Dict[str, Any]:
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

    def _negative_facts(self) -> List[Dict[str, Any]]:
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

    def _unknowns(self, services: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> Dict[str, str]:
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

    def _parse_port_fact(self, value: str) -> Dict[str, Any]:
        match = re.match(r"(\d+)/(tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value.strip(), re.IGNORECASE)
        if not match:
            return {}
        port, proto, service, banner = match.groups()
        return {
            "host": self.host,
            "port": int(port),
            "proto": proto.lower(),
            "service": (service or "").lower(),
            "banner": banner or "",
            "state": "confirmed_present",
        }

    def _parse_endpoint_fact(self, value: str) -> Dict[str, Any]:
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
        return {
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

    def _parse_secret_finding(self, value: str) -> Dict[str, Any]:
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

    def _parse_cloud_finding(self, value: str) -> Dict[str, Any]:
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

    def _parse_severity_finding(self, value: str, fields: tuple) -> Dict[str, Any]:
        parts = value.split(":", len(fields) - 1)
        parsed = {}
        for idx, field in enumerate(fields):
            parsed[field] = parts[idx] if idx < len(parts) else ""
        return parsed

    def _target_host(self, target: str) -> str:
        return (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
