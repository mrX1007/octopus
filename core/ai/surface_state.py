#!/usr/bin/env python3

from typing import Any, Dict, Iterable


class SurfaceState:
    """Classify major assessment surfaces as unknown/present/absent."""

    SURFACES = {
        "asm": {
            "positive_types": {"asset_domain", "asset_ip", "asset_url", "asset_service"},
            "negative_prefixes": ("asm_skipped:",),
        },
        "web": {
            "positive_types": {"web_endpoint", "web_title", "web_surface", "browser_rendered"},
            "negative_prefixes": ("web_content_discovery_skipped:no_http_response", "web_fetch_failed:"),
        },
        "api": {
            "positive_types": {"api_endpoint"},
            "negative_prefixes": ("api_surface_absent:", "graphql_absent:", "openapi_import_failed:"),
        },
        "ad": {
            "positive_types": {"ad_domain", "ad_users", "ad_groups", "ad_computers", "ad_graph_data"},
            "negative_prefixes": ("ad_not_detected:", "ldap_auth_failed:"),
        },
        "cloud": {
            "positive_types": {"cloud_finding"},
            "negative_prefixes": ("cloud_scan_skipped:", "cloud_auth_failed:"),
        },
        "secrets": {
            "positive_types": {"secret_finding"},
            "negative_prefixes": ("secrets_scan_clean:", "secret_validation_failed:"),
        },
        "code": {
            "positive_types": {"code_finding"},
            "negative_prefixes": ("code_scan_clean:",),
        },
        "ssh_access": {
            "positive_values": ("ssh_authenticated", "ssh_login_success:"),
            "negative_prefixes": ("ssh_auth_failed:",),
        },
    }

    def __init__(self, facts: Iterable[Dict[str, Any]]):
        self.facts = list(facts or [])

    def to_dict(self) -> Dict[str, str]:
        return {surface: self.state(surface) for surface in self.SURFACES}

    def state(self, surface: str) -> str:
        spec = self.SURFACES.get(surface) or {}
        positives = False
        negatives = False
        positive_types = set(spec.get("positive_types") or [])
        positive_values = tuple(spec.get("positive_values") or ())
        negative_prefixes = tuple(spec.get("negative_prefixes") or ())
        for fact in self.facts:
            ftype = str(fact.get("type", ""))
            value = str(fact.get("value", "")).lower()
            if ftype in positive_types:
                positives = True
            if any(value == marker or value.startswith(marker) for marker in positive_values):
                positives = True
            if any(value.startswith(prefix) for prefix in negative_prefixes):
                negatives = True
        if positives:
            return "confirmed_present"
        if negatives:
            return "confirmed_absent"
        return "unknown"
