#!/usr/bin/env python3

from typing import Any, Dict, List


class RiskAnalyzer:
    """Derive prioritized security analysis from normalized target model."""

    def __init__(self, model: Dict[str, Any]):
        self.model = model or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ad_attack_paths": self.ad_attack_paths(),
            "cloud_posture": self.cloud_posture(),
            "secret_rotation": self.secret_rotation(),
            "code_reachability": self.code_reachability(),
        }

    def ad_attack_paths(self) -> List[Dict[str, Any]]:
        ad = self.model.get("active_directory") or {}
        paths = []
        for item in ad.get("attack_paths", []):
            paths.append({"severity": "high", "kind": "attack_path", "value": item.get("value", ""), "reason": "BloodHound/domain-admin path observed"})
        for item in ad.get("adcs_issues", []):
            sev = "critical" if str(item.get("value", "")).startswith(("ESC1", "ESC2", "ESC8")) else "high"
            paths.append({"severity": sev, "kind": "adcs", "value": item.get("value", ""), "reason": "ADCS issue can enable privilege escalation"})
        for item in ad.get("delegation", []):
            paths.append({"severity": "high", "kind": "delegation", "value": item.get("value", ""), "reason": "delegation requires path review"})
        for item in ad.get("acl_issues", []):
            paths.append({"severity": "high", "kind": "acl", "value": item.get("value", ""), "reason": "dangerous ACL observed"})
        return paths

    def cloud_posture(self) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for finding in (self.model.get("security_findings") or {}).get("cloud", []):
            provider = finding.get("provider") or "unknown"
            grouped.setdefault(provider, []).append(finding)
        return grouped

    def secret_rotation(self) -> List[Dict[str, Any]]:
        actions = []
        for secret in (self.model.get("security_findings") or {}).get("secrets", []):
            actions.append({
                "secret_type": secret.get("secret_type", "unknown"),
                "location": secret.get("location", ""),
                "validated_or_not": secret.get("validated_or_not", "unknown"),
                "rotation_required": secret.get("rotation_required", "unknown"),
                "exposure_scope": secret.get("exposure_scope", "unknown"),
                "priority": "urgent" if secret.get("validated_or_not") == "validated" else "review",
            })
        return actions

    def code_reachability(self) -> List[Dict[str, Any]]:
        endpoints = self.model.get("endpoints") or []
        services = self.model.get("services") or []
        exposed = bool(endpoints or services)
        correlated = []
        for finding in (self.model.get("security_findings") or {}).get("code", []):
            correlated.append({
                "finding": finding.get("value", ""),
                "location": finding.get("location", ""),
                "exposed_surface_present": exposed,
                "priority": "higher" if exposed and finding.get("severity", "").lower() in {"high", "critical"} else "normal",
            })
        return correlated
