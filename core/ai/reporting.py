#!/usr/bin/env python3
"""Deterministic evidence/report enrichment for scan results."""

import re
from typing import Any, Dict, List


def build_evidence_index(facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build stable evidence records that link findings back to parsed facts."""
    evidence = []
    for idx, fact in enumerate(facts, 1):
        observations = fact.get("observations") or []
        sources = fact.get("sources") or ([fact.get("source")] if fact.get("source") else [])
        evidence.append({
            "evidence_id": f"E-{idx:03d}",
            "fact_id": fact.get("id"),
            "fact_type": fact.get("type"),
            "fact_value": fact.get("value"),
            "tool": sources[0] if sources else "",
            "command": sources[0] if sources else "",
            "raw_output_ref": f"evidence_hash:{str(fact.get('evidence_hash', ''))[:16]}",
            "parsed_by": _parser_name_for_fact(fact),
            "confidence": fact.get("confidence", 100),
            "observations": len(observations) or 1,
        })
    return evidence


def build_finding_groups(facts: List[Dict[str, Any]], state: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Group repeated facts into finding records with clear proof state."""
    state = state or {}
    evidence_by_fact_id = {
        fact.get("id"): f"E-{idx:03d}" for idx, fact in enumerate(facts, 1)
    }
    groups: Dict[str, Dict[str, Any]] = {}

    for fact in facts:
        ftype = fact.get("type")
        value = str(fact.get("value", ""))
        if ftype == "exploit_candidate":
            parsed = _parse_exploit_candidate(value)
            if not parsed:
                continue
            group = _group_for_module(groups, parsed["module"], parsed["service"], facts)
            group["candidate"] = True
            group["candidate_ports"].add(parsed["port"])
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
        elif ftype == "verification_command":
            module = _module_from_msf_command(value)
            if not module:
                continue
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["verification_commands"].append(value)
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
        elif ftype == "active_command":
            module = _module_from_msf_command(value)
            if not module:
                continue
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["active_commands"].append(value)
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
        elif ftype == "vulnerability" and value.startswith("msf_check_positive:"):
            module = value.split(":", 1)[1]
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["verification"] = "positive"
            group["verified"] = True
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
        elif ftype == "vulnerability_endpoint" and value.startswith("msf_check_positive:"):
            parsed = _parse_msf_endpoint(value)
            if not parsed:
                continue
            group = _group_for_module(groups, parsed["module"], _service_for_port(facts, parsed["port"]), facts)
            group["verified"] = True
            group["verification"] = "positive"
            group["verified_ports"].add(parsed["port"])
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
        elif ftype == "exploit_success":
            module = _module_from_success(value)
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["exploited"] = True
            group["impact_confirmed"] = True
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))

    if state.get("root_access_confirmed"):
        group = groups.setdefault("post_access:root_access", _new_group("root_access", "host"))
        group["verified"] = True
        group["exploited"] = True
        group["impact_confirmed"] = True
        group["severity"] = "CRITICAL"

    return [_finalize_group(group) for group in groups.values()]


def build_coverage_summary(facts: List[Dict[str, Any]]) -> Dict[str, Any]:
    checked = []
    degraded = []
    for fact in facts:
        if fact.get("type") != "service_status":
            continue
        value = str(fact.get("value", ""))
        if value.startswith("tool_timeout:"):
            tool = value.split(":", 1)[1]
            degraded.append({
                "tool": tool,
                "status": "timeout",
                "impact": f"{tool} coverage incomplete",
                "recommended_rerun": "increase timeout or narrow templates/scope",
            })
        elif any(marker in value for marker in (
            "_failed", "_skipped", "_not_vulnerable", "invalid_options",
            "no_injection_found", "unreliable_or_patched",
            "no_host_information", "no_get_parameters_found", "not_confirmed",
        )):
            checked.append({"status": value, "evidence": fact.get("id")})
    return {
        "confidence": "partial" if degraded else "normal",
        "checked_but_not_confirmed": checked,
        "degraded": degraded,
    }


def build_attack_path(facts: List[Dict[str, Any]], state: Dict[str, Any]) -> List[Dict[str, str]]:
    steps = []
    if any(f.get("type") == "credential" for f in facts):
        steps.append({"stage": "Initial access", "status": "observed", "detail": "Credential or session material present"})
    if any(f.get("type") == "post_exploit_stage" for f in facts):
        steps.append({"stage": "Host inventory", "status": "completed", "detail": "Post-access inventory collected"})
    if any(f.get("type") in {"privesc_vector", "exploit_attempted"} for f in facts):
        status = "confirmed" if state.get("root_access_confirmed") else "tested"
        steps.append({"stage": "Privilege escalation", "status": status, "detail": "Privilege escalation evidence present"})
    if state.get("root_access_confirmed"):
        steps.append({"stage": "Root access", "status": "confirmed", "detail": "uid=0/root access confirmed"})
    if state.get("persistence_established"):
        steps.append({"stage": "Persistence", "status": "completed", "detail": "Persistence mechanism recorded"})
    elif any("persistence" in str(f.get("value", "")).lower() for f in facts):
        steps.append({"stage": "Persistence", "status": "not_confirmed", "detail": "Persistence mentioned but not confirmed"})
    if state.get("internal_recon_completed") or any(f.get("type") in {"internal_host", "internal_subnet"} for f in facts):
        steps.append({"stage": "Internal recon", "status": "observed", "detail": "Internal hosts/subnets observed"})
    steps.append({"stage": "Cleanup", "status": "completed" if state.get("cleanup_completed") else "not_performed", "detail": "Cleanup stage gate"})
    return steps


def build_remediations(finding_groups: List[Dict[str, Any]], facts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    remediations = []
    for group in finding_groups:
        service = (group.get("service") or "").lower()
        module = group.get("module") or group.get("class") or "finding"
        if service == "redis" or "redis" in module.lower():
            fix = "Restrict Redis to trusted networks, require authentication, and disable dangerous unauthenticated replication paths."
        elif service in {"ssh", "openssh"}:
            fix = "Restrict SSH exposure, rotate credentials, disable password login where possible, and enforce MFA/key hygiene."
        elif "cpanel" in service or "cpanel" in module.lower():
            fix = "Patch cPanel/WHM, rotate sessions, restrict management ports, and review account activity."
        elif group.get("impact_confirmed"):
            fix = "Treat host as compromised: rotate credentials, patch the exploited component, and perform forensic review."
        else:
            fix = "Validate exposure, patch or disable the affected service, and restrict network access to trusted sources."
        remediations.append({"finding": module, "service": service or "unknown", "recommendation": fix})
    if any(f.get("type") == "service_status" and str(f.get("value", "")).startswith("tool_timeout:") for f in facts):
        remediations.append({
            "finding": "coverage_degraded",
            "service": "scan_coverage",
            "recommendation": "Rerun timed-out tools with a longer timeout or a narrower target/template scope.",
        })
    return remediations


def enrich_result_with_reporting(result: Dict[str, Any], facts: List[Dict[str, Any]], state: Dict[str, Any]) -> Dict[str, Any]:
    evidence_index = build_evidence_index(facts)
    finding_groups = build_finding_groups(facts, state)
    result["evidence_index"] = evidence_index
    result["finding_groups"] = finding_groups
    result["coverage"] = build_coverage_summary(facts)
    result["attack_path"] = build_attack_path(facts, state)
    result["remediations"] = build_remediations(finding_groups, facts)
    return result


def _parser_name_for_fact(fact: Dict[str, Any]) -> str:
    source = str(fact.get("source", ""))
    if source.startswith("derived:"):
        return "derived_fact_builder"
    if source.startswith("replay:"):
        return "replay_output_parser"
    return "output_parser"


def _new_group(module: str, service: str) -> Dict[str, Any]:
    return {
        "class": module,
        "module": module,
        "service": service or "unknown",
        "candidate": False,
        "verified": False,
        "verification": "not_run",
        "exploited": False,
        "impact_confirmed": False,
        "candidate_ports": set(),
        "verified_ports": set(),
        "verification_commands": [],
        "active_commands": [],
        "evidence_ids": set(),
        "severity": "INFO",
    }


def _group_for_module(groups: Dict[str, Dict[str, Any]], module: str, service: str, facts: List[Dict[str, Any]]) -> Dict[str, Any]:
    module = module or "unknown"
    service = service or _service_for_module(module, facts)
    key = f"{module}:{service}"
    if key not in groups:
        groups[key] = _new_group(module, service)
    elif groups[key].get("service") == "unknown" and service:
        groups[key]["service"] = service
    return groups[key]


def _finalize_group(group: Dict[str, Any]) -> Dict[str, Any]:
    verified_ports = sorted(p for p in group["verified_ports"] if p)
    candidate_ports = sorted(p for p in group["candidate_ports"] if p)
    group["ports"] = verified_ports or candidate_ports
    group["ports_count"] = len(group["ports"])
    group["evidence_ids"] = sorted(eid for eid in group["evidence_ids"] if eid)
    group["verification_commands"] = list(dict.fromkeys(group["verification_commands"]))
    group["active_commands"] = list(dict.fromkeys(group["active_commands"]))
    if group["impact_confirmed"]:
        group["severity"] = "CRITICAL"
    elif group["verified"]:
        group["severity"] = "HIGH"
    elif group["candidate"]:
        group["severity"] = "MEDIUM"
    for key in ("candidate_ports", "verified_ports"):
        group.pop(key, None)
    return group


def _parse_exploit_candidate(value: str) -> Dict[str, str]:
    if value.lstrip().startswith("{"):
        return {}
    match = re.match(r"(?P<module>\S+)\s+on\s+(?P<service>[^:\s]+):(?P<port>[^\s]+)\s+\[(?P<version>.*)\]$", value)
    return match.groupdict() if match else {}


def _parse_msf_endpoint(value: str) -> Dict[str, str]:
    match = re.match(r"msf_check_positive:(?P<module>.+):(?P<port>\d{1,5})$", value)
    return match.groupdict() if match else {}


def _module_from_msf_command(value: str) -> str:
    match = re.search(r"\bmsf_(?:check|run)\s+\S+\s+(\S+)", value or "")
    return match.group(1) if match else ""


def _module_from_success(value: str) -> str:
    if value.startswith("msf_session_opened:"):
        return value.split(":", 1)[1]
    cve = re.search(r"(CVE-\d{4}-\d{4,7})", value or "", re.IGNORECASE)
    return cve.group(1).upper() if cve else (value or "exploit_success")


def _service_for_module(module: str, facts: List[Dict[str, Any]]) -> str:
    text = (module or "").lower()
    for service in ("redis", "ssh", "apache", "nginx", "tomcat", "cpanel", "mysql", "postgresql", "mongodb"):
        if service in text:
            return service
    for fact in facts:
        if fact.get("type") == "port_open":
            value = str(fact.get("value", ""))
            match = re.match(r"\d+/(?:tcp|udp)\s+\(([^)]+)\)", value)
            if match:
                return match.group(1)
    return "unknown"


def _service_for_port(facts: List[Dict[str, Any]], port: str) -> str:
    for fact in facts:
        if fact.get("type") != "port_open":
            continue
        value = str(fact.get("value", ""))
        match = re.match(rf"{re.escape(str(port))}/(?:tcp|udp)\s+\(([^)]+)\)", value, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""
