#!/usr/bin/env python3
"""Deterministic evidence/report enrichment for scan results."""

import json
import re
from typing import Any, Optional

from core.ai.evaluated_facts import fact_is_decision_usable
from core.ai.report_schema import (
    EVIDENCE_REPORT_SCHEMA_VERSION,
    build_evidence_report,
)
from core.secrets import redact_data


def build_evidence_index(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build stable evidence records that link findings back to parsed facts."""
    evidence = []
    for idx, fact in enumerate(facts, 1):
        observations = fact.get("observations") or []
        sources = fact.get("sources") or ([fact.get("source")] if fact.get("source") else [])
        assessment = fact.get("assessment") or {}
        evidence.append({
            "evidence_id": f"E-{idx:03d}",
            "evidence_ref": (
                f"evidence://fact/{fact.get('id')}"
                if fact.get("id") is not None
                else f"evidence://index/{idx}"
            ),
            "fact_id": fact.get("id"),
            "fact_type": fact.get("type"),
            "fact_value": fact.get("value"),
            "tool": sources[0] if sources else "",
            "command": sources[0] if sources else "",
            "raw_output_ref": f"evidence_hash:{str(fact.get('evidence_hash', ''))[:16]}",
            "parsed_by": _parser_name_for_fact(fact),
            "confidence": fact.get("confidence", 100),
            "observations": len(observations) or 1,
            "assessment_ref": assessment.get("assessment_id") or fact.get("assessment_id"),
            "assessment_status": assessment.get("status") or fact.get("assessment_status", "observed"),
            "assessment_reason": assessment.get("reason", ""),
            "assessment_confidence": assessment.get("confidence", fact.get("confidence", 100)),
            "evidence_fact_ids": list(assessment.get("evidence_fact_ids") or []),
            "source_execution_ids": list(assessment.get("source_execution_ids") or []),
        })
    return evidence


def build_finding_groups(facts: list[dict[str, Any]], state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Group repeated facts into finding records with clear proof state."""
    state = state or {}
    evidence_by_fact_id = {
        fact.get("id"): f"E-{idx:03d}" for idx, fact in enumerate(facts, 1)
    }
    groups: dict[str, dict[str, Any]] = {}

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
            _attach_assessment(group, fact)
        elif ftype == "verification_command":
            module = _module_from_msf_command(value)
            if not module:
                continue
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["verification_commands"].append(value)
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
            _attach_assessment(group, fact)
        elif ftype == "active_command":
            module = _module_from_msf_command(value)
            if not module:
                continue
            if not _active_module_allows_run(module):
                continue
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["active_commands"].append(value)
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
            _attach_assessment(group, fact)
        elif ftype == "vulnerability" and value.startswith("msf_check_positive:"):
            module = value.split(":", 1)[1]
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["verification"] = "positive"
            group["verified"] = group["verified"] or _fact_is_verified(
                fact,
                legacy_default=True,
            )
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
            _attach_assessment(group, fact)
        elif ftype == "vulnerability_endpoint" and value.startswith("msf_check_positive:"):
            parsed = _parse_msf_endpoint(value)
            if not parsed:
                continue
            group = _group_for_module(groups, parsed["module"], _service_for_port(facts, parsed["port"]), facts)
            group["verified"] = group["verified"] or _fact_is_verified(
                fact,
                legacy_default=True,
            )
            group["verification"] = "positive"
            group["verified_ports"].add(parsed["port"])
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
            _attach_assessment(group, fact)
        elif ftype == "exploit_success":
            module = _module_from_success(value)
            group = _group_for_module(groups, module, _service_for_module(module, facts), facts)
            group["exploited"] = True
            group["impact_confirmed"] = group["impact_confirmed"] or _fact_is_verified(
                fact,
                legacy_default=True,
            )
            group["evidence_ids"].add(evidence_by_fact_id.get(fact.get("id"), ""))
            _attach_assessment(group, fact)

    return [_finalize_group(group) for group in groups.values()]


def build_access_findings(facts: list[dict[str, Any]], state: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Build access/compromise findings separately from CVE/misconfig findings."""
    state = state or {}
    findings: list[dict[str, Any]] = []
    if not state.get("root_access_confirmed"):
        return findings

    supporting_facts: list[dict[str, Any]] = []
    for fact in facts:
        ftype = str(fact.get("type", ""))
        value = str(fact.get("value", ""))
        if (
            (ftype == "credential" and value.startswith(("ssh_login_success:", "ssh_key_available:")))
            or (ftype == "service_status" and value == "ssh_authenticated")
            or (ftype == "system_access" and value in {"uid=0", "root_access_confirmed"})
            or (ftype == "verified_claim" and value == "root_access_confirmed")
        ):
            supporting_facts.append(fact)
    canonical_assessments = any(_has_assessment(fact) for fact in supporting_facts)
    if canonical_assessments:
        supporting_facts = [fact for fact in supporting_facts if _fact_is_verified(fact)]
        if not supporting_facts:
            return findings
    evidence = [
        f"{fact.get('type', '')}: {fact.get('value', '')}"
        for fact in supporting_facts
    ]
    assessments = [fact.get("assessment") or {} for fact in supporting_facts]
    findings.append({
        "severity": "CRITICAL",
        "name": "Root access confirmed on target",
        "class": "access_compromise",
        "service": "host",
        "verified": True,
        "impact_confirmed": True,
        "evidence": list(dict.fromkeys(evidence))[:8],
        "assessment_refs": list(dict.fromkeys(
            str(item.get("assessment_id"))
            for item in assessments
            if item.get("assessment_id")
        )),
        "assessment_reasons": list(dict.fromkeys(
            str(item.get("reason"))
            for item in assessments
            if item.get("reason")
        )),
        "source_execution_ids": list(dict.fromkeys(
            str(execution_id)
            for item in assessments
            for execution_id in item.get("source_execution_ids") or []
            if execution_id
        )),
        "detail": "Root-level access was verified independently of CVE-style vulnerability parsing.",
    })
    return findings


def build_coverage_summary(facts: list[dict[str, Any]]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    degraded: list[dict[str, Any]] = []

    def add_degraded(item: dict[str, Any]) -> None:
        for existing in degraded:
            if existing.get("tool") != item.get("tool") or existing.get("status") != item.get("status"):
                continue
            if item.get("kind") and existing.get("kind") and item.get("kind") != existing.get("kind"):
                continue
            scope = item.get("scope")
            if scope:
                scopes = existing.setdefault("scopes", [])
                if scope not in scopes:
                    scopes.append(scope)
            return
        scope = item.get("scope")
        if scope:
            item["scopes"] = [scope]
        degraded.append(item)

    def add_checked(item: dict[str, Any]) -> None:
        key = (
            item.get("status"),
            json.dumps(item.get("scope", {}), sort_keys=True),
        )
        for existing in checked:
            existing_key = (
                existing.get("status"),
                json.dumps(existing.get("scope", {}), sort_keys=True),
            )
            if existing_key == key:
                return
        checked.append(item)

    for fact in facts:
        if fact.get("type") == "check_result":
            try:
                check = json.loads(str(fact.get("value", "")))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            status = str(check.get("status", "")).lower()
            if status in {"timeout", "partial", "failed"}:
                add_degraded({
                    "tool": check.get("tool", "tool"),
                    "status": status,
                    "kind": check.get("kind", ""),
                    "scope": check.get("scope", {}),
                    "impact": f"{check.get('kind', check.get('tool', 'tool'))} coverage incomplete",
                    "recommended_rerun": "increase timeout or narrow templates/scope",
                })
            elif status in {"skipped", "completed_empty"}:
                add_checked({
                    "status": f"{check.get('kind', check.get('tool', 'tool'))}:{status}",
                    "scope": check.get("scope", {}),
                    "evidence": fact.get("id"),
                })
            continue
        if fact.get("type") != "service_status":
            continue
        value = str(fact.get("value", ""))
        if value.startswith("tool_timeout:"):
            tool = value.split(":", 1)[1]
            add_degraded({
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
            add_checked({"status": value, "evidence": fact.get("id")})
    return {
        "confidence": "partial" if degraded else "normal",
        "checked_but_not_confirmed": checked,
        "degraded": degraded,
    }


def build_attack_path(facts: list[dict[str, Any]], state: dict[str, Any]) -> list[dict[str, str]]:
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


def build_risk_explanation(result: dict[str, Any], access_findings: list[dict[str, Any]]) -> str:
    risk = str(result.get("risk_level", "UNKNOWN")).upper()
    if access_findings and risk == "CRITICAL":
        return (
            "Risk is CRITICAL because root-level access was verified, "
            "even if no CVE-style vulnerability was parsed."
        )
    if access_findings:
        return "Risk includes verified access compromise evidence."
    return ""


def build_remediations(
    finding_groups: list[dict[str, Any]],
    facts: list[dict[str, Any]],
    access_findings: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, str]]:
    remediations = []
    if access_findings:
        remediations.append({
            "finding": "root_access_confirmed",
            "service": "host",
            "recommendation": "Treat host as compromised: rotate credentials, review SSH/session material, patch the entry path, and perform forensic review.",
        })
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


def enrich_result_with_reporting(
    result: dict[str, Any],
    facts: list[dict[str, Any]],
    state: dict[str, Any],
    *,
    scan_id: str = "",
    target: str = "",
    hypotheses: Optional[list[dict[str, Any]]] = None,
    command_results: Optional[list[dict[str, Any]]] = None,
    command_trace: Optional[list[dict[str, Any]]] = None,
    action_reports: Optional[list[Any]] = None,
    context: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    evidence_index = build_evidence_index(facts)
    finding_groups = build_finding_groups(facts, state)
    access_findings = build_access_findings(facts, state)
    result["evidence_index"] = evidence_index
    result["finding_groups"] = finding_groups
    result["access_findings"] = access_findings
    result["risk_explanation"] = build_risk_explanation(result, access_findings)
    result["coverage"] = build_coverage_summary(facts)
    result["attack_path"] = build_attack_path(facts, state)
    result["remediations"] = build_remediations(finding_groups, facts, access_findings)
    result["fact_assessments"] = _assessment_summary(facts)
    result["report_schema_version"] = EVIDENCE_REPORT_SCHEMA_VERSION
    result["machine_report"] = build_evidence_report(
        scan_id or str(facts[0].get("scan_id") if facts else ""),
        target or str(facts[0].get("host") if facts else ""),
        facts,
        evidence_index=evidence_index,
        state=state,
        hypotheses=hypotheses or [],
        command_results=command_results or [],
        command_trace=command_trace or [],
        action_reports=action_reports or [],
        coverage=result["coverage"],
        context=context or state,
    )
    return redact_data(result)


def _has_assessment(fact: dict[str, Any]) -> bool:
    return bool(fact.get("assessment") or fact.get("assessment_id"))


def _assessment_status(fact: dict[str, Any]) -> str:
    assessment = fact.get("assessment") or {}
    return str(assessment.get("status") or fact.get("assessment_status") or "observed")


def _fact_is_verified(
    fact: dict[str, Any],
    *,
    legacy_default: bool = False,
) -> bool:
    if not fact_is_decision_usable(fact):
        return False
    if not _has_assessment(fact):
        return legacy_default
    return _assessment_status(fact) == "verified"


def _attach_assessment(group: dict[str, Any], fact: dict[str, Any]) -> None:
    assessment = fact.get("assessment") or {}
    status = _assessment_status(fact)
    if status == "contradicted":
        group["contradicted"] = True
        group["verified"] = False
        group["impact_confirmed"] = False
    assessment_id = assessment.get("assessment_id") or fact.get("assessment_id")
    if assessment_id:
        group["assessment_refs"].add(str(assessment_id))
    if assessment.get("reason"):
        group["assessment_reasons"].add(str(assessment["reason"]))
    for execution_id in assessment.get("source_execution_ids") or []:
        if execution_id:
            group["source_execution_ids"].add(str(execution_id))


def _assessment_summary(facts: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = ("observed", "inferred", "verified", "contradicted")
    return {
        "schema_version": "1.0",
        "counts": {
            status: sum(1 for fact in facts if _assessment_status(fact) == status)
            for status in statuses
        },
        "verified_fact_ids": [
            int(fact["id"])
            for fact in facts
            if fact.get("id") is not None and _assessment_status(fact) == "verified"
        ],
        "contradicted_fact_ids": [
            int(fact["id"])
            for fact in facts
            if fact.get("id") is not None and _assessment_status(fact) == "contradicted"
        ],
    }


def _parser_name_for_fact(fact: dict[str, Any]) -> str:
    source = str(fact.get("source", ""))
    if source.startswith("derived:"):
        return "derived_fact_builder"
    if source.startswith("replay:"):
        return "replay_output_parser"
    return "output_parser"


def _new_group(module: str, service: str) -> dict[str, Any]:
    return {
        "class": module,
        "module": module,
        "service": service or "unknown",
        "candidate": False,
        "verified": False,
        "verification": "not_run",
        "exploited": False,
        "impact_confirmed": False,
        "contradicted": False,
        "candidate_ports": set(),
        "verified_ports": set(),
        "verification_commands": [],
        "active_commands": [],
        "evidence_ids": set(),
        "assessment_refs": set(),
        "assessment_reasons": set(),
        "source_execution_ids": set(),
        "severity": "INFO",
    }


def _group_for_module(groups: dict[str, dict[str, Any]], module: str, service: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    module = module or "unknown"
    service = service or _service_for_module(module, facts)
    key = f"{module}:{service}"
    if key not in groups:
        groups[key] = _new_group(module, service)
    elif groups[key].get("service") == "unknown" and service:
        groups[key]["service"] = service
    return groups[key]


def _finalize_group(group: dict[str, Any]) -> dict[str, Any]:
    verified_ports = sorted(p for p in group["verified_ports"] if p)
    candidate_ports = sorted(p for p in group["candidate_ports"] if p)
    group["ports"] = verified_ports or candidate_ports
    group["ports_count"] = len(group["ports"])
    group["evidence_ids"] = sorted(eid for eid in group["evidence_ids"] if eid)
    group["verification_commands"] = list(dict.fromkeys(group["verification_commands"]))
    group["active_commands"] = list(dict.fromkeys(group["active_commands"]))
    group["assessment_refs"] = sorted(group["assessment_refs"])
    group["assessment_reasons"] = sorted(group["assessment_reasons"])
    group["source_execution_ids"] = sorted(group["source_execution_ids"])
    if group["contradicted"]:
        group["verified"] = False
        group["impact_confirmed"] = False
    if group["impact_confirmed"]:
        group["severity"] = "CRITICAL"
    elif group["verified"]:
        group["severity"] = "HIGH"
    elif group["candidate"]:
        group["severity"] = "MEDIUM"
    for key in ("candidate_ports", "verified_ports"):
        group.pop(key, None)
    return group


def _parse_exploit_candidate(value: str) -> dict[str, str]:
    if value.lstrip().startswith("{"):
        return {}
    match = re.match(r"(?P<module>\S+)\s+on\s+(?P<service>[^:\s]+):(?P<port>[^\s]+)\s+\[(?P<version>.*)\]$", value)
    return match.groupdict() if match else {}


def _parse_msf_endpoint(value: str) -> dict[str, str]:
    match = re.match(r"msf_check_positive:(?P<module>.+):(?P<port>\d{1,5})$", value)
    return match.groupdict() if match else {}


def _module_from_msf_command(value: str) -> str:
    match = re.search(r"\bmsf_(?:check|run)\s+\S+\s+(\S+)", value or "")
    return match.group(1) if match else ""


def _active_module_allows_run(module: str) -> bool:
    module_l = (module or "").lower()
    if module_l.startswith("auxiliary/"):
        return False
    if "_login" in module_l or module_l.endswith("/login"):
        return False
    return module_l.startswith("exploit/")


def _module_from_success(value: str) -> str:
    if value.startswith("msf_session_opened:"):
        return value.split(":", 1)[1]
    cve = re.search(r"(CVE-\d{4}-\d{4,7})", value or "", re.IGNORECASE)
    return cve.group(1).upper() if cve else (value or "exploit_success")


def _service_for_module(module: str, facts: list[dict[str, Any]]) -> str:
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


def _service_for_port(facts: list[dict[str, Any]], port: str) -> str:
    for fact in facts:
        if fact.get("type") != "port_open":
            continue
        value = str(fact.get("value", ""))
        match = re.match(rf"{re.escape(str(port))}/(?:tcp|udp)\s+\(([^)]+)\)", value, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""
