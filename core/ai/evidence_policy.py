"""Code-owned evidence policies for AnalysisAgent claims.

The analysis model is allowed to propose a claim, but it is not trusted to
define what proves that claim.  This module maps supported claim shapes to
small, deterministic proof predicates over persisted typed facts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from core.ai.fact_predicates import parse_port_open

_CLAIM_NORMALIZER = re.compile(r"[^a-z0-9]+")
_CVE_IN_CLAIM = re.compile(r"(?:^|_)cve_(?P<year>\d{4})_(?P<sequence>\d{4,})(?:_|$)")
_CVE_IN_VALUE = re.compile(r"(?i)(?<![a-z0-9])cve[-_](?P<year>\d{4})[-_](?P<sequence>\d{4,})(?![a-z0-9])")
_SERVICE_ACTIVE_CLAIM = re.compile(r"^(?P<service>[a-z][a-z0-9_]*)_service_(?:active|running)$")
_SERVICE_VERSION_CLAIM = re.compile(r"^(?P<service>[a-z][a-z0-9_]*)_version_observed$")
_SERVICE_WORKFLOW_CLAIM = re.compile(r"^(?P<service>[a-z][a-z0-9_]*)_service_needs_exploit_selection$")
_SSH_LOGIN = re.compile(r"(?i)^ssh_login_success:(?P<user>[^@\s:]+)@(?P<target>\S+)$")

_AUTHENTICATED_ACCESS_CLAIMS = {
    "authenticated_access_confirmed",
    "ssh_access_confirmed",
    "ssh_accessible",
    "ssh_authenticated",
    "ssh_is_accessible",
}
_SECURITY_IMPACT_MARKERS = {
    "access",
    "authenticated",
    "compromise",
    "compromised",
    "credential",
    "exploit",
    "exposed",
    "exposure",
    "root",
    "rce",
    "session",
    "vulnerability",
    "vulnerable",
}
_CVE_DIRECT_TYPES = {
    "check_result",
    "exploit_success",
    "verified_vulnerability",
    "vulnerability",
    "vulnerability_endpoint",
}
_CVE_CANDIDATE_TYPES = {
    "candidate",
    "exploit_candidate",
    "finding",
    "potential_vulnerability",
    "version_match",
    "vulnerability_candidate",
}


@dataclass(frozen=True)
class ClaimEvidencePolicy:
    """A deterministic proof contract selected from the normalized claim."""

    policy_id: str
    claim_kind: str
    requirement_labels: tuple[str, ...]
    supported: bool = True
    security_impact: bool = False
    requires_hard_evidence: bool = False
    service: str = ""
    cve_id: str = ""

    @property
    def persistence_labels(self) -> tuple[str, ...]:
        """Labels stored with a hypothesis in the legacy evidence column."""

        return (f"policy_id:{self.policy_id}", *self.requirement_labels)


@dataclass(frozen=True)
class PolicyEvidence:
    """Persisted facts that satisfy a policy's semantic predicate."""

    fact_ids: tuple[int, ...] = ()
    force_inferred: bool = False


def normalize_claim(value: str) -> str:
    return _CLAIM_NORMALIZER.sub("_", str(value or "").lower()).strip("_")


def claim_evidence_policy(claim: str) -> ClaimEvidencePolicy:
    """Select a code-owned policy without consulting model-supplied evidence."""

    normalized = normalize_claim(claim)
    if not normalized:
        return ClaimEvidencePolicy(
            policy_id="invalid.claim.v1",
            claim_kind="invalid",
            requirement_labels=(),
            supported=False,
        )

    if normalized == "root_access_confirmed":
        return ClaimEvidencePolicy(
            policy_id="access.root.v1",
            claim_kind="root_access",
            requirement_labels=("direct_root_access_fact",),
            security_impact=True,
            requires_hard_evidence=True,
        )

    if normalized in _AUTHENTICATED_ACCESS_CLAIMS:
        return ClaimEvidencePolicy(
            policy_id="access.ssh_authenticated.v1",
            claim_kind="authenticated_access",
            requirement_labels=("successful_ssh_authentication_fact",),
            security_impact=True,
            requires_hard_evidence=True,
        )

    cve_match = _CVE_IN_CLAIM.search(normalized)
    if cve_match:
        cve_id = f"CVE-{cve_match.group('year')}-{cve_match.group('sequence')}"
        return ClaimEvidencePolicy(
            policy_id="vulnerability.same_cve.v1",
            claim_kind="cve_vulnerability",
            requirement_labels=(f"same_cve_compatible_fact:{cve_id}",),
            security_impact=True,
            cve_id=cve_id,
        )

    service_match = _SERVICE_ACTIVE_CLAIM.fullmatch(normalized)
    if service_match:
        service = service_match.group("service")
        return ClaimEvidencePolicy(
            policy_id="service.active.v1",
            claim_kind="service_active",
            requirement_labels=(f"typed_service_presence:{service}",),
            service=service,
        )

    version_match = _SERVICE_VERSION_CLAIM.fullmatch(normalized)
    if version_match:
        service = version_match.group("service")
        return ClaimEvidencePolicy(
            policy_id="service.version_observed.v1",
            claim_kind="service_version",
            requirement_labels=(f"typed_service_version:{service}",),
            service=service,
        )

    workflow_match = _SERVICE_WORKFLOW_CLAIM.fullmatch(normalized)
    if workflow_match:
        service = workflow_match.group("service")
        return ClaimEvidencePolicy(
            policy_id="workflow.service_exploit_selection.v1",
            claim_kind="service_workflow",
            requirement_labels=(f"typed_service_presence:{service}",),
            service=service,
        )

    impact = bool(set(normalized.split("_")) & _SECURITY_IMPACT_MARKERS)
    return ClaimEvidencePolicy(
        policy_id=("unsupported.security_impact.v1" if impact else "unsupported.claim.v1"),
        claim_kind="unsupported",
        requirement_labels=(),
        supported=False,
        security_impact=impact,
    )


def policy_evidence(
    policy: ClaimEvidencePolicy,
    facts: Sequence[Mapping[str, Any]],
) -> PolicyEvidence:
    """Return only facts that semantically satisfy the selected policy."""

    if not policy.supported:
        return PolicyEvidence()

    if policy.claim_kind == "root_access":
        return PolicyEvidence(_matching_ids(facts, _fact_proves_root_access))
    if policy.claim_kind == "authenticated_access":
        return PolicyEvidence(_matching_ids(facts, _fact_proves_authenticated_access))
    if policy.claim_kind == "service_active":
        return PolicyEvidence(_matching_ids(facts, lambda fact: _fact_proves_service(fact, policy.service)))
    if policy.claim_kind == "service_version":
        return PolicyEvidence(
            _matching_ids(
                facts,
                lambda fact: _fact_proves_service_version(fact, policy.service),
            )
        )
    if policy.claim_kind == "service_workflow":
        return PolicyEvidence(
            _matching_ids(facts, lambda fact: _fact_proves_service(fact, policy.service)),
            force_inferred=True,
        )
    if policy.claim_kind == "cve_vulnerability":
        direct = _matching_ids(
            facts,
            lambda fact: _fact_proves_same_cve(fact, policy.cve_id, candidate=False),
        )
        if direct:
            return PolicyEvidence(direct)
        candidates = _matching_ids(
            facts,
            lambda fact: _fact_proves_same_cve(fact, policy.cve_id, candidate=True),
        )
        return PolicyEvidence(candidates, force_inferred=bool(candidates))
    return PolicyEvidence()


def _matching_ids(facts: Sequence[Mapping[str, Any]], predicate) -> tuple[int, ...]:
    matched: list[int] = []
    for fact in facts:
        raw_id = fact.get("id")
        try:
            fact_id = int(str(raw_id))
        except (TypeError, ValueError):
            continue
        if fact_id > 0 and predicate(fact):
            matched.append(fact_id)
    return tuple(dict.fromkeys(matched))


def _fact_proves_root_access(fact: Mapping[str, Any]) -> bool:
    fact_type = normalize_claim(str(fact.get("type", "")))
    value = str(fact.get("value", "")).strip()
    lowered = value.lower()
    if fact_type == "system_access":
        return lowered in {"uid=0", "root_access_confirmed"} and _source_tool(fact) in {"ssh_inventory", "ssh_session"}
    if fact_type != "credential":
        return False
    match = _SSH_LOGIN.fullmatch(value)
    return bool(
        match and match.group("user").lower() == "root" and _source_tool(fact) in {"ssh_inventory", "ssh_session"}
    )


def _source_tool(fact: Mapping[str, Any]) -> str:
    source_identity = str(fact.get("source_identity") or "").strip().casefold()
    if source_identity:
        return re.split(r"\s+", source_identity, maxsplit=1)[0]
    observations = fact.get("observations") or ()
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        identity = str(observation.get("source_identity") or "").strip().casefold()
        if identity:
            return re.split(r"\s+", identity, maxsplit=1)[0]
    source = str(fact.get("source") or "").strip().casefold()
    return re.split(r"\s+", source, maxsplit=1)[0] if source else ""


def _fact_proves_authenticated_access(fact: Mapping[str, Any]) -> bool:
    fact_type = normalize_claim(str(fact.get("type", "")))
    value = str(fact.get("value", "")).strip()
    if fact_type == "service_status":
        return value.lower() == "ssh_authenticated"
    return fact_type == "credential" and _SSH_LOGIN.fullmatch(value) is not None


def _fact_proves_service(fact: Mapping[str, Any], service: str) -> bool:
    fact_type = normalize_claim(str(fact.get("type", "")))
    if fact_type not in {"internal_service", "port_open", "service_version"}:
        return False
    return service in _typed_service_names(fact_type, str(fact.get("value", "")))


def _fact_proves_service_version(fact: Mapping[str, Any], service: str) -> bool:
    fact_type = normalize_claim(str(fact.get("type", "")))
    if fact_type != "service_version":
        return False
    return service in _typed_service_names(fact_type, str(fact.get("value", "")))


def _typed_service_names(fact_type: str, value: str) -> set[str]:
    raw_name = ""
    if fact_type in {"port_open", "internal_service"}:
        parsed = parse_port_open({"type": "port_open", "value": value})
        if parsed is not None:
            raw_name = parsed.service
    elif fact_type == "service_version":
        match = re.match(r"\s*(?P<service>[A-Za-z0-9_.+/-]+):", value)
        if match:
            raw_name = match.group("service")
    if not raw_name:
        return set()

    names = {normalize_claim(raw_name)}
    names.update(normalize_claim(part) for part in re.split(r"[/,+\s]+", raw_name) if normalize_claim(part))
    if "ssl" in names and "http" in names:
        names.add("https")
    return names


def _fact_proves_same_cve(
    fact: Mapping[str, Any],
    expected_cve: str,
    *,
    candidate: bool,
) -> bool:
    fact_type = normalize_claim(str(fact.get("type", "")))
    allowed_types = _CVE_CANDIDATE_TYPES if candidate else _CVE_DIRECT_TYPES
    if fact_type not in allowed_types:
        return False
    value = str(fact.get("value", ""))
    if expected_cve.upper() not in _cves_in_value(value):
        return False
    if fact_type == "check_result":
        return _positive_check_result(value)
    return True


def _cves_in_value(value: str) -> set[str]:
    return {f"CVE-{match.group('year')}-{match.group('sequence')}".upper() for match in _CVE_IN_VALUE.finditer(value)}


def _positive_check_result(value: str) -> bool:
    try:
        payload = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        normalized = normalize_claim(value)
        return any(marker in normalized.split("_") for marker in ("confirmed", "positive", "success", "vulnerable"))
    if not isinstance(payload, Mapping):
        return False
    status = normalize_claim(str(payload.get("status") or (payload.get("data") or {}).get("status") or ""))
    return status in {"confirmed", "positive", "success", "vulnerable"}
