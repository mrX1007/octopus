"""Canonical, evidence-backed machine report schema.

The legacy CLI report intentionally remains available in :mod:`core.ai.reporting`.
This module owns the stricter interchange contract: a fact is report-verified
only when its current assessment includes a complete evidence trail.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from core.ai.evaluated_facts import fact_is_decision_usable
from core.ai.fact_predicates import (
    NON_DECISION_TRUST_LEVELS,
    confirms_cleanup,
    fact_trust_level,
)
from core.secrets import redact_data

EVIDENCE_REPORT_SCHEMA_VERSION = "1.0"
EVIDENCE_REPORT_SECTION_ORDER = (
    "verified_vulnerabilities",
    "access_findings",
    "misconfigurations",
    "observations",
    "hypotheses_candidates",
    "attempted_unverified",
    "coverage_gaps",
    "policy_blocked_degraded_checks",
    "cleanup_outcomes",
)

_MAX_SECTION_ITEMS = 256
_MAX_EVIDENCE_ITEMS = 1_024
_MAX_CHAIN_ITEMS = 64
_MAX_REFS = 64
_MAX_TEXT_BYTES = 4_096

_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "report_id",
        "scan_id",
        "target",
        "snapshot_at",
        "section_order",
        "sections",
        "evidence_index",
        "summary",
        "bounds",
        "truncation",
        "legacy_adapter",
    }
)
_REPORT_REQUIRED_KEYS = _REPORT_KEYS - {"legacy_adapter"}
_ITEM_KEYS = frozenset(
    {
        "item_id",
        "kind",
        "title",
        "detail",
        "severity",
        "status",
        "assessment_status",
        "scope",
        "fact_ids",
        "evidence_chain",
        "source_execution_ids",
        "assessment_refs",
        "assessment_reasons",
        "sources",
        "timestamp",
        "verification_gap",
        "required_evidence",
        "policy_refs",
        "legacy_fields",
    }
)
_ITEM_REQUIRED_KEYS = frozenset(
    {
        "item_id",
        "kind",
        "title",
        "detail",
        "severity",
        "status",
        "assessment_status",
        "scope",
        "fact_ids",
        "evidence_chain",
        "source_execution_ids",
        "assessment_refs",
        "assessment_reasons",
        "timestamp",
    }
)
_EVIDENCE_KEYS = frozenset(
    {
        "evidence_id",
        "evidence_ref",
        "fact_id",
        "fact_type",
        "fact_value",
        "tool",
        "command",
        "raw_output_ref",
        "parsed_by",
        "confidence",
        "observations",
        "assessment_ref",
        "assessment_status",
        "assessment_reason",
        "assessment_confidence",
        "trust_level",
        "evidence_fact_ids",
        "source_execution_ids",
    }
)
_EVIDENCE_REQUIRED_KEYS = frozenset(
    {
        "evidence_id",
        "evidence_ref",
        "fact_id",
        "fact_type",
        "fact_value",
        "assessment_ref",
        "assessment_status",
        "assessment_reason",
        "trust_level",
        "source_execution_ids",
    }
)
_LEGACY_ADAPTER_KEYS = frozenset(
    {
        "source_schema",
        "session_id",
        "scan_date",
        "status",
        "risk_level",
        "analysis",
        "raw_output",
        "summary_id",
        "summary_session_id",
        "generated_at",
    }
)
_LEGACY_FIELD_KEYS = frozenset(
    {
        "legacy_id",
        "session_id",
        "title",
        "port",
        "service",
        "description",
        "confidence",
        "evidence_source",
        "raw_evidence",
        "reproduction_command",
        "cvss_score",
        "remediations",
        "tool",
        "payload",
        "result",
        "notes",
    }
)
_LEGACY_REMEDIATION_KEYS = frozenset({"id", "session_id", "text", "source"})

_VULNERABILITY_TYPES = frozenset(
    {
        "vulnerability",
        "vulnerability_endpoint",
        "verified_vulnerability",
        "vulnerability_claim",
        "nuclei_finding",
    }
)
_CANDIDATE_TYPES = frozenset(
    {
        "cve_candidate",
        "exploit_candidate",
        "potential_vulnerability",
        "vulnerability_candidate",
        "vulnerability_hypothesis",
    }
)
_MISCONFIGURATION_TYPES = frozenset(
    {
        "api_security_note",
        "cloud_finding",
        "code_finding",
        "misconfiguration",
        "secret_finding",
        "web_security_note",
    }
)
_ATTEMPT_TYPES = frozenset({"active_command", "exploit_attempted", "verification_command"})
_INTERNAL_FACT_TYPES = frozenset(
    {
        "check_result",
        "external_url",
        "llm_health",
        "network_edge",
        "network_node",
        "payload_recommendation",
    }
)
_DEGRADED_STATUSES = frozenset({"blocked", "cancelled", "failed", "partial", "timeout", "unavailable"})

RedactCallable = Callable[[Any], Any]


def build_evidence_report(
    scan_id: str,
    target: str,
    facts: Sequence[Mapping[str, Any]],
    *,
    evidence_index: Sequence[Mapping[str, Any]] = (),
    state: Mapping[str, Any] | None = None,
    hypotheses: Sequence[Mapping[str, Any]] = (),
    command_results: Sequence[Mapping[str, Any]] = (),
    command_trace: Sequence[Mapping[str, Any]] = (),
    action_reports: Sequence[Any] = (),
    coverage: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
    redact: RedactCallable = redact_data,
) -> dict[str, Any]:
    """Build the bounded canonical report without promoting weak evidence.

    ``snapshot_at`` is derived from persisted inputs rather than wall-clock time,
    which makes identical snapshots byte-for-byte reproducible.
    """

    state = state or {}
    context = context or {}
    coverage = coverage or {}
    fact_list = [dict(item) for item in facts if isinstance(item, Mapping)]
    evidence = _canonical_evidence_index(fact_list, evidence_index)
    evidence_by_fact = {
        _positive_int(item.get("fact_id")): item for item in evidence if _positive_int(item.get("fact_id")) is not None
    }
    raw_sections: dict[str, list[dict[str, Any]]] = {name: [] for name in EVIDENCE_REPORT_SECTION_ORDER}
    seen: dict[str, set[str]] = {name: set() for name in EVIDENCE_REPORT_SECTION_ORDER}
    verified_access: list[dict[str, Any]] = []

    for fact in fact_list:
        fact_type = _text(fact.get("type"), 256).lower()
        if not fact_type:
            continue
        if fact_trust_level(fact) in NON_DECISION_TRUST_LEVELS:
            item = _fact_item("observations", fact, evidence_by_fact)
            item["kind"] = "untrusted_observation"
            _append(raw_sections, seen, "observations", item)
            continue
        if _is_cleanup_fact(fact_type, fact):
            _append(
                raw_sections,
                seen,
                "cleanup_outcomes",
                _fact_item("cleanup_outcomes", fact, evidence_by_fact),
            )
            continue
        if fact_type in _ATTEMPT_TYPES:
            item = _fact_item("attempted_unverified", fact, evidence_by_fact)
            item["status"] = "attempted_unverified"
            item["assessment_status"] = _assessment_status(fact)
            _append(raw_sections, seen, "attempted_unverified", item)
            continue
        if _is_access_fact(fact_type, fact):
            if _report_verified(fact, evidence_by_fact):
                verified_access.append(fact)
            else:
                item = _fact_item("observations", fact, evidence_by_fact)
                item["kind"] = "access_observation"
                _append(raw_sections, seen, "observations", item)
            continue
        if fact_type in _VULNERABILITY_TYPES:
            if _report_verified(fact, evidence_by_fact):
                item = _fact_item(
                    "verified_vulnerabilities",
                    fact,
                    evidence_by_fact,
                )
                item["severity"] = _vulnerability_severity(fact)
                _append(raw_sections, seen, "verified_vulnerabilities", item)
            else:
                item = _fact_item("hypotheses_candidates", fact, evidence_by_fact)
                item["status"] = _candidate_status(fact)
                item["verification_gap"] = _verification_gap(fact, evidence_by_fact)
                _append(raw_sections, seen, "hypotheses_candidates", item)
            continue
        if fact_type in _CANDIDATE_TYPES or _looks_like_cve_candidate(fact_type, fact):
            item = _fact_item("hypotheses_candidates", fact, evidence_by_fact)
            item["status"] = _candidate_status(fact)
            item["verification_gap"] = _verification_gap(fact, evidence_by_fact)
            _append(raw_sections, seen, "hypotheses_candidates", item)
            continue
        if fact_type in _MISCONFIGURATION_TYPES:
            item = _fact_item("misconfigurations", fact, evidence_by_fact)
            _append(raw_sections, seen, "misconfigurations", item)
            continue
        if fact_type not in _INTERNAL_FACT_TYPES:
            _append(
                raw_sections,
                seen,
                "observations",
                _fact_item("observations", fact, evidence_by_fact),
            )

    if verified_access:
        _append(
            raw_sections,
            seen,
            "access_findings",
            _access_item(verified_access, evidence_by_fact, state),
        )

    for hypothesis in hypotheses:
        if isinstance(hypothesis, Mapping):
            _append(
                raw_sections,
                seen,
                "hypotheses_candidates",
                _hypothesis_item(hypothesis),
            )

    _add_coverage_items(raw_sections, seen, coverage, context)
    _add_degraded_check_items(
        raw_sections,
        seen,
        coverage,
        command_results,
        command_trace,
    )
    _add_action_report_items(raw_sections, seen, action_reports)
    _add_state_cleanup_item(raw_sections, seen, state)

    sections: dict[str, list[dict[str, Any]]] = {}
    omitted: dict[str, int] = {}
    for name in EVIDENCE_REPORT_SECTION_ORDER:
        ordered = sorted(raw_sections[name], key=_item_sort_key)
        sections[name] = ordered[:_MAX_SECTION_ITEMS]
        omitted[name] = max(0, len(ordered) - len(sections[name]))

    all_timestamps = [
        _number(item.get("timestamp"))
        for collection in (fact_list, command_results, hypotheses)
        for item in collection
        if isinstance(item, Mapping)
    ]
    snapshot_at = max(all_timestamps, default=0.0)
    report_identity = {
        "scan_id": _text(scan_id, 512),
        "target": _text(target, 2_048),
        "section_item_ids": {
            name: [item["item_id"] for item in sections[name]] for name in EVIDENCE_REPORT_SECTION_ORDER
        },
    }
    report_id = _stable_id("evidence-report", report_identity)
    verified_items = [
        item for name in EVIDENCE_REPORT_SECTION_ORDER for item in sections[name] if item.get("status") == "verified"
    ]
    complete_verified = [item for item in verified_items if _item_evidence_complete(item)]
    bounded_evidence = evidence[:_MAX_EVIDENCE_ITEMS]
    report = {
        "schema_version": EVIDENCE_REPORT_SCHEMA_VERSION,
        "report_id": report_id,
        "scan_id": _text(scan_id, 512),
        "target": _text(target, 2_048),
        "snapshot_at": snapshot_at,
        "section_order": list(EVIDENCE_REPORT_SECTION_ORDER),
        "sections": sections,
        "evidence_index": bounded_evidence,
        "summary": {
            "section_counts": {name: len(sections[name]) for name in EVIDENCE_REPORT_SECTION_ORDER},
            "verified_items": len(verified_items),
            "evidence_complete_verified_items": len(complete_verified),
            "evidence_completeness": (
                round(len(complete_verified) / len(verified_items), 6) if verified_items else 1.0
            ),
            "evidence_records": len(bounded_evidence),
        },
        "bounds": {
            "max_items_per_section": _MAX_SECTION_ITEMS,
            "max_evidence_items": _MAX_EVIDENCE_ITEMS,
            "max_chain_items": _MAX_CHAIN_ITEMS,
        },
        "truncation": {
            "section_items_omitted": omitted,
            "evidence_items_omitted": max(0, len(evidence) - len(bounded_evidence)),
        },
    }
    safe_report = redact(report)
    errors = validate_evidence_report(safe_report)
    if errors:
        raise ValueError("Invalid evidence report: " + "; ".join(errors))
    return safe_report


def validate_evidence_report(report: Mapping[str, Any]) -> tuple[str, ...]:
    """Validate the closed, bounded canonical report contract.

    The report is an interchange and export boundary, so accepting a partial
    duck type is unsafe: renderers must not discover malformed structures only
    after files have started to be written.  Schema ``1.0`` is therefore
    closed.  New fields require a schema-version change instead of becoming an
    unbounded extension channel.
    """

    errors: list[str] = []
    if not isinstance(report, Mapping):
        return ("report_not_mapping",)
    if report.get("schema_version") != EVIDENCE_REPORT_SCHEMA_VERSION:
        errors.append("unsupported_schema_version")
    sections = report.get("sections")
    if not isinstance(sections, Mapping):
        return (*errors, "sections_not_mapping")

    keys = set(report)
    for key in sorted(keys - _REPORT_KEYS, key=str):
        errors.append(f"unexpected_report_field:{key}")
    for key in sorted(_REPORT_REQUIRED_KEYS - keys):
        errors.append(f"missing_report_field:{key}")

    _validate_text(errors, "report_id", report.get("report_id"), 512, required=True)
    report_id = report.get("report_id")
    if isinstance(report_id, str) and not re.fullmatch(r"evidence-report://sha256/[0-9a-f]{64}", report_id):
        errors.append("invalid_report_id")
    _validate_text(errors, "scan_id", report.get("scan_id"), 512)
    _validate_text(errors, "target", report.get("target"), 2_048)
    if not _is_nonnegative_number(report.get("snapshot_at")):
        errors.append("invalid_snapshot_at")

    section_order = report.get("section_order")
    if not isinstance(section_order, list):
        errors.append("section_order_not_list")
    elif section_order != list(EVIDENCE_REPORT_SECTION_ORDER):
        errors.append("section_order_mismatch")

    extra_sections = set(sections) - set(EVIDENCE_REPORT_SECTION_ORDER)
    for name in sorted(extra_sections, key=str):
        errors.append(f"unexpected_section:{name}")

    all_item_ids: set[str] = set()
    has_legacy_fields = False
    for name in EVIDENCE_REPORT_SECTION_ORDER:
        items = sections.get(name)
        if not isinstance(items, list):
            errors.append(f"section_not_list:{name}")
            continue
        if len(items) > _MAX_SECTION_ITEMS:
            errors.append(f"section_unbounded:{name}")
        for item in items:
            if not isinstance(item, Mapping) or not item.get("item_id"):
                errors.append(f"invalid_item:{name}")
                continue
            _validate_report_item(errors, name, item)
            has_legacy_fields = has_legacy_fields or "legacy_fields" in item
            item_id = str(item.get("item_id"))
            if item_id in all_item_ids:
                errors.append(f"duplicate_item_id:{item_id}")
            all_item_ids.add(item_id)
            if item.get("status") == "verified" and not _item_evidence_complete(item):
                errors.append(f"verified_item_incomplete:{item.get('item_id')}")
    verified_vulnerabilities = sections.get("verified_vulnerabilities") or []
    for item in verified_vulnerabilities:
        if isinstance(item, Mapping) and item.get("status") != "verified":
            errors.append(f"unverified_vulnerability:{item.get('item_id')}")

    evidence_index = report.get("evidence_index")
    evidence_fact_ids: set[int] = set()
    if not isinstance(evidence_index, list):
        errors.append("evidence_index_not_list")
    else:
        if len(evidence_index) > _MAX_EVIDENCE_ITEMS:
            errors.append("evidence_index_unbounded")
        evidence_ids: set[str] = set()
        for index, evidence in enumerate(evidence_index):
            if not isinstance(evidence, Mapping):
                errors.append(f"invalid_evidence_record:{index}")
                continue
            _validate_evidence_record(errors, index, evidence)
            evidence_id = evidence.get("evidence_id")
            if isinstance(evidence_id, str):
                if evidence_id in evidence_ids:
                    errors.append(f"duplicate_evidence_id:{evidence_id}")
                evidence_ids.add(evidence_id)
            fact_id = _positive_int(evidence.get("fact_id"))
            if fact_id is not None:
                evidence_fact_ids.add(fact_id)

    for name in ("verified_vulnerabilities", "access_findings"):
        section_items = sections.get(name)
        if not isinstance(section_items, list):
            continue
        for item in section_items:
            if not isinstance(item, Mapping) or item.get("status") != "verified":
                continue
            fact_ids = item.get("fact_ids")
            missing = []
            if isinstance(fact_ids, list):
                missing = [str(fact_id) for fact_id in fact_ids if _positive_int(fact_id) not in evidence_fact_ids]
            if missing:
                errors.append(f"verified_item_missing_evidence:{item.get('item_id')}")

    _validate_summary(errors, report.get("summary"), sections, evidence_index)
    _validate_bounds(errors, report.get("bounds"))
    _validate_truncation(errors, report.get("truncation"))
    if has_legacy_fields and "legacy_adapter" not in report:
        errors.append("legacy_fields_without_adapter")
    if "legacy_adapter" in report:
        _validate_legacy_adapter(errors, report.get("legacy_adapter"))
    return tuple(errors)


def _validate_report_item(
    errors: list[str],
    section: str,
    item: Mapping[str, Any],
) -> None:
    item_id = str(item.get("item_id") or "")
    keys = set(item)
    for key in sorted(keys - _ITEM_KEYS, key=str):
        errors.append(f"unexpected_item_field:{section}:{item_id}:{key}")
    for key in sorted(_ITEM_REQUIRED_KEYS - keys):
        errors.append(f"missing_item_field:{section}:{item_id}:{key}")

    text_limits = {
        "item_id": 512,
        "kind": 256,
        "title": 512,
        "detail": _MAX_TEXT_BYTES,
        "severity": 32,
        "status": 128,
        "assessment_status": 64,
        "verification_gap": 256,
    }
    for field, limit in text_limits.items():
        if field in item:
            _validate_text(
                errors,
                f"item:{section}:{item_id}:{field}",
                item.get(field),
                limit,
                required=field == "item_id",
            )

    scope = item.get("scope")
    if not isinstance(scope, Mapping):
        errors.append(f"item_scope_not_mapping:{section}:{item_id}")
    else:
        if set(scope) - {"type", "value"}:
            errors.append(f"item_scope_unexpected_field:{section}:{item_id}")
        for field, limit in (("type", 128), ("value", 2_048)):
            if field in scope:
                _validate_text(
                    errors,
                    f"item:{section}:{item_id}:scope:{field}",
                    scope.get(field),
                    limit,
                )

    _validate_positive_int_list(errors, f"item:{section}:{item_id}:fact_ids", item.get("fact_ids"))
    for field, limit in (
        ("source_execution_ids", 512),
        ("assessment_refs", 512),
        ("assessment_reasons", _MAX_TEXT_BYTES),
        ("sources", 512),
        ("required_evidence", _MAX_TEXT_BYTES),
        ("policy_refs", 512),
    ):
        if field in item:
            _validate_text_list(
                errors,
                f"item:{section}:{item_id}:{field}",
                item.get(field),
                limit,
            )

    chain = item.get("evidence_chain")
    if not isinstance(chain, list):
        errors.append(f"item_evidence_chain_not_list:{section}:{item_id}")
    else:
        if len(chain) > _MAX_CHAIN_ITEMS:
            errors.append(f"item_evidence_chain_unbounded:{section}:{item_id}")
        for index, link in enumerate(chain):
            if not isinstance(link, Mapping):
                errors.append(f"invalid_evidence_link:{section}:{item_id}:{index}")
                continue
            if set(link) - {"evidence_ref", "evidence_id", "fact_id", "relation"}:
                errors.append(f"unexpected_evidence_link_field:{section}:{item_id}:{index}")
            for field in ("evidence_ref", "evidence_id", "relation"):
                if field in link:
                    _validate_text(
                        errors,
                        f"evidence_link:{section}:{item_id}:{index}:{field}",
                        link.get(field),
                        512,
                    )
            if _positive_int(link.get("fact_id")) is None:
                errors.append(f"invalid_evidence_link_fact_id:{section}:{item_id}:{index}")

    if not _is_nonnegative_number(item.get("timestamp")):
        errors.append(f"invalid_item_timestamp:{section}:{item_id}")
    if "legacy_fields" in item:
        if item.get("status") == "verified":
            errors.append(f"legacy_item_cannot_be_verified:{section}:{item_id}")
        _validate_legacy_fields(errors, section, item_id, item.get("legacy_fields"))


def _validate_evidence_record(
    errors: list[str],
    index: int,
    evidence: Mapping[str, Any],
) -> None:
    keys = set(evidence)
    for key in sorted(keys - _EVIDENCE_KEYS, key=str):
        errors.append(f"unexpected_evidence_field:{index}:{key}")
    for key in sorted(_EVIDENCE_REQUIRED_KEYS - keys):
        errors.append(f"missing_evidence_field:{index}:{key}")
    text_limits = {
        "evidence_id": 512,
        "evidence_ref": 512,
        "fact_type": 256,
        "fact_value": _MAX_TEXT_BYTES,
        "tool": 512,
        "command": _MAX_TEXT_BYTES,
        "raw_output_ref": 512,
        "parsed_by": 256,
        "assessment_ref": 512,
        "assessment_status": 64,
        "assessment_reason": _MAX_TEXT_BYTES,
        "trust_level": 64,
    }
    for field, limit in text_limits.items():
        if field in evidence:
            _validate_text(
                errors,
                f"evidence:{index}:{field}",
                evidence.get(field),
                limit,
                required=field in {"evidence_id", "evidence_ref"},
            )
    if evidence.get("fact_id") is not None and _positive_int(evidence.get("fact_id")) is None:
        errors.append(f"invalid_evidence_fact_id:{index}")
    for field in ("evidence_fact_ids",):
        if field in evidence:
            _validate_positive_int_list(errors, f"evidence:{index}:{field}", evidence.get(field))
    _validate_text_list(
        errors,
        f"evidence:{index}:source_execution_ids",
        evidence.get("source_execution_ids"),
        512,
    )
    for field in ("confidence", "assessment_confidence", "observations"):
        if field in evidence and not _is_json_scalar(evidence.get(field)):
            errors.append(f"invalid_evidence_scalar:{index}:{field}")


def _validate_summary(
    errors: list[str],
    value: Any,
    sections: Mapping[str, Any],
    evidence_index: Any,
) -> None:
    if not isinstance(value, Mapping):
        errors.append("summary_not_mapping")
        return
    expected_keys = {
        "section_counts",
        "verified_items",
        "evidence_complete_verified_items",
        "evidence_completeness",
        "evidence_records",
    }
    if set(value) != expected_keys:
        errors.append("summary_fields_mismatch")
    counts = value.get("section_counts")
    if not isinstance(counts, Mapping) or set(counts) != set(EVIDENCE_REPORT_SECTION_ORDER):
        errors.append("summary_section_counts_invalid")
    else:
        for name in EVIDENCE_REPORT_SECTION_ORDER:
            actual = sections.get(name)
            expected = len(actual) if isinstance(actual, list) else 0
            if type(counts.get(name)) is not int or counts.get(name) != expected:
                errors.append(f"summary_section_count_mismatch:{name}")
    for field in ("verified_items", "evidence_complete_verified_items", "evidence_records"):
        if type(value.get(field)) is not int or value.get(field, -1) < 0:
            errors.append(f"summary_invalid_count:{field}")
    section_items: list[Mapping[str, Any]] = []
    for name in EVIDENCE_REPORT_SECTION_ORDER:
        raw_items = sections.get(name)
        if isinstance(raw_items, list):
            section_items.extend(item for item in raw_items if isinstance(item, Mapping))
    verified_items = [item for item in section_items if item.get("status") == "verified"]
    complete_verified = [item for item in verified_items if _item_evidence_complete(item)]
    if value.get("verified_items") != len(verified_items):
        errors.append("summary_verified_items_mismatch")
    if value.get("evidence_complete_verified_items") != len(complete_verified):
        errors.append("summary_complete_verified_items_mismatch")
    completeness = value.get("evidence_completeness")
    if not _is_nonnegative_number(completeness):
        errors.append("summary_invalid_evidence_completeness")
    else:
        assert isinstance(completeness, (int, float))
        completeness_value = float(completeness)
        if completeness_value > 1.0:
            errors.append("summary_invalid_evidence_completeness")
        else:
            expected_completeness = round(len(complete_verified) / len(verified_items), 6) if verified_items else 1.0
            if completeness_value != expected_completeness:
                errors.append("summary_evidence_completeness_mismatch")
    if isinstance(evidence_index, list) and value.get("evidence_records") != len(evidence_index):
        errors.append("summary_evidence_records_mismatch")


def _validate_bounds(errors: list[str], value: Any) -> None:
    expected = {
        "max_items_per_section": _MAX_SECTION_ITEMS,
        "max_evidence_items": _MAX_EVIDENCE_ITEMS,
        "max_chain_items": _MAX_CHAIN_ITEMS,
    }
    if not isinstance(value, Mapping) or dict(value) != expected:
        errors.append("bounds_mismatch")


def _validate_truncation(errors: list[str], value: Any) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "section_items_omitted",
        "evidence_items_omitted",
    }:
        errors.append("truncation_invalid")
        return
    omitted = value.get("section_items_omitted")
    if not isinstance(omitted, Mapping) or set(omitted) != set(EVIDENCE_REPORT_SECTION_ORDER):
        errors.append("truncation_section_items_invalid")
    else:
        for name, count in omitted.items():
            if type(count) is not int or count < 0:
                errors.append(f"truncation_section_count_invalid:{name}")
    evidence_omitted = value.get("evidence_items_omitted")
    if type(evidence_omitted) is not int or evidence_omitted < 0:
        errors.append("truncation_evidence_count_invalid")


def _validate_legacy_adapter(errors: list[str], value: Any) -> None:
    if not isinstance(value, Mapping):
        errors.append("legacy_adapter_not_mapping")
        return
    if set(value) != _LEGACY_ADAPTER_KEYS:
        errors.append("legacy_adapter_fields_mismatch")
    if value.get("source_schema") != "octopus-db-session-v1":
        errors.append("legacy_adapter_source_schema_invalid")
    for field, limit in (
        ("source_schema", 64),
        ("session_id", 512),
        ("scan_date", 512),
        ("status", 128),
        ("risk_level", 64),
        ("analysis", _MAX_TEXT_BYTES),
        ("raw_output", _MAX_TEXT_BYTES),
        ("summary_id", 512),
        ("summary_session_id", 512),
        ("generated_at", 512),
    ):
        if field in value:
            _validate_text(errors, f"legacy_adapter:{field}", value.get(field), limit)


def _validate_legacy_fields(
    errors: list[str],
    section: str,
    item_id: str,
    value: Any,
) -> None:
    if not isinstance(value, Mapping):
        errors.append(f"legacy_fields_not_mapping:{section}:{item_id}")
        return
    if set(value) - _LEGACY_FIELD_KEYS:
        errors.append(f"legacy_fields_unexpected_field:{section}:{item_id}")
    for field, limit in (
        ("legacy_id", 512),
        ("session_id", 512),
        ("title", 512),
        ("port", 128),
        ("service", 512),
        ("description", _MAX_TEXT_BYTES),
        ("confidence", 128),
        ("evidence_source", 512),
        ("raw_evidence", _MAX_TEXT_BYTES),
        ("reproduction_command", _MAX_TEXT_BYTES),
        ("tool", 512),
        ("payload", _MAX_TEXT_BYTES),
        ("result", _MAX_TEXT_BYTES),
        ("notes", _MAX_TEXT_BYTES),
    ):
        if field in value:
            _validate_text(
                errors,
                f"legacy_fields:{section}:{item_id}:{field}",
                value.get(field),
                limit,
            )
    score = value.get("cvss_score")
    if score is not None and (not _is_nonnegative_number(score) or float(score) > 10.0):
        errors.append(f"legacy_fields_invalid_cvss:{section}:{item_id}")
    remediations = value.get("remediations")
    if remediations is not None:
        if not isinstance(remediations, list):
            errors.append(f"legacy_remediations_not_list:{section}:{item_id}")
        elif len(remediations) > _MAX_REFS:
            errors.append(f"legacy_remediations_unbounded:{section}:{item_id}")
        else:
            for index, remediation in enumerate(remediations):
                if not isinstance(remediation, Mapping) or set(remediation) != _LEGACY_REMEDIATION_KEYS:
                    errors.append(f"legacy_remediation_invalid:{section}:{item_id}:{index}")
                    continue
                for field, limit in (
                    ("id", 512),
                    ("session_id", 512),
                    ("text", _MAX_TEXT_BYTES),
                    ("source", 512),
                ):
                    _validate_text(
                        errors,
                        f"legacy_remediation:{section}:{item_id}:{index}:{field}",
                        remediation.get(field),
                        limit,
                    )


def _validate_positive_int_list(errors: list[str], name: str, value: Any) -> None:
    if not isinstance(value, list):
        errors.append(f"not_list:{name}")
        return
    if len(value) > _MAX_REFS:
        errors.append(f"unbounded_list:{name}")
    if any(_positive_int(item) is None for item in value):
        errors.append(f"invalid_positive_int_list:{name}")


def _validate_text_list(
    errors: list[str],
    name: str,
    value: Any,
    limit: int,
) -> None:
    if not isinstance(value, list):
        errors.append(f"not_list:{name}")
        return
    if len(value) > _MAX_REFS:
        errors.append(f"unbounded_list:{name}")
    for index, item in enumerate(value):
        _validate_text(errors, f"{name}:{index}", item, limit)


def _validate_text(
    errors: list[str],
    name: str,
    value: Any,
    limit: int,
    *,
    required: bool = False,
) -> None:
    if not isinstance(value, str):
        errors.append(f"text_required:{name}")
        return
    if required and not value:
        errors.append(f"text_empty:{name}")
    if len(value.encode("utf-8", "replace")) > limit:
        errors.append(f"text_unbounded:{name}")


def _is_nonnegative_number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(float(value)) and float(value) >= 0.0


def _is_json_scalar(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _canonical_evidence_index(
    facts: Sequence[Mapping[str, Any]],
    supplied: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_fact_id = {
        _positive_int(item.get("fact_id")): dict(item)
        for item in supplied
        if isinstance(item, Mapping) and _positive_int(item.get("fact_id")) is not None
    }
    records: list[dict[str, Any]] = []
    for index, fact in enumerate(facts, 1):
        fact_id = _positive_int(fact.get("id"))
        existing = dict(by_fact_id.get(fact_id, {}))
        evidence_ref = _evidence_ref(fact)
        assessment = _assessment(fact)
        existing.update(
            {
                "evidence_id": existing.get("evidence_id") or f"E-{index:03d}",
                "evidence_ref": evidence_ref,
                "fact_id": fact_id,
                "fact_type": _text(fact.get("type"), 256),
                "fact_value": _text(fact.get("value"), _MAX_TEXT_BYTES),
                "assessment_ref": _assessment_ref(fact),
                "assessment_status": _assessment_status(fact),
                "assessment_reason": _text(assessment.get("reason"), _MAX_TEXT_BYTES),
                "trust_level": _text(fact.get("trust_level") or "trusted", 64),
                "source_execution_ids": _refs(
                    assessment.get("source_execution_ids") or fact.get("source_execution_ids")
                ),
            }
        )
        records.append(existing)
    return records


def _fact_item(
    section: str,
    fact: Mapping[str, Any],
    evidence_by_fact: Mapping[int | None, Mapping[str, Any]],
) -> dict[str, Any]:
    assessment = _assessment(fact)
    chain = _evidence_chain(fact, evidence_by_fact)
    status = _assessment_status(fact)
    source_execution_ids = _refs(assessment.get("source_execution_ids") or fact.get("source_execution_ids"))
    reasons = _refs(
        [assessment.get("reason") or fact.get("assessment_reason")],
        text_limit=_MAX_TEXT_BYTES,
    )
    assessment_refs = _refs([_assessment_ref(fact)])
    coverage_status = str(fact.get("coverage_status") or "").strip().lower()
    freshness_status = str(fact.get("freshness_status") or "").strip().lower()
    if coverage_status == "degraded":
        report_status = "degraded"
    elif freshness_status == "stale":
        report_status = "stale"
    elif status == "verified" and not (chain and source_execution_ids and reasons):
        report_status = "verification_metadata_incomplete"
    else:
        report_status = status
    fact_id = _positive_int(fact.get("id"))
    identity = fact_id or {
        "type": fact.get("type"),
        "value": fact.get("value"),
        "source": fact.get("source"),
    }
    return {
        "item_id": _stable_id(section, identity),
        "kind": _text(fact.get("type"), 256),
        "title": _text(fact.get("type"), 256).replace("_", " ").title(),
        "detail": _text(fact.get("value"), _MAX_TEXT_BYTES),
        "severity": _severity(fact),
        "status": report_status,
        "assessment_status": status,
        "scope": {"type": "asset", "value": _text(fact.get("host"), 2_048)},
        "fact_ids": [fact_id] if fact_id is not None else [],
        "evidence_chain": chain,
        "source_execution_ids": source_execution_ids,
        "assessment_refs": assessment_refs,
        "assessment_reasons": reasons,
        "sources": _refs(fact.get("sources") or ([fact.get("source")] if fact.get("source") else [])),
        "timestamp": _number(fact.get("timestamp")),
    }


def _access_item(
    facts: Sequence[Mapping[str, Any]],
    evidence_by_fact: Mapping[int | None, Mapping[str, Any]],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    # Never let aggregate state upgrade an authenticated-access observation to
    # root severity.  Severity is derived again from the exact supporting facts
    # that passed the report-verification boundary.
    root = any(_is_root_access_fact(fact) for fact in facts)
    fact_items = [_fact_item("access_findings", fact, evidence_by_fact) for fact in facts]
    chain = _dedupe_dicts(link for item in fact_items for link in item["evidence_chain"])[:_MAX_CHAIN_ITEMS]
    source_ids = _refs(value for item in fact_items for value in item["source_execution_ids"])
    assessment_refs = _refs(value for item in fact_items for value in item["assessment_refs"])
    reasons = _refs(
        (value for item in fact_items for value in item["assessment_reasons"]),
        text_limit=_MAX_TEXT_BYTES,
    )
    fact_ids = sorted({fact_id for item in fact_items for fact_id in item["fact_ids"] if fact_id is not None})[
        :_MAX_REFS
    ]
    return {
        "item_id": _stable_id("access_findings", {"root": root, "facts": fact_ids}),
        "kind": "root_access" if root else "authenticated_access",
        "title": "Root access confirmed" if root else "Authenticated access confirmed",
        "detail": "Access is reported separately from vulnerability classification.",
        "severity": "CRITICAL" if root else "HIGH",
        "status": "verified",
        "assessment_status": "verified",
        "scope": {"type": "asset", "value": _text(facts[0].get("host"), 2_048)},
        "fact_ids": fact_ids,
        "evidence_chain": chain,
        "source_execution_ids": source_ids,
        "assessment_refs": assessment_refs,
        "assessment_reasons": reasons,
        "sources": _refs(value for item in fact_items for value in item["sources"]),
        "timestamp": max((item["timestamp"] for item in fact_items), default=0.0),
    }


def _hypothesis_item(hypothesis: Mapping[str, Any]) -> dict[str, Any]:
    hypothesis_id = _positive_int(hypothesis.get("id"))
    claim = _text(hypothesis.get("claim"), _MAX_TEXT_BYTES)
    identity: Any = hypothesis_id or {
        "claim": claim,
        "source": hypothesis.get("source"),
    }
    return {
        "item_id": _stable_id("hypotheses_candidates", identity),
        "kind": "hypothesis",
        "title": "Hypothesis / candidate",
        "detail": claim,
        "severity": "INFO",
        "status": "candidate",
        "assessment_status": "unassessed",
        "scope": {"type": "asset", "value": _text(hypothesis.get("host"), 2_048)},
        "fact_ids": [],
        "evidence_chain": [],
        "source_execution_ids": [],
        "assessment_refs": [],
        "assessment_reasons": [],
        "required_evidence": _refs(hypothesis.get("required_evidence") or [], text_limit=_MAX_TEXT_BYTES),
        "sources": _refs([hypothesis.get("source")]),
        "timestamp": _number(hypothesis.get("timestamp")),
    }


def _add_coverage_items(
    sections: dict[str, list[dict[str, Any]]],
    seen: dict[str, set[str]],
    coverage: Mapping[str, Any],
    context: Mapping[str, Any],
) -> None:
    candidates: list[Any] = list(coverage.get("checked_but_not_confirmed") or [])
    candidates.extend(context.get("coverage_gaps") or [])
    target_coverage = (context.get("target_model") or {}).get("coverage") or {}
    candidates.extend(target_coverage.get("gaps") or [])
    for candidate in candidates:
        payload = dict(candidate) if isinstance(candidate, Mapping) else {"status": candidate}
        detail = _text(
            payload.get("reason") or payload.get("status") or payload.get("gap") or payload,
            _MAX_TEXT_BYTES,
        )
        item = _operational_item(
            "coverage_gaps",
            payload,
            kind="coverage_gap",
            status="open",
            detail=detail,
        )
        _append(sections, seen, "coverage_gaps", item)


def _add_degraded_check_items(
    sections: dict[str, list[dict[str, Any]]],
    seen: dict[str, set[str]],
    coverage: Mapping[str, Any],
    command_results: Sequence[Mapping[str, Any]],
    command_trace: Sequence[Mapping[str, Any]],
) -> None:
    for degraded in coverage.get("degraded") or []:
        payload = dict(degraded) if isinstance(degraded, Mapping) else {"status": degraded}
        status = _text(payload.get("status"), 128).lower() or "degraded"
        item = _operational_item(
            "policy_blocked_degraded_checks",
            payload,
            kind="degraded_check",
            status=status,
            detail=_text(payload.get("impact") or payload, _MAX_TEXT_BYTES),
        )
        _append(sections, seen, "policy_blocked_degraded_checks", item)
    for result in command_results:
        if not isinstance(result, Mapping):
            continue
        status = _text(result.get("status"), 128).lower()
        if status not in _DEGRADED_STATUSES:
            continue
        payload = {
            "id": result.get("id"),
            "command_key": result.get("command_key"),
            "status": status,
            "execution_id": result.get("execution_id"),
            "policy_decision_ref": result.get("policy_decision_ref"),
            "error_class": result.get("error_class"),
            "timestamp": result.get("timestamp"),
        }
        item = _operational_item(
            "policy_blocked_degraded_checks",
            payload,
            kind="policy_blocked" if status == "blocked" else "degraded_execution",
            status=status,
            detail=_text(result.get("command_key") or result.get("command"), _MAX_TEXT_BYTES),
        )
        item["source_execution_ids"] = _refs([result.get("execution_id")])
        item["policy_refs"] = _refs([result.get("policy_decision_ref")])
        item["timestamp"] = _number(result.get("timestamp"))
        _append(sections, seen, "policy_blocked_degraded_checks", item)
    for decision in command_trace:
        if not isinstance(decision, Mapping) or decision.get("action") != "skip":
            continue
        item = _operational_item(
            "policy_blocked_degraded_checks",
            decision,
            kind="policy_skip",
            status="blocked",
            detail=_text(decision.get("reason") or "policy_skip", _MAX_TEXT_BYTES),
        )
        _append(sections, seen, "policy_blocked_degraded_checks", item)


def _add_action_report_items(
    sections: dict[str, list[dict[str, Any]]],
    seen: dict[str, set[str]],
    action_reports: Sequence[Any],
) -> None:
    for raw_report in action_reports:
        if hasattr(raw_report, "to_dict"):
            raw_report = raw_report.to_dict()
        if not isinstance(raw_report, Mapping):
            continue
        report = dict(raw_report)
        descriptor = report.get("descriptor") or {}
        lifecycle = report.get("lifecycle") or {}
        action_id = _text(descriptor.get("action_id") or descriptor.get("name"), 512)
        attempt = _text(lifecycle.get("attempt"), 128).lower()
        verification = _text(lifecycle.get("verification"), 128).lower()
        if attempt == "attempted" and verification != "verified":
            item = _operational_item(
                "attempted_unverified",
                {"action_id": action_id, "lifecycle": lifecycle},
                kind="action_attempt",
                status="attempted_unverified",
                detail=action_id,
            )
            result = report.get("execution_result") or {}
            verification_result = report.get("verification_result") or {}
            item["source_execution_ids"] = _refs(
                verification_result.get("source_execution_ids") or [result.get("execution_id")]
            )
            item["assessment_refs"] = _refs(verification_result.get("assessment_refs") or [])
            item["assessment_reasons"] = _refs([verification_result.get("reason")], text_limit=_MAX_TEXT_BYTES)
            item["evidence_chain"] = [
                {
                    "evidence_ref": f"evidence://fact/{fact_id}",
                    "fact_id": fact_id,
                    "relation": "verification",
                }
                for fact_id in _positive_ints(verification_result.get("evidence_fact_ids") or [])[:_MAX_CHAIN_ITEMS]
            ]
            _append(sections, seen, "attempted_unverified", item)
        cleanup = _text(lifecycle.get("cleanup"), 128).lower()
        if cleanup and cleanup != "not_required":
            cleanup_result = report.get("cleanup_result") or {}
            item = _operational_item(
                "cleanup_outcomes",
                {"action_id": action_id, "cleanup": cleanup},
                kind="action_cleanup",
                status=cleanup,
                detail=_text(cleanup_result.get("reason") or action_id, _MAX_TEXT_BYTES),
            )
            _append(sections, seen, "cleanup_outcomes", item)


def _add_state_cleanup_item(
    sections: dict[str, list[dict[str, Any]]],
    seen: dict[str, set[str]],
    state: Mapping[str, Any],
) -> None:
    if "cleanup_completed" not in state:
        return
    completed = bool(state.get("cleanup_completed"))
    item = _operational_item(
        "cleanup_outcomes",
        {"state_gate": "cleanup_completed", "completed": completed},
        kind="cleanup_stage_gate",
        status="succeeded" if completed else "not_completed",
        detail="Canonical cleanup stage gate.",
    )
    _append(sections, seen, "cleanup_outcomes", item)


def _operational_item(
    section: str,
    payload: Mapping[str, Any],
    *,
    kind: str,
    status: str,
    detail: str,
) -> dict[str, Any]:
    identity = {
        key: payload.get(key)
        for key in sorted(payload)
        if key not in {"timestamp", "duration", "created_at", "updated_at"}
    }
    return {
        "item_id": _stable_id(section, identity),
        "kind": kind,
        "title": kind.replace("_", " ").title(),
        "detail": detail,
        "severity": "INFO",
        "status": status,
        "assessment_status": "not_applicable",
        "scope": {},
        "fact_ids": [],
        "evidence_chain": [],
        "source_execution_ids": [],
        "assessment_refs": [],
        "assessment_reasons": [],
        "timestamp": _number(payload.get("timestamp")),
    }


def _evidence_chain(
    fact: Mapping[str, Any],
    evidence_by_fact: Mapping[int | None, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    assessment = _assessment(fact)
    subject_id = _positive_int(fact.get("id"))
    supporting = _positive_ints(assessment.get("evidence_fact_ids") or fact.get("derived_from") or [])
    ordered = _positive_ints([subject_id, *supporting])
    chain = []
    for fact_id in ordered[:_MAX_CHAIN_ITEMS]:
        evidence = evidence_by_fact.get(fact_id) or {}
        chain.append(
            {
                "evidence_ref": evidence.get("evidence_ref") or f"evidence://fact/{fact_id}",
                "evidence_id": evidence.get("evidence_id") or "",
                "fact_id": fact_id,
                "relation": "subject" if fact_id == subject_id else "supporting",
            }
        )
    return chain


def _report_verified(
    fact: Mapping[str, Any],
    evidence_by_fact: Mapping[int | None, Mapping[str, Any]],
) -> bool:
    if _assessment_status(fact) != "verified" or not fact_is_decision_usable(fact):
        return False
    assessment = _assessment(fact)
    return bool(
        _evidence_chain(fact, evidence_by_fact)
        and _text(assessment.get("reason") or fact.get("assessment_reason"), _MAX_TEXT_BYTES)
        and _refs(assessment.get("source_execution_ids") or fact.get("source_execution_ids"))
    )


def _verification_gap(
    fact: Mapping[str, Any],
    evidence_by_fact: Mapping[int | None, Mapping[str, Any]],
) -> str:
    status = _assessment_status(fact)
    if status == "contradicted":
        return "current_assessment_contradicted"
    if str(fact.get("coverage_status") or "").strip().lower() == "degraded":
        return "degraded_evidence_coverage"
    if str(fact.get("freshness_status") or "").strip().lower() == "stale":
        return "stale_evidence"
    if status != "verified":
        return f"current_assessment_{status}"
    if not _evidence_chain(fact, evidence_by_fact):
        return "missing_evidence_chain"
    assessment = _assessment(fact)
    if not _text(assessment.get("reason") or fact.get("assessment_reason"), _MAX_TEXT_BYTES):
        return "missing_assessment_reason"
    if not _refs(assessment.get("source_execution_ids") or fact.get("source_execution_ids")):
        return "missing_source_execution_ids"
    return "none"


def _candidate_status(fact: Mapping[str, Any]) -> str:
    status = _assessment_status(fact)
    if status == "contradicted":
        return "contradicted"
    return "candidate"


def _is_access_fact(fact_type: str, fact: Mapping[str, Any]) -> bool:
    value = _text(fact.get("value"), _MAX_TEXT_BYTES).lower()
    if fact_type == "system_access":
        return value in {"uid=0", "root_access_confirmed"}
    if fact_type == "application_access":
        return value == "authenticated_access_confirmed"
    if fact_type == "verified_access":
        return value in {
            "authenticated_access_confirmed",
            "root_access_confirmed",
        }
    if fact_type == "credential":
        return (
            re.fullmatch(
                r"ssh_login_success:[^\s@:]+(?:@[^\s:]+(?::\d{1,5})?)?",
                value,
            )
            is not None
        )
    if fact_type == "service_status":
        return value == "ssh_authenticated"
    return False


def _is_root_access_fact(fact: Mapping[str, Any]) -> bool:
    fact_type = _text(fact.get("type"), 256).lower()
    value = _text(fact.get("value"), _MAX_TEXT_BYTES).lower()
    if fact_type == "system_access":
        return value in {"uid=0", "root_access_confirmed"}
    if fact_type == "verified_access":
        return value == "root_access_confirmed"
    if fact_type == "credential":
        return (
            re.fullmatch(
                r"ssh_login_success:root(?:@[^\s:]+(?::\d{1,5})?)?",
                value,
            )
            is not None
        )
    return False


def _is_cleanup_fact(fact_type: str, fact: Mapping[str, Any]) -> bool:
    del fact_type
    return confirms_cleanup(fact)


def _looks_like_cve_candidate(fact_type: str, fact: Mapping[str, Any]) -> bool:
    if fact_type not in {"candidate", "finding", "version_match"}:
        return False
    value = _text(fact.get("value"), _MAX_TEXT_BYTES).upper()
    return "CVE-" in value


def _assessment(fact: Mapping[str, Any]) -> dict[str, Any]:
    value = fact.get("assessment")
    return dict(value) if isinstance(value, Mapping) else {}


def _assessment_ref(fact: Mapping[str, Any]) -> str:
    assessment = _assessment(fact)
    return _text(assessment.get("assessment_id") or fact.get("assessment_id"), 512)


def _assessment_status(fact: Mapping[str, Any]) -> str:
    assessment = _assessment(fact)
    status = _text(
        assessment.get("status") or fact.get("assessment_status") or "observed",
        64,
    ).lower()
    return status if status in {"observed", "inferred", "verified", "contradicted"} else "observed"


def _evidence_ref(fact: Mapping[str, Any]) -> str:
    fact_id = _positive_int(fact.get("id"))
    if fact_id is not None:
        return f"evidence://fact/{fact_id}"
    return _stable_id(
        "evidence",
        {
            "type": fact.get("type"),
            "value": fact.get("value"),
            "source": fact.get("source"),
        },
    )


def _vulnerability_severity(fact: Mapping[str, Any]) -> str:
    raw = _text(fact.get("severity"), 32).upper()
    return raw if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "HIGH"


def _severity(fact: Mapping[str, Any]) -> str:
    raw = _text(fact.get("severity"), 32).upper()
    return raw if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO"


def _item_evidence_complete(item: Mapping[str, Any]) -> bool:
    return bool(item.get("evidence_chain") and item.get("source_execution_ids") and item.get("assessment_reasons"))


def _append(
    sections: dict[str, list[dict[str, Any]]],
    seen: dict[str, set[str]],
    section: str,
    item: dict[str, Any],
) -> None:
    item_id = str(item.get("item_id") or "")
    if not item_id or item_id in seen[section]:
        return
    seen[section].add(item_id)
    sections[section].append(item)


def _item_sort_key(item: Mapping[str, Any]) -> tuple[float, str]:
    return (_number(item.get("timestamp")), str(item.get("item_id") or ""))


def _stable_id(namespace: str, payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8", "replace")
    return f"{namespace}://sha256/{hashlib.sha256(encoded).hexdigest()}"


def _dedupe_dicts(items: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        key = json.dumps(item, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(item))
    return result


def _refs(
    values: Any,
    *,
    text_limit: int = 512,
) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes)):
        values = [values]
    result: list[str] = []
    for value in values:
        text = _text(value, text_limit)
        if text and text not in result:
            result.append(text)
        if len(result) >= _MAX_REFS:
            break
    return result


def _positive_ints(values: Any) -> list[int]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, int)):
        values = [values]
    result: list[int] = []
    for value in values:
        parsed = _positive_int(value)
        if parsed is not None and parsed not in result:
            result.append(parsed)
    return result


def _positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _number(value: Any) -> float:
    try:
        parsed = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return parsed if parsed >= 0 else 0.0


def _text(value: Any, max_bytes: int) -> str:
    if value is None:
        return ""
    raw = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list, tuple)) else str(value)
    encoded = raw.encode("utf-8", "replace")
    if len(encoded) <= max_bytes:
        return raw
    return encoded[:max_bytes].decode("utf-8", "ignore")


__all__ = [
    "EVIDENCE_REPORT_SCHEMA_VERSION",
    "EVIDENCE_REPORT_SECTION_ORDER",
    "build_evidence_report",
    "validate_evidence_report",
]
