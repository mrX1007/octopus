"""Canonical report ingress and presentation projection for all exporters.

The evidence-backed ``machine_report`` is the only exporter input model.  The
legacy relational session shape is supported at the boundary by the explicit
``legacy_session_to_machine_report`` adapter; renderers never consume database
tuples directly.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from core.ai.report_schema import (
    EVIDENCE_REPORT_SECTION_ORDER,
    build_evidence_report,
    validate_evidence_report,
)
from core.secrets import get_redactor, is_secret_ref, redact_data, redact_text

_MAX_LEGACY_FINDINGS = 256
_MAX_LEGACY_ATTEMPTS = 256
_MAX_LEGACY_FIXES = 256
_MAX_LEGACY_REMEDIATIONS = 64
_MAX_LEGACY_TEXT_BYTES = 4_096

_SSHPASS_SECRET_RE = re.compile(
    r"(?ix)(?P<prefix>\bsshpass\b\s+-p\s+)"
    r"(?P<value>'[^']*'|\"[^\"]*\"|[^\s]+)"
)
_USERINFO_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_:/])(?P<user>[A-Za-z0-9_.@\\-]{1,128}):"
    r"(?P<value>[^\s,;]{4,})"
)
_NON_CREDENTIAL_PREFIXES = frozenset(
    {
        "http",
        "https",
        "ftp",
        "ssh",
        "evidence",
        "legacy",
        "login_success",
        "pth_auth_success",
        "scan",
        "service",
        "port",
        "sha256",
        "ssh_key_available",
        "ssh_login_success",
        "cracked_password_for",
    }
)


class MachineReportError(ValueError):
    """Raised when an exporter receives no valid canonical report."""


def extract_machine_report(
    data: Mapping[str, Any],
    *,
    include_legacy_raw_output: bool = False,
) -> dict[str, Any]:
    """Return a validated canonical report from a supported input envelope.

    Supported inputs are the canonical report itself, a pipeline/trace envelope
    containing ``machine_report``, or the historical DB-session mapping.  No
    other implicit schema conversion is performed.
    """

    if not isinstance(data, Mapping):
        raise TypeError("report input must be a mapping")

    if _looks_like_machine_report(data):
        report = deepcopy(dict(data))
    elif isinstance(data.get("machine_report"), Mapping):
        report = deepcopy(dict(data["machine_report"]))
    elif _looks_like_legacy_session(data):
        report = legacy_session_to_machine_report(
            data,
            include_raw_output=include_legacy_raw_output,
        )
    else:
        raise MachineReportError(
            "report input must be a canonical machine_report, a machine_report "
            "envelope, or an explicit legacy DB session"
        )

    errors = validate_evidence_report(report)
    if errors:
        raise MachineReportError("invalid machine_report: " + "; ".join(errors))
    report = _sanitize_report_data(report)
    errors = validate_evidence_report(report)
    if errors:
        raise MachineReportError("redacted machine_report violates its schema: " + "; ".join(errors))
    return report


def legacy_session_to_machine_report(
    data: Mapping[str, Any],
    *,
    include_raw_output: bool = False,
) -> dict[str, Any]:
    """Adapt the historical relational session mapping to ``machine_report``.

    Legacy confidence is presentation metadata, not a current evidence-backed
    assessment.  Every imported finding therefore remains a candidate.  The
    adapter preserves the historical fields in a closed, bounded extension but
    never invents assessment, execution, or verification references.
    """

    if not isinstance(data, Mapping):
        raise TypeError("legacy session must be a mapping")
    allowed_fields = {
        "history",
        "vulns",
        "vulnerabilities",
        "fixes",
        "exploits",
        "summary",
    }
    unexpected_fields = set(data) - allowed_fields
    if unexpected_fields:
        rendered = ", ".join(sorted(str(field) for field in unexpected_fields))
        raise MachineReportError(f"legacy session contains unsupported fields: {rendered}")
    if "vulns" in data and "vulnerabilities" in data:
        raise MachineReportError("legacy session contains both vulnerability aliases")
    history = data.get("history")
    if not isinstance(history, (list, tuple)) or len(history) < 2:
        raise MachineReportError("legacy session report has no history row")
    if len(history) > 4:
        raise MachineReportError("legacy history row exceeds the supported width")

    vulnerability_rows = data.get("vulns")
    if vulnerability_rows is None:
        vulnerability_rows = data.get("vulnerabilities")
    vulnerabilities = _legacy_rows(
        vulnerability_rows,
        "vulnerabilities",
        _MAX_LEGACY_FINDINGS,
        12,
    )
    fixes = _legacy_rows(data.get("fixes"), "fixes", _MAX_LEGACY_FIXES, 5)
    exploits = _legacy_rows(
        data.get("exploits"),
        "exploits",
        _MAX_LEGACY_ATTEMPTS,
        7,
    )
    summary = data.get("summary")
    if summary is not None and not isinstance(summary, (list, tuple)):
        raise MachineReportError("legacy summary row must be a list or tuple")
    if isinstance(summary, (list, tuple)) and len(summary) > 6:
        raise MachineReportError("legacy summary row exceeds the supported width")

    session_id = _legacy_text(
        _row_value(history, 0, "unknown"),
        "session_id",
        512,
    )
    target = _legacy_text(
        _row_value(history, 1, "unknown target"),
        "target",
        2_048,
    )
    scan_id = f"legacy-session:{session_id}"
    facts: list[dict[str, Any]] = []
    legacy_by_fact_id: dict[int, dict[str, Any]] = {}
    fixes_by_vulnerability: dict[str, list[dict[str, Any]]] = {}
    known_vulnerability_ids: set[str] = set()

    for fix in fixes:
        legacy_vulnerability_id = _legacy_text(
            _row_value(fix, 2, ""),
            "fix.vulnerability_id",
            512,
        )
        remediations = fixes_by_vulnerability.setdefault(legacy_vulnerability_id, [])
        if len(remediations) >= _MAX_LEGACY_REMEDIATIONS:
            raise MachineReportError("legacy fixes exceed the per-finding remediation bound")
        remediations.append(
            {
                "id": _legacy_text(_row_value(fix, 0, ""), "fix.id", 512),
                "session_id": _legacy_text(
                    _row_value(fix, 1, ""),
                    "fix.session_id",
                    512,
                ),
                "text": _legacy_text(
                    _row_value(fix, 3, ""),
                    "fix.text",
                    _MAX_LEGACY_TEXT_BYTES,
                ),
                "source": _legacy_text(
                    _row_value(fix, 4, ""),
                    "fix.source",
                    512,
                ),
            }
        )

    for vulnerability in vulnerabilities:
        fact_id = len(facts) + 1
        legacy_id = _legacy_text(
            _row_value(vulnerability, 0, fact_id),
            "vulnerability.id",
            512,
        )
        known_vulnerability_ids.add(legacy_id)
        confidence = (
            _legacy_text(
                _row_value(vulnerability, 7, ""),
                "vulnerability.confidence",
                128,
            )
            .strip()
            .upper()
        )
        source = _legacy_text(
            _row_value(vulnerability, 8, "legacy_db") or "legacy_db",
            "vulnerability.source",
            512,
        )
        title = _legacy_text(
            _row_value(vulnerability, 2, "Unnamed finding"),
            "vulnerability.title",
            512,
        )
        severity = _legacy_text(
            _row_value(vulnerability, 3, "UNKNOWN"),
            "vulnerability.severity",
            32,
        )
        fact: dict[str, Any] = {
            "id": fact_id,
            "scan_id": scan_id,
            "host": target,
            "type": "potential_vulnerability",
            "value": title,
            "severity": severity,
            "source": source,
            "sources": [source],
            "assessment_status": "observed",
        }
        facts.append(fact)
        legacy_by_fact_id[fact_id] = {
            "legacy_id": legacy_id,
            "session_id": _legacy_text(
                _row_value(vulnerability, 1, ""),
                "vulnerability.session_id",
                512,
            ),
            "title": title,
            "port": _legacy_text(
                _row_value(vulnerability, 4, ""),
                "vulnerability.port",
                128,
            ),
            "service": _legacy_text(
                _row_value(vulnerability, 5, ""),
                "vulnerability.service",
                512,
            ),
            "description": _legacy_text(
                _row_value(vulnerability, 6, ""),
                "vulnerability.description",
                _MAX_LEGACY_TEXT_BYTES,
            ),
            "confidence": confidence,
            "evidence_source": source,
            "raw_evidence": (
                _legacy_text(
                    _row_value(vulnerability, 9, ""),
                    "vulnerability.raw_evidence",
                    _MAX_LEGACY_TEXT_BYTES,
                )
                if include_raw_output
                else ""
            ),
            "reproduction_command": _legacy_text(
                _row_value(vulnerability, 10, ""),
                "vulnerability.reproduction_command",
                _MAX_LEGACY_TEXT_BYTES,
            ),
            "cvss_score": _legacy_cvss(_row_value(vulnerability, 11, None)),
            "remediations": fixes_by_vulnerability.get(legacy_id, []),
        }

    for referenced_vulnerability_id, remediations in fixes_by_vulnerability.items():
        if referenced_vulnerability_id in known_vulnerability_ids:
            continue
        for remediation in remediations:
            fact_id = len(facts) + 1
            source = remediation["source"] or "legacy_db"
            facts.append(
                {
                    "id": fact_id,
                    "scan_id": scan_id,
                    "host": target,
                    "type": "legacy_remediation",
                    "value": remediation["text"] or "Legacy remediation",
                    "source": source,
                    "sources": [source],
                    "assessment_status": "observed",
                }
            )
            legacy_by_fact_id[fact_id] = {
                "legacy_id": referenced_vulnerability_id,
                "session_id": remediation["session_id"],
                "remediations": [remediation],
            }

    for exploit in exploits:
        fact_id = len(facts) + 1
        legacy_id = _legacy_text(
            _row_value(exploit, 0, fact_id),
            "exploit.id",
            512,
        )
        source = _legacy_text(
            _row_value(exploit, 3, "legacy_db") or "legacy_db",
            "exploit.tool",
            512,
        )
        title = _legacy_text(
            _row_value(exploit, 2, "Unnamed attempt"),
            "exploit.title",
            512,
        )
        facts.append(
            {
                "id": fact_id,
                "scan_id": scan_id,
                "host": target,
                "type": "exploit_attempted",
                "value": title,
                "source": source,
                "sources": [source],
            }
        )
        legacy_by_fact_id[fact_id] = {
            "legacy_id": legacy_id,
            "session_id": _legacy_text(
                _row_value(exploit, 1, ""),
                "exploit.session_id",
                512,
            ),
            "tool": source,
            "payload": _legacy_text(
                _row_value(exploit, 4, ""),
                "exploit.payload",
                _MAX_LEGACY_TEXT_BYTES,
            ),
            "result": _legacy_text(
                _row_value(exploit, 5, ""),
                "exploit.result",
                _MAX_LEGACY_TEXT_BYTES,
            ),
            "notes": _legacy_text(
                _row_value(exploit, 6, ""),
                "exploit.notes",
                _MAX_LEGACY_TEXT_BYTES,
            ),
        }

    report = build_evidence_report(scan_id, target, facts)
    for section_name in report["section_order"]:
        for item in report["sections"][section_name]:
            fact_ids = item.get("fact_ids") or []
            if fact_ids and fact_ids[0] in legacy_by_fact_id:
                item["legacy_fields"] = legacy_by_fact_id[fact_ids[0]]

    report["legacy_adapter"] = {
        "source_schema": "octopus-db-session-v1",
        "session_id": session_id,
        "scan_date": _legacy_text(_row_value(history, 2, ""), "scan_date", 512),
        "status": _legacy_text(_row_value(history, 3, "unknown"), "status", 128),
        "risk_level": _legacy_text(
            _row_value(summary, 4, "UNKNOWN"),
            "risk_level",
            64,
        ),
        "analysis": _legacy_text(
            _row_value(summary, 3, ""),
            "analysis",
            _MAX_LEGACY_TEXT_BYTES,
        ),
        "raw_output": (
            _legacy_text(
                _row_value(summary, 2, ""),
                "raw_output",
                _MAX_LEGACY_TEXT_BYTES,
            )
            if include_raw_output
            else ""
        ),
        "summary_id": _legacy_text(_row_value(summary, 0, ""), "summary.id", 512),
        "summary_session_id": _legacy_text(
            _row_value(summary, 1, ""),
            "summary.session_id",
            512,
        ),
        "generated_at": _legacy_text(
            _row_value(summary, 5, ""),
            "summary.generated_at",
            512,
        ),
    }
    report = _sanitize_report_data(report)
    errors = validate_evidence_report(report)
    if errors:
        raise MachineReportError("legacy adapter produced invalid machine_report: " + "; ".join(errors))
    return report


def project_machine_report(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten every canonical item field into the shared renderer projection.

    The projection is deliberately lossless for the closed item schema.  Each
    non-JSON renderer may choose presentation syntax, but it receives the same
    provenance, assessment, operational, and bounded legacy fields.
    """

    errors = validate_evidence_report(report)
    if errors:
        raise MachineReportError("invalid machine_report: " + "; ".join(errors))
    sections = report["sections"]
    projected: list[dict[str, Any]] = []
    for section_name in report.get("section_order") or EVIDENCE_REPORT_SECTION_ORDER:
        for item in sections.get(section_name, []):
            legacy = item.get("legacy_fields") or {}
            scope = item.get("scope") or {}
            projected.append(
                {
                    "section": section_name,
                    "item_id": str(item.get("item_id") or ""),
                    "kind": str(item.get("kind") or ""),
                    "title": str(legacy.get("title") or item.get("title") or item.get("kind") or "Finding"),
                    "detail": str(legacy.get("description") or item.get("detail") or ""),
                    "severity": str(item.get("severity") or "INFO").upper(),
                    "status": str(item.get("status") or "unknown"),
                    "assessment_status": str(item.get("assessment_status") or ""),
                    "scope": deepcopy(dict(scope)),
                    "scope_value": str(scope.get("value") or report.get("target") or ""),
                    "fact_ids": list(item.get("fact_ids") or []),
                    "evidence_chain": deepcopy(list(item.get("evidence_chain") or [])),
                    "source_execution_ids": list(item.get("source_execution_ids") or []),
                    "assessment_refs": list(item.get("assessment_refs") or []),
                    "assessment_reasons": list(item.get("assessment_reasons") or []),
                    "sources": list(item.get("sources") or []),
                    "timestamp": item.get("timestamp", 0.0),
                    "verification_gap": str(item.get("verification_gap") or ""),
                    "required_evidence": list(item.get("required_evidence") or []),
                    "policy_refs": list(item.get("policy_refs") or []),
                    "legacy_id": str(legacy.get("legacy_id") or ""),
                    "legacy_session_id": str(legacy.get("session_id") or ""),
                    "port": str(legacy.get("port") or ""),
                    "service": str(legacy.get("service") or ""),
                    "confidence": str(legacy.get("confidence") or ""),
                    "evidence_source": str(
                        legacy.get("evidence_source") or ", ".join(str(value) for value in item.get("sources") or []),
                    ),
                    "raw_evidence": str(legacy.get("raw_evidence") or ""),
                    "reproduction_command": str(legacy.get("reproduction_command") or ""),
                    "cvss_score": legacy.get("cvss_score"),
                    "remediations": deepcopy(list(legacy.get("remediations") or [])),
                    "tool": str(legacy.get("tool") or ""),
                    "payload": str(legacy.get("payload") or ""),
                    "result": str(legacy.get("result") or ""),
                    "notes": str(legacy.get("notes") or ""),
                    "evidence_refs": [
                        str(link.get("evidence_ref"))
                        for link in item.get("evidence_chain") or []
                        if isinstance(link, Mapping) and link.get("evidence_ref")
                    ],
                }
            )
    return projected


def _looks_like_machine_report(data: Mapping[str, Any]) -> bool:
    return (
        "schema_version" in data
        and isinstance(data.get("sections"), Mapping)
        and isinstance(data.get("evidence_index"), list)
    )


def _looks_like_legacy_session(data: Mapping[str, Any]) -> bool:
    return "history" in data and any(
        key in data for key in ("vulns", "vulnerabilities", "fixes", "exploits", "summary")
    )


def _row_value(row: Any, index: int, default: Any = "") -> Any:
    if not isinstance(row, (list, tuple)) or len(row) <= index or row[index] is None:
        return default
    return row[index]


def _legacy_rows(
    value: Any,
    name: str,
    limit: int,
    max_width: int,
) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise MachineReportError(f"legacy {name} must be a list or tuple")
    if len(value) > limit:
        raise MachineReportError(f"legacy {name} exceed the supported bound of {limit}")
    rows = list(value)
    if any(not isinstance(row, (list, tuple)) for row in rows):
        raise MachineReportError(f"legacy {name} contain a non-row value")
    if any(len(row) > max_width for row in rows):
        raise MachineReportError(f"legacy {name} contain a row wider than supported")
    return rows


def _legacy_text(value: Any, name: str, limit: int) -> str:
    text = str(value if value is not None else "")
    if len(text.encode("utf-8", "replace")) > limit:
        raise MachineReportError(f"legacy {name} exceeds the supported text bound")
    return text


def _legacy_cvss(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        return None
    return score


def _sanitize_report_data(value: Any) -> Any:
    """Apply generic and report-semantic redaction before validation/export."""

    return _sanitize_report_value(redact_data(value))


def _sanitize_report_value(value: Any, *, field: str = "") -> Any:
    if isinstance(value, Mapping):
        semantic_type = str(value.get("kind") or value.get("fact_type") or "").casefold()
        return {
            key: _sanitize_report_value(
                item,
                field=(
                    f"{semantic_type}:{key}"
                    if semantic_type in {"credential", "password", "private_key", "token"}
                    else str(key)
                ),
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_report_value(item, field=field) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_report_value(item, field=field) for item in value)
    if isinstance(value, str):
        return _sanitize_report_text(value, field=field)
    return value


def _sanitize_report_text(value: str, *, field: str) -> str:
    text = redact_text(value, kind=f"report:{field or 'text'}")

    def sshpass_secret(match: re.Match[str]) -> str:
        return match.group("prefix") + _redacted_token(
            match.group("value"),
            kind="report_command_password",
        )

    def credential_pair(match: re.Match[str]) -> str:
        user = match.group("user")
        secret = match.group("value")
        if (
            user.casefold() in _NON_CREDENTIAL_PREFIXES
            or secret.startswith(("//", "[REDACTED", "secret://"))
            or secret.isdigit()
            or not (
                field in {"payload", "reproduction_command", "command"}
                or field.startswith(("credential:", "password:", "private_key:", "token:"))
                or _looks_like_password(secret)
            )
        ):
            return match.group(0)
        return f"{user}:{_redacted_token(secret, kind='report_credential')}"

    text = _SSHPASS_SECRET_RE.sub(sshpass_secret, text)
    text = _USERINFO_SECRET_RE.sub(credential_pair, text)
    if field in {"payload", "password", "token", "private_key"}:
        stripped = text.strip()
        if (
            stripped == text
            and not any(character.isspace() for character in stripped)
            and _password_character_classes(stripped) >= 3
        ):
            return _redacted_token(stripped, kind=f"report_{field}")
    if field in {
        "credential:detail",
        "credential:fact_value",
        "password:detail",
        "password:fact_value",
        "private_key:detail",
        "private_key:fact_value",
        "token:detail",
        "token:fact_value",
    } and not (
        text.startswith(("ssh_login_success:", "secret://", "[REDACTED"))
        or text in {"credential_available", "login_success"}
    ):
        return _redacted_token(text, kind="report_typed_secret")
    return text


def _looks_like_password(value: str) -> bool:
    if len(value) < 6:
        return False
    return _password_character_classes(value) >= 2


def _password_character_classes(value: str) -> int:
    return sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )


def _redacted_token(value: str, *, kind: str) -> str:
    quote = ""
    plaintext = value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        plaintext = value[1:-1]
    if not plaintext or is_secret_ref(plaintext) or plaintext.startswith("[REDACTED"):
        return value
    reference = get_redactor().protect(plaintext, kind=kind)
    replacement = f"[REDACTED {reference}]"
    return f"{quote}{replacement}{quote}" if quote else replacement


__all__ = [
    "MachineReportError",
    "extract_machine_report",
    "legacy_session_to_machine_report",
    "project_machine_report",
]
