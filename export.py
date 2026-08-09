#!/usr/bin/env python3
"""Canonical machine-report exporters.

JSON, CSV, HTML and PDF all consume the same validated ``machine_report``.
Historical DB session tuples are accepted only through
``core.ai.report_export.legacy_session_to_machine_report``.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import unicodedata
from collections.abc import Mapping
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer

from core.ai.report_export import (
    MachineReportError,
    extract_machine_report,
    project_machine_report,
)
from core.secrets import redact_data, redact_text
from core.version import APPLICATION_VERSION
from db import get_all_history, get_session

try:
    from config import CFG
except ImportError:
    CFG = {}


SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
    "info": "#2980b9",
    "unknown": "#7f8c8d",
}


def _as_bool(value: Any, default: bool = False) -> bool:
    """Coerce YAML/environment-compatible values to a real boolean."""

    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    return default


def _reporting_option(name: str, default: bool) -> bool:
    reporting = CFG.get("reporting", {}) if isinstance(CFG, dict) else {}
    if not isinstance(reporting, dict):
        return default
    return _as_bool(reporting.get(name), default)


def _include_raw_output() -> bool:
    return _reporting_option("include_raw_output", False)


def _cvss_scoring_enabled() -> bool:
    return _reporting_option("cvss_scoring", True)


def _normalize_session_report(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize only the historical DB shape for compatibility callers.

    Exporters do not call this function.  Their sole input model is the
    canonical report returned by :func:`extract_machine_report`.
    """

    if not isinstance(data, dict):
        raise TypeError("session report must be a dictionary")
    data = redact_data(data)
    vulnerabilities = data.get("vulns")
    if vulnerabilities is None:
        vulnerabilities = data.get("vulnerabilities")
    return {
        "history": data.get("history"),
        "vulns": list(vulnerabilities or []),
        "fixes": list(data.get("fixes") or []),
        "exploits": list(data.get("exploits") or []),
        "summary": data.get("summary"),
    }


def _row_value(row: Any, index: int, default: Any = "") -> Any:
    if row is None or not hasattr(row, "__len__") or len(row) <= index or row[index] is None:
        return default
    return row[index]


def _safe_component(value: Any, fallback: str) -> str:
    text = unicodedata.normalize("NFKC", redact_text(value, kind="report_filename"))
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    return text[:120] or fallback


def _report_path(output_dir: str, report_id: Any, target: Any, extension: str) -> str:
    """Build a contained, non-symlink report filename under ``output_dir``."""

    root_input = os.path.abspath(os.path.expanduser(str(output_dir or ".")))
    os.makedirs(root_input, exist_ok=True)
    root = os.path.realpath(root_input)
    safe_report_id = _safe_component(report_id, "unknown")
    safe_target = _safe_component(target, "target")
    safe_ext = re.sub(r"[^a-z0-9]", "", str(extension).lower())
    if not safe_ext:
        raise ValueError("report extension must contain letters or digits")
    candidate = os.path.abspath(os.path.join(root, f"octopus_SL{safe_report_id}_{safe_target}.{safe_ext}"))
    try:
        contained = os.path.commonpath((root, candidate)) == root
    except ValueError:
        contained = False
    if not contained:
        raise ValueError("report filename escaped the configured output directory")
    if os.path.lexists(candidate) and os.path.islink(candidate):
        raise ValueError("refusing to overwrite a symbolic-link report path")
    return candidate


def _html_text(value: Any) -> str:
    return html.escape(redact_text(value, kind="report"), quote=True)


def _pdf_text(value: Any) -> str:
    return html.escape(redact_text(value, kind="report"), quote=True)


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formulas while preserving non-string values."""

    if not isinstance(value, str):
        return value
    value = redact_text(value, kind="report")
    stripped = value.lstrip(" \t\r\n")
    if value.startswith(("\t", "\r")) or (stripped and stripped[0] in "=+-@"):
        return "'" + value
    return value


def _cvss_from_severity(severity: str) -> float:
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
        "unknown": 0.0,
    }
    return mapping.get((severity or "unknown").lower(), 0.0)


def _vuln_cvss(vulnerability: Any) -> float | None:
    stored = _row_value(vulnerability, 11, None)
    if stored not in (None, ""):
        try:
            return float(stored)
        except (TypeError, ValueError):
            pass
    if not _cvss_scoring_enabled():
        return None
    return _cvss_from_severity(_sev(vulnerability))


def _cvss_display(vulnerability: Any) -> str:
    score = _vuln_cvss(vulnerability)
    return "-" if score is None else f"{score:.1f}"


def _raw_scan_output(data: dict[str, Any]) -> str:
    if not _include_raw_output():
        return ""
    return redact_text(_row_value(data.get("summary"), 2, ""), kind="report")


def _vulnerability_raw_evidence(vulnerability: Any) -> str:
    if not _include_raw_output():
        return ""
    return redact_text(_row_value(vulnerability, 9, ""), kind="report")


def _generate_executive_summary(data: dict[str, Any]) -> str:
    """Compatibility summary for callers that still hold a DB session."""

    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    target = _row_value(data["history"], 1, "unknown target")
    risk = str(_row_value(data["summary"], 4, "UNKNOWN") or "UNKNOWN")
    vulnerabilities = data["vulns"]
    critical = sum(1 for item in vulnerabilities if _sev(item) == "critical")
    high = sum(1 for item in vulnerabilities if _sev(item) == "high")
    exploitation = (
        f" {len(data['exploits'])} exploitation attempts were recorded."
        if data["exploits"]
        else " No active exploitation was performed during this assessment."
    )
    return (
        f"A security assessment was conducted against {target}. "
        f"It recorded {len(vulnerabilities)} findings ({critical} critical, "
        f"{high} high severity). The stored risk level is {risk.upper()}."
        f"{exploitation}"
    )


def _get_report_dir() -> str:
    try:
        from config import CFG as current_config

        return current_config["paths"]["reports"]
    except Exception:
        return os.path.expanduser("~/OCTOPUS/reports")


def _canonical_input(data: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report = extract_machine_report(
        data,
        include_legacy_raw_output=_include_raw_output(),
    )
    return report, project_machine_report(report)


def _report_identity(report: Mapping[str, Any]) -> tuple[str, str]:
    legacy = report.get("legacy_adapter") or {}
    display_identity = str(legacy.get("session_id") or report.get("scan_id") or report.get("report_id") or "unknown")
    canonical = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    # Keep the content digest first so filename component truncation can never
    # discard the collision-resistant portion of the identity.
    identity = f"{hashlib.sha256(canonical).hexdigest()[:20]}-{display_identity}"
    return identity, str(report.get("target") or "target")


def _section_label(section: str) -> str:
    return str(section).replace("_", " ").title()


def _item_cvss(item: Mapping[str, Any]) -> str:
    stored = item.get("cvss_score")
    if stored not in (None, ""):
        try:
            return f"{float(str(stored)):.1f}"
        except (TypeError, ValueError):
            pass
    if not _cvss_scoring_enabled():
        return "-"
    return f"{_cvss_from_severity(str(item.get('severity') or 'unknown')):.1f}"


def _projection_text(value: Any) -> str:
    if isinstance(value, (Mapping, list, tuple)):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    return str(value if value is not None else "")


def _item_detail_pairs(item: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Return the complete non-tabular projection for HTML and PDF."""

    values = (
        ("Kind", item.get("kind")),
        ("Assessment", item.get("assessment_status")),
        ("Scope", item.get("scope")),
        ("Port", item.get("port")),
        ("Service", item.get("service")),
        ("CVSS", _item_cvss(item)),
        ("Confidence", item.get("confidence")),
        ("Fact IDs", item.get("fact_ids")),
        ("Evidence chain", item.get("evidence_chain")),
        ("Source executions", item.get("source_execution_ids")),
        ("Assessment refs", item.get("assessment_refs")),
        ("Assessment reasons", item.get("assessment_reasons")),
        ("Sources", item.get("sources")),
        ("Evidence source", item.get("evidence_source")),
        ("Timestamp", item.get("timestamp")),
        ("Verification gap", item.get("verification_gap")),
        ("Required evidence", item.get("required_evidence")),
        ("Policy refs", item.get("policy_refs")),
        ("Legacy ID", item.get("legacy_id")),
        ("Legacy session ID", item.get("legacy_session_id")),
        ("Raw evidence", item.get("raw_evidence")),
        ("Reproduction command", item.get("reproduction_command")),
        ("Remediations", item.get("remediations")),
        ("Tool", item.get("tool")),
        ("Payload", item.get("payload")),
        ("Result", item.get("result")),
        ("Notes", item.get("notes")),
    )
    pairs = []
    for label, value in values:
        if value in (None, "", [], {}, ()):
            continue
        pairs.append((label, _projection_text(value)))
    return pairs


def export_json(data: Mapping[str, Any], output_dir: str = ".") -> str:
    """Write the canonical ``machine_report`` without a second JSON schema."""

    report, _items = _canonical_input(data)
    identity, target = _report_identity(report)
    filename = _report_path(output_dir, identity, target, "json")
    with open(filename, "w", encoding="utf-8") as handle:
        json.dump(
            report,
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        )
        handle.write("\n")
    return filename


def export_csv(data: Mapping[str, Any], output_dir: str = ".") -> str:
    """Write one row per canonical section item."""

    report, items = _canonical_input(data)
    identity, target = _report_identity(report)
    filename = _report_path(output_dir, identity, target, "csv")
    fields = [
        "Report ID",
        "Item ID",
        "Target",
        "Section",
        "Kind",
        "Title",
        "Severity",
        "Status",
        "Assessment Status",
        "Scope",
        "CVSS",
        "Port",
        "Service",
        "Description",
        "Confidence",
        "Evidence Source",
        "Evidence Refs",
        "Evidence Chain",
        "Fact IDs",
        "Source Execution IDs",
        "Assessment Refs",
        "Assessment Reasons",
        "Sources",
        "Timestamp",
        "Verification Gap",
        "Required Evidence",
        "Policy Refs",
        "Legacy ID",
        "Legacy Session ID",
        "Raw Evidence",
        "Reproduction Command",
        "Remediations",
        "Tool",
        "Payload",
        "Result",
        "Notes",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(fields)
        for item in items:
            writer.writerow(
                [
                    _csv_safe(report.get("report_id", "")),
                    _csv_safe(item["item_id"]),
                    _csv_safe(target),
                    _csv_safe(item["section"]),
                    _csv_safe(item["kind"]),
                    _csv_safe(item["title"]),
                    _csv_safe(item["severity"]),
                    _csv_safe(item["status"]),
                    _csv_safe(item["assessment_status"]),
                    _csv_safe(_projection_text(item["scope"])),
                    _csv_safe(_item_cvss(item)),
                    _csv_safe(item["port"]),
                    _csv_safe(item["service"]),
                    _csv_safe(item["detail"]),
                    _csv_safe(item["confidence"]),
                    _csv_safe(item["evidence_source"]),
                    _csv_safe("; ".join(item["evidence_refs"])),
                    _csv_safe(_projection_text(item["evidence_chain"])),
                    _csv_safe(_projection_text(item["fact_ids"])),
                    _csv_safe(_projection_text(item["source_execution_ids"])),
                    _csv_safe(_projection_text(item["assessment_refs"])),
                    _csv_safe(_projection_text(item["assessment_reasons"])),
                    _csv_safe(_projection_text(item["sources"])),
                    _csv_safe(item["timestamp"]),
                    _csv_safe(item["verification_gap"]),
                    _csv_safe(_projection_text(item["required_evidence"])),
                    _csv_safe(_projection_text(item["policy_refs"])),
                    _csv_safe(item["legacy_id"]),
                    _csv_safe(item["legacy_session_id"]),
                    _csv_safe(item["raw_evidence"]),
                    _csv_safe(item["reproduction_command"]),
                    _csv_safe(_projection_text(item["remediations"])),
                    _csv_safe(item["tool"]),
                    _csv_safe(item["payload"]),
                    _csv_safe(item["result"]),
                    _csv_safe(item["notes"]),
                ]
            )
    return filename


def export_html(data: Mapping[str, Any], output_dir: str | None = None) -> str:
    """Render every canonical report section as escaped HTML."""

    report, items = _canonical_input(data)
    identity, target = _report_identity(report)
    output_dir = output_dir or _get_report_dir()
    filename = _report_path(output_dir, identity, target, "html")
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in report.get("section_order") or []}
    for item in items:
        grouped.setdefault(item["section"], []).append(item)

    section_html: list[str] = []
    for section in report.get("section_order") or []:
        rows = []
        for item in grouped.get(section, []):
            color = SEVERITY_COLORS.get(item["severity"].lower(), "#7f8c8d")
            extras = _item_detail_pairs(item)
            rows.append(
                "<tr data-item-id='{}'><td><code>{}</code></td><td><strong>{}</strong>"
                "<div class='detail'>{}</div>{}</td><td style='color:{}'>{}</td>"
                "<td>{}</td></tr>".format(
                    _html_text(item["item_id"]),
                    _html_text(item["item_id"][:12]),
                    _html_text(item["title"]),
                    _html_text(item["detail"]),
                    "".join(
                        f"<small><b>{_html_text(label)}:</b> {_html_text(value)}</small>" for label, value in extras
                    ),
                    color,
                    _html_text(item["severity"]),
                    _html_text(item["status"]),
                )
            )
        content = (
            "<table><thead><tr><th>Item</th><th>Finding</th><th>Severity</th>"
            "<th>Status</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
            if rows
            else "<p class='empty'>None recorded.</p>"
        )
        section_html.append(f"<section><h2>{_html_text(_section_label(section))}</h2>{content}</section>")

    summary = report.get("summary") or {}
    legacy = report.get("legacy_adapter") or {}
    metadata_rows = [
        ("Schema", report.get("schema_version", "")),
        ("Snapshot", report.get("snapshot_at", "")),
        ("Summary", summary),
        ("Bounds", report.get("bounds") or {}),
        ("Truncation", report.get("truncation") or {}),
    ]
    if legacy:
        metadata_rows.extend(
            [
                ("Legacy source schema", legacy.get("source_schema", "")),
                ("Legacy session ID", legacy.get("session_id", "")),
                ("Legacy scan date", legacy.get("scan_date", "")),
                ("Legacy status", legacy.get("status", "")),
                ("Legacy risk level", legacy.get("risk_level", "")),
                ("Legacy summary ID", legacy.get("summary_id", "")),
                ("Legacy summary session ID", legacy.get("summary_session_id", "")),
                ("Legacy generated at", legacy.get("generated_at", "")),
            ]
        )
    metadata_html = "".join(
        f"<div class='card'><b>{_html_text(label)}</b><br>{_html_text(_projection_text(value))}</div>"
        for label, value in metadata_rows
    )
    legacy_context = ""
    if legacy.get("analysis") or legacy.get("raw_output"):
        context_parts = []
        if legacy.get("analysis"):
            context_parts.append(f"<h3>Stored analysis</h3><pre>{_html_text(legacy['analysis'])}</pre>")
        if legacy.get("raw_output"):
            context_parts.append(f"<h3>Raw tool output</h3><pre>{_html_text(legacy['raw_output'])}</pre>")
        legacy_context = "<section><h2>Legacy session context</h2>" + "".join(context_parts) + "</section>"
    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Octopus machine report — {_html_text(target)}</title>
<style>
*{{box-sizing:border-box}} body{{font-family:system-ui,sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}}
.container{{max-width:1100px;margin:auto}} h1,h2{{color:#c0392b}} .meta{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}}
.card{{background:#1a1a1a;border:1px solid #333;padding:12px}} table{{width:100%;border-collapse:collapse}}
th,td{{padding:9px;border-bottom:1px solid #333;text-align:left;vertical-align:top}} th{{color:#aaa}}
code{{color:#e74c3c}} small{{display:block;color:#999;margin-top:4px}} .detail{{margin-top:4px}}
.empty,.footer{{color:#777}} section{{margin-top:28px}} .footer{{margin-top:36px;border-top:1px solid #333;padding-top:12px;text-align:center}}
</style></head><body><div class="container">
<h1>OCTOPUS machine report</h1>
<div class="meta">
<div class="card"><b>Target</b><br>{_html_text(target)}</div>
<div class="card"><b>Scan</b><br>{_html_text(report.get("scan_id", ""))}</div>
<div class="card"><b>Report</b><br>{_html_text(report.get("report_id", ""))}</div>
<div class="card"><b>Evidence completeness</b><br>{_html_text(summary.get("evidence_completeness", 0))}</div>
{metadata_html}
</div>
{"".join(section_html)}
{legacy_context}
<div class="footer">Generated by OCTOPUS v{_html_text(APPLICATION_VERSION)} — For authorized use only.</div>
</div></body></html>"""
    with open(filename, "w", encoding="utf-8") as handle:
        handle.write(document)
    return filename


def export_pdf(data: Mapping[str, Any], output_dir: str | None = None) -> str:
    """Render every canonical report section to PDF from the shared projection."""

    report, items = _canonical_input(data)
    identity, target = _report_identity(report)
    output_dir = output_dir or _get_report_dir()
    filename = _report_path(output_dir, identity, target, "pdf")
    document = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        title=f"OCTOPUS machine report — {target}",
        author=f"OCTOPUS {APPLICATION_VERSION}",
        subject=f"machine_report {report.get('report_id', '')}",
    )
    title_style = ParagraphStyle(
        "title", fontSize=20, fontName="Helvetica-Bold", textColor=colors.HexColor("#c0392b"), spaceAfter=6
    )
    heading_style = ParagraphStyle(
        "heading",
        fontSize=12,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2c3e50"),
        spaceBefore=10,
        spaceAfter=5,
    )
    body_style = ParagraphStyle("body", fontSize=8, leading=11)
    footer_style = ParagraphStyle("footer", fontSize=7, textColor=colors.grey, alignment=TA_CENTER)
    story: list[Any] = [
        Paragraph("OCTOPUS machine report", title_style),
        Paragraph(_pdf_text(f"Target: {target}"), body_style),
        Paragraph(_pdf_text(f"Scan: {report.get('scan_id', '')}"), body_style),
        Paragraph(_pdf_text(f"Report: {report.get('report_id', '')}"), body_style),
        Paragraph(_pdf_text(f"Schema: {report.get('schema_version', '')}"), body_style),
        Paragraph(_pdf_text(f"Snapshot: {report.get('snapshot_at', '')}"), body_style),
        Paragraph(
            _pdf_text(f"Summary: {_projection_text(report.get('summary') or {})}"),
            body_style,
        ),
        Paragraph(
            _pdf_text(f"Bounds: {_projection_text(report.get('bounds') or {})}"),
            body_style,
        ),
        Paragraph(
            _pdf_text(f"Truncation: {_projection_text(report.get('truncation') or {})}"),
            body_style,
        ),
    ]
    legacy = report.get("legacy_adapter") or {}
    if legacy:
        story.extend(
            [
                Paragraph(_pdf_text(f"Legacy source schema: {legacy.get('source_schema', '')}"), body_style),
                Paragraph(_pdf_text(f"Legacy session ID: {legacy.get('session_id', '')}"), body_style),
                Paragraph(_pdf_text(f"Legacy scan date: {legacy.get('scan_date', '')}"), body_style),
                Paragraph(_pdf_text(f"Legacy status: {legacy.get('status', '')}"), body_style),
                Paragraph(_pdf_text(f"Legacy risk level: {legacy.get('risk_level', '')}"), body_style),
                Paragraph(_pdf_text(f"Legacy summary ID: {legacy.get('summary_id', '')}"), body_style),
                Paragraph(
                    _pdf_text(f"Legacy summary session ID: {legacy.get('summary_session_id', '')}"),
                    body_style,
                ),
                Paragraph(_pdf_text(f"Legacy generated at: {legacy.get('generated_at', '')}"), body_style),
            ]
        )
    story.append(Spacer(1, 6))
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in report.get("section_order") or []}
    for item in items:
        grouped.setdefault(item["section"], []).append(item)
    for section in report.get("section_order") or []:
        story.append(Paragraph(_pdf_text(_section_label(section)), heading_style))
        story.append(HRFlowable(width="100%", thickness=0.4, color=colors.lightgrey, spaceAfter=4))
        section_items = grouped.get(section, [])
        if not section_items:
            story.append(Paragraph("None recorded.", body_style))
            continue
        for item in section_items:
            story.append(
                Paragraph(
                    "<b>{}</b> — {} — {} — {}".format(
                        _pdf_text(item["title"]),
                        _pdf_text(item["item_id"]),
                        _pdf_text(item["severity"]),
                        _pdf_text(item["status"]),
                    ),
                    body_style,
                )
            )
            story.append(Paragraph(_pdf_text(item["detail"]), body_style))
            for label, value in _item_detail_pairs(item):
                story.append(
                    Paragraph(
                        f"<b>{_pdf_text(label)}:</b> {_pdf_text(value)}",
                        body_style,
                    )
                )
            story.append(Spacer(1, 4))
    if legacy.get("analysis") or legacy.get("raw_output"):
        story.append(Paragraph("Legacy session context", heading_style))
        if legacy.get("analysis"):
            story.append(Paragraph(_pdf_text(legacy["analysis"]), body_style))
        if legacy.get("raw_output"):
            story.append(Paragraph(_pdf_text(legacy["raw_output"]), body_style))
    story.extend(
        [
            Spacer(1, 10),
            HRFlowable(width="100%", thickness=0.4, color=colors.lightgrey, spaceAfter=4),
            Paragraph(
                _pdf_text(f"Generated by OCTOPUS v{APPLICATION_VERSION} — For authorized use only."),
                footer_style,
            ),
        ]
    )
    document.build(story)
    return filename


def export_menu(data: Mapping[str, Any]) -> None:
    try:
        report, _items = _canonical_input(data)
    except MachineReportError as exc:
        if "no history" in str(exc):
            print("[!] No session data to export.")
            return
        raise
    identity, target = _report_identity(report)
    print(f"\n\033[33m{'─' * 20} EXPORT {identity} — {target} {'─' * 20}\033[0m")
    print("  [1] PDF report")
    print("  [2] HTML report")
    print("  [3] JSON (canonical machine_report)")
    print("  [4] CSV (canonical section items)")
    print("  [5] All formats")
    print("  [0] Back")
    print(f"\033[90m{'─' * 60}\033[0m")
    choice = input("\033[36mExport format: \033[0m").strip()
    output_dir = _get_report_dir()
    os.makedirs(output_dir, exist_ok=True)
    renderers = {
        "1": (("PDF", export_pdf),),
        "2": (("HTML", export_html),),
        "3": (("JSON", export_json),),
        "4": (("CSV", export_csv),),
        "5": (
            ("PDF", export_pdf),
            ("HTML", export_html),
            ("JSON", export_json),
            ("CSV", export_csv),
        ),
    }
    if choice == "0":
        return
    selected = renderers.get(choice)
    if selected is None:
        print("\033[93m[!] Invalid choice.\033[0m")
        return
    for label, renderer in selected:
        path = renderer(report, output_dir)
        print(f"\033[92m[+] {label} saved: {path}\033[0m")


def _sev(vulnerability: Any) -> str:
    return str(_row_value(vulnerability, 3, "unknown") or "unknown").lower().strip()


if __name__ == "__main__":
    print(f"\n\033[91m    OCTOPUS v{APPLICATION_VERSION} — Standalone Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")
    rows = get_all_history()
    if not rows:
        print("[!] No sessions found in database yet.")
        raise SystemExit(0)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {row[2]!s:<22} {row[3]}")
    sl_input = input("\n\033[36mEnter SL# to export: \033[0m").strip()
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        raise SystemExit(2)
    session = get_session(int(sl_input))
    if not session or not session.get("history"):
        print(f"[!] Session SL#{sl_input} not found.")
        raise SystemExit(1)
    export_menu(session)
