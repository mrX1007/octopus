#!/usr/bin/env python3


import datetime
import html
import os
import re
import unicodedata
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.secrets import redact_data, redact_text
from db import get_all_history, get_session

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "unknown":  "#7f8c8d",
}

RISK_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "UNKNOWN":  "#7f8c8d",
}


def _normalize_session_report(data: dict) -> dict:
    """Return the canonical DB session-report shape without mutating the caller.

    ``db.get_session()`` uses ``vulns``.  Older tests and third-party callers used
    ``vulnerabilities``; accept that spelling only as an input compatibility alias.
    """
    if not isinstance(data, dict):
        raise TypeError("session report must be a dictionary")
    data = redact_data(data)
    vulns = data.get("vulns")
    if vulns is None:
        vulns = data.get("vulnerabilities")
    return {
        "history": data.get("history"),
        "vulns": list(vulns or []),
        "fixes": list(data.get("fixes") or []),
        "exploits": list(data.get("exploits") or []),
        "summary": data.get("summary"),
    }


def _row_value(row, index: int, default=""):
    if row is None or len(row) <= index or row[index] is None:
        return default
    return row[index]


def _safe_component(value, fallback: str) -> str:
    text = unicodedata.normalize("NFKC", redact_text(value, kind="report_filename"))
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("._-")
    return (text[:120] or fallback)


def _report_path(output_dir: str, sl_no, target, extension: str) -> str:
    """Build a contained, non-symlink report filename under ``output_dir``."""
    root_input = os.path.abspath(os.path.expanduser(str(output_dir or ".")))
    os.makedirs(root_input, exist_ok=True)
    root = os.path.realpath(root_input)
    safe_sl = _safe_component(sl_no, "unknown")
    safe_target = _safe_component(target, "target")
    safe_ext = re.sub(r"[^a-z0-9]", "", str(extension).lower())
    if not safe_ext:
        raise ValueError("report extension must contain letters or digits")
    candidate = os.path.abspath(
        os.path.join(root, f"octopus_SL{safe_sl}_{safe_target}.{safe_ext}")
    )
    try:
        contained = os.path.commonpath((root, candidate)) == root
    except ValueError:
        contained = False
    if not contained:
        raise ValueError("report filename escaped the configured output directory")
    if os.path.lexists(candidate) and os.path.islink(candidate):
        raise ValueError("refusing to overwrite a symbolic-link report path")
    return candidate


def _html_text(value) -> str:
    return html.escape(redact_text(value, kind="report"), quote=True)


def _pdf_text(value) -> str:
    # ReportLab Paragraph consumes a small XML/HTML dialect.
    return html.escape(redact_text(value, kind="report"), quote=True)


def _csv_safe(value):
    """Neutralize spreadsheet formulas while preserving non-string values."""
    if not isinstance(value, str):
        return value
    value = redact_text(value, kind="report")
    stripped = value.lstrip(" \t\r\n")
    if value.startswith(("\t", "\r")) or (stripped and stripped[0] in "=+-@"):
        return "'" + value
    return value


def _cvss_from_severity(severity: str) -> float:
    """Map severity label to approximate CVSS base score."""
    mapping = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.5,
        "low": 2.5,
        "unknown": 0.0,
    }
    return mapping.get((severity or "unknown").lower(), 0.0)


def _vuln_cvss(vulnerability) -> float:
    """Prefer the score stored by the scanner, then fall back to severity."""
    stored = _row_value(vulnerability, 11, None)
    if stored not in (None, ""):
        try:
            return float(stored)
        except (TypeError, ValueError):
            pass
    return _cvss_from_severity(_sev(vulnerability))


def _generate_executive_summary(data: dict) -> str:
    """Generate a three-paragraph executive summary from scan results."""
    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    tgt = _row_value(data["history"], 1, "unknown target")
    risk = str(_row_value(data["summary"], 4, "UNKNOWN") or "UNKNOWN")
    vulns = data["vulns"]
    exploits = data["exploits"]

    critical_count = sum(1 for v in vulns if _sev(v) == "critical")
    high_count = sum(1 for v in vulns if _sev(v) == "high")
    total_vulns = len(vulns)
    total_exploits = len(exploits)

    para1 = (f"A comprehensive penetration test was conducted against {tgt}. "
             f"The assessment identified {total_vulns} vulnerabilities "
             f"({critical_count} critical, {high_count} high severity) "
             f"across the target's external attack surface.")

    if total_exploits > 0:
        para2 = (f"During exploitation, {total_exploits} attack vectors were tested. "
                 f"The overall risk level is assessed as {risk.upper()}, "
                 f"indicating immediate remediation is required for critical findings.")
    else:
        para2 = (f"The overall risk level is assessed as {risk.upper()}. "
                 f"No active exploitation was performed during this assessment.")

    para3 = ("Recommended next steps: prioritize patching of all CRITICAL and HIGH "
             "severity vulnerabilities, implement network segmentation to limit "
             "lateral movement, and schedule a re-assessment within 30 days.")

    return f"{para1}\n\n{para2}\n\n{para3}"


def _get_report_dir() -> str:
    """Get report output directory from config or default."""
    try:
        from config import CFG
        return CFG["paths"]["reports"]
    except Exception:
        return os.path.expanduser("~/OCTOPUS/reports")


def export_pdf(data: dict, output_dir: Optional[str] = None) -> str:
    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    h        = data["history"]
    sl       = h[0]
    tgt      = h[1]
    date     = str(h[2])
    risk     = str(_row_value(data["summary"], 4, "UNKNOWN") or "UNKNOWN")
    ai       = _row_value(data["summary"], 3, "")

    if output_dir is None:
        output_dir = _get_report_dir()

    filename = _report_path(output_dir, sl, tgt, "pdf")
    doc      = SimpleDocTemplate(filename, pagesize=A4,
                                  topMargin=15*mm, bottomMargin=15*mm,
                                  leftMargin=15*mm, rightMargin=15*mm)

    title_style  = ParagraphStyle("t",  fontSize=22, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#c0392b"), spaceAfter=4)
    sub_style    = ParagraphStyle("s",  fontSize=10, fontName="Helvetica",
                                   textColor=colors.HexColor("#555555"), spaceAfter=2)
    h1_style     = ParagraphStyle("h1", fontSize=13, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#2c3e50"),
                                   spaceBefore=10, spaceAfter=4)
    body_style   = ParagraphStyle("b",  fontSize=9,  fontName="Helvetica",
                                   textColor=colors.black, leading=13)
    code_style   = ParagraphStyle("c",  fontSize=7.5, fontName="Courier",
                                   textColor=colors.HexColor("#2c3e50"),
                                   backColor=colors.HexColor("#f4f4f4"),
                                   leading=11, leftIndent=6, rightIndent=6,
                                   spaceBefore=2, spaceAfter=2)
    footer_style = ParagraphStyle("f",  fontSize=7,
                                   textColor=colors.HexColor("#aaaaaa"),
                                   alignment=TA_CENTER)
    story = []

    story.append(Paragraph("OCTOPUS", title_style))
    story.append(Paragraph("AI Penetration Testing Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=colors.HexColor("#c0392b"), spaceAfter=8))

    risk_color = colors.HexColor(RISK_COLORS.get(risk.upper(), "#7f8c8d"))
    meta = [["Target", tgt], ["Scan Date", date],
            ["Session", f"SL# {sl}"], ["Risk Level", risk],
            ["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")]]
    mt = Table(meta, colWidths=[35*mm, 130*mm])
    mt.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
        ("TEXTCOLOR",      (0,0), (0,-1),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (1,3), (1,3),   risk_color),
        ("FONTNAME",       (1,3), (1,3),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
        ("PADDING",        (0,0), (-1,-1), 5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Vulnerabilities", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))

    exec_summary = _generate_executive_summary(data)
    exec_style = ParagraphStyle("es", fontSize=9, fontName="Helvetica-Oblique",
                                 textColor=colors.HexColor("#2c3e50"),
                                 leading=13, spaceBefore=2, spaceAfter=8,
                                 backColor=colors.HexColor("#f0f7ff"),
                                 leftIndent=6, rightIndent=6)
    story.append(Paragraph("Executive Summary", h1_style))
    for para in exec_summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(_pdf_text(para.strip()), exec_style))
            story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Vulnerability Matrix", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["vulns"]:
        vd = [["#", "Vulnerability", "Severity", "CVSS", "Port", "Service"]]
        for v in data["vulns"]:
            cvss = _vuln_cvss(v)
            vd.append([str(_row_value(v, 0, "-")), str(_row_value(v, 2, "-") or "-"),
                       str(_row_value(v, 3, "-") or "-").upper(), f"{cvss:.1f}",
                       str(_row_value(v, 4, "-") or "-"),
                       str(_row_value(v, 5, "-") or "-")])
        vt  = Table(vd, colWidths=[10*mm, 60*mm, 22*mm, 15*mm, 15*mm, 28*mm], repeatRows=1)
        vts = [
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ]
        for i, v in enumerate(data["vulns"], 1):
            sc = colors.HexColor(SEVERITY_COLORS.get(_sev(v), "#7f8c8d"))
            vts.append(("TEXTCOLOR", (2,i), (2,i), sc))
            vts.append(("FONTNAME",  (2,i), (2,i), "Helvetica-Bold"))
            vts.append(("TEXTCOLOR", (3,i), (3,i), sc))
            vts.append(("FONTNAME",  (3,i), (3,i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vts))
        story.append(vt)
        story.append(Spacer(1, 6))

        story.append(Paragraph("Vulnerability Details", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                 color=colors.HexColor("#dddddd"), spaceAfter=6))
        for v in data["vulns"]:
            severity = str(_row_value(v, 3, "UNKNOWN") or "UNKNOWN")
            sc  = colors.HexColor(SEVERITY_COLORS.get(severity.lower(), "#7f8c8d"))
            lbl = ParagraphStyle("vl", fontSize=9, fontName="Helvetica-Bold", textColor=sc)
            name = _row_value(v, 2, "-") or "-"
            story.append(Paragraph(_pdf_text(f"[{severity.upper()}] {name}"), lbl))
            description = _row_value(v, 6, "")
            if description:
                story.append(Paragraph(_pdf_text(description), body_style))
            provenance = []
            confidence = _row_value(v, 7, "")
            evidence_source = _row_value(v, 8, "")
            raw_evidence = _row_value(v, 9, "")
            repro_cmd = _row_value(v, 10, "")
            if confidence:
                provenance.append(f"Confidence: {confidence}")
            if evidence_source:
                provenance.append(f"Evidence source: {evidence_source}")
            if provenance:
                story.append(Paragraph(_pdf_text(" | ".join(provenance)), body_style))
            if raw_evidence:
                story.append(Paragraph(_pdf_text(f"Evidence: {raw_evidence}"), code_style))
            if repro_cmd:
                story.append(Paragraph(_pdf_text(f"Reproduce: {repro_cmd}"), code_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No vulnerabilities recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Fixes & Mitigations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["fixes"]:
        for f in data["fixes"]:
            story.append(Paragraph(
                _pdf_text(f"Fix for vuln id={_row_value(f, 2, '-')}"), body_style
            ))
            story.append(Paragraph(_pdf_text(_row_value(f, 3, "-") or "-"), code_style))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("No fixes recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Exploits Attempted", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["exploits"]:
        ed = [["#", "Exploit", "Tool", "Result"]]
        for e in data["exploits"]:
            ed.append([str(e[0]), str(e[2] or "-")[:60],
                       str(e[3] or "-")[:30], str(e[5] or "-")[:30]])
        et = Table(ed, colWidths=[10*mm, 80*mm, 40*mm, 28*mm])
        et.setStyle(TableStyle([
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ]))
        story.append(et)
    else:
        story.append(Paragraph("No exploits recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("AI Analysis Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if ai:
        for line in str(ai).split("\n"):
            line = line.strip()
            if line:
                story.append(Paragraph(_pdf_text(line), body_style))
                story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No AI analysis recorded.", body_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=4))
    story.append(Paragraph(
        "Generated by OCTOPUS v7.0 — Autonomous Strategic AI Pentest Engine | "
        "github.com/sooryathejas/OCTOPUS | For authorized use only.",
        footer_style))

    doc.build(story)
    return filename


def export_html(data: dict, output_dir: Optional[str] = None) -> str:
    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    h    = data["history"]
    sl   = h[0]
    tgt  = h[1]
    date = str(h[2])
    risk = str(_row_value(data["summary"], 4, "UNKNOWN") or "UNKNOWN")
    ai   = _row_value(data["summary"], 3, "")
    rc   = RISK_COLORS.get(risk.upper(), "#7f8c8d")

    if output_dir is None:
        output_dir = _get_report_dir()

    filename = _report_path(output_dir, sl, tgt, "html")
    vuln_rows = ""
    for v in data["vulns"]:
        severity = str(_row_value(v, 3, "unknown") or "unknown")
        sc = SEVERITY_COLORS.get(severity.lower(), "#7f8c8d")
        provenance = []
        if _row_value(v, 7, ""):
            provenance.append(f"Confidence: {_row_value(v, 7)}")
        if _row_value(v, 8, ""):
            provenance.append(f"Source: {_row_value(v, 8)}")
        if _row_value(v, 9, ""):
            provenance.append(f"Evidence: {_row_value(v, 9)}")
        if _row_value(v, 10, ""):
            provenance.append(f"Reproduce: {_row_value(v, 10)}")
        provenance_html = "".join(
            f"<br><small>{_html_text(item)}</small>" for item in provenance
        )
        vuln_rows += (f"<tr><td>{_html_text(_row_value(v, 0, '-'))}</td>"
                      f"<td><strong>{_html_text(_row_value(v, 2, '-'))}</strong>"
                      f"<br><small>{_html_text(_row_value(v, 6, ''))}</small>{provenance_html}</td>"
                      f"<td><span style='color:{sc};font-weight:bold'>"
                      f"{_html_text(severity.upper())}</span></td>"
                      f"<td>{_html_text(_row_value(v, 4, '-') or '-')}</td>"
                      f"<td>{_html_text(_row_value(v, 5, '-') or '-')}</td></tr>")

    fix_rows = ""
    for f in data["fixes"]:
        fix_rows += (f"<tr><td>{_html_text(_row_value(f, 0, '-'))}</td>"
                     f"<td>vuln #{_html_text(_row_value(f, 2, '-'))}</td>"
                     f"<td><code>{_html_text(_row_value(f, 3, '-') or '-')}</code></td>"
                     f"<td>{_html_text(_row_value(f, 4, 'ai') or 'ai')}</td></tr>")

    exp_rows = ""
    for e in data["exploits"]:
        exp_rows += (f"<tr><td>{_html_text(_row_value(e, 0, '-'))}</td>"
                     f"<td>{_html_text(_row_value(e, 2, '-') or '-')}</td>"
                     f"<td>{_html_text(_row_value(e, 3, '-') or '-')}</td>"
                     f"<td><code>{_html_text(str(_row_value(e, 4, '-') or '-')[:80])}</code></td>"
                     f"<td>{_html_text(_row_value(e, 5, '-') or '-')}</td></tr>")

    ai_html = "".join(f"<p>{_html_text(line)}</p>"
                      for line in str(ai).split("\n") if line.strip())

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Octopus Report — {_html_text(tgt)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}}
.container{{max-width:960px;margin:auto}}
.header{{border-left:5px solid #c0392b;padding-left:16px;margin-bottom:30px}}
.header h1{{font-size:2.2em;color:#c0392b}}
.header p{{color:#888;font-size:.95em}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:30px}}
.meta-card{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:14px}}
.meta-card .label{{font-size:.75em;color:#888;text-transform:uppercase;margin-bottom:4px}}
.meta-card .value{{font-size:1.1em;font-weight:bold}}
.risk{{color:{rc}}}
section{{margin-bottom:30px}}
section h2{{font-size:1.2em;color:#c0392b;border-bottom:1px solid #333;
            padding-bottom:8px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}
th{{background:#1e1e1e;color:#aaa;text-align:left;padding:10px;
    font-size:.8em;text-transform:uppercase;border-bottom:2px solid #333}}
td{{padding:10px;border-bottom:1px solid #222;vertical-align:top}}
tr:hover td{{background:#1a1a1a}}
code{{background:#1e1e1e;padding:2px 6px;border-radius:3px;
      font-family:monospace;font-size:.85em;color:#e74c3c}}
.ai-box{{background:#111;border:1px solid #333;border-radius:6px;
         padding:16px;font-size:.9em;line-height:1.7;color:#ccc}}
.ai-box p{{margin-bottom:8px}}
.footer{{text-align:center;color:#444;font-size:.78em;
         margin-top:40px;border-top:1px solid #222;padding-top:16px}}
a{{color:#555}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>🔱 OCTOPUS</h1>
  <p>AI Penetration Testing Report</p>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{_html_text(tgt)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {_html_text(sl)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{_html_text(date)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Risk Level</div>
    <div class="value risk">{_html_text(risk)}</div>
  </div>
</div>

<section>
  <h2>Vulnerabilities</h2>
  {'<table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Port</th><th>Service</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if data["vulns"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Fixes &amp; Mitigations</h2>
  {'<table><thead><tr><th>#</th><th>Vuln</th><th>Fix</th><th>Source</th></tr></thead><tbody>' + fix_rows + '</tbody></table>' if data["fixes"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Exploits Attempted</h2>
  {'<table><thead><tr><th>#</th><th>Exploit</th><th>Tool</th><th>Payload</th><th>Result</th></tr></thead><tbody>' + exp_rows + '</tbody></table>' if data["exploits"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>AI Analysis Summary</h2>
  <div class="ai-box">
    {ai_html if ai_html else '<p style="color:#888">None recorded.</p>'}
  </div>
</section>

<div class="footer">
  Generated by OCTOPUS &mdash;
  <a href="https://github.com/sooryathejas/OCTOPUS">github.com/sooryathejas/OCTOPUS</a>
  &mdash; For authorized use only.
</div>

</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return filename


def export_menu(data: dict):
    data = _normalize_session_report(data)
    if not data["history"]:
        print("[!] No session data to export.")
        return

    h   = data["history"]
    sl  = h[0]
    tgt = h[1]

    print(f"\n\033[33m{'─'*20} EXPORT SL#{sl} — {tgt} {'─'*20}\033[0m")
    print("  [1] PDF report")
    print("  [2] HTML report")
    print("  [3] JSON (machine-readable)")
    print("  [4] CSV (spreadsheet)")
    print("  [5] All formats")
    print("  [0] Back")
    print(f"\033[90m{'─'*60}\033[0m")

    choice     = input("\033[36mExport format: \033[0m").strip()
    output_dir = _get_report_dir()
    os.makedirs(output_dir, exist_ok=True)

    if choice == "1":
        p = export_pdf(data, output_dir)
        print(f"\033[92m[+] PDF saved: {p}\033[0m")
    elif choice == "2":
        p = export_html(data, output_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "3":
        p = export_json(data, output_dir)
        print(f"\033[92m[+] JSON saved: {p}\033[0m")
    elif choice == "4":
        p = export_csv(data, output_dir)
        print(f"\033[92m[+] CSV saved: {p}\033[0m")
    elif choice == "5":
        p1 = export_pdf(data, output_dir)
        p2 = export_html(data, output_dir)
        p3 = export_json(data, output_dir)
        p4 = export_csv(data, output_dir)
        print(f"\033[92m[+] PDF  : {p1}\033[0m")
        print(f"\033[92m[+] HTML : {p2}\033[0m")
        print(f"\033[92m[+] JSON : {p3}\033[0m")
        print(f"\033[92m[+] CSV  : {p4}\033[0m")
    elif choice == "0":
        return
    else:
        print("\033[93m[!] Invalid choice.\033[0m")



def export_json(data: dict, output_dir: str = ".") -> str:
    """Export scan results as structured JSON.

    Includes all data: history, vulnerabilities (with CVSS),
    fixes, exploits, summary, and metadata.
    """
    import json

    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    h = data["history"]
    sl_no = h[0]
    target = h[1]
    scan_date = str(h[2]) if h[2] else ""
    status = h[3] if len(h) > 3 else "unknown"

    vulns = data["vulns"]
    fixes = data["fixes"]
    exploits = data["exploits"]
    summary = data["summary"]

    report = {
        "metadata": {
            "tool": "OCTOPUS",
            "version": "10.0",
            "export_date": datetime.datetime.now().isoformat(),
            "format_version": "1.0",
        },
        "scan": {
            "sl_no": sl_no,
            "target": target,
            "scan_date": scan_date,
            "status": status,
        },
        "summary": {
            "risk_level": summary[4] if summary and len(summary) > 4 else "UNKNOWN",
            "ai_analysis": summary[3] if summary and len(summary) > 3 else "",
            "generated_at": str(summary[5]) if summary and len(summary) > 5 else "",
        },
        "statistics": {
            "total_vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if _sev(v) == "critical"),
            "high": sum(1 for v in vulns if _sev(v) == "high"),
            "medium": sum(1 for v in vulns if _sev(v) == "medium"),
            "low": sum(1 for v in vulns if _sev(v) == "low"),
            "exploits_attempted": len(exploits),
            "cvss_max": max((_vuln_cvss(v) for v in vulns), default=0.0),
        },
        "vulnerabilities": [
            {
                "id": _row_value(v, 0),
                "name": _row_value(v, 2),
                "severity": _row_value(v, 3),
                "port": _row_value(v, 4),
                "service": _row_value(v, 5),
                "description": _row_value(v, 6),
                "confidence": _row_value(v, 7),
                "evidence_source": _row_value(v, 8),
                "raw_evidence": _row_value(v, 9),
                "repro_cmd": _row_value(v, 10),
                "cvss_score": _vuln_cvss(v),
            }
            for v in vulns
        ],
        "fixes": [
            {
                "id": f[0],
                "vuln_id": f[2] if len(f) > 2 else "",
                "fix_text": f[3] if len(f) > 3 else "",
                "source": f[4] if len(f) > 4 else "",
            }
            for f in fixes
        ],
        "exploits_attempted": [
            {
                "id": e[0],
                "name": e[2] if len(e) > 2 else "",
                "tool_used": e[3] if len(e) > 3 else "",
                "payload": e[4] if len(e) > 4 else "",
                "result": e[5] if len(e) > 5 else "",
                "notes": e[6] if len(e) > 6 else "",
            }
            for e in exploits
        ],
    }

    filename = _report_path(output_dir, sl_no, target, "json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return filename


def _sev(v) -> str:
    """Extract severity string from vulnerability tuple, lowercase."""
    return str(_row_value(v, 3, "unknown") or "unknown").lower().strip()



def export_csv(data: dict, output_dir: str = ".") -> str:
    """Export vulnerabilities as CSV for spreadsheet analysis."""
    import csv

    data = _normalize_session_report(data)
    if not data["history"]:
        raise ValueError("session report has no history row")
    h = data["history"]
    sl_no = h[0]
    target = h[1]
    vulns = data["vulns"]

    filename = _report_path(output_dir, sl_no, target, "csv")

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "SL#", "Target", "Vulnerability", "Severity",
            "CVSS", "Port", "Service", "Description", "Confidence",
            "Evidence Source", "Raw Evidence", "Reproduction Command",
        ])
        for v in vulns:
            writer.writerow([_csv_safe(value) for value in [
                _row_value(v, 0),
                sl_no,
                target,
                _row_value(v, 2),
                _row_value(v, 3),
                _vuln_cvss(v),
                _row_value(v, 4),
                _row_value(v, 5),
                _row_value(v, 6),
                _row_value(v, 7),
                _row_value(v, 8),
                _row_value(v, 9),
                _row_value(v, 10),
            ]])

    return filename


if __name__ == "__main__":
    print("\n\033[91m    OCTOPUS — Standalone Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")

    rows = get_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        exit()

    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {row[2]!s:<22} {row[3]}")
    print()

    sl_input = input("\033[36mEnter SL# to export: \033[0m").strip()
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        exit()

    data = get_session(int(sl_input))
    if not data["history"]:
        print(f"[!] SL# {sl_input} not found.")
        exit()

    export_menu(data)
