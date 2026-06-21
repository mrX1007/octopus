#!/usr/bin/env python3


import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER

# DB access — import from db.py (single source of truth)
from db import get_connection, get_session, get_all_history

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


# v7.0: CVSS base score mapping from severity
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


def _generate_executive_summary(data: dict) -> str:
    """v7.0: Generate a 3-paragraph executive summary from scan results."""
    tgt = data["history"][1]
    risk = data["summary"][4] if data["summary"] else "UNKNOWN"
    vulns = data.get("vulns", [])
    exploits = data.get("exploits", [])

    critical_count = sum(1 for v in vulns if (v[3] or "").lower() == "critical")
    high_count = sum(1 for v in vulns if (v[3] or "").lower() == "high")
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

    para3 = (f"Recommended next steps: prioritize patching of all CRITICAL and HIGH "
             f"severity vulnerabilities, implement network segmentation to limit "
             f"lateral movement, and schedule a re-assessment within 30 days.")

    return f"{para1}\n\n{para2}\n\n{para3}"


def _get_report_dir() -> str:
    """Get report output directory from config or default."""
    try:
        from config import CFG
        return CFG["paths"]["reports"]
    except Exception as e:
        return os.path.expanduser("~/OCTOPUS/reports")


def export_pdf(data: dict, output_dir: str = None) -> str:
    h        = data["history"]
    sl       = h[0]
    tgt      = h[1]
    date     = str(h[2])
    risk     = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai       = data["summary"][3] if data["summary"] else ""

    if output_dir is None:
        output_dir = _get_report_dir()

    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"octopus_SL{sl}_{safe}.pdf")
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

    # v7.0: Executive Summary
    exec_summary = _generate_executive_summary(data)
    exec_style = ParagraphStyle("es", fontSize=9, fontName="Helvetica-Oblique",
                                 textColor=colors.HexColor("#2c3e50"),
                                 leading=13, spaceBefore=2, spaceAfter=8,
                                 backColor=colors.HexColor("#f0f7ff"),
                                 leftIndent=6, rightIndent=6)
    story.append(Paragraph("Executive Summary", h1_style))
    for para in exec_summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), exec_style))
            story.append(Spacer(1, 3))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Vulnerability Matrix", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["vulns"]:
        vd = [["#", "Vulnerability", "Severity", "CVSS", "Port", "Service"]]
        for v in data["vulns"]:
            cvss = _cvss_from_severity(v[3])
            vd.append([str(v[0]), str(v[2] or "-"),
                       str(v[3] or "-").upper(), f"{cvss:.1f}",
                       str(v[4] or "-"), str(v[5] or "-")])
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
            sc = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            vts.append(("TEXTCOLOR", (2,i), (2,i), sc))
            vts.append(("FONTNAME",  (2,i), (2,i), "Helvetica-Bold"))
            # v7.0: Color CVSS score too
            vts.append(("TEXTCOLOR", (3,i), (3,i), sc))
            vts.append(("FONTNAME",  (3,i), (3,i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vts))
        story.append(vt)
        story.append(Spacer(1, 6))

        story.append(Paragraph("Vulnerability Details", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                 color=colors.HexColor("#dddddd"), spaceAfter=6))
        for v in data["vulns"]:
            sc  = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            lbl = ParagraphStyle("vl", fontSize=9, fontName="Helvetica-Bold", textColor=sc)
            story.append(Paragraph(f"[{(v[3] or 'UNKNOWN').upper()}] {v[2]}", lbl))
            if v[6]:
                story.append(Paragraph(str(v[6]), body_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No vulnerabilities recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Fixes & Mitigations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["fixes"]:
        for f in data["fixes"]:
            story.append(Paragraph(f"Fix for vuln id={f[2]}:", body_style))
            story.append(Paragraph(str(f[3] or "-"), code_style))
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
                story.append(Paragraph(line, body_style))
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


def export_html(data: dict, output_dir: str = None) -> str:
    h    = data["history"]
    sl   = h[0]
    tgt  = h[1]
    date = str(h[2])
    risk = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai   = data["summary"][3] if data["summary"] else ""
    rc   = RISK_COLORS.get(risk.upper(), "#7f8c8d")

    if output_dir is None:
        output_dir = _get_report_dir()

    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"octopus_SL{sl}_{safe}.html")
    vuln_rows = ""
    for v in data["vulns"]:
        sc = SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
        vuln_rows += (f"<tr><td>{v[0]}</td>"
                      f"<td><strong>{v[2]}</strong><br><small>{v[6] or ''}</small></td>"
                      f"<td><span style='color:{sc};font-weight:bold'>"
                      f"{(v[3] or 'unknown').upper()}</span></td>"
                      f"<td>{v[4] or '-'}</td><td>{v[5] or '-'}</td></tr>")

    fix_rows = ""
    for f in data["fixes"]:
        fix_rows += (f"<tr><td>{f[0]}</td><td>vuln #{f[2]}</td>"
                     f"<td><code>{f[3] or '-'}</code></td>"
                     f"<td>{f[4] or 'ai'}</td></tr>")

    exp_rows = ""
    for e in data["exploits"]:
        exp_rows += (f"<tr><td>{e[0]}</td><td>{e[2] or '-'}</td>"
                     f"<td>{e[3] or '-'}</td>"
                     f"<td><code>{str(e[4] or '-')[:80]}</code></td>"
                     f"<td>{e[5] or '-'}</td></tr>")

    ai_html = "".join(f"<p>{line}</p>"
                      for line in str(ai).split("\n") if line.strip())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Octopus Report — {tgt}</title>
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
    <div class="value">{tgt}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {sl}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{date}</div>
  </div>
  <div class="meta-card">
    <div class="label">Risk Level</div>
    <div class="value risk">{risk}</div>
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

    with open(filename, "w") as f:
        f.write(html)
    return filename


def export_menu(data: dict):
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


# ─────────────────────────────────────────────
# JSON EXPORT
# ─────────────────────────────────────────────

def export_json(data: dict, output_dir: str = ".") -> str:
    """Export scan results as structured JSON.

    Includes all data: history, vulnerabilities (with CVSS),
    fixes, exploits, summary, and metadata.
    """
    import json

    h = data["history"]
    sl_no = h[0]
    target = h[1]
    scan_date = str(h[2]) if h[2] else ""
    status = h[3] if len(h) > 3 else "unknown"

    vulns = data.get("vulnerabilities", [])
    fixes = data.get("fixes", [])
    exploits = data.get("exploits", [])
    summary = data.get("summary")

    # Build structured output
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
            "cvss_max": max((_cvss_from_severity(_sev(v)) for v in vulns), default=0.0),
        },
        "vulnerabilities": [
            {
                "id": v[0],
                "name": v[2] if len(v) > 2 else "",
                "severity": v[3] if len(v) > 3 else "",
                "port": v[4] if len(v) > 4 else "",
                "service": v[5] if len(v) > 5 else "",
                "description": v[6] if len(v) > 6 else "",
                "confidence": v[7] if len(v) > 7 else "",
                "cvss_score": _cvss_from_severity(v[3] if len(v) > 3 else ""),
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

    filename = os.path.join(output_dir, f"octopus_SL{sl_no}_{target.replace('.', '_')}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    return filename


def _sev(v) -> str:
    """Extract severity string from vulnerability tuple, lowercase."""
    return (v[3] if len(v) > 3 else "unknown").lower().strip()


# ─────────────────────────────────────────────
# CSV EXPORT
# ─────────────────────────────────────────────

def export_csv(data: dict, output_dir: str = ".") -> str:
    """Export vulnerabilities as CSV for spreadsheet analysis."""
    import csv

    h = data["history"]
    sl_no = h[0]
    target = h[1]
    vulns = data.get("vulnerabilities", [])

    filename = os.path.join(output_dir, f"octopus_SL{sl_no}_{target.replace('.', '_')}.csv")

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ID", "SL#", "Target", "Vulnerability", "Severity",
            "CVSS", "Port", "Service", "Description", "Confidence",
        ])
        for v in vulns:
            writer.writerow([
                v[0],
                sl_no,
                target,
                v[2] if len(v) > 2 else "",
                v[3] if len(v) > 3 else "",
                _cvss_from_severity(v[3] if len(v) > 3 else ""),
                v[4] if len(v) > 4 else "",
                v[5] if len(v) > 5 else "",
                v[6] if len(v) > 6 else "",
                v[7] if len(v) > 7 else "",
            ])

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
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
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
