#!/usr/bin/env python3
"""Tests for export.py — JSON/CSV export and CVSS mapping."""

import copy
import csv
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestCvssMapping:
    """Test severity-to-CVSS score mapping."""

    def test_critical_maps_high(self):
        from export import _cvss_from_severity
        score = _cvss_from_severity("critical")
        assert score >= 9.0

    def test_high_maps_correctly(self):
        from export import _cvss_from_severity
        score = _cvss_from_severity("high")
        assert 7.0 <= score < 9.0

    def test_medium_maps_correctly(self):
        from export import _cvss_from_severity
        score = _cvss_from_severity("medium")
        assert 4.0 <= score < 7.0

    def test_low_maps_correctly(self):
        from export import _cvss_from_severity
        score = _cvss_from_severity("low")
        assert 0.0 < score < 4.0

    def test_unknown_returns_zero(self):
        from export import _cvss_from_severity
        score = _cvss_from_severity("unknown")
        assert score == 0.0

    def test_case_insensitive(self):
        from export import _cvss_from_severity
        assert _cvss_from_severity("HIGH") == _cvss_from_severity("high")
        assert _cvss_from_severity("Critical") == _cvss_from_severity("critical")


class TestJsonExport:
    """Test JSON export format."""

    def test_creates_json_file(self, sample_session_data, tmp_path):
        from export import export_json
        filepath = export_json(sample_session_data, str(tmp_path))

        assert os.path.exists(filepath)
        assert filepath.endswith(".json")

    def test_json_valid_structure(self, sample_session_data, tmp_path):
        from export import export_json
        filepath = export_json(sample_session_data, str(tmp_path))

        with open(filepath) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "scan" in data
        assert "vulnerabilities" in data
        assert "statistics" in data
        assert data["metadata"]["tool"] == "OCTOPUS"

    def test_json_vuln_count_matches(self, sample_session_data, tmp_path):
        from export import export_json
        filepath = export_json(sample_session_data, str(tmp_path))

        with open(filepath) as f:
            data = json.load(f)

        assert data["statistics"]["total_vulnerabilities"] == 2
        assert len(data["vulnerabilities"]) == 2

    def test_json_target_correct(self, sample_session_data, tmp_path):
        from export import export_json
        filepath = export_json(sample_session_data, str(tmp_path))

        with open(filepath) as f:
            data = json.load(f)

        assert data["scan"]["target"] == "192.168.1.100"

    def test_json_preserves_vulnerability_provenance(self, sample_session_data, tmp_path):
        from export import export_json

        filepath = export_json(sample_session_data, str(tmp_path))
        with open(filepath, encoding="utf-8") as f:
            vuln = json.load(f)["vulnerabilities"][0]

        assert vuln["evidence_source"] == "nmap"
        assert vuln["raw_evidence"] == "HTTP 200 with /etc/passwd"
        assert vuln["repro_cmd"] == "curl --path-as-is ..."
        assert vuln["cvss_score"] == 8.1

    def test_export_filename_is_contained(self, sample_session_data, tmp_path):
        from export import export_json

        report = copy.deepcopy(sample_session_data)
        report["history"] = (1, "../../outside/evil", "2026-06-15", "complete")
        filepath = Path(export_json(report, str(tmp_path)))

        assert filepath.resolve().parent == tmp_path.resolve()
        assert filepath.name.endswith(".json")


class TestCsvExport:
    """Test CSV export format."""

    def test_creates_csv_file(self, sample_session_data, tmp_path):
        from export import export_csv
        filepath = export_csv(sample_session_data, str(tmp_path))

        assert os.path.exists(filepath)
        assert filepath.endswith(".csv")

    def test_csv_has_header(self, sample_session_data, tmp_path):
        from export import export_csv
        filepath = export_csv(sample_session_data, str(tmp_path))

        with open(filepath) as f:
            reader = csv.reader(f)
            header = next(reader)

        assert "ID" in header
        assert "Vulnerability" in header
        assert "Severity" in header
        assert "CVSS" in header

    def test_csv_row_count(self, sample_session_data, tmp_path):
        from export import export_csv
        filepath = export_csv(sample_session_data, str(tmp_path))

        with open(filepath) as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 2 vulnerabilities
        assert len(rows) == 3

    def test_csv_neutralizes_spreadsheet_formulas(self, sample_session_data, tmp_path):
        from export import export_csv

        report = copy.deepcopy(sample_session_data)
        report["history"] = (1, "=HYPERLINK(\"https://example.test\")", "date", "complete")
        original = list(report["vulns"][0])
        original[2] = "  +SUM(1,1)"
        original[6] = "@malicious"
        original[9] = "-2+3"
        original[10] = "\t=cmd"
        report["vulns"][0] = tuple(original)

        filepath = export_csv(report, str(tmp_path))
        with open(filepath, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))

        row = rows[0]
        assert row["Target"].startswith("'=")
        assert row["Vulnerability"].startswith("'  +")
        assert row["Description"].startswith("'@")
        assert row["Raw Evidence"].startswith("'-")
        assert row["Reproduction Command"].startswith("'\t")


class TestRenderedExports:
    def test_html_escapes_all_dynamic_markup(self, sample_session_data, tmp_path):
        from export import export_html

        report = copy.deepcopy(sample_session_data)
        report["history"] = (1, "<script>target()</script>", "<date>", "complete")
        vuln = list(report["vulns"][0])
        vuln[2] = "<img src=x onerror=alert(1)>"
        vuln[6] = "evidence & <script>vuln()</script>"
        vuln[9] = "<svg onload=alert(2)>"
        report["vulns"][0] = tuple(vuln)
        report["summary"] = (1, 1, "raw", "<script>analysis()</script>", "HIGH", "now")

        filepath = export_html(report, str(tmp_path))
        rendered = Path(filepath).read_text(encoding="utf-8")

        assert "<script>target()" not in rendered
        assert "<img src=x onerror" not in rendered
        assert "<svg onload" not in rendered
        assert "&lt;script&gt;analysis()&lt;/script&gt;" in rendered
        assert "evidence &amp; &lt;script&gt;vuln()&lt;/script&gt;" in rendered

    def test_pdf_escapes_reportlab_markup(self, sample_session_data, tmp_path):
        from export import export_pdf

        report = copy.deepcopy(sample_session_data)
        report["history"] = (1, "<b>unterminated & target", "date", "complete")
        vuln = list(report["vulns"][0])
        vuln[2] = "<font color='red'>finding &"
        vuln[6] = "<b>not reportlab markup"
        report["vulns"][0] = tuple(vuln)

        filepath = Path(export_pdf(report, str(tmp_path)))

        assert filepath.is_file()
        assert filepath.stat().st_size > 0


class TestExecutiveSummary:
    """Test executive summary generation."""

    def test_summary_generation(self, sample_session_data):
        from export import _generate_executive_summary
        summary = _generate_executive_summary(sample_session_data)

        assert isinstance(summary, str)
        assert len(summary) > 0
        # Should mention vulnerability count
        assert "2" in summary or "vulnerabilities" in summary.lower()
