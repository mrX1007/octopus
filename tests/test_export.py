#!/usr/bin/env python3
"""Tests for export.py — JSON/CSV export and CVSS mapping."""

import os
import sys
import json
import csv
import pytest
from unittest.mock import patch

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


class TestExecutiveSummary:
    """Test executive summary generation."""

    def test_summary_generation(self, sample_session_data):
        from export import _generate_executive_summary
        summary = _generate_executive_summary(sample_session_data)

        assert isinstance(summary, str)
        assert len(summary) > 0
        # Should mention vulnerability count
        assert "2" in summary or "vulnerabilities" in summary.lower()
