"""Contracts for reporting and Shodan runtime configuration wiring."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.contract


def test_cvss_scoring_switch_preserves_stored_scores_and_disables_inference(monkeypatch):
    import export

    monkeypatch.setattr(export, "CFG", {"reporting": {"cvss_scoring": False}})
    stored = (1, 1, "stored", "HIGH", "443", "https", "desc", "CONFIRMED",
              "source", "evidence", "repro", 8.4)
    inferred = (2, 1, "inferred", "HIGH", "80", "http", "desc")

    assert export._vuln_cvss(stored) == 8.4
    assert export._vuln_cvss(inferred) is None
    assert export._cvss_display(inferred) == "-"


def test_json_raw_output_is_controlled_by_reporting_config(
    monkeypatch, sample_session_data, tmp_path,
):
    import export

    monkeypatch.setattr(export, "CFG", {"reporting": {"include_raw_output": False}})
    without_raw = Path(export.export_json(sample_session_data, str(tmp_path / "off")))
    payload = json.loads(without_raw.read_text(encoding="utf-8"))
    assert "raw_output" not in payload["summary"]
    assert payload["vulnerabilities"][0]["raw_evidence"] == ""
    assert "raw scan data..." not in without_raw.read_text(encoding="utf-8")
    assert "HTTP 200 with /etc/passwd" not in without_raw.read_text(encoding="utf-8")

    monkeypatch.setattr(export, "CFG", {"reporting": {"include_raw_output": True}})
    with_raw = Path(export.export_json(sample_session_data, str(tmp_path / "on")))
    payload = json.loads(with_raw.read_text(encoding="utf-8"))
    assert payload["summary"]["raw_output"] == "raw scan data..."
    assert payload["vulnerabilities"][0]["raw_evidence"] == "HTTP 200 with /etc/passwd"


def test_auto_export_generates_pdf_without_opening_export_menu(monkeypatch):
    import octopus

    calls = []
    monkeypatch.setattr(octopus, "CFG", {"reporting": {"auto_export": True}})
    monkeypatch.setattr(
        octopus,
        "_lazy_module_call",
        lambda module, function, data: calls.append((module, function, data)) or "/tmp/report.pdf",
    )
    monkeypatch.setattr(octopus, "success", lambda *_args: None)

    data = {"history": (7, "example.test", "today", "complete")}
    assert octopus._auto_export_session(data) is True
    assert calls == [("export", "export_pdf", data)]


def test_auto_shodan_context_only_runs_when_enabled(monkeypatch):
    import octopus

    calls = []
    monkeypatch.setattr(octopus, "info", lambda *_args: None)
    monkeypatch.setattr(octopus, "warn", lambda *_args: None)
    monkeypatch.setattr(
        octopus,
        "_lazy_module_call",
        lambda module, function, target: calls.append((module, function, target))
        or "[SHODAN HOST: 192.0.2.10]\nPorts: 443",
    )

    monkeypatch.setattr(octopus, "CFG", {"shodan": {"auto_scan": False}})
    assert octopus._append_auto_shodan_context("192.0.2.10", "NMAP") == "NMAP"
    assert calls == []

    monkeypatch.setattr(octopus, "CFG", {"shodan": {"auto_scan": True}})
    enriched = octopus._append_auto_shodan_context("192.0.2.10", "NMAP")
    assert "NMAP" in enriched
    assert "[SHODAN HOST: 192.0.2.10]" in enriched
    assert calls == [("shodan_module", "run_shodan_smart", "192.0.2.10")]


def test_shodan_timeout_is_applied_to_underlying_http_session():
    import shodan_module

    requests_seen = []

    class Session:
        def request(self, method, url, **kwargs):
            requests_seen.append((method, url, kwargs))
            return {"ok": True}

    client = SimpleNamespace(_session=Session())
    assert shodan_module._configure_http_timeout(client, 17.5) is True
    client._session.request("GET", "https://api.shodan.test")
    client._session.request("GET", "https://api.shodan.test", timeout=2)

    assert requests_seen[0][2]["timeout"] == 17.5
    assert requests_seen[1][2]["timeout"] == 2


def test_shodan_save_results_false_keeps_results_in_memory_only():
    import shodan_module

    recon = shodan_module.ShodanRecon.__new__(shodan_module.ShodanRecon)
    recon.api = SimpleNamespace(search=lambda _query, limit: {
        "total": 1,
        "matches": [{"ip_str": "192.0.2.10", "port": 443, "product": "https"}],
    })
    recon.max_results = 10
    recon.save_results = False
    recon._last_results = []
    recon.save_to_db = MagicMock()
    recon._save_json = MagicMock()

    result = recon.search("port:443")

    assert result["retrieved"] == 1
    assert recon._last_results[0]["ip"] == "192.0.2.10"
    recon.save_to_db.assert_not_called()
    recon._save_json.assert_not_called()
