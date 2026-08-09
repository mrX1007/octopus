"""Branch-complete, hermetic coverage tests for :mod:`export`."""

from __future__ import annotations

import builtins
import copy
import json
import runpy
from pathlib import Path

import pytest

import export

pytestmark = pytest.mark.contract


def _empty_report() -> dict:
    return {
        "history": (7, "target.test", "2026-07-29", "complete"),
        "vulns": [],
        "fixes": [],
        "exploits": [],
        "summary": None,
    }


def test_config_import_fallback(monkeypatch):
    real_import = builtins.__import__

    def import_without_config(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config":
            raise ImportError("config deliberately unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_config)
    namespace = runpy.run_path(export.__file__, run_name="export_without_config")

    assert namespace["CFG"] == {}


def test_boolean_config_and_normalization_helpers(monkeypatch):
    assert export._as_bool(True) is True
    assert export._as_bool(None, True) is True
    assert export._as_bool(0) is False
    assert export._as_bool(2) is True
    assert export._as_bool(" YES ") is True
    assert export._as_bool("off", True) is False
    assert export._as_bool("surprise", True) is True

    monkeypatch.setattr(export, "CFG", object())
    assert export._reporting_option("anything", True) is True
    monkeypatch.setattr(export, "CFG", {"reporting": "invalid"})
    assert export._reporting_option("anything", False) is False

    with pytest.raises(TypeError, match="dictionary"):
        export._normalize_session_report([])
    normalized = export._normalize_session_report({"history": (1,), "vulnerabilities": [(1,)], "fixes": None})
    assert normalized["vulns"] == [(1,)]
    assert normalized["fixes"] == []

    assert export._row_value(None, 0, "fallback") == "fallback"
    assert export._row_value((), 0, "fallback") == "fallback"
    assert export._row_value((None,), 0, "fallback") == "fallback"
    assert export._row_value(("value",), 0, "fallback") == "value"


def test_filename_csv_and_cvss_edge_cases(monkeypatch, tmp_path):
    assert export._safe_component("***", "fallback") == "fallback"
    assert export._csv_safe(4) == 4
    assert export._csv_safe("ordinary") == "ordinary"
    assert export._csv_safe("\rformula").startswith("'")

    with pytest.raises(ValueError, match="extension"):
        export._report_path(str(tmp_path), 1, "target", "***")

    monkeypatch.setattr(export.os.path, "commonpath", lambda _paths: "/elsewhere")
    with pytest.raises(ValueError, match="escaped"):
        export._report_path(str(tmp_path), 1, "target", "txt")


def test_report_path_commonpath_error_and_symlink(monkeypatch, tmp_path):
    def incompatible_paths(_paths):
        raise ValueError("different drives")

    monkeypatch.setattr(export.os.path, "commonpath", incompatible_paths)
    with pytest.raises(ValueError, match="escaped"):
        export._report_path(str(tmp_path), 1, "target", "txt")

    monkeypatch.undo()
    candidate = tmp_path / "octopus_SL1_target.txt"
    candidate.symlink_to(tmp_path / "destination")
    with pytest.raises(ValueError, match="symbolic-link"):
        export._report_path(str(tmp_path), 1, "target", "txt")


def test_cvss_raw_output_and_summary_edges(monkeypatch):
    invalid_stored = (1, 1, "finding", "HIGH", 80, "http", "", "", "", "", "", object())
    monkeypatch.setattr(export, "CFG", {"reporting": {"cvss_scoring": False}})
    assert export._vuln_cvss(invalid_stored) is None
    assert export._cvss_display(invalid_stored) == "-"
    assert export._raw_scan_output({"summary": None}) == ""
    assert export._vulnerability_raw_evidence(invalid_stored) == ""

    report = _empty_report()
    summary = export._generate_executive_summary(report)
    assert "No active exploitation" in summary

    report["history"] = None
    with pytest.raises(ValueError, match="no history"):
        export._generate_executive_summary(report)


def test_report_directory_config_and_fallback(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CFG", {"paths": {"reports": str(tmp_path)}})
    assert export._get_report_dir() == str(tmp_path)

    monkeypatch.setattr(config, "CFG", {})
    monkeypatch.setattr(export.os.path, "expanduser", lambda path: f"expanded:{path}")
    assert export._get_report_dir() == "expanded:~/OCTOPUS/reports"


@pytest.mark.parametrize("renderer", [export.export_pdf, export.export_html])
def test_renderers_reject_missing_history(renderer, tmp_path):
    report = _empty_report()
    report["history"] = None
    with pytest.raises(ValueError, match="no history"):
        renderer(report, str(tmp_path))


def test_pdf_empty_report_uses_default_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(export, "_get_report_dir", lambda: str(tmp_path))
    path = Path(export.export_pdf(_empty_report()))

    assert path.is_file()
    assert path.stat().st_size > 0


def test_pdf_covers_optional_finding_content(monkeypatch, sample_session_data, tmp_path):
    report = copy.deepcopy(sample_session_data)
    empty_fields = [2, 7, "", "", "", "", "", "", "", "", "", "invalid"]
    report["vulns"].append(tuple(empty_fields))
    report["summary"] = (1, 1, "first line\n\nthird line", "analysis\n\nnext", "ODD", "now")

    monkeypatch.setattr(
        export,
        "CFG",
        {"reporting": {"include_raw_output": True, "cvss_scoring": True}},
    )
    original_summary = export._generate_executive_summary

    def summary_with_blank(data):
        return original_summary(data) + "\n\n \n\nFinal paragraph"

    monkeypatch.setattr(export, "_generate_executive_summary", summary_with_blank)
    path = Path(export.export_pdf(report, str(tmp_path)))

    assert path.is_file()


def test_html_empty_report_uses_default_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(export, "_get_report_dir", lambda: str(tmp_path))
    rendered = Path(export.export_html(_empty_report())).read_text(encoding="utf-8")

    assert rendered.count("None recorded.") == len(
        export.extract_machine_report(_empty_report())["section_order"]
    )


def test_html_finding_without_optional_provenance(monkeypatch, tmp_path):
    report = _empty_report()
    report["vulns"] = [(1, 7, "minimal", "LOW", None, None, "", "", "", "", "")]
    monkeypatch.setattr(export, "CFG", {"reporting": {"include_raw_output": False}})

    rendered = Path(export.export_html(report, str(tmp_path))).read_text(encoding="utf-8")

    assert "minimal" in rendered
    assert "Confidence:" not in rendered


def test_export_menu_without_history(capsys):
    report = _empty_report()
    report["history"] = None
    assert export.export_menu(report) is None
    assert "No session data" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("choice", "expected"),
    [
        ("1", ["pdf"]),
        ("2", ["html"]),
        ("3", ["json"]),
        ("4", ["csv"]),
        ("5", ["pdf", "html", "json", "csv"]),
        ("0", []),
        ("invalid", []),
    ],
)
def test_export_menu_choices(monkeypatch, tmp_path, capsys, choice, expected):
    calls = []

    def fake_renderer(kind):
        def render(_data, output_dir):
            calls.append(kind)
            assert output_dir == str(tmp_path)
            return str(tmp_path / f"report.{kind}")

        return render

    monkeypatch.setattr(builtins, "input", lambda _prompt: choice)
    monkeypatch.setattr(export, "_get_report_dir", lambda: str(tmp_path))
    for kind in ("pdf", "html", "json", "csv"):
        monkeypatch.setattr(export, f"export_{kind}", fake_renderer(kind))

    assert export.export_menu(_empty_report()) is None
    assert calls == expected
    output = capsys.readouterr().out
    if choice == "invalid":
        assert "Invalid choice" in output


@pytest.mark.parametrize("renderer", [export.export_json, export.export_csv])
def test_machine_exports_reject_missing_history(renderer, tmp_path):
    report = _empty_report()
    report["history"] = None
    with pytest.raises(ValueError, match="no history"):
        renderer(report, str(tmp_path))


def test_json_handles_short_rows_and_empty_scores(monkeypatch, tmp_path):
    report = _empty_report()
    report["history"] = (7, "target", None)
    report["vulns"] = [(1,)]
    report["fixes"] = [(1,), (2, 7, 8), (3, 7, 8, "fix")]
    report["exploits"] = [
        (1,),
        (2, 7, "name"),
        (3, 7, "name", "tool"),
        (4, 7, "name", "tool", "payload"),
        (5, 7, "name", "tool", "payload", "ok"),
    ]
    monkeypatch.setattr(export, "CFG", {"reporting": {"cvss_scoring": False}})

    payload = json.loads(Path(export.export_json(report, str(tmp_path))).read_text())

    assert payload["legacy_adapter"]["scan_date"] == ""
    assert payload["legacy_adapter"]["status"] == "unknown"
    candidate = payload["sections"]["hypotheses_candidates"][0]
    assert candidate["legacy_fields"]["cvss_score"] is None


def _run_main(monkeypatch, *, rows, inputs, session=None):
    import db

    answers = iter(inputs)
    monkeypatch.setattr(db, "get_all_history", lambda: rows)
    monkeypatch.setattr(db, "get_session", lambda _sl: session)
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    runpy.run_path(export.__file__, run_name="__main__")


def test_main_no_sessions_exits(monkeypatch):
    monkeypatch.setattr(
        builtins,
        "exit",
        lambda: (_ for _ in ()).throw(SystemExit),
    )
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, rows=[], inputs=[])


def test_main_invalid_session_number_exits(monkeypatch):
    monkeypatch.setattr(
        builtins,
        "exit",
        lambda: (_ for _ in ()).throw(SystemExit),
    )
    with pytest.raises(SystemExit):
        _run_main(
            monkeypatch,
            rows=[(7, "target", "date", "complete")],
            inputs=["not-a-number"],
        )


def test_main_missing_session_exits(monkeypatch):
    monkeypatch.setattr(
        builtins,
        "exit",
        lambda: (_ for _ in ()).throw(SystemExit),
    )
    with pytest.raises(SystemExit):
        _run_main(
            monkeypatch,
            rows=[(7, "target", "date", "complete")],
            inputs=["7"],
            session={"history": None},
        )


def test_main_opens_export_menu(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CFG", {"paths": {"reports": str(tmp_path)}})
    _run_main(
        monkeypatch,
        rows=[(7, "target", "date", "complete")],
        inputs=["7", "0"],
        session=_empty_report(),
    )
