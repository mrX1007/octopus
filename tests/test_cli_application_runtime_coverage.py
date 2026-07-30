"""Hermetic coverage for legacy CLI runtime and Shodan boundaries."""

from __future__ import annotations

import builtins
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.cli import application as app

pytestmark = [pytest.mark.unit, pytest.mark.contract]


@pytest.fixture(autouse=True)
def quiet_cli(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "banner",
        "divider",
        "error",
        "info",
        "print_results_table",
        "success",
        "warn",
    ):
        monkeypatch.setattr(app, name, MagicMock())
    monkeypatch.setattr(app, "_current_sl_no", None)
    monkeypatch.setattr(app, "_supervisor", None)
    monkeypatch.setattr(app, "_cached_api_key", None)


def test_import_fallback_and_lazy_provider_boundaries(monkeypatch: pytest.MonkeyPatch, capsys):
    real_import = builtins.__import__

    def import_without_config(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config":
            raise ImportError("fixture config unavailable")
        return real_import(name, globals, locals, fromlist, level)

    module_name = "_octopus_cli_application_config_fallback"
    spec = importlib.util.spec_from_file_location(module_name, app.__file__)
    assert spec is not None and spec.loader is not None
    fallback = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, fallback)
    monkeypatch.setattr(builtins, "__import__", import_without_config)
    spec.loader.exec_module(fallback)
    assert fallback.CFG["paths"]["logs"] == "~/OCTOPUS/logs"

    provider = SimpleNamespace(run=lambda value, *, flag=False: (value, flag))
    monkeypatch.setattr(app, "import_module", lambda _name: provider)
    assert app._lazy_module_call("fixture", "run", 3, flag=True) == (3, True)
    monkeypatch.setattr(
        app,
        "import_module",
        MagicMock(side_effect=ImportError("missing dependency")),
    )
    with pytest.raises(RuntimeError, match="fixture module unavailable"):
        app._lazy_module_call("fixture", "run")

    wrapper = app._lazy_db("fetch")
    assert wrapper.__name__ == "fetch"
    lazy = MagicMock(return_value="row")
    monkeypatch.setattr(app, "_lazy_module_call", lazy)
    assert wrapper(1, active=True) == "row"
    lazy.assert_called_once_with("db", "fetch", 1, active=True)

    lazy.reset_mock(return_value=True)
    lazy.return_value = "exported"
    assert app.export_menu("data", fmt="json") == "exported"
    lazy.assert_called_once_with("export", "export_menu", "data", fmt="json")
    lazy.side_effect = RuntimeError("no export")
    assert app.export_menu("data") is None
    assert "Export module unavailable" in capsys.readouterr().out

    lazy.side_effect = None
    lazy.return_value = "tools"
    assert app.interactive_tool_run("target") == "tools"
    lazy.assert_called_with("tools", "interactive_tool_run", "target")


@pytest.mark.parametrize(
    ("cfg", "section", "name", "default", "expected"),
    (
        (None, "x", "flag", True, True),
        ({"x": "bad"}, "x", "flag", False, False),
        ({"x": {"flag": True}}, "x", "flag", False, True),
        ({"x": {"flag": None}}, "x", "flag", True, True),
        ({"x": {"flag": 0}}, "x", "flag", True, False),
        ({"x": {"flag": 2.5}}, "x", "flag", False, True),
        ({"x": {"flag": " YES "}}, "x", "flag", False, True),
        ({"x": {"flag": "off"}}, "x", "flag", True, False),
        ({"x": {"flag": "surprise"}}, "x", "flag", True, True),
    ),
)
def test_config_bool_normalizes_supported_values(monkeypatch, cfg, section, name, default, expected):
    monkeypatch.setattr(app, "CFG", cfg)
    assert app._config_bool(section, name, default) is expected


def test_auto_shodan_context_handles_every_boundary(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app, "CFG", {"shodan": {"auto_scan": False}})
    provider = MagicMock()
    monkeypatch.setattr(app, "_lazy_module_call", provider)
    assert app._append_auto_shodan_context("host", "scan") == "scan"
    provider.assert_not_called()

    monkeypatch.setattr(app, "CFG", {"shodan": {"auto_scan": True}})
    assert app._append_auto_shodan_context("host", "[SHODAN host]\nscan") == (
        "[SHODAN host]\nscan"
    )
    provider.side_effect = RuntimeError("offline")
    assert app._append_auto_shodan_context("host", "scan") == "scan"
    app.warn.assert_called_with("Automatic Shodan lookup unavailable: offline")

    provider.side_effect = None
    for output in (None, "", "[!] unavailable"):
        provider.return_value = output
        assert app._append_auto_shodan_context("host", "scan") == "scan"
    app.warn.assert_called_with("[!] unavailable")

    provider.return_value = " [SHODAN host]\nPorts: 443 "
    assert app._append_auto_shodan_context("host", " scan ") == (
        "scan\n\n[SHODAN host]\nPorts: 443\n"
    )
    assert app._append_auto_shodan_context("host", "") == "[SHODAN host]\nPorts: 443\n"
    app.info.assert_called_with("Shodan context added automatically.")


def test_auto_export_handles_disabled_failure_and_success(monkeypatch: pytest.MonkeyPatch):
    provider = MagicMock(return_value="/tmp/report.pdf")
    monkeypatch.setattr(app, "_lazy_module_call", provider)
    monkeypatch.setattr(app, "CFG", {"reporting": {"auto_export": False}})
    assert app._auto_export_session({"id": 1}) is False
    provider.assert_not_called()

    monkeypatch.setattr(app, "CFG", {"reporting": {"auto_export": True}})
    provider.side_effect = OSError("disk full")
    assert app._auto_export_session({"id": 1}) is False
    app.warn.assert_called_with("Automatic PDF export failed: disk full")

    provider.side_effect = None
    assert app._auto_export_session({"id": 1}) is True
    app.success.assert_called_with("PDF report exported automatically: /tmp/report.pdf")


def test_logging_readline_trace_and_sigint_boundaries(monkeypatch: pytest.MonkeyPatch, tmp_path):
    class Clock:
        @staticmethod
        def now():
            return SimpleNamespace(strftime=lambda _fmt: "20260729_120000")

    handler = object()
    monkeypatch.setattr(app, "CFG", {"paths": {"logs": str(tmp_path)}})
    monkeypatch.setattr(app, "_datetime", Clock)
    monkeypatch.setattr(app.logging, "FileHandler", MagicMock(return_value=handler))
    basic_config = MagicMock()
    monkeypatch.setattr(app.logging, "basicConfig", basic_config)
    import core.secrets

    install = MagicMock()
    monkeypatch.setattr(core.secrets, "install_logging_redaction", install)
    log_path = app._setup_logging()
    assert log_path.endswith("octopus_20260729_120000.log")
    assert basic_config.call_args.kwargs["handlers"] == [handler]
    install.assert_called_once_with()

    setup = MagicMock()
    monkeypatch.setattr(app, "setup_readline", setup)
    app._setup_readline()
    setup.assert_called_once_with(app._HISTORY_FILE)

    pipeline = SimpleNamespace(
        trace_report=MagicMock(return_value={"trace": True}),
        trace_reporter=SimpleNamespace(
            to_json=lambda _report: '{"trace":true}',
            to_text=lambda _report: "trace text",
        ),
    )
    app._save_trace_report(pipeline, "scan-1", "host")
    assert (tmp_path / "trace_scan-1.json").read_text() == '{"trace":true}'
    assert (tmp_path / "trace_scan-1.txt").read_text() == "trace text"
    pipeline.trace_report.side_effect = RuntimeError("trace failure")
    app._save_trace_report(pipeline, "scan-2", "host")
    app.warn.assert_called_with("Trace report save failed: trace failure")

    cancellation = MagicMock()
    context = SimpleNamespace(cancellation=cancellation)
    import core.execution

    monkeypatch.setattr(core.execution, "current_execution_context", lambda: context)
    update = MagicMock()
    supervisor = MagicMock()
    monkeypatch.setattr(app, "update_session_status", update)
    monkeypatch.setattr(app, "_current_sl_no", 7)
    monkeypatch.setattr(app, "_supervisor", supervisor)
    with pytest.raises(KeyboardInterrupt):
        app._sigint_handler(None, None)
    cancellation.cancel.assert_called_once_with("sigint")
    update.assert_called_once_with(7, "interrupted")
    supervisor.stop.assert_called_once_with()

    monkeypatch.setattr(
        core.execution,
        "current_execution_context",
        MagicMock(side_effect=RuntimeError("no context")),
    )
    broken_supervisor = MagicMock()
    broken_supervisor.stop.side_effect = RuntimeError("stop failed")
    monkeypatch.setattr(app, "_current_sl_no", None)
    monkeypatch.setattr(app, "_supervisor", broken_supervisor)
    with pytest.raises(KeyboardInterrupt):
        app._sigint_handler(None, None)
    monkeypatch.setattr(app, "_supervisor", None)
    with pytest.raises(KeyboardInterrupt):
        app._sigint_handler(None, None)


def test_trace_report_cli_supports_context_failure_and_both_formats(monkeypatch, capsys):
    reporter = SimpleNamespace(
        build=MagicMock(return_value={"report": True}),
        to_json=lambda _report: '{"report":true}',
        to_text=lambda _report: "report text",
    )
    monkeypatch.setattr(app, "FactStore", lambda: object())
    monkeypatch.setattr(app, "TraceReporter", lambda _store: reporter)
    pipeline = SimpleNamespace(
        context_builder=SimpleNamespace(build_context=lambda *_args: {"context": True})
    )
    monkeypatch.setattr(app, "AIPipeline", lambda: pipeline)
    app._print_trace_report_cli("scan", "host", "json")
    assert '{"report":true}' in capsys.readouterr().out
    reporter.build.assert_called_with("scan", "host", context={"context": True})

    monkeypatch.setattr(app, "AIPipeline", MagicMock(side_effect=RuntimeError("offline")))
    app._print_trace_report_cli("scan", "host", "text")
    assert "report text" in capsys.readouterr().out
    reporter.build.assert_called_with("scan", "host", context={})


def test_new_scan_dispatch_and_direct_scan_boundaries(monkeypatch: pytest.MonkeyPatch):
    original = app._new_scan_direct
    direct = MagicMock()
    shodan = MagicMock()
    monkeypatch.setattr(app, "_new_scan_direct", direct)
    monkeypatch.setattr(app, "_new_scan_shodan", shodan)
    for answer in ("1", "2", "bad"):
        monkeypatch.setattr(app, "prompt", lambda _text, answer=answer: answer)
        app.new_scan()
    direct.assert_called_once_with()
    shodan.assert_called_once_with()
    app.warn.assert_called_with("Invalid choice.")

    monkeypatch.setattr(app, "_new_scan_direct", original)
    monkeypatch.setattr(app, "prompt", lambda _text: "")
    original()
    app.warn.assert_called_with("No target entered.")

    monkeypatch.setattr(app, "prompt", lambda _text: "host")
    monkeypatch.setattr(app, "get_all_history", lambda: [(1, "host")])
    monkeypatch.setattr(app, "confirm", lambda _text: False)
    create = MagicMock()
    monkeypatch.setattr(app, "create_session", create)
    original()
    create.assert_not_called()

    monkeypatch.setattr(app, "get_all_history", list)
    monkeypatch.setattr(app, "create_session", MagicMock(return_value=8))
    monkeypatch.setattr(app, "interactive_tool_run", lambda _target: "")
    monkeypatch.setattr(app, "_append_auto_shodan_context", lambda _target, raw: raw)
    delete = MagicMock()
    monkeypatch.setattr(app, "delete_full_session", delete)
    original()
    delete.assert_called_once_with(8)
    assert app._current_sl_no is None

    class Pipeline:
        def __init__(self):
            self.fact_store = object()

        def run_scan(self, scan_id, target, *, raw_scan):
            return {"scan": scan_id, "target": target, "raw": raw_scan}

    monkeypatch.setattr(app, "get_all_history", lambda: [(1, "host")])
    monkeypatch.setattr(app, "confirm", lambda _text: True)
    monkeypatch.setattr(app, "create_session", MagicMock(return_value=9))
    monkeypatch.setattr(app, "interactive_tool_run", lambda _target: "raw scan")
    monkeypatch.setattr(app, "AIPipeline", Pipeline)
    monkeypatch.setattr(app, "_save_trace_report", MagicMock())
    monkeypatch.setattr(
        app,
        "_adapt_state_to_result",
        MagicMock(return_value={"risk_level": "LOW"}),
    )
    update = MagicMock()
    show = MagicMock()
    monkeypatch.setattr(app, "update_session_status", update)
    monkeypatch.setattr(app, "_save_and_show_results", show)
    original()
    update.assert_called_once_with(9, "complete")
    show.assert_called_once()
    assert app._current_sl_no is None


def test_shodan_worker_count_context_and_recon_results(monkeypatch: pytest.MonkeyPatch):
    assert app._clamp_shodan_workers("4", object()) == 1
    assert app._clamp_shodan_workers(object(), 3, default=2, maximum=0) == 1
    assert app._clamp_shodan_workers("99", 20, maximum=8) == 8

    context = app._build_shodan_context({
        "ip": "192.0.2.1",
        "ports": [80, 443],
        "org": "Example",
        "os": "Linux",
        "vulns": ["CVE-1"],
        "services": ["invalid", {"port": 443, "name": "https", "version": "1.2"}],
    })
    assert "Known CVEs: CVE-1" in context
    assert "443/https 1.2" in context
    minimal = app._build_shodan_context({})
    assert "Org: unknown" in minimal
    assert "Known CVEs" not in minimal

    missing = app._shodan_recon_worker(1, 2, {"ports": []})
    assert missing["error"] == "Shodan target has no IP"

    marker = "__OCTOPUS_RECON_JSON__="

    def run_child(returncode=0, stdout="", stderr=""):
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(app, "CFG", {"shodan": {"timeout": "bad"}})
    monkeypatch.setattr(
        app.subprocess,
        "run",
        MagicMock(return_value=run_child(stdout=f"ui\n{marker}" + json.dumps({"host": "data"}) + "\n")),
    )
    success_result = app._shodan_recon_worker(1, 1, {"ip": "host"})
    assert success_result["error"] is None
    assert success_result["raw_scan"].endswith("data")
    assert success_result["worker_output"] == "ui\n"
    assert app.subprocess.run.call_args.kwargs["timeout"] == 120

    monkeypatch.setattr(app, "CFG", {"shodan": {"timeout": 20}})
    cases = (
        run_child(returncode=1, stderr="stderr failure"),
        run_child(returncode=1, stdout="stdout failure"),
        run_child(returncode=1),
        run_child(stdout="missing marker"),
        run_child(stdout=f"{marker}[]\n"),
    )
    for child in cases:
        app.subprocess.run.return_value = child
        assert app._shodan_recon_worker(1, 1, {"ip": "host"})["error"]

    app.subprocess.run.side_effect = OSError("spawn failed")
    failed = app._shodan_recon_worker(1, 1, {"ip": "host"})
    assert failed["error"] == "spawn failed"
    assert "RECON ERROR" in failed["raw_scan"]


def test_shodan_scan_log_success_fallback_and_write_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "CFG", {"paths": {"logs": str(tmp_path)}})
    path = Path(app._write_shodan_scan_log("bad/sl", "...", "content"))
    assert path.parent == tmp_path
    assert path.read_text() == "content"

    real_makedirs = app.os.makedirs
    calls = 0

    def fail_once(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("configured log root unavailable")
        return real_makedirs(path, *args, **kwargs)

    monkeypatch.setattr(app.os, "makedirs", fail_once)
    fallback = app._write_shodan_scan_log(1, "host", "fallback")
    assert Path(fallback).read_text() == "fallback"

    import tempfile

    monkeypatch.setattr(tempfile, "mkstemp", MagicMock(side_effect=OSError("no file")))
    assert app._write_shodan_scan_log(1, "host", "data") == "unavailable"

    monkeypatch.setattr(tempfile, "mkstemp", MagicMock(return_value=(77, str(tmp_path / "partial"))))
    monkeypatch.setattr(app.os, "fdopen", MagicMock(side_effect=OSError("fdopen failed")))
    close = MagicMock()
    unlink = MagicMock()
    monkeypatch.setattr(app.os, "close", close)
    monkeypatch.setattr(app.os, "unlink", unlink)
    assert app._write_shodan_scan_log(1, "host", "data") == "unavailable"
    close.assert_called_once_with(77)
    unlink.assert_called_once_with(str(tmp_path / "partial"))


def test_selection_parser_and_saved_shodan_queries(monkeypatch: pytest.MonkeyPatch):
    items = ["a", "b", "c", "d"]
    assert app._parse_selection("", items) == []
    assert app._parse_selection("1, 3-5, bad-range, 0, 99, nope", items) == [
        "a",
        "c",
        "d",
    ]

    sr = SimpleNamespace(_get_db=lambda: None)
    app._shodan_load_saved(sr)
    app.error.assert_called_with("Database not available.")

    empty_cursor = MagicMock()
    empty_cursor.fetchall.return_value = []
    empty_conn = MagicMock()
    empty_conn.cursor.return_value = empty_cursor
    sr._get_db = lambda: empty_conn
    app._shodan_load_saved(sr)
    app.warn.assert_called_with("No saved Shodan results in database.")

    rows = [("port:443", 2, "2026-01-01")]
    summary_cursor = MagicMock()
    summary_cursor.fetchall.return_value = rows
    detail_cursor = MagicMock()
    detail_cursor.fetchall.return_value = [
        {
            "ip": "192.0.2.1",
            "port": 443,
            "service": "https",
            "version": "1",
            "vulns": "[]",
        }
    ]
    conn = MagicMock()
    conn.cursor.side_effect = [summary_cursor, detail_cursor]
    sr._get_db = lambda: conn
    monkeypatch.setattr(app, "prompt", lambda _text: "1")
    app._shodan_load_saved(sr)
    detail_cursor.execute.assert_called_once()
    detail_cursor.close.assert_called_once_with()

    for choice in ("", "bad", "2"):
        cursor = MagicMock()
        cursor.fetchall.return_value = rows
        single_conn = MagicMock()
        single_conn.cursor.return_value = cursor
        sr._get_db = lambda single_conn=single_conn: single_conn
        monkeypatch.setattr(app, "prompt", lambda _text, choice=choice: choice)
        app._shodan_load_saved(sr)

    broken = MagicMock()
    broken.cursor.side_effect = RuntimeError("db failed")
    sr._get_db = lambda: broken
    app._shodan_load_saved(sr)
    app.error.assert_called_with("DB query failed: db failed")


class PipelineFixture:
    def __init__(self):
        self.fact_store = object()

    def run_scan(self, scan_id, target, *, raw_scan):
        return {"scan_id": scan_id, "target": target, "raw_scan": raw_scan}


def _patch_resume_success(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(app, "AIPipeline", PipelineFixture)
    monkeypatch.setattr(app, "_save_trace_report", MagicMock())
    monkeypatch.setattr(app, "_adapt_state_to_result", lambda *_args: {"risk_level": "LOW"})
    monkeypatch.setattr(app, "update_session_status", MagicMock())
    monkeypatch.setattr(app, "_save_and_show_results", MagicMock())


def test_resume_scan_no_files_corruption_and_invalid_choices(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "CFG", {"paths": {"checkpoints": str(tmp_path)}})
    app.resume_scan()
    app.warn.assert_called_with("No unfinished sessions found.")

    (tmp_path / "octopus_checkpoint_bad.json").write_text("not json")
    app.resume_scan()
    app.warn.assert_called_with("Found checkpoint files but they are corrupted or unreadable.")

    checkpoint = tmp_path / "octopus_checkpoint_7.json"
    checkpoint.write_text(json.dumps({"sl_no": 7, "target": "host", "loop": 2, "facts": []}))
    for choice in ("", "bad", "9"):
        monkeypatch.setattr(app, "prompt", lambda _text, choice=choice: choice)
        app.resume_scan()
    app.error.assert_called_with("Invalid choice.")

    checkpoint.write_text(json.dumps({"sl_no": 7, "target": "", "facts": []}))
    monkeypatch.setattr(app, "prompt", lambda _text: "1")
    app.resume_scan()
    app.error.assert_called_with("Checkpoint has no target field — cannot resume.")


def test_resume_scan_fresh_and_database_paths(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "CFG", {"paths": {"checkpoints": str(tmp_path)}})
    _patch_resume_success(monkeypatch)

    fresh = tmp_path / "octopus_checkpoint_fresh.json"
    fresh.write_text(
        json.dumps({"sl_no": 8, "target": "fresh-host", "loop": 2, "facts": ["port 80"]})
    )
    monkeypatch.setattr(app, "prompt", lambda _text: "1")
    monkeypatch.setattr(app, "confirm", lambda _text: True)
    monkeypatch.setattr(app, "interactive_tool_run", lambda _target: "")
    app.resume_scan()
    assert not fresh.exists()
    app.warn.assert_called_with("No scan data. Resuming with empty recon.")

    stored = tmp_path / "octopus_checkpoint_stored.json"
    stored.write_text(json.dumps({"sl_no": 9, "target": "stored-host", "facts": []}))
    monkeypatch.setattr(app, "confirm", lambda _text: False)
    monkeypatch.setattr(app, "get_session", lambda _sl: {"summary": (1, 2, "stored raw")})
    remove = MagicMock(side_effect=OSError("cannot remove"))
    monkeypatch.setattr(app.os, "remove", remove)
    app.resume_scan()
    remove.assert_called_once_with(str(stored))

    stored.write_text(json.dumps({"sl_no": 10, "target": "fallback-host", "facts": []}))
    monkeypatch.setattr(app.os, "remove", lambda path: Path(path).unlink())
    monkeypatch.setattr(app, "get_session", lambda _sl: {"summary": None})
    app.resume_scan()
    assert not stored.exists()


def test_resume_scan_preserves_nonempty_fresh_recon(monkeypatch, tmp_path):
    checkpoint = tmp_path / "octopus_checkpoint_nonempty.json"
    checkpoint.write_text(json.dumps({"sl_no": 11, "target": "fresh-host", "facts": []}))
    monkeypatch.setattr(app, "CFG", {"paths": {"checkpoints": str(tmp_path)}})
    _patch_resume_success(monkeypatch)
    monkeypatch.setattr(app, "prompt", lambda _text: "1")
    monkeypatch.setattr(app, "confirm", lambda _text: True)
    monkeypatch.setattr(app, "interactive_tool_run", lambda _target: "fresh raw")
    app.resume_scan()
    assert not checkpoint.exists()


def test_parallel_scan_rare_creation_worker_status_and_guard_failures(monkeypatch):
    import concurrent.futures

    monkeypatch.setattr(concurrent.futures, "as_completed", lambda jobs: tuple(jobs))
    sessions = iter((10, 11))

    def create(target):
        if target == "missing-session":
            raise RuntimeError("create failed")
        return next(sessions)

    def worker(_index, _total, target):
        if target["ip"] == "crash":
            raise RuntimeError("worker crashed")
        return {
            "error": "recon failed",
            "traceback": "trace",
            "raw_scan": "",
            "worker_output": "child output",
            "elapsed_seconds": 0.0,
        }

    monkeypatch.setattr(app, "create_session", create)
    monkeypatch.setattr(app, "_shodan_recon_worker", worker)
    updates = MagicMock(side_effect=(RuntimeError("first status failure"), None, RuntimeError("guard failure")))
    monkeypatch.setattr(app, "update_session_status", updates)
    monkeypatch.setattr(app, "_write_shodan_scan_log", lambda *_args: "log")
    outcome = app._run_shodan_parallel_scans(
        [{"ip": "missing-session"}, {"ip": "crash"}, {"ip": "worker-error"}],
        workers=3,
    )
    assert outcome == {"completed": 0, "failed": 3, "workers": 3}
    assert updates.call_count == 3

    class RejectingExecutor:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def submit(self, *_args, **_kwargs):
            raise RuntimeError("submit failed")

    monkeypatch.setattr(concurrent.futures, "ThreadPoolExecutor", RejectingExecutor)
    monkeypatch.setattr(concurrent.futures, "as_completed", lambda _jobs: ())
    monkeypatch.setattr(app, "create_session", MagicMock(side_effect=(20, 21)))
    updates = MagicMock(side_effect=(None, RuntimeError("submit status failed"), None))
    monkeypatch.setattr(app, "update_session_status", updates)
    outcome = app._run_shodan_parallel_scans([{"ip": "a"}, {"ip": "b"}], workers=2)
    assert outcome == {"completed": 0, "failed": 2, "workers": 2}
    assert updates.call_count == 3


def test_parallel_scan_reraises_interrupt_after_terminal_attempt(monkeypatch):
    monkeypatch.setattr(app, "create_session", lambda _target: 30)
    monkeypatch.setattr(
        app,
        "_shodan_recon_worker",
        lambda *_args: {
            "error": None,
            "traceback": "",
            "raw_scan": "raw",
            "worker_output": "",
            "elapsed_seconds": 0.0,
        },
    )

    class InterruptingPipeline:
        def run_scan(self, *_args, **_kwargs):
            raise KeyboardInterrupt

    monkeypatch.setattr(app, "AIPipeline", InterruptingPipeline)
    monkeypatch.setattr(app, "update_session_status", MagicMock(side_effect=(RuntimeError("status"), None)))
    monkeypatch.setattr(app, "_write_shodan_scan_log", lambda *_args: "log")
    with pytest.raises(KeyboardInterrupt):
        app._run_shodan_parallel_scans([{"ip": "host"}], workers=1)
