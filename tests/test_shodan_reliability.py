#!/usr/bin/env python3
"""Regression tests for Shodan worker isolation and storage safety."""

import builtins
import json
import threading
from pathlib import Path
from unittest.mock import MagicMock


def test_worker_count_is_validated_and_clamped():
    import octopus

    assert octopus._clamp_shodan_workers("999", 3) == 3
    assert octopus._clamp_shodan_workers("0", 10) == 1
    assert octopus._clamp_shodan_workers("-9", 10) == 1
    assert octopus._clamp_shodan_workers("invalid", 2) == 2
    assert octopus._clamp_shodan_workers("999", 100) == 16


def test_recon_worker_captures_child_output_and_returns_data(monkeypatch):
    import octopus

    marker = "__OCTOPUS_RECON_JSON__="

    class Child:
        returncode = 0
        stdout = "child UI output\n" + marker + json.dumps({"10.0.0.1": "NMAP DATA"}) + "\n"
        stderr = ""

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Child()

    monkeypatch.setattr(octopus.subprocess, "run", fake_run)
    result = octopus._shodan_recon_worker(1, 1, {
        "ip": "10.0.0.1", "ports": [80], "services": [], "vulns": [],
    })

    assert result["error"] is None
    assert "NMAP DATA" in result["raw_scan"]
    assert "child UI output" in result["worker_output"]
    assert calls[0][1]["stdin"] is octopus.subprocess.DEVNULL
    assert calls[0][1]["capture_output"] is True
    assert "stdout" not in calls[0][1]
    assert "stderr" not in calls[0][1]


def test_parallel_recon_keeps_pipeline_prompts_and_persistence_on_main(monkeypatch):
    import octopus

    main_thread = threading.get_ident()
    worker_threads = []
    pipeline_threads = []
    persistence_threads = []
    status_updates = []
    next_session = iter([101, 102])

    def fake_worker(index, total, target):
        worker_threads.append(threading.get_ident())
        return {
            "index": index, "total": total, "target": target["ip"],
            "raw_scan": f"raw:{target['ip']}", "error": None,
            "traceback": "", "worker_output": "", "elapsed_seconds": 0.01,
        }

    class FakePipeline:
        def __init__(self):
            pipeline_threads.append(threading.get_ident())
            self.fact_store = object()

        def run_scan(self, scan_id, target, raw_scan):
            pipeline_threads.append(threading.get_ident())
            return {"scan_id": scan_id, "target": target, "raw": raw_scan}

    def create_session(target):
        persistence_threads.append(threading.get_ident())
        return next(next_session)

    def update_status(sl_no, status):
        persistence_threads.append(threading.get_ident())
        status_updates.append((sl_no, status))

    def save_results(*_args):
        persistence_threads.append(threading.get_ident())

    monkeypatch.setattr(builtins, "input", lambda *_args: (_ for _ in ()).throw(
        AssertionError("worker orchestration must not call input directly")
    ))
    monkeypatch.setattr(octopus, "_shodan_recon_worker", fake_worker)
    monkeypatch.setattr(octopus, "AIPipeline", FakePipeline)
    monkeypatch.setattr(octopus, "create_session", create_session)
    monkeypatch.setattr(octopus, "update_session_status", update_status)
    monkeypatch.setattr(octopus, "_save_trace_report", lambda *_args: None)
    monkeypatch.setattr(octopus, "_adapt_state_to_result", lambda *_args: {
        "risk_level": "LOW",
    })
    monkeypatch.setattr(octopus, "_save_and_show_results", save_results)
    monkeypatch.setattr(octopus, "_write_shodan_scan_log", lambda *_args: "scan.log")
    monkeypatch.setattr(octopus, "error", lambda *_args: None)

    outcome = octopus._run_shodan_parallel_scans([
        {"ip": "10.0.0.1"}, {"ip": "10.0.0.2"},
    ], workers=999)

    assert outcome == {"completed": 2, "failed": 0, "workers": 2}
    assert worker_threads and all(thread != main_thread for thread in worker_threads)
    assert pipeline_threads and set(pipeline_threads) == {main_thread}
    assert persistence_threads and set(persistence_threads) == {main_thread}
    assert sorted(status_updates) == [(101, "complete"), (102, "complete")]


def test_recon_and_pipeline_failures_mark_every_session_terminal(monkeypatch):
    import octopus

    sessions = iter([201, 202])
    updates = []

    def fake_worker(index, total, target):
        if index == 1:
            return {
                "error": "recon failed", "traceback": "trace", "raw_scan": "",
                "worker_output": "", "elapsed_seconds": 0.0,
            }
        return {
            "error": None, "traceback": "", "raw_scan": "raw",
            "worker_output": "", "elapsed_seconds": 0.0,
        }

    class FailingPipeline:
        def __init__(self):
            self.fact_store = object()

        def run_scan(self, *_args, **_kwargs):
            raise RuntimeError("pipeline failed")

    monkeypatch.setattr(octopus, "_shodan_recon_worker", fake_worker)
    monkeypatch.setattr(octopus, "AIPipeline", FailingPipeline)
    monkeypatch.setattr(octopus, "create_session", lambda _target: next(sessions))
    monkeypatch.setattr(octopus, "update_session_status", lambda sl, status: updates.append((sl, status)))
    monkeypatch.setattr(octopus, "_write_shodan_scan_log", lambda *_args: "scan.log")
    monkeypatch.setattr(octopus, "error", lambda *_args: None)

    outcome = octopus._run_shodan_parallel_scans([
        {"ip": "10.0.0.1"}, {"ip": "10.0.0.2"},
    ], workers=2)

    assert outcome == {"completed": 0, "failed": 2, "workers": 2}
    assert sorted(updates) == [(201, "failed"), (202, "failed")]


def test_scan_log_filename_is_exclusive_and_contained(monkeypatch, tmp_path):
    import octopus

    monkeypatch.setattr(octopus, "CFG", {"paths": {"logs": str(tmp_path)}})
    path = Path(octopus._write_shodan_scan_log(
        7, "../../bad/name\x00target", "log content",
    ))

    assert path.resolve().parent == tmp_path.resolve()
    assert ".." not in path.name
    assert path.read_text(encoding="utf-8") == "log content"


def test_shodan_json_backup_filename_is_exclusive_and_contained(tmp_path):
    from shodan_module import ShodanRecon

    recon = ShodanRecon.__new__(ShodanRecon)
    recon.results_dir = str(tmp_path)
    path = Path(recon._save_json({"ok": True}, "../../escape/me"))

    assert path.resolve().parent == tmp_path.resolve()
    assert ".." not in path.name
    assert json.loads(path.read_text(encoding="utf-8")) == {"ok": True}


def test_shodan_db_failure_rolls_back_and_closes_cursor():
    from shodan_module import ShodanRecon

    connection = MagicMock()
    cursor = MagicMock()
    cursor.executemany.side_effect = RuntimeError("write failed")
    connection.cursor.return_value = cursor
    recon = ShodanRecon.__new__(ShodanRecon)
    recon._get_db = lambda: connection

    recon.save_to_db({
        "query": "port:443",
        "matches": [{"ip": "10.0.0.1", "port": 443}],
    })

    connection.rollback.assert_called_once()
    cursor.close.assert_called_once()
