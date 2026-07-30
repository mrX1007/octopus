"""Hermetic coverage for legacy CLI preflight, Shodan, main, and C2 menus."""

from __future__ import annotations

import builtins
import json
import os
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
        "success",
        "warn",
    ):
        monkeypatch.setattr(app, name, MagicMock())
    monkeypatch.setattr(app, "_cached_api_key", None)


def _patch_preflight(
    monkeypatch: pytest.MonkeyPatch,
    *,
    env_file: bool,
    db_ok: bool,
    response,
    tools: set[str],
    wordlists: dict[str, str | None],
    optional_modules: set[str],
):
    import shutil

    import requests

    import config

    monkeypatch.setattr(app.os.path, "isfile", lambda _path: env_file)
    monkeypatch.setattr(
        app,
        "_lazy_module_call",
        MagicMock(return_value=None) if db_ok else MagicMock(side_effect=RuntimeError("db down")),
    )
    connection = MagicMock()
    monkeypatch.setattr(
        app,
        "get_connection",
        MagicMock(return_value=connection) if db_ok else MagicMock(side_effect=RuntimeError("db down")),
    )
    monkeypatch.setattr(
        requests,
        "get",
        MagicMock(side_effect=response) if isinstance(response, Exception) else MagicMock(return_value=response),
    )
    monkeypatch.setattr(shutil, "which", lambda name: f"/bin/{name}" if name in tools else None)
    monkeypatch.setattr(config, "find_wordlist", lambda name: wordlists.get(name))
    monkeypatch.setattr(
        app.importlib.util,
        "find_spec",
        lambda name: object() if name in optional_modules else None,
    )
    return connection


def test_preflight_all_success_and_all_absent(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        app,
        "CFG",
        {
            "ollama": {
                "url": "http://ollama/api/generate",
                "model": "fixture-model",
            }
        },
    )
    monkeypatch.setenv("SHODAN_API_KEY", "configured")
    response = SimpleNamespace(
        status_code=200,
        json=lambda: {"models": [{"name": "fixture-model:latest"}]},
    )
    connection = _patch_preflight(
        monkeypatch,
        env_file=True,
        db_ok=True,
        response=response,
        tools={"nmap", "curl", "whois", "jmx2rce", "nuclei", "hashcat", "john"},
        wordlists={"passwords": "/lists/passwords.txt", "web_dirs": "/lists/web.txt"},
        optional_modules={"scrapling", "shodan"},
    )
    assert app.preflight_checks() is True
    connection.close.assert_called_once_with()
    app.success.assert_any_call("Ollama: model 'fixture-model' ready")
    app.success.assert_any_call("Shodan: API key configured")

    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    missing_model = SimpleNamespace(status_code=200, json=lambda: {"models": [{"name": "other"}]})
    _patch_preflight(
        monkeypatch,
        env_file=False,
        db_ok=False,
        response=missing_model,
        tools=set(),
        wordlists={"passwords": None, "web_dirs": None},
        optional_modules=set(),
    )
    assert app.preflight_checks() is True
    app.warn.assert_any_call("Password wordlist: NONE found -- bruteforce will fail")
    app.warn.assert_any_call("Shodan: NOT installed. Fix: pip install shodan")


def test_preflight_http_and_optional_failure_paths(monkeypatch: pytest.MonkeyPatch):
    import requests

    monkeypatch.setattr(app, "CFG", {"ollama": {"model": "model"}})
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    _patch_preflight(
        monkeypatch,
        env_file=True,
        db_ok=True,
        response=SimpleNamespace(status_code=503),
        tools={"curl"},
        wordlists={},
        optional_modules={"scrapling", "shodan"},
    )
    assert app.preflight_checks() is True
    app.warn.assert_any_call("Ollama: unexpected status 503")
    app.warn.assert_any_call("Shodan: library installed but no API key in .env")

    _patch_preflight(
        monkeypatch,
        env_file=True,
        db_ok=True,
        response=requests.exceptions.ConnectionError("offline"),
        tools=set(),
        wordlists={},
        optional_modules=set(),
    )
    assert app.preflight_checks() is False
    app.error.assert_any_call("Ollama: not running")

    _patch_preflight(
        monkeypatch,
        env_file=True,
        db_ok=True,
        response=RuntimeError("bad response"),
        tools=set(),
        wordlists={},
        optional_modules=set(),
    )
    assert app.preflight_checks() is True
    app.warn.assert_any_call("Ollama: check failed -- bad response")


def test_preflight_handles_missing_config_import(monkeypatch: pytest.MonkeyPatch):
    _patch_preflight(
        monkeypatch,
        env_file=True,
        db_ok=True,
        response=SimpleNamespace(status_code=503),
        tools=set(),
        wordlists={},
        optional_modules=set(),
    )
    real_import = builtins.__import__

    def block_config(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config":
            raise ImportError("fixture")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", block_config)
    assert app.preflight_checks() is True
    app.warn.assert_any_call("Config module not available -- wordlist check skipped")


class ShodanFixture:
    def __init__(self, *, api=True, results=None, targets=None):
        self.api = object() if api else None
        self.results = results if results is not None else {"matches": [{"ip": "x"}], "total": 1}
        self.targets = (
            targets if targets is not None else [{"ip": "192.0.2.1", "ports": [80], "org": "Example", "vulns": []}]
        )
        self.results_dir = "/fixture/results"
        self.search_calls = []

    def search(self, query, *, max_results):
        self.search_calls.append((query, max_results))
        return self.results

    def format_for_pipeline(self, _results):
        return self.targets

    def _get_db(self):
        return None


def run_shodan(
    monkeypatch: pytest.MonkeyPatch,
    answers,
    *,
    fixture: ShodanFixture | None = None,
    confirms=(),
    outcome=None,
):
    import shodan_module

    fixture = fixture or ShodanFixture()
    monkeypatch.setattr(shodan_module, "ShodanRecon", lambda: fixture)
    prompts = iter(answers)
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompts))
    confirm_values = iter(confirms)
    monkeypatch.setattr(app, "confirm", lambda _text: next(confirm_values))
    monkeypatch.setattr(
        app,
        "_run_shodan_parallel_scans",
        MagicMock(return_value=outcome or {"completed": 1, "failed": 0}),
    )
    app._new_scan_shodan()
    return fixture


def test_shodan_import_api_and_empty_search_builder_paths(monkeypatch):
    real_import = builtins.__import__

    def block_shodan(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "shodan_module":
            raise ImportError("missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", block_shodan)
    app._new_scan_shodan()
    app.error.assert_called_with("shodan_module.py not found. Install: pip install shodan")
    monkeypatch.setattr(builtins, "__import__", real_import)

    run_shodan(monkeypatch, (), fixture=ShodanFixture(api=False))
    app.error.assert_called_with("Shodan API not configured. Set SHODAN_API_KEY in .env")

    cases = (
        ("1", "", ""),
        ("2", ""),
        ("3", ""),
        ("4", ""),
        ("5", ""),
        ("6", "", ""),
        ("6", "US", ""),
        ("7", ""),
        ("8", ""),
        ("invalid",),
    )
    for answers in cases:
        run_shodan(monkeypatch, answers)

    load_saved = MagicMock()
    monkeypatch.setattr(app, "_shodan_load_saved", load_saved)
    fixture = run_shodan(monkeypatch, ("9",))
    load_saved.assert_called_once_with(fixture)


@pytest.mark.parametrize(
    ("answers", "expected_query", "expected_limit"),
    (
        (
            ("1", "443", "US", "Linux", "2026-01-01", "2025-01-01", "7", "0"),
            'port:443 country:US os:"Linux" before:2026-01-01 after:2025-01-01',
            7,
        ),
        (("1", "80, ,443", "", "", "", "", "bad", "0"), "port:80 port:443", 100),
        (("2", "nginx", "1.2", "DE", "", "", "", "", "0"), 'product:"nginx" version:"1.2" country:DE', 100),
        (("2", "nginx", "", "", "", "", "", "", "0"), 'product:"nginx"', 100),
        (("3", "CVE-1", "", "", "", "", "0"), "vuln:CVE-1", 100),
        (("4", "192.0.2.0/24", "", "", "", "", "0"), "net:192.0.2.0/24", 100),
        (("4", "net:192.0.2.0/24", "", "", "", "", "0"), "net:192.0.2.0/24", 100),
        (("5", "Example", "", "", "", "", "0"), 'org:"Example"', 100),
        (("6", "ch", "22", "", "", "", "", "0"), "country:CH port:22", 100),
        (("7", "ics", "", "", "", "", "0"), "tag:ics", 100),
        (("8", "ssl:true", "", "", "", "", "0"), "ssl:true", 100),
    ),
)
def test_shodan_valid_query_builders(monkeypatch, answers, expected_query, expected_limit):
    fixture = run_shodan(monkeypatch, answers)
    assert fixture.search_calls == [(expected_query, expected_limit)]


def test_shodan_empty_result_error_and_matches_short_circuit(monkeypatch):
    error_fixture = ShodanFixture(results={"error": "quota", "matches": [{"ip": "x"}]})
    run_shodan(
        monkeypatch,
        (
            "8",
            "query",
            "",
            "",
            "",
            "",
        ),
        fixture=error_fixture,
    )
    app.error.assert_called_with("No results: quota")

    empty_fixture = ShodanFixture(results={"matches": []})
    run_shodan(
        monkeypatch,
        (
            "8",
            "query",
            "",
            "",
            "",
            "",
        ),
        fixture=empty_fixture,
    )
    app.error.assert_called_with("No results: empty")


def _targets(count=3, *, vulnerable=True):
    return [
        {
            "ip": f"192.0.2.{index}",
            "ports": [80, 443] if index % 2 else [22],
            "org": "" if index == 1 else "Example",
            "vulns": ["CVE-1"] if vulnerable and index == 1 else [],
        }
        for index in range(1, count + 1)
    ]


def test_shodan_action_selection_filters_confirmation_and_outcomes(monkeypatch):
    large = ShodanFixture(targets=_targets(25))
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "1", "5"),
        fixture=large,
        confirms=(False,),
    )

    failed_outcome = {"completed": 2, "failed": 1}
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "1", "2"),
        fixture=ShodanFixture(targets=_targets(3)),
        confirms=(True,),
        outcome=failed_outcome,
    )
    app.warn.assert_called_with("Pipeline finished: 2 complete, 1 failed.")
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "1", "2"),
        fixture=ShodanFixture(targets=_targets(3)),
        confirms=(True,),
    )
    app.success.assert_called_with("Pipeline complete: 1 target(s) scanned.")

    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "2", "1,3", "1"),
        fixture=ShodanFixture(targets=_targets(3)),
        confirms=(False,),
    )
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "2", "bad"),
        fixture=ShodanFixture(targets=_targets(3)),
    )
    app.warn.assert_called_with("No targets selected.")

    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "3"),
        fixture=ShodanFixture(targets=_targets(3, vulnerable=False)),
    )
    app.warn.assert_called_with("No hosts with known CVEs.")
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "3", "1"),
        fixture=ShodanFixture(targets=_targets(3)),
        confirms=(False,),
    )

    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "4", "bad"),
        fixture=ShodanFixture(targets=_targets(3)),
    )
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "4", "999"),
        fixture=ShodanFixture(targets=_targets(3)),
    )
    app.warn.assert_called_with("No hosts with port 999.")
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "4", "443", "1"),
        fixture=ShodanFixture(targets=_targets(3)),
        confirms=(False,),
    )


def test_shodan_host_save_recursive_and_invalid_actions(monkeypatch):
    import shodan_module

    host = MagicMock(return_value="host details")
    monkeypatch.setattr(shodan_module, "run_shodan_host", host)
    for number in ("", "bad", "9", "1"):
        run_shodan(
            monkeypatch,
            ("8", "query", "", "", "", "", "5", number),
            fixture=ShodanFixture(targets=_targets(2)),
        )
    host.assert_called_once_with("192.0.2.1")

    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "6"),
        fixture=ShodanFixture(targets=_targets(2)),
    )
    app.success.assert_called_with("Results saved to DB (2 hosts) + JSON in /fixture/results")

    original = app._new_scan_shodan
    recursive = MagicMock()
    monkeypatch.setattr(app, "_new_scan_shodan", recursive)
    import shodan_module as shodan_provider

    fixture = ShodanFixture(targets=_targets(2))
    monkeypatch.setattr(shodan_provider, "ShodanRecon", lambda: fixture)
    prompts = iter(("8", "query", "", "", "", "", "7"))
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompts))
    original()
    recursive.assert_called_once_with()

    monkeypatch.setattr(app, "_new_scan_shodan", original)
    run_shodan(
        monkeypatch,
        ("8", "query", "", "", "", "", "invalid"),
        fixture=ShodanFixture(targets=_targets(2)),
    )
    app.warn.assert_called_with("Invalid action.")


def test_main_menu_dispatches_every_choice_and_pending_display(monkeypatch):
    monkeypatch.setattr(app, "_check_pending_checkpoints", MagicMock(side_effect=(1, 0, 1, 0, 0, 0)))
    choices = iter(("1", "2", "3", "4", "bad", "5"))
    monkeypatch.setattr(app, "prompt", lambda _text: next(choices))
    monkeypatch.setattr(builtins, "input", lambda _text: "")
    operations = {
        "new_scan": MagicMock(),
        "view_history": MagicMock(),
        "resume_scan": MagicMock(),
        "c2_management_menu": MagicMock(),
    }
    for name, operation in operations.items():
        monkeypatch.setattr(app, name, operation)
    with pytest.raises(SystemExit) as raised:
        app.main_menu()
    assert raised.value.code == 0
    for operation in operations.values():
        operation.assert_called_once_with()
    app.warn.assert_called_with("Invalid choice.")


def test_api_key_and_daemon_socket_boundaries(monkeypatch, tmp_path):
    monkeypatch.setenv("OCTOPUS_API_KEY", "environment-key")
    assert app._load_api_key() == "environment-key"
    monkeypatch.delenv("OCTOPUS_API_KEY")
    project = tmp_path / "project"
    key_file = project / "data" / "default_admin.key"
    key_file.parent.mkdir(parents=True)
    key_file.write_text("file-key\n")
    monkeypatch.setattr(app, "PROJECT_ROOT", str(project))
    assert app._load_api_key() == "file-key"
    key_file.unlink()
    assert app._load_api_key() == ""

    monkeypatch.setattr(app.os.path, "exists", lambda _path: False)
    assert app._send_to_daemon("ping")["status"] == "error"

    monkeypatch.setattr(app.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(app, "_load_api_key", MagicMock(return_value="loaded-key"))
    import socket

    sock = MagicMock()
    sock.recv.return_value = json.dumps({"status": "ok"}).encode()
    socket_factory = MagicMock(return_value=sock)
    monkeypatch.setattr(socket, "socket", socket_factory)
    assert app._send_to_daemon("queue", value=7) == {"status": "ok"}
    request = json.loads(sock.sendall.call_args.args[0].decode())
    assert request == {"action": "queue", "api_key": "loaded-key", "value": 7}
    assert app._send_to_daemon("ping") == {"status": "ok"}
    app._load_api_key.assert_called_once_with()

    socket_factory.side_effect = OSError("socket failed")
    assert app._send_to_daemon("ping") == {"status": "error", "msg": "socket failed"}


class ProcessFixture:
    def __init__(self, *, poll=None, pid=4321, log=""):
        self.pid = pid
        self.poll_result = poll
        self.log = log

    def poll(self):
        return self.poll_result


def test_start_daemon_already_running_missing_dependency_and_success(monkeypatch, tmp_path):
    monkeypatch.setattr(app.os.path, "exists", lambda path: path == "/tmp/octopus.sock")
    monkeypatch.setattr(app, "_send_to_daemon", lambda _action: {"status": "ok"})
    app._start_c2_daemon()
    app.success.assert_called_with("Daemon is already running.")

    real_import = builtins.__import__

    def block_fastapi(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "fastapi":
            raise ImportError("fastapi missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(app.os.path, "exists", lambda _path: False)
    monkeypatch.setattr(builtins, "__import__", block_fastapi)
    app._start_c2_daemon()
    app.error.assert_called_with("Missing dependency for C2 daemon: fastapi missing")
    monkeypatch.setattr(builtins, "__import__", real_import)

    project = tmp_path / "success"
    monkeypatch.setattr(app, "PROJECT_ROOT", str(project))
    sock_checks = iter((True, True))

    def exists(path):
        if path == "/tmp/octopus.sock":
            return next(sock_checks)
        return Path(path).exists()

    monkeypatch.setattr(app.os.path, "exists", exists)
    responses = iter(({"status": "error"}, {"status": "ok"}))
    monkeypatch.setattr(app, "_send_to_daemon", lambda _action: next(responses))
    import subprocess
    import time

    process = ProcessFixture()
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    app._start_c2_daemon()
    app.success.assert_called_with("Daemon started (PID 4321).")


def test_start_daemon_failure_log_and_suppressed_read_error(monkeypatch, tmp_path):
    import subprocess
    import time

    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(app, "_send_to_daemon", lambda _action: {"status": "error"})
    monkeypatch.setattr(app.os.path, "exists", lambda _path: False)

    for index, log_text in enumerate(("daemon failed\nline 2", "")):
        project = tmp_path / f"failed-{index}"
        monkeypatch.setattr(app, "PROJECT_ROOT", str(project))

        def popen(*_args, log_text=log_text, **kwargs):
            if log_text:
                kwargs["stdout"].write(log_text)
                kwargs["stdout"].flush()
            return ProcessFixture(poll=1)

        monkeypatch.setattr(subprocess, "Popen", popen)
        app._start_c2_daemon()
        app.error.assert_called_with("Failed to start daemon.")

    project = tmp_path / "unlinked"
    monkeypatch.setattr(app, "PROJECT_ROOT", str(project))

    def unlinking_popen(*_args, **kwargs):
        os.unlink(kwargs["stdout"].name)
        return ProcessFixture(poll=1)

    monkeypatch.setattr(subprocess, "Popen", unlinking_popen)
    app._start_c2_daemon()

    project = tmp_path / "read-error"
    monkeypatch.setattr(app, "PROJECT_ROOT", str(project))
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=ProcessFixture(poll=1)))
    real_open = builtins.open

    def fail_read(path, mode="r", *args, **kwargs):
        if "r" in mode and str(path).endswith("c2_daemon.log"):
            raise OSError("read failed")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_read)
    app._start_c2_daemon()


def test_start_daemon_exhausts_alive_process_and_rechecks_unready_socket(monkeypatch, tmp_path):
    import subprocess
    import time

    project = tmp_path / "alive"
    monkeypatch.setattr(app, "PROJECT_ROOT", str(project))
    checks = iter((False, True, False, False, False, False, False, False, False))

    def exists(path):
        if path == "/tmp/octopus.sock":
            return next(checks)
        return Path(path).exists()

    monkeypatch.setattr(app.os.path, "exists", exists)
    monkeypatch.setattr(app, "_send_to_daemon", lambda _action: {"status": "starting"})
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=ProcessFixture(poll=None)))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    app._start_c2_daemon()
    app.error.assert_called_with("Failed to start daemon.")


def run_c2_menu(monkeypatch, answers, responses, *, initial=None):
    prompt_values = iter(answers)
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompt_values))
    monkeypatch.setattr(builtins, "input", lambda _text: "")
    queues = {name: iter(values) for name, values in responses.items()}

    def send(action, **_kwargs):
        if action == "ping":
            return initial or {"status": "ok"}
        return next(queues[action])

    monkeypatch.setattr(app, "_send_to_daemon", send)
    monkeypatch.setattr(app, "_start_c2_daemon", MagicMock())
    import subprocess

    monkeypatch.setattr(subprocess, "run", MagicMock())
    app.c2_management_menu()
    return subprocess.run


def test_c2_initial_start_decline_and_accept(monkeypatch):
    monkeypatch.setattr(app, "_send_to_daemon", lambda _action: {"status": "error"})
    monkeypatch.setattr(app, "confirm", lambda _text: False)
    start = MagicMock()
    monkeypatch.setattr(app, "_start_c2_daemon", start)
    app.c2_management_menu()
    start.assert_not_called()

    prompts = iter(("0",))
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompts))
    monkeypatch.setattr(app, "confirm", lambda _text: True)
    app.c2_management_menu()
    start.assert_called_once_with()


def test_c2_missing_agent_or_command_immediately_continues(monkeypatch):
    prompts = iter(("2", "", "ignored", "2", "agent", "", "0"))
    monkeypatch.setattr(app, "prompt", lambda _text: next(prompts))
    monkeypatch.setattr(app, "_send_to_daemon", lambda action, **_kwargs: {"status": "ok"})
    app.c2_management_menu()


def test_c2_agent_task_result_and_builder_paths(monkeypatch):
    answers = (
        "1",
        "1",
        "1",
        "2",
        "",
        "2",
        "agent",
        "",
        "2",
        "agent",
        "id",
        "2",
        "agent",
        "id",
        "3",
        "",
        "3",
        "agent",
        "3",
        "agent",
        "3",
        "agent",
        "4",
        "",
        "",
        "",
        "",
        "4",
        "windows",
        "arm64",
        "https://c2",
        "pin",
        "bad",
        "0",
    )
    responses = {
        "list_agents": (
            {"status": "error", "msg": "failed"},
            {"status": "ok", "agents": {}},
            {
                "status": "ok",
                "agents": {
                    "a": {
                        "user": "u",
                        "hostname": "h",
                        "ip": "192.0.2.1",
                        "last_seen": "now",
                    }
                },
            },
        ),
        "queue_task": (
            {"status": "ok", "task_id": "t1"},
            {"status": "error", "msg": "queue failed"},
        ),
        "get_results": (
            {"status": "error", "msg": "results failed"},
            {"status": "ok", "results": []},
            {
                "status": "ok",
                "results": [
                    {"task_id": "t1", "error": "boom", "output": "failed output"},
                    {"task_id": "t2", "output": "success output"},
                ],
            },
        ),
    }
    run = run_c2_menu(monkeypatch, answers, responses)
    assert run.call_count == 2
    first, second = run.call_args_list
    assert "--pins" not in first.args[0]
    assert second.args[0][-2:] == ["--pins", "pin"]
    app.warn.assert_called_with("Invalid choice.")


def test_c2_operator_management_success_and_failure_paths(monkeypatch):
    answers = (
        "5",
        "a",
        "5",
        "a",
        "5",
        "b",
        "alice",
        "",
        "5",
        "b",
        "bob",
        "admin",
        "5",
        "c",
        "alice",
        "5",
        "c",
        "bob",
        "5",
        "d",
        "alice",
        "5",
        "d",
        "bob",
        "5",
        "unknown",
        "0",
    )
    responses = {
        "manage_operators": (
            {
                "status": "ok",
                "operators": [
                    {"name": "active", "role": "admin", "active": True},
                    {"name": "inactive", "role": "readonly", "active": False},
                ],
            },
            {"status": "error", "msg": "list failed"},
            {"status": "ok", "api_key": "key-1"},
            {"status": "error", "msg": "create failed"},
            {"status": "ok"},
            {"status": "error", "msg": "deactivate failed"},
            {"status": "ok", "api_key": "key-2"},
            {"status": "error", "msg": "rotate failed"},
        ),
    }
    run_c2_menu(monkeypatch, answers, responses)
    app.success.assert_any_call("Operator created. API Key: key-1")
    app.success.assert_any_call("Operator 'alice' deactivated.")
    app.success.assert_any_call("New API Key: key-2")
    app.error.assert_any_call("rotate failed")
