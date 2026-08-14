"""CLI decomposition, compatibility, and import-side-effect contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import ClassVar

import pytest

from core.cli.main import OctopusCLIApplication, create_app, create_parser, main
from core.version import APPLICATION_VERSION

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]


def test_importing_legacy_entrypoint_has_no_runtime_side_effects(tmp_path: Path) -> None:
    probe = textwrap.dedent(
        """
        import atexit
        import signal
        import socket
        import sqlite3
        import subprocess
        import sys
        import threading

        import requests.sessions

        try:
            import mysql.connector
            import mysql.connector.pooling
        except ModuleNotFoundError as exc:
            if exc.name != "mysql":
                raise
            mysql = None

        def forbidden(kind):
            def call(*_args, **_kwargs):
                raise AssertionError(f"import attempted {kind}")
            return call

        atexit.register = forbidden("exit-hook registration")
        signal.signal = forbidden("signal registration")
        threading.Thread.__init__ = forbidden("thread construction")
        threading.Thread.start = forbidden("thread start")
        subprocess.Popen = forbidden("process start")
        socket.create_connection = forbidden("network connection")
        sqlite3.connect = forbidden("SQLite connection")
        if mysql is not None:
            mysql.connector.connect = forbidden("MySQL connection")
            mysql.connector.pooling.MySQLConnectionPool = forbidden("MySQL pool")
        requests.sessions.Session.request = forbidden("HTTP request")

        import octopus

        assert octopus.__version__
        assert "db" not in sys.modules
        assert "export" not in sys.modules
        assert "core.c2.daemon" not in sys.modules
        """
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.fspath(ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert not tuple(tmp_path.iterdir())


def test_create_parser_preserves_trace_and_supervisor_commands() -> None:
    parser = create_parser()

    trace = parser.parse_args(["trace", "scan-1", "example.com", "json"])
    assert (trace.command, trace.scan_id, trace.target, trace.format) == (
        "trace",
        "scan-1",
        "example.com",
        "json",
    )
    plugin = parser.parse_args(["plugin", "checked_plugin", "example.com", "check", "label=neutral fixture"])
    assert (plugin.command, plugin.plugin_name, plugin.target, plugin.action, plugin.metadata) == (
        "plugin",
        "checked_plugin",
        "example.com",
        "check",
        ["label=neutral fixture"],
    )
    assert parser.parse_args(["status"]).command == "status"
    assert parser.parse_args([]).command is None


def test_main_routes_trace_without_starting_interactive_lifecycle() -> None:
    calls: list[tuple[str, str, str]] = []
    workflows = SimpleNamespace(
        _print_trace_report_cli=lambda scan_id, target, fmt: calls.append((scan_id, target, fmt))
    )
    app = SimpleNamespace(
        workflows=workflows,
        run=lambda: pytest.fail("interactive lifecycle must not start"),
    )

    assert main(["trace", "scan-2", "https://example.com", "json"], app=app) == 0
    assert calls == [("scan-2", "https://example.com", "json")]


def test_main_routes_plugin_and_inventory_through_canonical_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    from core.ai import runtime as runtime_module
    from core.ai.runtime import PipelineRuntime
    from core.plugins.schema import empty_input_schema
    from core.tools.registry import get_tool

    descriptor = SimpleNamespace(
        name="checked_plugin",
        plugin_type="recon",
        description="Inert CLI fixture",
        version="1.0",
        requires=[],
        python_deps=[],
        capabilities=[],
        supports_check=True,
        supports_run=False,
        input_schema={
            **empty_input_schema(),
            "properties": {"label": {"type": "string"}},
        },
    )

    class Manager:
        plugins: ClassVar[dict[str, object]] = {descriptor.name: descriptor}
        skipped_plugins: ClassVar[dict[str, str]] = {}

        def __init__(self) -> None:
            self.check_calls: list[tuple[str, str, dict[str, object]]] = []

        def get_plugin(self, name: str):
            return self.plugins.get(name)

        def validate(self, _name: str) -> list[str]:
            return []

        def list_plugins(self) -> list[dict[str, object]]:
            return [{"name": descriptor.name, "type": "recon", "version": "1.0"}]

        def list_skipped_plugins(self) -> list[dict[str, str]]:
            return []

        def check(self, name: str, target: str, **kwargs: object) -> SimpleNamespace:
            self.check_calls.append((name, target, dict(kwargs)))
            return SimpleNamespace(
                vulnerable=False,
                confidence=0.5,
                details="canonical CLI check",
                evidence="fixture",
                version="1.0",
            )

        def execute(self, *_args: object, **_kwargs: object) -> None:
            pytest.fail("read-only CLI check must not execute plugin run")

    def forbidden_legacy(*_args: object, **_kwargs: object) -> str:
        pytest.fail("legacy plugin provider invoked")

    manager = Manager()
    runtime = PipelineRuntime(
        str(tmp_path / "facts.db"),
        runner=forbidden_legacy,
        plugin_manager=manager,
    )
    commands: list[str] = []

    class RuntimeFacade:
        def __init__(self, *, runner) -> None:
            self.runner = runner

        def dispatch(self, command: str, facts, executed_keys, context):
            assert tuple(facts) == ()
            assert executed_keys == set()
            commands.append(command)
            return runtime.dispatch(command, (), set(), context)

    monkeypatch.setattr(runtime_module, "PipelineRuntime", RuntimeFacade)
    for tool_name in ("plugin", "plugin_inventory"):
        tool_def = get_tool(tool_name)
        assert tool_def is not None
        monkeypatch.setattr(tool_def, "func", forbidden_legacy)

    app = SimpleNamespace(
        workflows=SimpleNamespace(),
        run=lambda: pytest.fail("plugin CLI must not start interactive lifecycle"),
    )
    target = "192.0.2.40"

    assert (
        main(
            ["plugin", descriptor.name, target, "check", "label=neutral fixture"],
            app=app,
        )
        == 0
    )
    check_payload = json.loads(capsys.readouterr().out)
    assert check_payload["details"] == "canonical CLI check"
    assert manager.check_calls == [
        (
            descriptor.name,
            target,
            {"timeout": 300, "label": "neutral fixture"},
        )
    ]

    assert main(["plugin", "list"], app=app) == 0
    inventory = json.loads(capsys.readouterr().out)
    assert inventory == {
        "plugins": manager.list_plugins(),
        "skipped": manager.list_skipped_plugins(),
    }
    assert commands == [
        "plugin checked_plugin 192.0.2.40 check 'label=neutral fixture'",
        "plugin list",
    ]


def test_main_routes_interactive_and_supervisor_commands(monkeypatch) -> None:
    app = SimpleNamespace(workflows=SimpleNamespace(), run=lambda: 7)
    supervisor_calls: list[str] = []
    monkeypatch.setattr(
        "core.cli.main._run_supervisor_command",
        lambda command: supervisor_calls.append(command) or 3,
    )

    assert main([], app=app) == 7
    assert main(["legacy-ignored-argument"], app=app) == 7
    assert main(["health"], app=app) == 3
    assert supervisor_calls == ["health"]


def test_create_app_is_composition_only(monkeypatch) -> None:
    import signal

    workflows = ModuleType("fixture_cli_workflows")
    monkeypatch.setattr(
        signal,
        "signal",
        lambda *_args: pytest.fail("create_app must not register signals"),
    )

    app = create_app(workflows)

    assert isinstance(app, OctopusCLIApplication)
    assert app.workflows is workflows
    assert app.supervisor is None


def test_interactive_lifecycle_orders_effects_and_restores_signal(monkeypatch) -> None:
    import signal

    events: list[str] = []
    workflows = ModuleType("fixture_cli_workflows")
    workflows._sigint_handler = lambda *_args: None
    workflows._supervisor = None
    workflows._setup_logging = lambda: events.append("logging") or "fixture.log"
    workflows._setup_readline = lambda: events.append("readline")
    workflows.preflight_checks = lambda: events.append("preflight") or True
    workflows.info = lambda message: events.append(f"info:{message}")
    workflows.error = lambda message: events.append(f"error:{message}")
    workflows.main_menu = lambda: events.append("menu")

    previous_handler = object()
    signal_calls: list[object] = []
    monkeypatch.setattr(signal, "getsignal", lambda _signal: previous_handler)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda _signal, handler: signal_calls.append(handler),
    )

    app = OctopusCLIApplication(workflows)
    monkeypatch.setattr(
        app,
        "_start_supervisor",
        lambda: events.append("supervisor") or True,
    )
    monkeypatch.setattr(
        app,
        "_discover_extensions",
        lambda: events.append("plugins"),
    )

    assert app.run() == 0
    assert events == [
        "logging",
        "readline",
        "supervisor",
        "preflight",
        "info:Logging to: fixture.log",
        "plugins",
        "menu",
    ]
    assert signal_calls == [workflows._sigint_handler, previous_handler]
    assert workflows._supervisor is None


def test_thin_entrypoint_version_does_not_start_application(tmp_path: Path) -> None:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, os.fspath(ROOT / "octopus.py"), "--version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == f"octopus {APPLICATION_VERSION}"
    assert not tuple(tmp_path.iterdir())
