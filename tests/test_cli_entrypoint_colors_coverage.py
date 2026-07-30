"""Hermetic coverage for CLI composition, dispatch, and ANSI formatting."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

import core.cli as cli_facade
import octopus
from core import colors
from core.cli import application as default_workflows
from core.cli import main as cli_main

pytestmark = pytest.mark.unit


ROOT = Path(__file__).resolve().parents[1]


def _workflow_double(*, preflight: bool = True, current_scan: int | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        PROJECT_ROOT="/fixture/project",
        _current_sl_no=current_scan,
        _sigint_handler=lambda *_args: None,
        _start_c2_daemon=MagicMock(),
        _setup_logging=MagicMock(return_value="fixture.log"),
        _setup_readline=MagicMock(),
        _supervisor=None,
        error=MagicMock(),
        info=MagicMock(),
        main_menu=MagicMock(),
        preflight_checks=MagicMock(return_value=preflight),
        update_session_status=MagicMock(),
        warn=MagicMock(),
    )


def _supervisor_module(create_supervisor) -> tuple[ModuleType, type[Exception]]:
    module = ModuleType("core.supervisor")

    class AlreadyRunningError(Exception):
        pass

    module.AlreadyRunningError = AlreadyRunningError  # type: ignore[attr-defined]
    module.create_supervisor = create_supervisor  # type: ignore[attr-defined]
    return module, AlreadyRunningError


def test_lazy_cli_facade_resolves_caches_and_rejects_unknown_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = object()
    imported_module = SimpleNamespace(success=exported)
    importer = MagicMock(return_value=imported_module)
    monkeypatch.setattr(cli_facade, "import_module", importer)
    monkeypatch.setattr(cli_facade, "success", "previous", raising=False)

    assert cli_facade.__getattr__("success") is exported
    assert cli_facade.success is exported
    importer.assert_called_once_with(".presentation", "core.cli")

    with pytest.raises(AttributeError, match="no attribute 'not_exported'"):
        cli_facade.__getattr__("not_exported")

    public_dir = cli_facade.__dir__()
    assert public_dir == sorted(public_dir)
    assert set(cli_facade.__all__).issubset(public_dir)
    assert "setup_readline" in cli_facade.__all__


def test_parser_exposes_version_trace_and_every_supervisor_command(capsys) -> None:
    parser = cli_main.create_parser()

    trace = parser.parse_args(["trace", "scan-1", "example.test"])
    assert (trace.command, trace.scan_id, trace.target, trace.format) == (
        "trace",
        "scan-1",
        "example.test",
        "text",
    )
    for command in cli_main._SUPERVISOR_COMMANDS:
        assert parser.parse_args([command]).command == command

    with pytest.raises(SystemExit) as raised:
        parser.parse_args(["--version"])
    assert raised.value.code == 0
    assert "octopus" in capsys.readouterr().out


def test_application_run_covers_success_and_both_early_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import signal

    previous_handler = object()
    signal_calls: list[object] = []
    monkeypatch.setattr(signal, "getsignal", lambda _signal: previous_handler)
    monkeypatch.setattr(signal, "signal", lambda _signal, handler: signal_calls.append(handler))

    successful_workflows = _workflow_double()
    successful = cli_main.OctopusCLIApplication(successful_workflows)
    supervisor = MagicMock()
    successful.supervisor = supervisor
    monkeypatch.setattr(successful, "_start_supervisor", MagicMock(return_value=True))
    discover = MagicMock()
    monkeypatch.setattr(successful, "_discover_extensions", discover)

    assert successful.run() == 0
    successful_workflows.info.assert_called_once_with("Logging to: fixture.log")
    successful_workflows._start_c2_daemon.assert_called_once_with()
    discover.assert_called_once_with()
    successful_workflows.main_menu.assert_called_once_with()
    supervisor.stop.assert_called_once_with()
    assert successful_workflows._supervisor is None

    no_supervisor_workflows = _workflow_double()
    no_supervisor = cli_main.OctopusCLIApplication(no_supervisor_workflows)
    monkeypatch.setattr(no_supervisor, "_start_supervisor", MagicMock(return_value=False))
    assert no_supervisor.run() == 1
    no_supervisor_workflows.preflight_checks.assert_not_called()

    failed_preflight_workflows = _workflow_double(preflight=False)
    failed_preflight = cli_main.OctopusCLIApplication(failed_preflight_workflows)
    monkeypatch.setattr(failed_preflight, "_start_supervisor", MagicMock(return_value=True))
    assert failed_preflight.run() == 1
    failed_preflight_workflows.error.assert_called_once_with(
        "Critical pre-flight checks failed. Fix issues above and restart."
    )
    assert signal_calls == [
        successful_workflows._sigint_handler,
        previous_handler,
        no_supervisor_workflows._sigint_handler,
        previous_handler,
        failed_preflight_workflows._sigint_handler,
        previous_handler,
    ]


def test_start_supervisor_supports_crash_recovery_and_shutdown_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflows = _workflow_double(current_scan=17)
    supervisor = MagicMock()
    supervisor._pid = 4321
    supervisor.get_crash_info.return_value = {"previous_pid": 1234}
    shutdown_hooks: list[object] = []
    supervisor.on_shutdown.side_effect = shutdown_hooks.append
    create = MagicMock(return_value=supervisor)
    module, _error_type = _supervisor_module(create)
    monkeypatch.setitem(sys.modules, "core.supervisor", module)

    app = cli_main.OctopusCLIApplication(workflows)
    assert app._start_supervisor() is True

    create.assert_called_once_with(monitor_ollama=True, monitor_db=True, monitor_events=True)
    supervisor.start.assert_called_once_with()
    workflows.info.assert_called_once_with("Supervisor: PID 4321 locked")
    assert "Previous instance (PID 1234) crashed" in workflows.warn.call_args.args[0]
    assert len(shutdown_hooks) == 1
    shutdown_hooks[0]()
    workflows.update_session_status.assert_called_once_with(17, "interrupted")
    assert app.supervisor is supervisor
    assert workflows._supervisor is supervisor


def test_start_supervisor_handles_clean_state_running_instance_and_missing_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean_workflows = _workflow_double(current_scan=None)
    clean_supervisor = MagicMock()
    clean_supervisor._pid = 99
    clean_supervisor.get_crash_info.return_value = None
    clean_hooks: list[object] = []
    clean_supervisor.on_shutdown.side_effect = clean_hooks.append
    module, already_running = _supervisor_module(MagicMock(return_value=clean_supervisor))
    monkeypatch.setitem(sys.modules, "core.supervisor", module)

    clean_app = cli_main.OctopusCLIApplication(clean_workflows)
    assert clean_app._start_supervisor() is True
    clean_hooks[0]()
    clean_workflows.update_session_status.assert_not_called()
    clean_workflows.warn.assert_not_called()

    blocked_workflows = _workflow_double()
    blocked_supervisor = MagicMock()
    blocked_supervisor.start.side_effect = already_running("PID is locked")
    module.create_supervisor = MagicMock(return_value=blocked_supervisor)  # type: ignore[attr-defined]
    blocked_app = cli_main.OctopusCLIApplication(blocked_workflows)
    assert blocked_app._start_supervisor() is False
    blocked_workflows.error.assert_called_once_with("PID is locked")

    missing_workflows = _workflow_double()
    monkeypatch.setitem(sys.modules, "core.supervisor", None)
    missing_app = cli_main.OctopusCLIApplication(missing_workflows)
    assert missing_app._start_supervisor() is True
    assert missing_workflows._supervisor is None
    missing_workflows.warn.assert_called_once_with(
        "Supervisor not available (core/supervisor.py missing)"
    )


def test_extension_discovery_reports_loaded_counts_and_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflows = _workflow_double()
    app = cli_main.OctopusCLIApplication(workflows)
    registry = ModuleType("core.tools.registry")
    paths: list[str] = []

    def discover(path: str) -> int:
        paths.append(path)
        return 0 if path.endswith("plugins") else 2

    registry.discover_plugins = discover  # type: ignore[attr-defined]
    registry.print_registry_stats = MagicMock()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "core.tools.registry", registry)

    app._discover_extensions()
    assert paths == ["/fixture/project/plugins", "/fixture/project/modules"]
    workflows.info.assert_called_once_with(
        "Discovered metadata for 0 plugins and 2 modules; execution remains "
        "behind the registered plugin gateway."
    )
    registry.print_registry_stats.assert_called_once_with()  # type: ignore[attr-defined]

    paths.clear()
    workflows.info.reset_mock()
    registry.print_registry_stats.reset_mock()  # type: ignore[attr-defined]
    registry.discover_plugins = lambda _path: 0  # type: ignore[attr-defined]
    app._discover_extensions()
    workflows.info.assert_not_called()
    registry.print_registry_stats.assert_not_called()  # type: ignore[attr-defined]

    registry.discover_plugins = MagicMock(side_effect=RuntimeError("bad plugin"))  # type: ignore[attr-defined]
    app._discover_extensions()
    workflows.warn.assert_called_once_with("Error during plugin discovery: bad plugin")


def test_create_app_uses_explicit_or_default_workflows() -> None:
    explicit = SimpleNamespace(name="explicit")

    explicit_app = cli_main.create_app(explicit)
    default_app = cli_main.create_app()

    assert explicit_app.workflows is explicit
    assert default_app.workflows is default_workflows


def test_supervisor_command_adapter_restores_argv_and_preserves_exit_codes(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    module = ModuleType("core.supervisor")
    observed_argv: list[list[str]] = []
    module.cli = lambda: observed_argv.append(sys.argv[:])  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "core.supervisor", module)
    previous_argv = sys.argv

    assert cli_main._run_supervisor_command("status") == 0
    assert observed_argv == [[previous_argv[0], "status"]]
    assert sys.argv is previous_argv

    def exit_with(code):
        raise SystemExit(code)

    module.cli = lambda: exit_with(7)  # type: ignore[attr-defined]
    assert cli_main._run_supervisor_command("stop") == 7
    assert sys.argv is previous_argv

    module.cli = lambda: exit_with(None)  # type: ignore[attr-defined]
    assert cli_main._run_supervisor_command("pid") == 0
    assert sys.argv is previous_argv

    monkeypatch.setitem(sys.modules, "core.supervisor", None)
    assert cli_main._run_supervisor_command("health") == 0
    assert "Supervisor module not available" in capsys.readouterr().out


def test_main_dispatches_compatibility_trace_supervisor_and_interactive_paths(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    traces: list[tuple[str, str, str]] = []
    app = SimpleNamespace(
        workflows=SimpleNamespace(
            _print_trace_report_cli=lambda scan_id, target, fmt: traces.append(
                (scan_id, target, fmt)
            )
        ),
        run=MagicMock(return_value=12),
    )
    supervisor_commands: list[str] = []
    monkeypatch.setattr(
        cli_main,
        "_run_supervisor_command",
        lambda command: supervisor_commands.append(command) or 6,
    )

    assert cli_main.main(["trace", "scan-9", "host.test", "json"], app=app) == 0
    assert traces == [("scan-9", "host.test", "json")]
    assert cli_main.main(["health"], app=app) == 6
    assert supervisor_commands == ["health"]
    assert cli_main.main(["legacy-option"], app=app) == 12
    assert cli_main.main([], app=app) == 12

    monkeypatch.setattr(cli_main.sys, "argv", ["octopus"])
    assert cli_main.main(None, app=app) == 12

    created_app = SimpleNamespace(workflows=SimpleNamespace(), run=MagicMock(return_value=14))
    create = MagicMock(return_value=created_app)
    monkeypatch.setattr(cli_main, "create_app", create)
    assert cli_main.main([]) == 14
    create.assert_called_once_with()

    with pytest.raises(SystemExit) as raised:
        cli_main.main(["--version"], app=app)
    assert raised.value.code == 0
    assert "octopus" in capsys.readouterr().out


def test_color_helpers_cover_known_unknown_titled_and_plain_formats() -> None:
    assert colors.C.SUCCESS == colors.C.GREEN
    assert colors.C.ERROR == colors.C.RED
    assert colors.C.HIGHLIGHT == colors.C.BOLD + colors.C.CYAN
    assert colors.severity_color("  CRITICAL ") == colors.C.BOLD + colors.C.RED
    assert colors.severity_color("unranked") == colors.C.GRAY
    assert colors.style("text", colors.C.BLUE) == f"{colors.C.BLUE}text{colors.C.RESET}"
    assert colors.success("done") == f"{colors.C.GREEN}[+] done{colors.C.RESET}"
    assert colors.warn("careful") == f"{colors.C.YELLOW}[!] careful{colors.C.RESET}"
    assert colors.error("failed") == f"{colors.C.RED}[✗] failed{colors.C.RESET}"
    assert colors.info("working") == f"{colors.C.CYAN}[*] working{colors.C.RESET}"

    titled = colors.divider("TEST", width=20, char="=")
    assert titled == f"{colors.C.CYAN}======= TEST ======={colors.C.RESET}"
    assert colors.divider(width=4, char="-") == f"{colors.C.CYAN}----{colors.C.RESET}"

    header = colors.table_header(("NAME", 8), ("STATE", 6))
    assert "  NAME    STATE " in header
    assert "─" * 14 in header
    assert colors.table_header() == f"{colors.C.CYAN}  \n  {colors.C.RESET}"


def test_legacy_namespace_rebinds_owned_functions_and_active_provider_stubs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_application = ModuleType("fixture_application")
    exec("def owned():\n    return 'application'", fixture_application.__dict__)

    def foreign() -> str:
        return "foreign"

    fixture_application.foreign = foreign  # type: ignore[attr-defined]
    fixture_application.value = 3  # type: ignore[attr-defined]
    monkeypatch.setattr(octopus, "_application_module", fixture_application)
    for name in ("owned", "foreign", "value"):
        monkeypatch.setattr(octopus, name, object(), raising=False)

    db_provider = ModuleType("db")
    db_provider.owned = "provider-owned"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "db", db_provider)
    monkeypatch.setitem(sys.modules, "export", ModuleType("export"))
    monkeypatch.setitem(sys.modules, "tools", None)

    forwarded = octopus._bind_legacy_namespace()

    assert set(forwarded) >= {"owned", "foreign", "value"}
    assert octopus.owned == "provider-owned"
    assert octopus.foreign() == "foreign"
    assert octopus.value == 3


def test_legacy_create_app_and_main_preserve_module_local_monkeypatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    explicit_workflows = SimpleNamespace(name="explicit")
    created: list[object] = []
    app_from_factory = object()

    def fake_create(workflows):
        created.append(workflows)
        return app_from_factory

    monkeypatch.setattr(octopus, "_create_app", fake_create)
    assert octopus.create_app(explicit_workflows) is app_from_factory
    assert octopus.create_app() is app_from_factory
    assert created == [explicit_workflows, octopus]

    dispatches: list[tuple[object, object]] = []

    def fake_main(argv, *, app):
        dispatches.append((argv, app))
        return 21

    default_app = object()
    create_app = MagicMock(return_value=default_app)
    monkeypatch.setattr(octopus, "_main", fake_main)
    monkeypatch.setattr(octopus, "create_app", create_app)
    explicit_app = object()

    assert octopus.main(["status"], app=explicit_app) == 21
    assert octopus.main() == 21
    assert dispatches == [(["status"], explicit_app), (None, default_app)]
    create_app.assert_called_once_with()


def test_legacy_entrypoint_exits_with_dispatcher_code_when_run_as_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_for: list[object] = []

    def fake_create(workflows):
        created_for.append(workflows)
        return "script-app"

    dispatcher = MagicMock(return_value=23)
    monkeypatch.setattr(cli_main, "create_app", fake_create)
    monkeypatch.setattr(cli_main, "main", dispatcher)

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(ROOT / "octopus.py"), run_name="__main__")

    assert raised.value.code == 23
    assert len(created_for) == 1
    dispatcher.assert_called_once_with(None, app="script-app")
