"""Explicit parser and process lifecycle for the OCTOPUS CLI."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any

from core.version import APPLICATION_VERSION

_SUPERVISOR_COMMANDS = ("status", "stop", "health", "pid")


def create_parser() -> argparse.ArgumentParser:
    """Build the CLI parser without touching process or application state."""

    parser = argparse.ArgumentParser(
        prog="octopus",
        description="OCTOPUS autonomous security assessment CLI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APPLICATION_VERSION}",
    )
    commands = parser.add_subparsers(dest="command")
    trace = commands.add_parser("trace", help="render a persisted trace report")
    trace.add_argument("scan_id")
    trace.add_argument("target")
    trace.add_argument("format", nargs="?", default="text")
    for command in _SUPERVISOR_COMMANDS:
        commands.add_parser(command, help=f"supervisor {command}")
    return parser


class OctopusCLIApplication:
    """Own startup/shutdown effects for one interactive CLI invocation."""

    def __init__(self, workflows: Any) -> None:
        self.workflows = workflows
        self.supervisor: Any | None = None

    def run(self) -> int:
        """Run the legacy interactive menu under an explicit lifecycle."""

        import signal

        previous_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self.workflows._sigint_handler)
        try:
            log_file = self.workflows._setup_logging()
            self.workflows._setup_readline()
            if not self._start_supervisor():
                return 1
            if not self.workflows.preflight_checks():
                self.workflows.error(
                    "Critical pre-flight checks failed. Fix issues above and restart."
                )
                return 1
            self.workflows.info(f"Logging to: {log_file}")
            self.workflows._start_c2_daemon()
            self._discover_extensions()
            self.workflows.main_menu()
            return 0
        finally:
            if self.supervisor is not None:
                self.supervisor.stop()
            self.workflows._supervisor = None
            signal.signal(signal.SIGINT, previous_sigint)

    def _start_supervisor(self) -> bool:
        try:
            from core.supervisor import AlreadyRunningError, create_supervisor
        except ImportError:
            self.workflows._supervisor = None
            self.workflows.warn("Supervisor not available (core/supervisor.py missing)")
            return True

        supervisor = create_supervisor(
            monitor_ollama=True,
            monitor_db=True,
            monitor_events=True,
        )
        self.supervisor = supervisor
        self.workflows._supervisor = supervisor

        def save_scan_on_shutdown() -> None:
            if self.workflows._current_sl_no:
                self.workflows.update_session_status(
                    self.workflows._current_sl_no,
                    "interrupted",
                )
                logging.info(
                    "Session SL# %s saved on shutdown",
                    self.workflows._current_sl_no,
                )

        supervisor.on_shutdown(save_scan_on_shutdown)
        try:
            supervisor.start()
        except AlreadyRunningError as exc:
            self.workflows.error(str(exc))
            return False

        self.workflows.info(f"Supervisor: PID {supervisor._pid} locked")
        crash = supervisor.get_crash_info()
        if crash:
            self.workflows.warn(
                f"Previous instance (PID {crash['previous_pid']}) crashed. "
                "Checkpoint recovery available via 'Resume Unfinished Scan'."
            )
        return True

    def _discover_extensions(self) -> None:
        try:
            from core.tools.registry import discover_plugins, print_registry_stats

            root = self.workflows.PROJECT_ROOT
            loaded_plugins = discover_plugins(os.path.join(root, "plugins"))
            loaded_modules = discover_plugins(os.path.join(root, "modules"))
            if loaded_plugins or loaded_modules:
                self.workflows.info(
                    f"Dynamically loaded {loaded_plugins} plugins and "
                    f"{loaded_modules} modules."
                )
                print_registry_stats()
        except Exception as exc:
            self.workflows.warn(f"Error during plugin discovery: {exc}")


def create_app(workflows: Any | None = None) -> OctopusCLIApplication:
    """Compose an application without starting any lifecycle component."""

    if workflows is None:
        from core.cli import application as default_workflows

        workflows = default_workflows
    return OctopusCLIApplication(workflows)


def _run_supervisor_command(command: str) -> int:
    try:
        from core.supervisor import cli as supervisor_cli
    except ImportError:
        print("[!] Supervisor module not available")
        return 0

    previous_argv = sys.argv
    sys.argv = [previous_argv[0], command]
    try:
        supervisor_cli()
    except SystemExit as exc:
        return int(exc.code or 0)
    finally:
        sys.argv = previous_argv
    return 0


def main(
    argv: Sequence[str] | None = None,
    *,
    app: OctopusCLIApplication | None = None,
) -> int:
    """Dispatch one CLI invocation and return its process exit code."""

    arguments = list(argv) if argv is not None else list(sys.argv[1:])
    known_commands = {"trace", *_SUPERVISOR_COMMANDS}
    if (
        arguments
        and arguments[0] not in known_commands
        and arguments[0] not in {"-h", "--help", "--version"}
    ):
        # The historical script ignored unrecognized argv and entered the
        # interactive menu. Preserve that compatibility quirk while the
        # explicit parser owns all documented commands.
        return (app or create_app()).run()
    args, _unknown = create_parser().parse_known_args(arguments)
    if args.command == "trace":
        active_app = app or create_app()
        active_app.workflows._print_trace_report_cli(
            args.scan_id,
            args.target,
            args.format,
        )
        return 0
    if args.command in _SUPERVISOR_COMMANDS:
        return _run_supervisor_command(args.command)
    return (app or create_app()).run()


__all__ = [
    "OctopusCLIApplication",
    "create_app",
    "create_parser",
    "main",
]
