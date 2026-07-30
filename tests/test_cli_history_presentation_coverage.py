"""Hermetic branch coverage for the interactive CLI's small boundary helpers."""

from __future__ import annotations

import builtins
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from core.cli import history, presentation

pytestmark = pytest.mark.unit


def test_completer_filters_case_insensitively_and_handles_exhaustion() -> None:
    completer = history.OctopusCompleter(["scan", "Back", "status"])

    assert completer.options == ["Back", "scan", "status"]
    assert completer.complete("S", 0) == "scan"
    assert completer.complete("S", 1) == "status"
    assert completer.complete("S", 2) is None

    assert completer.complete("", 0) == "Back"
    assert completer.complete("", 99) is None

    default_completer = history.OctopusCompleter()
    assert "scan" in default_completer.options


def test_history_entries_are_redacted_at_the_readline_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    source_entries = {1: "token=first", 2: "password=second"}
    redaction_calls: list[tuple[str | None, str]] = []

    monkeypatch.setattr(history.readline, "get_current_history_length", lambda: 2)
    monkeypatch.setattr(history.readline, "get_history_item", source_entries.get)

    from core import secrets as secret_helpers

    def fake_redact(value: str | None, *, kind: str) -> str:
        redaction_calls.append((value, kind))
        return f"redacted-{len(redaction_calls)}"

    monkeypatch.setattr(secret_helpers, "redact_text", fake_redact)

    assert history._redacted_history_entries() == ["redacted-1", "redacted-2"]
    assert redaction_calls == [
        ("token=first", "readline_history"),
        ("password=second", "readline_history"),
    ]


def test_write_history_replaces_entries_and_hardens_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    clear_history = MagicMock()
    add_history = MagicMock()
    write_history_file = MagicMock()
    chmod = MagicMock()

    monkeypatch.setattr(history, "_redacted_history_entries", lambda: ["safe one", "safe two"])
    monkeypatch.setattr(history.readline, "clear_history", clear_history)
    monkeypatch.setattr(history.readline, "add_history", add_history)
    monkeypatch.setattr(history.readline, "write_history_file", write_history_file)
    monkeypatch.setattr(history.os, "chmod", chmod)

    history._write_redacted_history("/tmp/octopus-test-history")

    clear_history.assert_called_once_with()
    assert add_history.call_args_list == [call("safe one"), call("safe two")]
    write_history_file.assert_called_once_with("/tmp/octopus-test-history")
    chmod.assert_called_once_with("/tmp/octopus-test-history", 0o600)


def test_setup_readline_loads_redacts_and_registers_shutdown_writer(monkeypatch: pytest.MonkeyPatch) -> None:
    set_completer = MagicMock()
    parse_and_bind = MagicMock()
    set_delims = MagicMock()
    read_history = MagicMock()
    set_length = MagicMock()
    write_redacted = MagicMock()
    register = MagicMock()

    monkeypatch.setattr(history.readline, "set_completer", set_completer)
    monkeypatch.setattr(history.readline, "parse_and_bind", parse_and_bind)
    monkeypatch.setattr(history.readline, "set_completer_delims", set_delims)
    monkeypatch.setattr(history.readline, "read_history_file", read_history)
    monkeypatch.setattr(history.readline, "set_history_length", set_length)
    monkeypatch.setattr(history, "_write_redacted_history", write_redacted)
    monkeypatch.setattr(history.atexit, "register", register)

    history.setup_readline("/tmp/existing-history")

    completer_callback = set_completer.call_args.args[0]
    assert isinstance(completer_callback.__self__, history.OctopusCompleter)
    parse_and_bind.assert_called_once_with("tab: complete")
    set_delims.assert_called_once_with(" \t\n;")
    read_history.assert_called_once_with("/tmp/existing-history")
    set_length.assert_called_once_with(500)
    write_redacted.assert_called_once_with("/tmp/existing-history")
    register.assert_called_once_with(write_redacted, "/tmp/existing-history")


def test_setup_readline_tolerates_first_run_without_registering_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history.readline, "set_completer", MagicMock())
    monkeypatch.setattr(history.readline, "parse_and_bind", MagicMock())
    monkeypatch.setattr(history.readline, "set_completer_delims", MagicMock())
    monkeypatch.setattr(
        history.readline,
        "read_history_file",
        MagicMock(side_effect=FileNotFoundError("not created yet")),
    )
    set_length = MagicMock()
    write_redacted = MagicMock()
    register = MagicMock()
    monkeypatch.setattr(history.readline, "set_history_length", set_length)
    monkeypatch.setattr(history, "_write_redacted_history", write_redacted)
    monkeypatch.setattr(history.atexit, "register", register)

    history.setup_readline("/tmp/new-history", register_exit=False)

    set_length.assert_not_called()
    write_redacted.assert_not_called()
    register.assert_not_called()


def test_presentation_imports_have_a_dependency_free_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Execute the module's import fallbacks without changing the installed environment."""

    real_import = builtins.__import__

    def import_without_optional_dependencies(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "config" or name == "rich" or name.startswith("rich."):
            raise ImportError(f"blocked optional dependency: {name}")
        return real_import(name, globals, locals, fromlist, level)

    module_name = "_octopus_presentation_fallback_test"
    spec = importlib.util.spec_from_file_location(module_name, Path(presentation.__file__))
    assert spec is not None and spec.loader is not None
    fallback_module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, fallback_module)
    monkeypatch.setattr(builtins, "__import__", import_without_optional_dependencies)

    spec.loader.exec_module(fallback_module)

    assert fallback_module.RICH_AVAILABLE is False
    assert fallback_module.console is None
    assert fallback_module.CFG == {}


def test_banner_dividers_prompt_and_status_messages(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    clear = MagicMock(return_value=0)
    monkeypatch.setattr(presentation.os, "system", clear)
    monkeypatch.setattr(presentation, "CFG", {"ollama": {"model": "unit-model"}})

    presentation.banner("9.8.7")
    presentation.divider("DETAILS")
    presentation.divider()

    answers = iter(["  response  "])
    monkeypatch.setattr(builtins, "input", lambda _text: next(answers))
    assert presentation.prompt("Value: ") == "response"

    info_log = MagicMock()
    warning_log = MagicMock()
    error_log = MagicMock()
    monkeypatch.setattr(presentation.logging, "info", info_log)
    monkeypatch.setattr(presentation.logging, "warning", warning_log)
    monkeypatch.setattr(presentation.logging, "error", error_log)

    presentation.success("saved")
    presentation.warn("careful")
    presentation.error("failed")
    presentation.info("working")

    output = capsys.readouterr().out
    clear.assert_called_once_with("clear")
    assert "9.8.7" in output
    assert "unit-model" in output
    assert "DETAILS" in output
    assert "[+] saved" in output
    assert "[!] careful" in output
    assert "[✗] failed" in output
    assert "[*] working" in output
    assert info_log.call_args_list == [call("saved"), call("working")]
    warning_log.assert_called_once_with("careful")
    error_log.assert_called_once_with("failed")


def test_confirm_accepts_only_a_single_y(monkeypatch: pytest.MonkeyPatch) -> None:
    prompt_mock = MagicMock(side_effect=["Y", "yes"])
    monkeypatch.setattr(presentation, "prompt", prompt_mock)

    assert presentation.confirm("Proceed?") is True
    assert presentation.confirm("Proceed?") is False
    assert prompt_mock.call_args_list == [call("Proceed? [y/N]: "), call("Proceed? [y/N]: ")]


def test_spinner_uses_rich_context_and_plain_fallback(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    progress = MagicMock()
    progress_context = MagicMock()
    progress_context.__enter__.return_value = progress
    progress_factory = MagicMock(return_value=progress_context)
    monkeypatch.setattr(presentation, "Progress", progress_factory)
    monkeypatch.setattr(presentation, "RICH_AVAILABLE", True)

    def operation(value: int, *, increment: int) -> int:
        return value + increment

    assert presentation.run_with_spinner("Calculating", operation, 4, increment=3) == 7
    progress.add_task.assert_called_once_with("Calculating", total=None)
    progress_factory.assert_called_once()

    monkeypatch.setattr(presentation, "RICH_AVAILABLE", False)
    assert presentation.run_with_spinner("Fallback", operation, 5, increment=2) == 7
    assert "Fallback..." in capsys.readouterr().out


def test_rich_and_plain_table_renderers(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    table = MagicMock()
    table_factory = MagicMock(return_value=table)
    console = MagicMock()
    monkeypatch.setattr(presentation, "RichTable", table_factory)
    monkeypatch.setattr(presentation, "console", console)
    monkeypatch.setattr(presentation, "RICH_AVAILABLE", True)

    columns = [("Name", "cyan"), ("Long Heading", "green")]
    rows = [("alpha", 7), (None, "omega")]
    presentation.print_rich_table("Inventory", columns, rows)

    table_factory.assert_called_once_with(title="Inventory", border_style="dim", header_style="bold cyan")
    assert table.add_column.call_args_list == [call("Name", style="cyan"), call("Long Heading", style="green")]
    assert table.add_row.call_args_list == [call("alpha", "7"), call("None", "omega")]
    console.print.assert_called_once_with(table)

    monkeypatch.setattr(presentation, "RICH_AVAILABLE", False)
    presentation.print_rich_table("Inventory", columns, rows)
    output = capsys.readouterr().out
    assert "Name" in output
    assert "Long Heading" in output
    assert "alpha" in output
    assert "omega" in output


def test_reporting_helpers_normalize_values() -> None:
    assert presentation._truncate(None) == ""
    assert presentation._truncate("abcdef", 3) == "abc"
    assert presentation._ports_text({"ports": [0, 22, None, "443"]}) == "22,443"
    assert presentation._ports_text({}) == "n/a"


def test_reporting_sections_render_every_optional_block(capsys) -> None:
    result = {
        "outcome_summary": ["x" * 320],
        "access_findings": [
            {"severity": "HIGH", "name": "Admin access", "evidence": ["shell", "proof"]},
            {"name": None, "evidence": []},
        ],
        "risk_explanation": "Reachable administrative interface",
        "finding_groups": [
            {
                "module": "web",
                "service": "https",
                "ports": [443, 0],
                "candidate": True,
                "verified": True,
                "exploited": False,
                "impact_confirmed": False,
            },
            {"module": "dns", "service": "domain", "ports": []},
        ],
        "coverage": {
            "confidence": "degraded",
            "degraded": [{"tool": "scanner", "status": "timeout", "impact": "partial"}],
            "checked_but_not_confirmed": [{"status": "not-observed"}],
        },
        "attack_path": [{"stage": "discovery", "status": "complete", "detail": "service found"}],
        "remediations": [
            {"service": "https", "recommendation": "Restrict administrative access"},
            {"recommendation": "Review exposure"},
        ],
    }

    presentation.print_reporting_sections(result)
    output = capsys.readouterr().out

    for heading in (
        "FINAL OUTCOME",
        "ACCESS FINDINGS",
        "RISK EXPLANATION",
        "FINDING STATUS",
        "COVERAGE",
        "ATTACK PATH",
        "REMEDIATION",
    ):
        assert heading in output
    assert "Evidence: shell; proof" in output
    assert "ports=443" in output
    assert "ports=n/a" in output
    assert "unknown: Review exposure" in output
    assert "x" * 300 in output
    assert "x" * 301 not in output


def test_reporting_sections_are_silent_when_no_sections_apply(capsys) -> None:
    presentation.print_reporting_sections({})
    assert capsys.readouterr().out == ""

    presentation.print_reporting_sections({"coverage": {"checked_but_not_confirmed": [{"status": "clean"}]}})
    output = capsys.readouterr().out
    assert "COVERAGE" in output
    assert "checked: clean" in output


def test_results_table_renders_rich_vulnerabilities_and_filters_facts(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    table = MagicMock()
    table_factory = MagicMock(return_value=table)
    console = MagicMock()
    reporting = MagicMock()
    monkeypatch.setattr(presentation, "RichTable", table_factory)
    monkeypatch.setattr(presentation, "console", console)
    monkeypatch.setattr(presentation, "RICH_AVAILABLE", True)
    monkeypatch.setattr(presentation, "print_reporting_sections", reporting)

    result = {
        "risk_level": "HIGH",
        "vulnerabilities": [
            {"severity": "odd", "port": "123456789", "service": "custom-service-name-long", "vuln_name": "z" * 50},
            {"severity": "critical", "port": "443", "service": "https", "vuln_name": "Critical issue"},
        ],
        "confirmed_facts": [
            "<thought>hidden</thought>\n\n[TOOL:nmap]\n[DELEGATE:worker]\nMeaningful confirmed intelligence",
            "short",
            "[TOOL:ignored]",
        ],
    }

    presentation.print_results_table(result)

    table_factory.assert_called_once()
    assert table.add_column.call_count == 4
    assert table.add_row.call_count == 2
    first_row, second_row = table.add_row.call_args_list
    assert "CRITICAL" in first_row.args[0]
    assert "ODD" in second_row.args[0]
    assert second_row.args[1] == "12345678"
    assert second_row.args[2] == "custom-service-nam"
    assert second_row.args[3] == "z" * 40
    console.print.assert_called_once_with(table)
    reporting.assert_called_once_with(result)

    output = capsys.readouterr().out
    assert "CONFIRMED INTELLIGENCE" in output
    assert "Meaningful confirmed intelligence" in output
    assert "hidden" not in output
    assert "TOOL" not in output
    assert "DELEGATE" not in output
    assert "short" not in output


def test_results_table_plain_mode_covers_vulnerable_and_empty_results(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(presentation, "RICH_AVAILABLE", False)
    reporting = MagicMock()
    monkeypatch.setattr(presentation, "print_reporting_sections", reporting)

    vulnerable = {
        "risk_level": "MEDIUM",
        "vulnerabilities": [
            {"severity": "low", "port": "80", "service": "http", "vuln_name": "Known issue"},
            {"severity": "informational", "port": "0", "service": "other", "vuln_name": "Unranked item"},
        ],
        "confirmed_facts": [],
    }
    presentation.print_results_table(vulnerable)

    empty = {"risk_level": "CUSTOM", "vulnerabilities": [], "confirmed_facts": []}
    presentation.print_results_table(empty)

    output = capsys.readouterr().out
    assert "RISK LEVEL: MEDIUM" in output
    assert "LOW" in output
    assert "INFORMATIONAL" in output
    assert "Known issue" in output
    assert "No vulnerabilities parsed" in output
    assert reporting.call_args_list == [call(vulnerable), call(empty)]
