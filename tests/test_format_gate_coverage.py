"""Hermetic edge coverage for the changed-file formatting gate."""

from __future__ import annotations

import runpy
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from scripts.quality import format_gate

pytestmark = pytest.mark.unit


def test_changed_files_validates_base_and_maps_git_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(format_gate.FormatGateError, match="format base must"):
        format_gate.changed_python_files(tmp_path, "not-a-sha")

    def failed_git(*_args, **_kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(format_gate.subprocess, "run", failed_git)
    with pytest.raises(
        format_gate.FormatGateError,
        match="cannot enumerate changed files: OSError",
    ):
        format_gate.changed_python_files(tmp_path, "a" * 40)


def test_changed_files_filters_excluded_missing_and_non_python_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src" / "kept.py"
    source.parent.mkdir()
    source.write_text("value = 1\n", encoding="utf-8")
    text = tmp_path / "src" / "ignored.txt"
    text.write_text("ignored\n", encoding="utf-8")
    completed = subprocess.CompletedProcess(
        ["git", "diff"],
        0,
        "\n".join(
            (
                "",
                "vendor/excluded.py",
                "tests/fixtures/excluded.py",
                "src/missing.py",
                "src/ignored.txt",
                "src\\kept.py",
                "src/kept.py",
            ),
        ),
        "",
    )
    monkeypatch.setattr(
        format_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: completed,
    )

    assert format_gate.changed_python_files(tmp_path, "b" * 40) == (source.resolve(),)


def test_changed_files_rejects_repository_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["git", "diff"],
        0,
        "../escape.py\n",
        "",
    )
    monkeypatch.setattr(
        format_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: completed,
    )

    with pytest.raises(
        format_gate.FormatGateError,
        match="changed path escapes repository",
    ):
        format_gate.changed_python_files(tmp_path, "c" * 40)


def test_run_gate_handles_empty_diff_and_formatter_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(format_gate, "changed_python_files", lambda *_args: ())
    assert format_gate.run_format_gate(tmp_path, "d" * 40, ruff="ruff") == 0
    assert "no changed Python files" in capsys.readouterr().out

    source = tmp_path / "changed.py"
    source.write_text("value=1\n", encoding="utf-8")
    monkeypatch.setattr(
        format_gate,
        "changed_python_files",
        lambda *_args: (source,),
    )
    monkeypatch.setattr(
        format_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["ruff", "format"],
            1,
        ),
    )
    with pytest.raises(format_gate.FormatGateError, match="ruff format rejected"):
        format_gate.run_format_gate(tmp_path, "d" * 40, ruff="ruff")


def test_main_parses_arguments_and_reports_gate_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[Path, str, str]] = []
    monkeypatch.setattr(
        format_gate,
        "run_format_gate",
        lambda root, base, *, ruff: calls.append((root, base, ruff)) or 0,
    )
    arguments = [
        "--root",
        str(tmp_path),
        "--base",
        "e" * 40,
        "--ruff",
        "custom-ruff",
    ]
    assert format_gate.main(arguments) == 0
    assert calls == [(tmp_path, "e" * 40, "custom-ruff")]

    def rejected(*_args, **_kwargs):
        raise format_gate.FormatGateError("rejected")

    monkeypatch.setattr(format_gate, "run_format_gate", rejected)
    assert format_gate.main(arguments) == 1
    assert "format gate failed: rejected" in capsys.readouterr().err


def test_module_entrypoint_exits_after_validation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["format-gate", "--root", str(tmp_path), "--base", "invalid"],
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("scripts.quality.format_gate", run_name="__main__")

    assert exc_info.value.code == 1
