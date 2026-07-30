"""Hermetic edge coverage for deterministic SBOM generation."""

from __future__ import annotations

import json
import runpy
import sys
import warnings
from pathlib import Path

import pytest

from scripts.quality import sbom

pytestmark = pytest.mark.unit


def test_records_ignore_comments_and_reject_unterminated_continuation() -> None:
    digest = "a" * 64
    assert sbom._records(
        f"\n  # generated lock  \nDemo==1.0 --hash=sha256:{digest}\n",
    ) == (f"Demo==1.0 --hash=sha256:{digest}",)

    with pytest.raises(sbom.SbomError, match="unterminated requirement continuation"):
        sbom._records("Demo==1.0 \\")


def test_build_sbom_maps_read_and_inexact_record_errors(tmp_path: Path) -> None:
    with pytest.raises(sbom.SbomError, match="cannot read lock: FileNotFoundError"):
        sbom.build_sbom(tmp_path / "missing.lock")

    lock = tmp_path / "inexact.lock"
    lock.write_text("demo>=1.0\n", encoding="utf-8")
    with pytest.raises(sbom.SbomError, match="lock record is not exact and hashed"):
        sbom.build_sbom(lock)


def test_main_reports_sbom_error_without_writing_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lock = tmp_path / "invalid.lock"
    output = tmp_path / "sbom.json"
    lock.write_text("demo==1.0\n", encoding="utf-8")

    assert sbom.main([str(lock), "--output", str(output)]) == 1
    assert not output.exists()
    assert "SBOM generation failed:" in capsys.readouterr().err


def test_module_entrypoint_generates_sbom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = tmp_path / "runtime.lock"
    output = tmp_path / "sbom.json"
    lock.write_text(
        f"demo==1.0 --hash=sha256:{'b' * 64}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["sbom", str(lock), "--output", str(output)],
    )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("scripts.quality.sbom", run_name="__main__")

    assert exc_info.value.code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["components"][0]["name"] == "demo"
