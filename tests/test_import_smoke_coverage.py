"""Hermetic branch coverage for the first-party import smoke gate."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

from scripts.quality import import_smoke as smoke

pytestmark = pytest.mark.unit


def test_run_import_smoke_inserts_root_and_collects_all_failures(monkeypatch) -> None:
    isolated_path = ["fixture-search-path"]
    imported = []
    cache_invalidations = []

    def fake_import(module):
        imported.append(module)
        if module == "broken":
            raise RuntimeError("fixture import failure")
        return object()

    monkeypatch.setattr(smoke.sys, "path", isolated_path)
    monkeypatch.setattr(smoke.importlib, "import_module", fake_import)
    monkeypatch.setattr(
        smoke.importlib,
        "invalidate_caches",
        lambda: cache_invalidations.append(True),
    )

    failures = smoke.run_import_smoke(("working", "broken", "also-working"))

    assert isolated_path[0] == str(smoke.PROJECT_ROOT)
    assert imported == ["working", "broken", "also-working"]
    assert failures == [
        smoke.ImportFailure(
            module="broken",
            error_type="RuntimeError",
            message="fixture import failure",
        )
    ]

    assert smoke.run_import_smoke(("working",)) == []
    assert cache_invalidations == [True, True]


def test_main_uses_profile_or_explicit_modules_and_reports_results(
    monkeypatch,
    capsys,
) -> None:
    calls = []

    def fake_smoke(modules):
        calls.append(modules)
        if modules == ("broken-one", "broken-two"):
            return [
                smoke.ImportFailure(
                    module="broken-one",
                    error_type="ImportError",
                    message="first failure",
                ),
                smoke.ImportFailure(
                    module="broken-two",
                    error_type="ValueError",
                    message="second failure",
                ),
            ]
        return []

    monkeypatch.setattr(smoke, "run_import_smoke", fake_smoke)

    assert smoke.main(("--profile", "c2")) == 0
    assert calls[-1] == smoke.PROFILE_MODULES["c2"]
    assert "import smoke passed: 3 modules" in capsys.readouterr().out

    assert smoke.main(
        (
            "--module",
            "broken-one",
            "--module",
            "broken-two",
            "--profile",
            "runtime",
        )
    ) == 1
    assert calls[-1] == ("broken-one", "broken-two")
    errors = capsys.readouterr().err
    assert "broken-one: ImportError: first failure" in errors
    assert "broken-two: ValueError: second failure" in errors


def test_script_main_guard_runs_in_process_without_real_imports(
    monkeypatch,
    capsys,
) -> None:
    script = Path(smoke.__file__)
    imported = []
    monkeypatch.setattr(sys, "argv", [str(script), "--module", "fixture-module"])
    monkeypatch.setattr(
        smoke.importlib,
        "import_module",
        lambda module: imported.append(module) or object(),
    )

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(script), run_name="__main__")

    assert raised.value.code == 0
    assert imported == ["fixture-module"]
    assert "import smoke passed: 1 modules" in capsys.readouterr().out
