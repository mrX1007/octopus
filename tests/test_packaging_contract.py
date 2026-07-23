"""Installable package and application-version contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
    import tomli as tomllib

from core.version import APPLICATION_VERSION

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_package_has_build_backend_version_and_console_entrypoints() -> None:
    payload = _pyproject()

    assert payload["build-system"]["build-backend"] == "setuptools.build_meta"
    assert payload["project"]["version"] == APPLICATION_VERSION
    assert payload["project"]["scripts"] == {
        "octobench": "core.benchmarks.__main__:main",
        "octobench-competitors": "core.benchmarks.competitors.__main__:main",
        "octopus": "core.application:main",
        "octopus-c2": "core.c2.daemon:main",
    }


def test_optional_profiles_are_explicit_and_core_has_no_unused_litellm() -> None:
    project = _pyproject()["project"]

    assert set(project["optional-dependencies"]) == {
        "c2",
        "mysql",
        "osint-browser",
        "reporting",
    }
    assert all("litellm" not in item.lower() for item in project["dependencies"])


def test_importing_legacy_cli_does_not_install_signal_handler(monkeypatch) -> None:
    import importlib
    import signal
    import sys

    calls: list[tuple] = []
    monkeypatch.setattr(signal, "signal", lambda *args: calls.append(args))
    sys.modules.pop("octopus", None)

    module = importlib.import_module("octopus")

    assert module.__version__ == APPLICATION_VERSION
    assert calls == []
