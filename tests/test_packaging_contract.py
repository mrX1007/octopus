"""Installable package and application-version contracts."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
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
    assert payload["project"]["dynamic"] == ["version"]
    assert "version" not in payload["project"]
    assert payload["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "core.version.__version__"}
    assert APPLICATION_VERSION
    assert payload["project"]["scripts"] == {
        "octobench": "core.benchmarks.__main__:main",
        "octobench-competitors": "core.benchmarks.competitors.__main__:main",
        "octopus": "core.application:main",
        "octopus-c2": "octopus_c2:main",
        "octopus-c2-bootstrap-admin": "scripts.bootstrap_c2_admin:main",
    }


def test_shipped_config_is_declared_for_sdist_and_installed_beside_module() -> None:
    payload = _pyproject()

    assert "config" in payload["tool"]["setuptools"]["py-modules"]
    assert "octopus_c2" in payload["tool"]["setuptools"]["py-modules"]
    assert "include config.yaml" in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    setup_source = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert 'os.path.join(self.build_lib, "config.yaml")' in setup_source


def test_runtime_build_sources_and_service_are_in_wheel_and_sdist_manifests() -> None:
    payload = _pyproject()["tool"]["setuptools"]

    assert set(payload["package-data"]["core.c2"]) == {
        "go.mod",
        "go.sum",
        "implant.go",
        "toolchain.json",
    }
    assert "core.opsec" not in payload["package-data"]
    assert payload["exclude-package-data"]["core.opsec"] == ["ja3_client.go"]
    assert payload["data-files"]["share/octopus-security/systemd"] == ["data/octopus-c2.service"]
    manifest = set((ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines())
    assert {
        "include config.yaml",
        "include core/c2/go.mod",
        "include core/c2/go.sum",
        "include core/c2/implant.go",
        "include core/c2/toolchain.json",
        "include core/opsec/ja3_client.go",
        "include data/octopus-c2.service",
    } <= manifest

    toolchain = (ROOT / "core" / "c2" / "toolchain.json").read_text(encoding="utf-8")
    assert '"go": "go1.21.13"' in toolchain
    assert '"garble": "v0.12.1"' in toolchain


def test_systemd_service_template_is_portable_and_non_root() -> None:
    service = (ROOT / "data" / "octopus-c2.service").read_text(encoding="utf-8")

    assert "DynamicUser=yes" in service
    assert "StateDirectory=octopus" in service
    assert "RuntimeDirectory=octopus" in service
    assert "ExecStart=/usr/bin/env octopus-c2" in service
    assert "OCTOPUS_DATA_DIR=/var/lib/octopus" in service
    assert "OCTOPUS_C2_SOCKET=/run/octopus/octopus-c2.sock" in service
    assert "User=root" not in service
    assert "/Users/" not in service


def test_c2_console_entrypoint_reports_missing_extra_without_traceback() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            "import octopus_c2; raise SystemExit(octopus_c2.main())",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env={key: value for key, value in os.environ.items() if key not in {"PYTHONHOME", "PYTHONPATH"}},
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "octopus-security[c2]" in completed.stderr
    assert "fastapi" in completed.stderr
    assert "uvicorn" in completed.stderr
    assert "Traceback" not in completed.stderr


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
