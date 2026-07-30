from __future__ import annotations

import importlib
import importlib.util
import runpy
import sys
import types
from pathlib import Path

import pytest
import setuptools
from setuptools import Distribution
from setuptools.command.build_py import build_py as BaseBuildPy

import octopus_c2
from core import application

pytestmark = pytest.mark.contract
ROOT = Path(__file__).resolve().parents[1]


def test_application_entrypoint_forwards_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.cli import main as cli

    calls: list[object] = []
    monkeypatch.setattr(cli, "main", lambda argv: calls.append(argv) or 23)

    assert application.main(("--version",)) == 23
    assert calls == [("--version",)]


def test_c2_dependency_probe_and_missing_extra_message(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        octopus_c2.importlib.util,
        "find_spec",
        lambda name: None if name == "fastapi" else object(),
    )
    assert octopus_c2._missing_dependencies() == ["fastapi"]

    monkeypatch.setattr(octopus_c2, "_missing_dependencies", lambda: ["fastapi", "uvicorn"])
    assert octopus_c2.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "missing: fastapi, uvicorn" in captured.err
    assert "octopus-security[c2]" in captured.err


def test_c2_entrypoint_preserves_integer_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = types.ModuleType("core.c2.daemon")
    monkeypatch.setitem(sys.modules, "core.c2.daemon", daemon)
    monkeypatch.setattr(octopus_c2, "_missing_dependencies", list)

    daemon.main = lambda: 7  # type: ignore[attr-defined]
    assert octopus_c2.main() == 7
    daemon.main = lambda: None  # type: ignore[attr-defined]
    assert octopus_c2.main() == 0


def test_c2_script_exits_cleanly_when_extra_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(ROOT / "octopus_c2.py"), run_name="__main__")

    assert raised.value.code == 2
    assert "fastapi" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("module_name", "target"),
    (
        ("benchmarks.competitors.run_adapter", "core.benchmarks.competitors.adapter"),
        ("benchmarks.competitors.run_campaign", "core.benchmarks.competitors.campaign"),
        (
            "benchmarks.competitors.run_diagnostic_adapter",
            "core.benchmarks.competitors.diagnostic_worker",
        ),
        ("benchmarks.competitors.run_lab", "core.benchmarks.competitors.labctl"),
    ),
)
def test_repository_wrappers_dispatch_as_import_and_script(
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    target: str,
) -> None:
    module = importlib.import_module(module_name)
    calls: list[tuple[str, str | None, str]] = []

    def fake_run_module(name: str, *, run_name: str | None = None) -> None:
        calls.append((name, run_name, sys.path[0]))

    monkeypatch.setattr(runpy, "run_module", fake_run_module)
    original_path = sys.path[:]
    try:
        module.main()
        sys.path[:] = original_path
        runpy.run_path(str(Path(module.__file__).resolve()), run_name="__main__")
    finally:
        sys.path[:] = original_path

    assert calls == [
        (target, "__main__", str(ROOT)),
        (target, "__main__", str(ROOT)),
    ]


def test_setup_build_command_copies_and_reports_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    setup_calls: list[dict[str, object]] = []
    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: setup_calls.append(kwargs))
    spec = importlib.util.spec_from_file_location("octopus_setup_contract", ROOT / "setup.py")
    assert spec is not None and spec.loader is not None
    setup_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup_module)

    assert len(setup_calls) == 1
    command_class = setup_calls[0]["cmdclass"]["build_py"]
    assert command_class is setup_module.BuildPyWithConfig

    base_runs: list[object] = []
    copies: list[tuple[str, str]] = []
    output_flags: list[bool] = []
    monkeypatch.setattr(BaseBuildPy, "run", lambda self: base_runs.append(self))
    monkeypatch.setattr(
        BaseBuildPy,
        "get_outputs",
        lambda _self, include_bytecode=True: output_flags.append(include_bytecode) or ["module.py"],
    )
    monkeypatch.setattr(
        command_class,
        "copy_file",
        lambda _self, source, destination: copies.append((source, destination)),
    )

    command = command_class(Distribution())
    command.build_lib = str(tmp_path / "build")
    command.run()
    assert command.get_outputs(include_bytecode=False) == [
        "module.py",
        str(tmp_path / "build" / "config.yaml"),
    ]
    assert base_runs == [command]
    assert copies == [("config.yaml", str(tmp_path / "build" / "config.yaml"))]
    assert output_flags == [False]
