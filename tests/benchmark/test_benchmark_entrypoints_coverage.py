"""Hermetic CLI coverage for benchmark entrypoints."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

import core.benchmarks.__main__ as builtin_main
import core.benchmarks.competitors.__main__ as competitor_main
import core.benchmarks.harness as harness_module
import core.benchmarks.schema as benchmark_schema
import core.benchmarks.task_efficiency as efficiency_module
from core.benchmarks.schema import BenchmarkSchemaError

pytestmark = [pytest.mark.benchmark, pytest.mark.contract]


class HarnessDouble:
    instances: ClassVar[list[HarnessDouble]] = []

    def __init__(self):
        self.runs = []
        self.writes = []
        self.__class__.instances.append(self)

    def run(self, scenario):
        self.runs.append(scenario)
        return {"scenario": scenario.scenario_id}

    def write(self, aggregate, destination):
        self.writes.append((aggregate, destination))
        return destination


def test_builtin_main_full_and_comparison_only_paths(tmp_path, monkeypatch, capsys):
    scenario = SimpleNamespace(scenario_id="one")
    comparison = tmp_path / "comparison.json"
    monkeypatch.setattr(harness_module, "BenchmarkHarness", HarnessDouble)
    monkeypatch.setattr(benchmark_schema, "load_scenarios", lambda _path: (scenario,))
    monkeypatch.setattr(
        efficiency_module,
        "write_task_efficiency_comparison",
        lambda path: Path(path),
    )

    assert (
        builtin_main.main(
            [
                "--scenario-directory",
                str(tmp_path),
                "--output-directory",
                str(tmp_path / "output"),
                "--comparison-output",
                str(comparison),
            ]
        )
        == 0
    )
    instance = HarnessDouble.instances[-1]
    assert instance.runs == [scenario]
    assert instance.writes[0][1].name == "one-v1.json"
    assert str(comparison) in capsys.readouterr().out

    before = len(HarnessDouble.instances)
    assert (
        builtin_main.main(
            [
                "--comparison-only",
                "--comparison-output",
                str(comparison),
            ]
        )
        == 0
    )
    assert len(HarnessDouble.instances) == before


def _result(*, strict_failures=False):
    return SimpleNamespace(
        matrix_id="matrix",
        completeness={
            "written_aggregates": 1,
            "expected_aggregates": 1,
            "failed_runs": 0,
            "timeout_runs": 0,
            "partial_runs": 0,
            "invalid_runs": 0,
            "policy_violations": 0,
        },
        has_strict_failures=strict_failures,
    )


def _competitor_args(tmp_path, *, strict=False):
    args = [
        "--system-manifest",
        str(tmp_path / "system.json"),
        "--scenario-directory",
        str(tmp_path / "scenarios"),
        "--output-directory",
        str(tmp_path / "output"),
    ]
    if strict:
        args.append("--strict")
    return args


def test_competitor_main_success_strict_and_failure_paths(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(competitor_main, "_load_manifests", lambda *_args: ("manifest",))
    monkeypatch.setattr(competitor_main, "load_scenarios", lambda _path: ("scenario",))
    current = _result()
    monkeypatch.setattr(
        competitor_main,
        "run_competitor_matrix",
        lambda *_args, **_kwargs: current,
    )
    monkeypatch.setattr(
        competitor_main,
        "publish_competitor_matrix",
        lambda _result, path: path,
    )
    assert competitor_main.main(_competitor_args(tmp_path)) == 0
    assert "matrix=matrix" in capsys.readouterr().out

    current.has_strict_failures = True
    assert competitor_main.main(_competitor_args(tmp_path, strict=True)) == 1

    monkeypatch.setattr(
        competitor_main,
        "run_competitor_matrix",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(BenchmarkSchemaError("bad")),
    )
    assert competitor_main.main(_competitor_args(tmp_path)) == 2
    assert "competitor benchmark failed: bad" in capsys.readouterr().err


def test_competitor_main_requires_manifest_and_repetition_parser(tmp_path):
    with pytest.raises(SystemExit) as captured:
        competitor_main.main(
            [
                "--scenario-directory",
                str(tmp_path),
                "--output-directory",
                str(tmp_path / "output"),
            ]
        )
    assert captured.value.code == 2
    with pytest.raises(Exception, match="integer"):
        competitor_main._repetitions("bad")
    with pytest.raises(Exception, match="at least"):
        competitor_main._repetitions("1")
    assert competitor_main._repetitions("5") == 5


def test_load_manifests_combines_files_and_directories(tmp_path, monkeypatch):
    monkeypatch.setattr(competitor_main, "load_system_manifest", lambda path: f"file:{path.name}")
    monkeypatch.setattr(
        competitor_main,
        "load_system_manifests",
        lambda path: (f"dir:{path.name}:one", f"dir:{path.name}:two"),
    )
    result = competitor_main._load_manifests((tmp_path / "one.json",), (tmp_path / "systems",))
    assert result == ("file:one.json", "dir:systems:one", "dir:systems:two")


@pytest.mark.parametrize(
    "module_name",
    (
        "core.benchmarks.__main__",
        "core.benchmarks.competitors.__main__",
        "core.benchmarks.v4.__main__",
    ),
)
def test_module_entry_guards_execute_help(module_name, monkeypatch):
    monkeypatch.setattr(sys, "argv", [module_name, "--help"])
    with pytest.raises(SystemExit) as captured:
        runpy.run_module(module_name, run_name="__main__")
    assert captured.value.code == 0
