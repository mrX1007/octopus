"""Statement and branch coverage for the repository coverage gate."""

from __future__ import annotations

import math
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
from coverage import Coverage
from coverage.exceptions import CoverageException

from scripts.quality import coverage_gate as gate

pytestmark = pytest.mark.contract


def _source_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    root = tmp_path / "repo"
    package = root / "core" / "demo"
    package.mkdir(parents=True)
    source = package / "worker.py"
    source.write_text("value = 1\n", encoding="utf-8")
    config = root / "coverage.ini"
    config.write_text("[run]\nbranch = True\n", encoding="utf-8")
    return root, source, config


def test_relative_and_package_source_selection(tmp_path):
    root, source, _config = _source_tree(tmp_path)
    assert gate._package_sources(root, "core.demo") == [source]

    with pytest.raises(gate.CoverageGateError, match="invalid package"):
        gate._package_sources(root, "")
    with pytest.raises(gate.CoverageGateError, match="has no Python sources"):
        gate._package_sources(root, "../outside")

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(gate.CoverageGateError, match="escapes repository"):
        gate._package_sources(root, "escape")
    (root / "escape").unlink()

    with pytest.raises(gate.CoverageGateError, match="has no Python sources"):
        gate._package_sources(root, "missing")


def test_package_threshold_parser_errors():
    for value, message in (
        ("core.ai", "PACKAGE=PERCENT"),
        ("=50", "PACKAGE=PERCENT"),
        ("core.ai=not-a-number", "numeric"),
        ("core.ai=-1", "between 0 and 100"),
    ):
        with pytest.raises(gate.CoverageGateError, match=message):
            gate._parse_package_threshold(value)


def test_global_threshold_parser_rejects_invalid_and_nonfinite_values():
    assert gate._parse_threshold("100") == 100.0
    with pytest.raises(gate.CoverageGateError, match="numeric"):
        gate._parse_threshold("not-a-number")
    for value in (-1, 101, math.inf, math.nan):
        with pytest.raises(gate.CoverageGateError, match="between 0 and 100"):
            gate._parse_threshold(value)


def test_changed_python_lines_validates_sha_and_git_failures(monkeypatch, tmp_path):
    root, _source, _config = _source_tree(tmp_path)
    with pytest.raises(gate.CoverageGateError, match="Git commit SHA"):
        gate._changed_python_lines(root, "not-a-sha")

    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("git missing")),
    )
    with pytest.raises(gate.CoverageGateError, match="OSError"):
        gate._changed_python_lines(root, "a" * 40)

    error = subprocess.CalledProcessError(1, ["git"])
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(gate.CoverageGateError, match="CalledProcessError"):
        gate._changed_python_lines(root, "a" * 40)


def test_changed_python_lines_parses_only_allowed_sources(monkeypatch, tmp_path):
    root, source, _config = _source_tree(tmp_path)
    diff = "\n".join(
        [
            "diff --git a/core/demo/worker.py b/core/demo/worker.py",
            "+++ b/core/demo/worker.py",
            "@@ -1 +2,2 @@",
            "+first",
            "+second",
            "+++ b/tests/test_worker.py",
            "@@ -0,0 +1 @@",
            "+ignored",
            "not a hunk",
        ]
    )
    monkeypatch.setattr(
        gate.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, diff, ""),
    )
    assert gate._changed_python_lines(root, "a" * 40) == {source.resolve(): {2, 3}}


def test_discovery_rejects_empty_tree_non_sources_and_symlinks(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(gate.CoverageGateError, match="no first-party"):
        gate.discover_first_party_python(empty)

    (empty / "notes.txt").write_text("not Python", encoding="utf-8")
    excluded = empty / "tests"
    excluded.mkdir()
    (excluded / "test_hidden.py").write_text("value = 0\n", encoding="utf-8")
    with pytest.raises(gate.CoverageGateError, match="no first-party"):
        gate.discover_first_party_python(empty)

    target = empty / "target.py"
    target.write_text("value = 1\n", encoding="utf-8")
    assert gate.discover_first_party_python(empty) == [target]

    linked_source = empty / "linked.py"
    linked_source.symlink_to(target)
    with pytest.raises(gate.CoverageGateError, match="Python source is a symlink"):
        gate.discover_first_party_python(empty)
    linked_source.unlink()

    linked_directory = empty / "linked-directory"
    linked_directory.symlink_to(empty, target_is_directory=True)
    with pytest.raises(gate.CoverageGateError, match="source directory is a symlink"):
        gate.discover_first_party_python(empty)


class FakeCoverage:
    report_values: ClassVar[list[float]] = []
    statements: ClassVar[list[int]] = [1, 2]
    missing_lines: ClassVar[list[int]] = [2]
    branch_values: ClassVar[dict[int, tuple[int, int]]] = {}
    has_arcs: ClassVar[bool] = True
    line_exclusions: ClassVar[list[str]] = []
    partial_exclusions: ClassVar[list[str]] = []
    options: ClassVar[dict[str, object]] = {
        "run:branch": True,
        "run:omit": ["build/*", "tests/*", "vendor/*", "venv/*"],
        "run:include": [],
        "report:include": None,
        "report:omit": None,
    }
    analysis_error: Exception | None = None
    branch_error: Exception | None = None
    instances: ClassVar[list[FakeCoverage]] = []

    def __init__(self, *, config_file, data_file):
        self.config_file = config_file
        self.data_file = data_file
        self.loaded = False
        self.xml_calls = []
        self.__class__.instances.append(self)

    def load(self):
        self.loaded = True

    def report(self, *, morfs, file):
        self.last_morfs = morfs
        return self.__class__.report_values.pop(0)

    def analysis2(self, _path):
        if self.__class__.analysis_error is not None:
            raise self.__class__.analysis_error
        return "file", self.__class__.statements, [], self.__class__.missing_lines, ""

    def get_data(self):
        has_arcs = self.__class__.has_arcs
        return SimpleNamespace(has_arcs=lambda: has_arcs)

    def branch_stats(self, _path):
        if self.__class__.branch_error is not None:
            raise self.__class__.branch_error
        return self.__class__.branch_values

    def get_exclude_list(self, which="exclude"):
        if which == "partial":
            return self.__class__.partial_exclusions
        return self.__class__.line_exclusions

    def get_option(self, option):
        return self.__class__.options[option]

    def _get_file_reporter(self, _path):
        return SimpleNamespace(translate_lines=lambda lines: set(lines))

    def xml_report(self, *, morfs, outfile):
        self.xml_calls.append((morfs, outfile))


@pytest.fixture
def fake_coverage(monkeypatch):
    FakeCoverage.report_values = []
    FakeCoverage.statements = [1, 2]
    FakeCoverage.missing_lines = [2]
    FakeCoverage.branch_values = {}
    FakeCoverage.has_arcs = True
    FakeCoverage.line_exclusions = []
    FakeCoverage.partial_exclusions = []
    FakeCoverage.options = {
        "run:branch": True,
        "run:omit": ["build/*", "tests/*", "vendor/*", "venv/*"],
        "run:include": [],
        "report:include": None,
        "report:omit": None,
    }
    FakeCoverage.analysis_error = None
    FakeCoverage.branch_error = None
    FakeCoverage.instances = []
    monkeypatch.setattr(gate, "Coverage", FakeCoverage)
    return FakeCoverage


def test_evaluate_rejects_global_regression(fake_coverage, tmp_path):
    root, _source, config = _source_tree(tmp_path)
    fake_coverage.report_values = [49.0]
    with pytest.raises(gate.CoverageGateError, match="coverage regression"):
        gate.evaluate_coverage(root, config, 50.0)


def test_evaluate_simple_success_without_optional_reports(fake_coverage, tmp_path):
    root, _source, config = _source_tree(tmp_path)
    fake_coverage.report_values = [100.0]
    assert gate.evaluate_coverage(root, config, 100.0) == 100.0


def test_evaluate_requires_branch_data_and_forbids_all_exclusions(fake_coverage, tmp_path):
    root, _source, config = _source_tree(tmp_path)
    fake_coverage.has_arcs = False
    with pytest.raises(gate.CoverageGateError, match="coverage data has no arcs"):
        gate.evaluate_coverage(root, config, 100.0)

    fake_coverage.has_arcs = True
    fake_coverage.line_exclusions = ["pragma: no cover"]
    with pytest.raises(gate.CoverageGateError, match="line exclusions are forbidden"):
        gate.evaluate_coverage(root, config, 100.0)

    fake_coverage.line_exclusions = []
    fake_coverage.partial_exclusions = ["pragma: no branch"]
    with pytest.raises(gate.CoverageGateError, match="partial-branch exclusions are forbidden"):
        gate.evaluate_coverage(root, config, 100.0)


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("run:branch", False, "branch measurement must be enabled"),
        ("run:omit", ["core/*"], "omit patterns"),
        ("run:include", ["core/*"], "run include filters"),
        ("report:include", ["core/*"], "report include/omit filters"),
        ("report:omit", ["core/*"], "report include/omit filters"),
    ],
)
def test_evaluate_rejects_configuration_that_can_narrow_production_coverage(
    fake_coverage,
    tmp_path,
    option,
    value,
    message,
):
    root, _source, config = _source_tree(tmp_path)
    fake_coverage.options[option] = value
    with pytest.raises(gate.CoverageGateError, match=message):
        gate.evaluate_coverage(root, config, 100.0)


def test_evaluate_package_regression(monkeypatch, fake_coverage, tmp_path):
    root, source, config = _source_tree(tmp_path)
    fake_coverage.report_values = [90.0, 40.0]
    monkeypatch.setattr(gate, "_package_sources", lambda *_args: [source])
    with pytest.raises(gate.CoverageGateError, match="package coverage regression"):
        gate.evaluate_coverage(root, config, 80.0, package_thresholds=[("core", 50.0)])

    with pytest.raises(gate.CoverageGateError, match="between 0 and 100"):
        gate.evaluate_coverage(
            root,
            config,
            80.0,
            package_thresholds=[("core", math.nan)],
        )


def test_evaluate_full_success_with_package_diff_and_xml(
    monkeypatch,
    fake_coverage,
    tmp_path,
    capsys,
):
    root, source, config = _source_tree(tmp_path)
    xml = root / "coverage.xml"
    data_file = root / "isolated.coverage"
    fake_coverage.report_values = [100.0, 100.0]
    fake_coverage.statements = [1, 2]
    fake_coverage.missing_lines = []
    fake_coverage.branch_values = {1: (2, 2)}
    monkeypatch.setattr(gate, "_package_sources", lambda *_args: [source])
    monkeypatch.setattr(gate, "_changed_python_lines", lambda *_args: {source: {1, 2, 9}})

    total = gate.evaluate_coverage(
        root,
        config,
        100.0,
        xml,
        package_thresholds=[("core", 100.0)],
        diff_base="a" * 40,
        diff_fail_under=100.0,
        data_file=data_file,
    )

    assert total == 100.0
    instance = fake_coverage.instances[-1]
    assert instance.loaded is True
    assert instance.data_file == str(data_file.resolve())
    assert instance.xml_calls
    output = capsys.readouterr().out
    assert "package coverage passed" in output
    assert "diff coverage passed" in output
    assert "2/2 lines, 2/2 branches" in output
    assert "coverage gate passed" in output


def test_evaluate_diff_zero_executable_is_full(monkeypatch, fake_coverage, tmp_path):
    root, source, config = _source_tree(tmp_path)
    fake_coverage.report_values = [100.0]
    fake_coverage.statements = [1]
    monkeypatch.setattr(gate, "_changed_python_lines", lambda *_args: {source: {9}})
    assert (
        gate.evaluate_coverage(
            root,
            config,
            100.0,
            diff_base="a" * 40,
            diff_fail_under=100.0,
        )
        == 100.0
    )


def test_evaluate_diff_regression_and_analysis_error(
    monkeypatch,
    fake_coverage,
    tmp_path,
):
    root, source, config = _source_tree(tmp_path)
    monkeypatch.setattr(gate, "_changed_python_lines", lambda *_args: {source: {1, 2}})
    fake_coverage.report_values = [100.0]
    with pytest.raises(gate.CoverageGateError, match="diff coverage regression"):
        gate.evaluate_coverage(
            root,
            config,
            100.0,
            diff_base="a" * 40,
            diff_fail_under=75.0,
        )

    fake_coverage.report_values = [100.0]
    fake_coverage.analysis_error = CoverageException("cannot parse")
    with pytest.raises(gate.CoverageGateError, match="cannot analyze changed file"):
        gate.evaluate_coverage(root, config, 100.0, diff_base="a" * 40)

    fake_coverage.report_values = [100.0]
    fake_coverage.analysis_error = None
    fake_coverage.branch_error = CoverageException("cannot derive branches")
    with pytest.raises(gate.CoverageGateError, match="cannot analyze changed file"):
        gate.evaluate_coverage(root, config, 100.0, diff_base="a" * 40)


def test_evaluate_diff_rejects_missing_arcs_and_uncovered_changed_branch(
    monkeypatch,
    fake_coverage,
    tmp_path,
):
    root, source, config = _source_tree(tmp_path)
    monkeypatch.setattr(gate, "_changed_python_lines", lambda *_args: {source: {1, 2}})
    fake_coverage.report_values = [100.0]
    fake_coverage.has_arcs = False
    with pytest.raises(gate.CoverageGateError, match="coverage data has no arcs"):
        gate.evaluate_coverage(root, config, 100.0, diff_base="a" * 40)

    fake_coverage.report_values = [100.0]
    fake_coverage.has_arcs = True
    fake_coverage.missing_lines = []
    fake_coverage.branch_values = {1: (2, 1)}
    with pytest.raises(gate.CoverageGateError, match=r"2/2 lines, 1/2 branches"):
        gate.evaluate_coverage(root, config, 100.0, diff_base="a" * 40)

    fake_coverage.report_values = [100.0]
    fake_coverage.branch_values = {1: (10**16, 10**16 - 1)}
    with pytest.raises(gate.CoverageGateError, match="diff coverage regression"):
        gate.evaluate_coverage(
            root,
            config,
            100.0,
            diff_base="a" * 40,
            diff_fail_under=100.0,
        )


def test_real_coverage_data_counts_branch_exits_from_changed_origin_line(
    monkeypatch,
    tmp_path,
    capsys,
):
    root = tmp_path / "repo"
    root.mkdir()
    source = root / "decision.py"
    source.write_text(
        "def choose(flag):\n    if (\n        flag\n    ):\n        return 'yes'\n    return 'no'\n",
        encoding="utf-8",
    )
    config = root / "coverage.ini"
    config.write_text(
        "[run]\n"
        "branch = True\n"
        "omit =\n"
        "    build/*\n"
        "    tests/*\n"
        "    vendor/*\n"
        "    venv/*\n"
        "[report]\n"
        "exclude_lines =\n"
        "partial_branches =\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "_changed_python_lines", lambda *_args: {source: {3}})

    def measure(path, flags):
        measured = Coverage(config_file=str(config), data_file=str(path))
        measured.start()
        namespace = runpy.run_path(str(source))
        for flag in flags:
            namespace["choose"](flag)
        measured.stop()
        measured.save()

    partial_data = root / "partial.coverage"
    measure(partial_data, [True])
    with pytest.raises(
        gate.CoverageGateError,
        match=r"1/1 lines, 1/2 branches",
    ):
        gate.evaluate_coverage(
            root,
            config,
            0.0,
            diff_base="a" * 40,
            diff_fail_under=100.0,
            data_file=partial_data,
        )

    complete_data = root / "complete.coverage"
    measure(complete_data, [True, False])
    assert (
        gate.evaluate_coverage(
            root,
            config,
            0.0,
            diff_base="a" * 40,
            diff_fail_under=100.0,
            data_file=complete_data,
        )
        >= 0.0
    )
    assert "1/1 lines, 2/2 branches" in capsys.readouterr().out


def test_main_resolves_paths_and_handles_success_and_failure(monkeypatch, tmp_path):
    root, _source, config = _source_tree(tmp_path)
    data_file = root / "data.coverage"
    calls = []

    def evaluate(*args, **kwargs):
        calls.append((args, kwargs))
        return 100.0

    monkeypatch.setattr(gate, "evaluate_coverage", evaluate)
    assert (
        gate.main(
            [
                "--root",
                str(root),
                "--config",
                config.name,
                "--data-file",
                data_file.name,
                "--xml",
                str(root / "coverage.xml"),
            ]
        )
        == 0
    )
    assert calls[0][0][1] == config
    assert calls[0][1]["data_file"] == data_file

    assert gate.main(["--root", str(root), "--config", str(config)]) == 0

    monkeypatch.setattr(
        gate,
        "evaluate_coverage",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unreadable")),
    )
    assert gate.main(["--root", str(root), "--config", str(config)]) == 1


def test_script_entrypoint_returns_failure(monkeypatch, tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [gate.__file__, "--root", str(root), "--config", "missing.ini"],
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(gate.__file__, run_name="__main__")
    assert exc.value.code == 1
