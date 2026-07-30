"""Hermetic statement and branch coverage for the Go coverage gate."""

from __future__ import annotations

import math
import runpy
import sys
from pathlib import Path

import pytest

from scripts.quality import go_coverage_gate as gate

pytestmark = pytest.mark.contract


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _repo(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    source = _write(root / "pkg" / "main.go", "package main\nfunc main() {}\n")
    _write(root / "pkg" / "go.mod", "module example.test/demo\n\ngo 1.21\n")
    return root, source


def _profile(
    path: Path,
    rows: list[str],
    *,
    mode: str = "set",
    newline: str = "\n",
) -> Path:
    return _write(path, newline.join([f"mode: {mode}", *rows]) + newline)


def test_discovery_is_sorted_and_excludes_nonproduction_trees(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    expected = [
        _write(root / "a.go", "package root\n"),
        _write(root / "data" / "generated.go", "package data\n"),
        _write(root / "z" / "last.go", "package z\n"),
    ]
    _write(root / "a_test.go", "package root\n")
    _write(root / "notes.txt", "not Go")
    for excluded in ("build", "tests", "vendor", "venv", ".pytest_cache"):
        _write(root / excluded / "hidden.go", "package hidden\n")

    assert gate.discover_first_party_go(root) == expected


def test_discovery_rejects_empty_and_included_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(gate.GoCoverageGateError, match="no first-party Go"):
        gate.discover_first_party_go(root)

    source = _write(root / "source.go", "package root\n")
    linked_source = root / "linked.go"
    linked_source.symlink_to(source)
    with pytest.raises(gate.GoCoverageGateError, match="Go source is a symlink"):
        gate.discover_first_party_go(root)
    linked_source.unlink()

    linked_directory = root / "linked"
    linked_directory.symlink_to(root, target_is_directory=True)
    with pytest.raises(gate.GoCoverageGateError, match="source directory is a symlink"):
        gate.discover_first_party_go(root)


def test_module_discovery_accepts_comments_quotes_and_inline_comment(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _write(root / "one" / "go.mod", '// comment\nmodule "example.test/one" // owner\ngo 1.21\n')
    _write(root / "two" / "go.mod", "module example.test/two\n")
    _write(root / "ignored" / "notes.txt", "none")

    assert gate.discover_go_modules(root) == {
        "example.test/one": (root / "one").resolve(),
        "example.test/two": (root / "two").resolve(),
    }


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("go 1.21\n", "missing module"),
        ("module one\nmodule two\n", "duplicate module"),
        ("module\n", "invalid module"),
        ('module "unterminated\n', "invalid module"),
        ("module /absolute\n", "invalid module"),
        ("module example.test//bad\n", "invalid module"),
        ("module example.test/bad/\n", "invalid module"),
        ("module example.test\\bad\n", "invalid module"),
        ("module example.test/../bad\n", "invalid module"),
        ("module \x00bad\n", "invalid module"),
    ],
)
def test_module_discovery_rejects_invalid_declarations(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    root = tmp_path / "repo"
    _write(root / "pkg" / "go.mod", content)
    with pytest.raises(gate.GoCoverageGateError, match=message):
        gate.discover_go_modules(root)


def test_module_discovery_rejects_duplicate_paths_symlink_and_invalid_utf8(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    first = _write(root / "one" / "go.mod", "module example.test/same\n")
    _write(root / "two" / "go.mod", "module example.test/same\n")
    with pytest.raises(gate.GoCoverageGateError, match="duplicate Go module path"):
        gate.discover_go_modules(root)

    (root / "two" / "go.mod").unlink()
    linked = root / "two" / "go.mod"
    linked.symlink_to(first)
    with pytest.raises(gate.GoCoverageGateError, match=r"go\.mod is a symlink"):
        gate.discover_go_modules(root)

    linked.unlink()
    _write(root / "two" / "go.mod", b"module \xff\n")
    with pytest.raises(
        gate.GoCoverageGateError,
        match=r"cannot read first-party go\.mod",
    ):
        gate.discover_go_modules(root)


def test_parser_accepts_module_alias_repo_relative_absolute_and_all_modes(
    tmp_path: Path,
) -> None:
    root, source = _repo(tmp_path)
    second = _write(root / "pkg" / "second.go", "package main\nfunc second() {}\n")
    third = _write(root / "pkg" / "third.go", "package main\nfunc third() {}\n")
    profiles = [
        _profile(
            tmp_path / "set.out",
            [
                "example.test/demo/main.go:1.1,1.5 1 1",
                "coreless-placeholder:1.1,1.2 0 0",
            ],
        ),
    ]
    # Replace the placeholder with an exact repository-relative path.
    profiles[0].write_text(
        profiles[0].read_text(encoding="utf-8").replace("coreless-placeholder", second.relative_to(root).as_posix()),
        encoding="utf-8",
    )
    absolute = str(third.resolve())
    profiles.append(_profile(tmp_path / "absolute.out", [f"{absolute}:1.1,1.5 1 1"]))

    mode, blocks = gate.parse_coverprofiles(root, profiles)
    assert mode == "set"
    assert set(blocks) == {source.resolve(), second.resolve(), third.resolve()}
    assert blocks[third.resolve()][0].count == 1


def test_parser_accepts_count_atomic_crlf_duplicates_and_adjacent_blocks(
    tmp_path: Path,
) -> None:
    root, source = _repo(tmp_path)
    first = _profile(
        tmp_path / "one.out",
        [
            "example.test/demo/main.go:1.1,1.5 2 3",
            "example.test/demo/main.go:1.5,2.1 0 0",
        ],
        mode="atomic",
        newline="\r\n",
    )
    second = _profile(
        tmp_path / "two.out",
        ["example.test/demo/main.go:1.1,1.5 2 4"],
        mode="atomic",
    )

    mode, blocks = gate.parse_coverprofiles(root, [first, second])
    assert mode == "atomic"
    assert blocks[source.resolve()][0].count == 7
    assert blocks[source.resolve()][1].statements == 0

    count_profile = _profile(
        tmp_path / "count.out",
        ["example.test/demo/main.go:1.1,2.1 1 9"],
        mode="count",
    )
    assert gate.parse_coverprofiles(root, [count_profile])[0] == "count"


def test_set_duplicate_uses_maximum_execution_count(tmp_path: Path) -> None:
    root, source = _repo(tmp_path)
    profile = _profile(
        tmp_path / "set.out",
        [
            "example.test/demo/main.go:1.1,2.1 1 0",
            "example.test/demo/main.go:1.1,2.1 1 1",
        ],
    )
    _mode, blocks = gate.parse_coverprofiles(root, [profile])
    assert blocks[source.resolve()][0].count == 1


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([""], "malformed"),
        (["not a profile row"], "malformed"),
        (["example.test/demo/main.go:0.1,1.2 1 0"], "invalid Go coverage block"),
        (["example.test/demo/main.go:1.0,1.2 1 0"], "invalid Go coverage block"),
        (["example.test/demo/main.go:1.1,2.0 1 0"], "invalid Go coverage block"),
        (["example.test/demo/main.go:2.1,1.2 1 0"], "invalid Go coverage block"),
        (["example.test/demo/main.go:1.1,1.2 1 2"], "invalid set-mode"),
        (["missing.go:1.1,1.2 1 0"], "unknown Go source"),
        (["../pkg/main.go:1.1,1.2 1 0"], "invalid coverprofile source"),
        (["./pkg/main.go:1.1,1.2 1 0"], "invalid coverprofile source"),
        (["pkg//main.go:1.1,1.2 1 0"], "invalid coverprofile source"),
        (["pkg\\main.go:1.1,1.2 1 0"], "invalid coverprofile source"),
        (["pkg/./main.go:1.1,1.2 1 0"], "invalid coverprofile source"),
        (["pkg/main.go\x00:1.1,1.2 1 0"], "invalid coverprofile source"),
    ],
)
def test_parser_rejects_malformed_rows_and_paths(
    tmp_path: Path,
    rows: list[str],
    message: str,
) -> None:
    root, _source = _repo(tmp_path)
    profile = _profile(tmp_path / "bad.out", rows)
    with pytest.raises(gate.GoCoverageGateError, match=message):
        gate.parse_coverprofiles(root, [profile])


def test_parser_rejects_missing_bad_and_inconsistent_headers(tmp_path: Path) -> None:
    root, _source = _repo(tmp_path)
    with pytest.raises(gate.GoCoverageGateError, match="at least one"):
        gate.parse_coverprofiles(root, [])

    for content, message in (
        ("", "missing mode"),
        ("not-mode\n", "missing mode"),
        ("mode: branch\n", "unsupported"),
    ):
        profile = _write(tmp_path / f"bad-{len(content)}.out", content)
        with pytest.raises(gate.GoCoverageGateError, match=message):
            gate.parse_coverprofiles(root, [profile])

    first = _profile(
        tmp_path / "set.out",
        ["example.test/demo/main.go:1.1,1.2 1 1"],
    )
    second = _profile(
        tmp_path / "count.out",
        ["example.test/demo/main.go:1.1,1.2 1 1"],
        mode="count",
    )
    with pytest.raises(gate.GoCoverageGateError, match="inconsistent"):
        gate.parse_coverprofiles(root, [first, second])


def test_parser_rejects_unreadable_symlink_and_invalid_utf8_profile(tmp_path: Path) -> None:
    root, _source = _repo(tmp_path)
    missing = tmp_path / "missing.out"
    with pytest.raises(gate.GoCoverageGateError, match="cannot read Go coverprofile"):
        gate.parse_coverprofiles(root, [missing])

    target = _profile(
        tmp_path / "target.out",
        ["example.test/demo/main.go:1.1,1.2 1 1"],
    )
    linked = tmp_path / "linked.out"
    linked.symlink_to(target)
    with pytest.raises(gate.GoCoverageGateError, match="coverprofile is a symlink"):
        gate.parse_coverprofiles(root, [linked])

    invalid = _write(tmp_path / "invalid.out", b"mode: set\n\xff")
    with pytest.raises(gate.GoCoverageGateError, match="cannot read Go coverprofile"):
        gate.parse_coverprofiles(root, [invalid])


def test_parser_requires_module_ownership_and_every_source(tmp_path: Path) -> None:
    root, _source = _repo(tmp_path)
    orphan = _write(root / "orphan.go", "package orphan\n")
    profile = _profile(
        tmp_path / "profile.out",
        [
            "example.test/demo/main.go:1.1,1.2 1 1",
            f"{orphan.relative_to(root).as_posix()}:1.1,1.2 1 1",
        ],
    )
    with pytest.raises(gate.GoCoverageGateError, match="outside every Go module"):
        gate.parse_coverprofiles(root, [profile])

    orphan.unlink()
    second = _write(root / "pkg" / "second.go", "package main\n")
    _profile(
        profile,
        ["example.test/demo/main.go:1.1,1.2 1 1"],
    )
    with pytest.raises(gate.GoCoverageGateError, match="missing from coverprofiles"):
        gate.parse_coverprofiles(root, [profile])
    assert second.exists()


def test_parser_rejects_conflicts_overlap_ambiguity_and_external_paths(
    tmp_path: Path,
) -> None:
    root, _source = _repo(tmp_path)
    conflict = _profile(
        tmp_path / "conflict.out",
        [
            "example.test/demo/main.go:1.1,2.1 1 1",
            "example.test/demo/main.go:1.1,2.1 2 1",
        ],
    )
    with pytest.raises(gate.GoCoverageGateError, match="conflicting Go statement"):
        gate.parse_coverprofiles(root, [conflict])

    overlap = _profile(
        tmp_path / "overlap.out",
        [
            "example.test/demo/main.go:1.1,2.2 1 1",
            "example.test/demo/main.go:2.1,3.1 1 1",
        ],
    )
    with pytest.raises(gate.GoCoverageGateError, match="overlapping Go coverage"):
        gate.parse_coverprofiles(root, [overlap])

    outside = _write(tmp_path / "outside.go", "package outside\n")
    external = _profile(
        tmp_path / "external.out",
        [f"{outside.resolve()}:1.1,1.2 1 1"],
    )
    with pytest.raises(gate.GoCoverageGateError, match="unknown Go source"):
        gate.parse_coverprofiles(root, [external])

    # The same raw path can mean a repository path and a nested module alias.
    _write(root / "go.mod", "module root.test/repo\n")
    _write(root / "example.test" / "demo" / "go.mod", "module pkg\n")
    _write(root / "example.test" / "demo" / "main.go", "package nested\n")
    ambiguous = _profile(tmp_path / "ambiguous.out", ["pkg/main.go:1.1,1.2 1 1"])
    with pytest.raises(gate.GoCoverageGateError, match="ambiguous"):
        gate.parse_coverprofiles(root, [ambiguous])


def test_evaluate_weights_statements_and_enforces_exact_threshold(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, _source = _repo(tmp_path)
    profile = _profile(
        tmp_path / "profile.out",
        [
            "example.test/demo/main.go:1.1,1.2 9 7",
            "example.test/demo/main.go:1.2,2.1 1 0",
        ],
        mode="count",
    )

    result = gate.evaluate_go_coverage(root, [profile], 90.0)
    assert result == gate.CoverageResult(9, 10, 90.0)
    assert "9/10 statements (90.00%)" in capsys.readouterr().out

    with pytest.raises(gate.GoCoverageGateError, match="coverage regression"):
        gate.evaluate_go_coverage(root, [profile], 100.0)

    huge = _profile(
        tmp_path / "huge.out",
        [
            "example.test/demo/main.go:1.1,1.2 9999999999999999 1",
            "example.test/demo/main.go:1.2,2.1 1 0",
        ],
        mode="count",
    )
    with pytest.raises(gate.GoCoverageGateError, match="coverage regression"):
        gate.evaluate_go_coverage(root, [huge], 100.0)


def test_evaluate_zero_statements_invalid_thresholds_and_success_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, _source = _repo(tmp_path)
    zero = _profile(
        tmp_path / "zero.out",
        ["example.test/demo/main.go:1.1,2.1 0 0"],
    )
    with pytest.raises(gate.GoCoverageGateError, match="no executable statements"):
        gate.evaluate_go_coverage(root, [zero])

    zero_source = _write(root / "pkg" / "zero.go", "package main\n")
    full = _profile(
        tmp_path / "full.out",
        [
            "example.test/demo/main.go:1.1,2.1 2 1",
            "example.test/demo/zero.go:1.1,1.2 0 0",
        ],
    )
    result = gate.evaluate_go_coverage(root, [full])
    assert result.percent == 100.0
    output = capsys.readouterr().out
    assert "Go coverage gate passed: 100.00%" in output
    assert f"{zero_source.relative_to(root).as_posix()}: 0/0 statements (100.00%)" in output

    for threshold in (-1.0, 101.0, math.inf, math.nan):
        with pytest.raises(gate.GoCoverageGateError, match="between 0 and 100"):
            gate.evaluate_go_coverage(root, [full], threshold)


def test_cli_contract_main_results_and_module_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, _source = _repo(tmp_path)
    profile = _profile(
        root / "profile.out",
        ["example.test/demo/main.go:1.1,2.1 1 1"],
    )
    parser = gate._argument_parser()
    args = parser.parse_args(["--profile", "one", "--profile", "two"])
    assert args.profile == [Path("one"), Path("two")]
    assert args.fail_under == 100.0
    with pytest.raises(SystemExit):
        parser.parse_args([])

    assert gate.main(["--root", str(root), "--profile", "profile.out"]) == 0
    assert gate.main(["--root", str(root), "--profile", "missing.out"]) == 1
    assert "Go coverage gate failed:" in capsys.readouterr().err
    assert gate.main(["--root", str(root / "missing"), "--profile", "profile.out"]) == 1

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "go_coverage_gate.py",
            "--root",
            str(root),
            "--profile",
            str(profile),
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(gate.__file__, run_name="__main__")
    assert exc_info.value.code == 0
