#!/usr/bin/env python3
"""Report coverage over every first-party Python file and enforce a floor."""

from __future__ import annotations

import argparse
import io
import os
import re
import subprocess
import sys
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from coverage import Coverage
from coverage.exceptions import CoverageException

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "data",
        "tests",
        "vendor",
        "venv",
    }
)


class CoverageGateError(argparse.ArgumentTypeError):
    """Raised when the complete first-party coverage gate cannot be evaluated."""


def _relative_source(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _package_sources(root: Path, package: str) -> list[Path]:
    normalized = str(package).strip().replace(".", "/").strip("/")
    if not normalized or normalized.startswith(".."):
        raise CoverageGateError(f"invalid package coverage path: {package}")
    package_root = (root / normalized).resolve()
    try:
        package_root.relative_to(root.resolve())
    except ValueError as exc:
        raise CoverageGateError(f"package path escapes repository: {package}") from exc
    sources = [
        item
        for item in discover_first_party_python(root)
        if item == package_root or package_root in item.parents
    ]
    if not sources:
        raise CoverageGateError(f"package coverage path has no Python sources: {package}")
    return sources


def _parse_package_threshold(value: str) -> tuple[str, float]:
    package, separator, raw_threshold = str(value).partition("=")
    if not separator or not package.strip():
        raise CoverageGateError("package threshold must be PACKAGE=PERCENT")
    try:
        threshold = float(raw_threshold)
    except ValueError as exc:
        raise CoverageGateError("package threshold must be numeric") from exc
    if not 0 <= threshold <= 100:
        raise CoverageGateError("package threshold must be between 0 and 100")
    return package.strip(), threshold


def _changed_python_lines(root: Path, base: str) -> dict[Path, set[int]]:
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", str(base or "")):
        raise CoverageGateError("diff coverage base must be a Git commit SHA")
    try:
        completed = subprocess.run(
            [
                "git",
                "diff",
                "--unified=0",
                "--diff-filter=ACMR",
                f"{base}...HEAD",
                "--",
                "*.py",
            ],
            cwd=str(root),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CoverageGateError(f"unable to inspect changed Python lines: {type(exc).__name__}") from exc

    changed: dict[Path, set[int]] = defaultdict(set)
    current: Path | None = None
    allowed = set(discover_first_party_python(root))
    hunk = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
    for line in completed.stdout.splitlines():
        if line.startswith("+++ b/"):
            candidate = (root / line[6:]).resolve()
            current = candidate if candidate in allowed else None
            continue
        match = hunk.match(line)
        if current is None or match is None:
            continue
        start = int(match.group(1))
        count = int(match.group(2) or "1")
        changed[current].update(range(start, start + count))
    return dict(changed)


def _line_data(coverage: Coverage, root: Path, path: Path) -> set[int]:
    data = coverage.get_data()
    relative = _relative_source(root, path)
    return set(data.lines(relative) or data.lines(str(path.resolve())) or ())


def discover_first_party_python(root: Path) -> list[Path]:
    """Return every Python source outside generated, test, venv, and vendor trees."""
    root = root.resolve(strict=True)
    sources = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRECTORIES and not (Path(current) / name).is_symlink()
        )
        current_path = Path(current)
        for file_name in sorted(file_names):
            path = current_path / file_name
            if path.suffix == ".py" and not path.is_symlink():
                sources.append(path)
    if not sources:
        raise CoverageGateError(f"no first-party Python files found below {root}")
    return sorted(sources)


def evaluate_coverage(
    root: Path,
    config_path: Path,
    fail_under: float,
    xml_path: Path | None = None,
    package_thresholds: Sequence[tuple[str, float]] = (),
    diff_base: str = "",
    diff_fail_under: float = 0.0,
    data_file: Path | None = None,
) -> float:
    """Load measured data, report every source, and enforce the exact floor."""
    root = root.resolve(strict=True)
    sources = discover_first_party_python(root)
    coverage_data = root / ".coverage" if data_file is None else data_file
    coverage = Coverage(
        config_file=str(config_path.resolve(strict=True)),
        data_file=str(coverage_data.resolve()),
    )
    coverage.load()
    total = coverage.report(morfs=[str(path) for path in sources], file=sys.stdout)
    if total < fail_under:
        raise CoverageGateError(
            f"coverage regression: {total:.2f}% is below the required {fail_under:.2f}%"
        )
    for package, threshold in package_thresholds:
        package_sources = _package_sources(root, package)
        package_total = coverage.report(
            morfs=[str(path) for path in package_sources],
            file=io.StringIO(),
        )
        if package_total < threshold:
            raise CoverageGateError(
                f"package coverage regression: {package} {package_total:.2f}% "
                f"is below {threshold:.2f}%"
            )
        print(
            f"package coverage passed: {package} "
            f"{package_total:.2f}% >= {threshold:.2f}%"
        )
    if diff_base:
        changed = _changed_python_lines(root, diff_base)
        executable = 0
        covered = 0
        for path, lines in changed.items():
            try:
                _filename, statements, _excluded, _missing, _formatted = coverage.analysis2(
                    str(path)
                )
            except CoverageException as exc:
                raise CoverageGateError(f"cannot analyze changed file {path}: {exc}") from exc
            relevant = set(statements).intersection(lines)
            executable += len(relevant)
            covered += len(relevant.intersection(_line_data(coverage, root, path)))
        diff_total = 100.0 if executable == 0 else 100.0 * covered / executable
        if diff_total < diff_fail_under:
            raise CoverageGateError(
                f"diff coverage regression: {diff_total:.2f}% is below "
                f"{diff_fail_under:.2f}% ({covered}/{executable} lines)"
            )
        print(
            f"diff coverage passed: {diff_total:.2f}% >= "
            f"{diff_fail_under:.2f}% ({covered}/{executable} lines)"
        )
    if xml_path is not None:
        coverage.xml_report(
            morfs=[str(path) for path in sources],
            outfile=str(xml_path.resolve()),
        )
    print(f"coverage gate passed: {total:.2f}% >= {fail_under:.2f}% ({len(sources)} files)")
    return total


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, default=Path("quality/coverage-ci.ini"))
    parser.add_argument("--fail-under", type=float, default=59.50)
    parser.add_argument("--xml", type=Path)
    parser.add_argument(
        "--package-fail-under",
        action="append",
        default=[],
        type=_parse_package_threshold,
        metavar="PACKAGE=PERCENT",
    )
    parser.add_argument("--diff-base", default="")
    parser.add_argument("--diff-fail-under", type=float, default=80.0)
    parser.add_argument("--data-file", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    config_path = args.config
    if not config_path.is_absolute():
        config_path = args.root / config_path
    data_file = args.data_file
    if data_file is not None and not data_file.is_absolute():
        data_file = args.root / data_file
    try:
        evaluate_coverage(
            args.root,
            config_path,
            args.fail_under,
            args.xml,
            package_thresholds=args.package_fail_under,
            diff_base=args.diff_base,
            diff_fail_under=args.diff_fail_under,
            data_file=data_file,
        )
    except (CoverageException, CoverageGateError, OSError) as exc:
        print(f"coverage gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
