#!/usr/bin/env python3
"""Report coverage over every first-party Python file and enforce a floor."""

from __future__ import annotations

import argparse
import os
import sys
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
        "data",
        "tests",
        "vendor",
        "venv",
    }
)


class CoverageGateError(RuntimeError):
    """Raised when the complete first-party coverage gate cannot be evaluated."""


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
) -> float:
    """Load measured data, report every source, and enforce the exact floor."""
    root = root.resolve(strict=True)
    sources = discover_first_party_python(root)
    coverage = Coverage(
        config_file=str(config_path.resolve(strict=True)),
        data_file=str(root / ".coverage"),
    )
    coverage.load()
    total = coverage.report(morfs=[str(path) for path in sources], file=sys.stdout)
    if total < fail_under:
        raise CoverageGateError(
            f"coverage regression: {total:.2f}% is below the required {fail_under:.2f}%"
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
    parser.add_argument("--fail-under", type=float, default=42.70)
    parser.add_argument("--xml", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    config_path = args.config
    if not config_path.is_absolute():
        config_path = args.root / config_path
    try:
        evaluate_coverage(args.root, config_path, args.fail_under, args.xml)
    except (CoverageException, CoverageGateError, OSError) as exc:
        print(f"coverage gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
