#!/usr/bin/env python3
"""Apply the Python formatter ratchet to files changed from a Git base."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

_EXCLUDED_PARTS = {"data", "tests/fixtures", "vendor", "venv"}


class FormatGateError(RuntimeError):
    """The diff or formatter could not be evaluated safely."""


def changed_python_files(root: Path, base: str) -> tuple[Path, ...]:
    """Return tracked changed Python files contained by *root*."""

    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", str(base or "")):
        raise FormatGateError("format base must be a Git commit SHA")
    root = root.resolve(strict=True)
    try:
        completed = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
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
        raise FormatGateError(f"cannot enumerate changed files: {type(exc).__name__}") from exc

    result: list[Path] = []
    for relative in completed.stdout.splitlines():
        normalized = relative.strip().replace("\\", "/")
        if not normalized or any(
            normalized == part or normalized.startswith(f"{part}/")
            for part in _EXCLUDED_PARTS
        ):
            continue
        candidate = (root / normalized).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise FormatGateError(f"changed path escapes repository: {relative}") from exc
        if candidate.is_file() and candidate.suffix == ".py":
            result.append(candidate)
    return tuple(sorted(set(result)))


def run_format_gate(root: Path, base: str, *, ruff: str) -> int:
    files = changed_python_files(root, base)
    if not files:
        print("format gate passed: no changed Python files")
        return 0
    completed = subprocess.run(
        [ruff, "format", "--check", *[str(path) for path in files]],
        cwd=str(root),
        check=False,
    )
    if completed.returncode:
        raise FormatGateError(f"ruff format rejected {len(files)} changed files")
    print(f"format gate passed: {len(files)} changed Python files")
    return 0


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--ruff", default="ruff")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        return run_format_gate(args.root, args.base, ruff=args.ruff)
    except (FormatGateError, OSError) as exc:
        print(f"format gate failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
