#!/usr/bin/env python3
"""Fail closed unless every first-party Go source has complete statement coverage."""

from __future__ import annotations

import argparse
import math
import os
import re
import shlex
import sys
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import NamedTuple

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
        "tests",
        "vendor",
        "venv",
    }
)
_PROFILE_ROW = re.compile(
    r"^(?P<source>.+):(?P<start_line>\d+)\.(?P<start_column>\d+),"
    r"(?P<end_line>\d+)\.(?P<end_column>\d+) "
    r"(?P<statements>\d+) (?P<count>\d+)$"
)
_VALID_MODES = frozenset({"atomic", "count", "set"})


class GoCoverageGateError(ValueError):
    """The complete first-party Go coverage gate cannot be evaluated."""


class Position(NamedTuple):
    line: int
    column: int


@dataclass(frozen=True)
class CoverageBlock:
    """One basic block from a Go coverprofile."""

    source: Path
    start: Position
    end: Position
    statements: int
    count: int


@dataclass(frozen=True)
class CoverageResult:
    """Aggregated first-party Go statement coverage."""

    covered_statements: int
    total_statements: int
    percent: float


def _walk_first_party(root: Path):
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        included_directories = []
        for name in sorted(directory_names):
            if name in _EXCLUDED_DIRECTORIES:
                continue
            directory = current_path / name
            if directory.is_symlink():
                raise GoCoverageGateError(f"first-party source directory is a symlink: {directory}")
            included_directories.append(name)
        directory_names[:] = included_directories
        yield current_path, sorted(file_names)


def discover_first_party_go(root: Path) -> list[Path]:
    """Return every production Go source outside test, generated, and vendor trees."""
    root = root.resolve(strict=True)
    sources = []
    for current_path, file_names in _walk_first_party(root):
        for file_name in file_names:
            path = current_path / file_name
            if path.suffix != ".go" or path.name.endswith("_test.go"):
                continue
            if path.is_symlink():
                raise GoCoverageGateError(f"first-party Go source is a symlink: {path}")
            sources.append(path.resolve(strict=True))
    if not sources:
        raise GoCoverageGateError(f"no first-party Go files found below {root}")
    return sorted(sources)


def discover_go_modules(root: Path) -> dict[str, Path]:
    """Map every checked-in Go module path to its repository directory."""
    root = root.resolve(strict=True)
    modules: dict[str, Path] = {}
    for current_path, file_names in _walk_first_party(root):
        if "go.mod" not in file_names:
            continue
        go_mod = current_path / "go.mod"
        if go_mod.is_symlink():
            raise GoCoverageGateError(f"first-party go.mod is a symlink: {go_mod}")
        try:
            raw_lines = go_mod.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise GoCoverageGateError(f"cannot read first-party go.mod {go_mod}: {exc}") from exc
        declarations = []
        for raw_line in raw_lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            declaration = re.split(r"\s+//", stripped, maxsplit=1)[0].strip()
            if "\\" in declaration or "\x00" in declaration:
                raise GoCoverageGateError(f"invalid module declaration in {go_mod}")
            try:
                fields = shlex.split(declaration)
            except ValueError as exc:
                raise GoCoverageGateError(f"invalid module declaration in {go_mod}") from exc
            if fields and fields[0] == "module":
                if len(fields) != 2 or not fields[1].strip():
                    raise GoCoverageGateError(f"invalid module declaration in {go_mod}")
                declarations.append(fields[1].strip())
        if len(declarations) != 1:
            qualifier = "missing" if not declarations else "duplicate"
            raise GoCoverageGateError(f"{qualifier} module declaration in {go_mod}")
        module_path = declarations[0]
        module_parts = PurePosixPath(module_path).parts
        if (
            module_path.startswith("/")
            or module_path.endswith("/")
            or "\\" in module_path
            or "//" in module_path
            or "\x00" in module_path
            or any(part in {"", ".", ".."} for part in module_parts)
        ):
            raise GoCoverageGateError(f"invalid module declaration in {go_mod}")
        if module_path in modules:
            raise GoCoverageGateError(f"duplicate Go module path: {module_path}")
        modules[module_path] = current_path.resolve(strict=True)
    return modules


def _validate_source_ownership(
    root: Path,
    sources: set[Path],
    modules: dict[str, Path],
) -> None:
    module_roots = tuple(modules.values())
    for source in sorted(sources):
        owners = [
            module_root for module_root in module_roots if module_root == source.parent or module_root in source.parents
        ]
        if not owners:
            raise GoCoverageGateError(
                f"first-party Go source is outside every Go module: {source.relative_to(root).as_posix()}"
            )


def _resolve_profile_source(
    root: Path,
    raw_source: str,
    sources: set[Path],
    modules: dict[str, Path],
) -> Path:
    normalized = raw_source
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or "\\" in normalized
        or "\x00" in normalized
        or normalized.startswith("./")
        or "//" in normalized
        or "/./" in normalized
        or normalized.endswith("/.")
        or ".." in pure.parts
    ):
        raise GoCoverageGateError(f"invalid coverprofile source path: {raw_source}")

    candidates = []
    direct = Path(normalized)
    if direct.is_absolute():
        candidates.append(direct)
    else:
        candidates.append(root / direct)
        for module_path, module_root in sorted(modules.items(), key=lambda item: len(item[0]), reverse=True):
            prefix = f"{module_path}/"
            if normalized.startswith(prefix):
                candidates.append(module_root / normalized[len(prefix) :])

    matches = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved in sources:
            matches.add(resolved)
    if len(matches) > 1:
        raise GoCoverageGateError(f"ambiguous coverprofile source path: {raw_source}")
    if matches:
        return matches.pop()
    raise GoCoverageGateError(f"coverprofile references unknown Go source: {raw_source}")


def parse_coverprofiles(
    root: Path,
    profiles: list[Path],
) -> tuple[str, dict[Path, list[CoverageBlock]]]:
    """Parse and validate standard Go coverprofiles against repository sources."""
    root = root.resolve(strict=True)
    if not profiles:
        raise GoCoverageGateError("at least one Go coverprofile is required")
    sources = set(discover_first_party_go(root))
    modules = discover_go_modules(root)
    _validate_source_ownership(root, sources, modules)
    mode = ""
    blocks: dict[Path, list[CoverageBlock]] = {source: [] for source in sources}

    for supplied_profile in profiles:
        profile = supplied_profile
        if not profile.is_absolute():
            profile = root / profile
        if profile.is_symlink():
            raise GoCoverageGateError(f"Go coverprofile is a symlink: {profile}")
        try:
            lines = profile.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise GoCoverageGateError(f"cannot read Go coverprofile {profile}: {exc}") from exc
        if not lines or not lines[0].startswith("mode: "):
            raise GoCoverageGateError(f"missing mode header in Go coverprofile: {profile}")
        profile_mode = lines[0][len("mode: ") :].strip()
        if profile_mode not in _VALID_MODES:
            raise GoCoverageGateError(f"unsupported Go coverage mode {profile_mode!r} in {profile}")
        if mode and profile_mode != mode:
            raise GoCoverageGateError(f"inconsistent Go coverage modes: {mode!r} and {profile_mode!r}")
        mode = profile_mode

        for line_number, row in enumerate(lines[1:], start=2):
            if not row.strip():
                raise GoCoverageGateError(f"malformed Go coverprofile row {profile}:{line_number}")
            match = _PROFILE_ROW.fullmatch(row)
            if match is None:
                raise GoCoverageGateError(f"malformed Go coverprofile row {profile}:{line_number}")
            source = _resolve_profile_source(
                root,
                match.group("source"),
                sources,
                modules,
            )
            start = Position(
                int(match.group("start_line")),
                int(match.group("start_column")),
            )
            end = Position(
                int(match.group("end_line")),
                int(match.group("end_column")),
            )
            statements = int(match.group("statements"))
            count = int(match.group("count"))
            if start.line < 1 or start.column < 1 or end.line < 1 or end.column < 1 or end <= start:
                raise GoCoverageGateError(f"invalid Go coverage block range {profile}:{line_number}")
            if profile_mode == "set" and count not in {0, 1}:
                raise GoCoverageGateError(f"invalid set-mode execution count {profile}:{line_number}")
            blocks[source].append(
                CoverageBlock(
                    source=source,
                    start=start,
                    end=end,
                    statements=statements,
                    count=count,
                )
            )

    for source, source_blocks in blocks.items():
        if not source_blocks:
            relative = source.relative_to(root).as_posix()
            raise GoCoverageGateError(f"Go source is missing from coverprofiles: {relative}")
        merged: dict[tuple[Position, Position], CoverageBlock] = {}
        for block in source_blocks:
            span = (block.start, block.end)
            previous = merged.get(span)
            if previous is None:
                merged[span] = block
                continue
            if previous.statements != block.statements:
                relative = source.relative_to(root).as_posix()
                raise GoCoverageGateError(
                    f"conflicting Go statement counts for {relative}: {previous.statements} and {block.statements}"
                )
            combined_count = max(previous.count, block.count) if mode == "set" else previous.count + block.count
            merged[span] = CoverageBlock(
                source=source,
                start=block.start,
                end=block.end,
                statements=block.statements,
                count=combined_count,
            )
        ordered = sorted(merged.values(), key=lambda block: (block.start, block.end))
        for previous, current in zip(ordered, ordered[1:]):
            if current.start < previous.end:
                relative = source.relative_to(root).as_posix()
                raise GoCoverageGateError(
                    f"overlapping Go coverage blocks for {relative}: "
                    f"{previous.start}-{previous.end} and {current.start}-{current.end}"
                )
        blocks[source] = ordered
    return mode, blocks


def evaluate_go_coverage(
    root: Path,
    profiles: list[Path],
    fail_under: float = 100.0,
) -> CoverageResult:
    """Aggregate first-party Go statement coverage and enforce an exact floor."""
    if not math.isfinite(fail_under) or not 0 <= fail_under <= 100:
        raise GoCoverageGateError("Go coverage threshold must be between 0 and 100")
    root = root.resolve(strict=True)
    _mode, blocks = parse_coverprofiles(root, profiles)
    total = sum(block.statements for source_blocks in blocks.values() for block in source_blocks)
    covered = sum(block.statements for source_blocks in blocks.values() for block in source_blocks if block.count > 0)
    if total < 1:
        raise GoCoverageGateError("Go coverprofiles contain no executable statements")
    percent = 100.0 * covered / total

    for source in sorted(blocks):
        source_blocks = blocks[source]
        source_total = sum(block.statements for block in source_blocks)
        source_covered = sum(block.statements for block in source_blocks if block.count > 0)
        source_percent = 100.0 if source_total == 0 else 100.0 * source_covered / source_total
        print(
            f"{source.relative_to(root).as_posix()}: {source_covered}/{source_total} statements ({source_percent:.2f}%)"
        )
    required = Decimal(str(fail_under)) * Decimal(total)
    measured = Decimal(covered) * Decimal(100)
    if measured < required:
        raise GoCoverageGateError(
            f"Go coverage regression: {percent:.2f}% is below "
            f"the required {fail_under:.2f}% ({covered}/{total} statements)"
        )
    print(
        f"Go coverage gate passed: {percent:.2f}% >= {fail_under:.2f}% "
        f"({covered}/{total} statements, {len(blocks)} files)"
    )
    return CoverageResult(covered, total, percent)


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--profile",
        action="append",
        required=True,
        type=Path,
        help="Go coverprofile; repeat for multiple modules",
    )
    parser.add_argument("--fail-under", type=float, default=100.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        evaluate_go_coverage(args.root, args.profile, args.fail_under)
    except (GoCoverageGateError, OSError) as exc:
        print(f"Go coverage gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
