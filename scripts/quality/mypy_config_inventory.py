#!/usr/bin/env python3
"""Inventory live mypy configuration consumers.

The migration removes the legacy leaf configuration and routes operator and CI
commands through ``scripts/quality/mypy_gate.py``. This module deliberately
uses a small lexical classifier: an unrecognised live command is an error, not
an implicitly allowed consumer.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LEGACY_CONFIG_PATH = "quality/mypy-import-aware.ini"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
PLAN_PATH = "docs/architecture/typed-providers-implementation-plan-v6.13.md"
INVENTORY_IMPLEMENTATION_PATH = "scripts/quality/mypy_config_inventory.py"
CANONICAL_CI_ENTRYPOINT = "python scripts/quality/mypy_gate.py check"

_IGNORED_PARTS = frozenset(
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
        "dist",
        "generated",
        "node_modules",
        "vendor",
        "venv",
    }
)
_TEXT_SUFFIXES = frozenset(
    {
        ".cfg",
        ".ini",
        ".json",
        ".md",
        ".py",
        ".pyi",
        ".rst",
        ".sh",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)
_TEXT_NAMES = frozenset({"Dockerfile", "Makefile"})

_DIRECT_MYPY_RE = re.compile(
    r"(?:"
    r"(?:^|[\s`$])(?:[A-Za-z0-9_.-]+/)*python(?:3(?:\.\d+)?)?\s+(?:-[A-Za-z]+\s+)*-m\s+mypy\b"
    r"|"
    r"(?:^|\brun:\s+|[`$]\s*|[;&|]\s*)mypy\s+(?=(?:--|[./]))"
    r")",
    re.IGNORECASE,
)
_GATE_CHECK_RE = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)*python(?:3(?:\.\d+)?)?\s+"
    r"scripts/quality/mypy_gate\.py\s+check(?=\s|`|$)",
)
_GATE_COMMAND_RE = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)*python(?:3(?:\.\d+)?)?\s+"
    r"scripts/quality/mypy_gate\.py\s+([a-z][a-z-]*)\b",
)
_FOLLOW_IMPORTS_RE = re.compile(r"\bfollow_imports\b")
_IGNORE_MISSING_IMPORTS_RE = re.compile(r"\bignore_missing_imports\b")


class ReferenceKind(str, Enum):
    LEGACY_CONFIG = "legacy_config"
    DIRECT_MYPY = "direct_mypy"
    GATE_CHECK = "gate_check"
    FOLLOW_IMPORTS = "follow_imports"
    IGNORE_MISSING_IMPORTS = "ignore_missing_imports"


class ReferenceClassification(str, Enum):
    LIVE_CONSUMER = "live_consumer"
    NORMATIVE_EVIDENCE = "normative_evidence"
    IMPLEMENTATION_EVIDENCE = "implementation_evidence"
    CONFIGURATION_EVIDENCE = "configuration_evidence"


@dataclass(frozen=True, order=True)
class MypyConfigReference:
    path: str
    line: int
    kind: ReferenceKind
    classification: ReferenceClassification
    text: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "kind": self.kind.value,
            "classification": self.classification.value,
            "text": self.text,
        }


@dataclass(frozen=True)
class MypyConfigInventory:
    references: tuple[MypyConfigReference, ...]
    violations: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.violations

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "references": [reference.as_dict() for reference in self.references],
            "violations": list(self.violations),
        }


def _is_text_candidate(relative_path: Path) -> bool:
    if any(part in _IGNORED_PARTS for part in relative_path.parts):
        return False
    return relative_path.suffix.lower() in _TEXT_SUFFIXES or relative_path.name in _TEXT_NAMES


def _iter_text_files(root_dir: Path) -> Iterable[tuple[str, Path]]:
    for path in sorted(root_dir.rglob("*"), key=lambda candidate: candidate.as_posix()):
        if not path.is_symlink() and not path.is_file():
            continue
        relative_path = path.relative_to(root_dir)
        if _is_text_candidate(relative_path):
            yield relative_path.as_posix(), path


def _classification(path: str, kind: ReferenceKind) -> ReferenceClassification:
    if path == PLAN_PATH:
        return ReferenceClassification.NORMATIVE_EVIDENCE
    if path == INVENTORY_IMPLEMENTATION_PATH:
        return ReferenceClassification.IMPLEMENTATION_EVIDENCE
    if kind in {ReferenceKind.LEGACY_CONFIG, ReferenceKind.DIRECT_MYPY}:
        return ReferenceClassification.LIVE_CONSUMER
    return ReferenceClassification.CONFIGURATION_EVIDENCE


def _line_references(path: str, line_number: int, line: str) -> list[MypyConfigReference]:
    stripped = line.strip()
    matches: list[tuple[ReferenceKind, bool]] = [
        (ReferenceKind.LEGACY_CONFIG, LEGACY_CONFIG_PATH in line),
        (ReferenceKind.DIRECT_MYPY, _DIRECT_MYPY_RE.search(line) is not None),
        (ReferenceKind.GATE_CHECK, _GATE_CHECK_RE.search(line) is not None),
        (ReferenceKind.FOLLOW_IMPORTS, _FOLLOW_IMPORTS_RE.search(line) is not None),
        (
            ReferenceKind.IGNORE_MISSING_IMPORTS,
            _IGNORE_MISSING_IMPORTS_RE.search(line) is not None,
        ),
    ]
    return [
        MypyConfigReference(
            path=path,
            line=line_number,
            kind=kind,
            classification=_classification(path, kind),
            text=stripped,
        )
        for kind, matched in matches
        if matched
    ]


def inventory_repository(root_dir: Path = PROJECT_ROOT) -> MypyConfigInventory:
    """Return a deterministic inventory and all fail-closed violations."""

    root_dir = root_dir.resolve()
    references: list[MypyConfigReference] = []
    violations: list[str] = []

    if not root_dir.is_dir():
        return MypyConfigInventory((), (f"repository root is not a directory: {root_dir}",))

    for relative_path, path in _iter_text_files(root_dir):
        if path.is_symlink():
            violations.append(f"inventory candidate must not be a symlink: {relative_path}")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            violations.append(f"cannot read inventory candidate {relative_path}: {type(exc).__name__}")
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            references.extend(_line_references(relative_path, line_number, line))

    legacy_file = root_dir / LEGACY_CONFIG_PATH
    if legacy_file.exists() or legacy_file.is_symlink():
        violations.append(f"deleted legacy mypy config still exists: {LEGACY_CONFIG_PATH}")

    for reference in references:
        if reference.classification is not ReferenceClassification.LIVE_CONSUMER:
            continue
        if reference.kind is ReferenceKind.LEGACY_CONFIG:
            violations.append(f"stale legacy mypy config consumer: {reference.path}:{reference.line}")
        elif reference.kind is ReferenceKind.DIRECT_MYPY:
            violations.append(
                f"direct mypy consumer bypasses the repository gate: {reference.path}:{reference.line}"
            )

    workflow_path = root_dir / CI_WORKFLOW_PATH
    if not workflow_path.is_file():
        violations.append(f"missing CI workflow: {CI_WORKFLOW_PATH}")
    else:
        try:
            workflow = workflow_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            violations.append(f"cannot read CI workflow {CI_WORKFLOW_PATH}: {type(exc).__name__}")
        else:
            gate_commands = [match.group(1) for match in _GATE_COMMAND_RE.finditer(workflow)]
            check_count = gate_commands.count("check")
            if check_count != 1:
                violations.append(
                    "CI must invoke exactly one mypy gate check entrypoint; "
                    f"found {check_count}"
                )
            unexpected_commands = sorted(command for command in gate_commands if command != "check")
            if unexpected_commands:
                violations.append(
                    "CI invokes non-check mypy gate commands: " + ", ".join(unexpected_commands)
                )

    return MypyConfigInventory(
        references=tuple(sorted(references)),
        violations=tuple(sorted(set(violations))),
    )


def audit_repository(root_dir: Path = PROJECT_ROOT) -> tuple[list[MypyConfigReference], list[str]]:
    """Compatibility-friendly tuple API for tests and other quality gates."""

    inventory = inventory_repository(root_dir)
    return list(inventory.references), list(inventory.violations)


def render_inventory(inventory: MypyConfigInventory) -> str:
    return json.dumps(inventory.as_dict(), indent=2, sort_keys=True) + "\n"


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory live mypy configuration consumers")
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    inventory = inventory_repository(args.root)
    if args.as_json:
        sys.stdout.write(render_inventory(inventory))
    else:
        for reference in inventory.references:
            print(
                f"{reference.path}:{reference.line}: "
                f"{reference.kind.value} ({reference.classification.value})"
            )
        for violation in inventory.violations:
            print(f"ERROR: {violation}", file=sys.stderr)
        if inventory.ok:
            print("Mypy config inventory: clean")
    return 0 if inventory.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
