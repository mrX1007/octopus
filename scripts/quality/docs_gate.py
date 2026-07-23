#!/usr/bin/env python3
"""Validate documentation links, JSON schemas, and shipped schema instances."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

_MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\((?P<target><[^>]+>|[^)\s]+)(?:\s+['\"].*?['\"])?\)")
_IGNORED_SCHEMES = ("app://", "data:", "http://", "https://", "mailto:")


class DocsGateError(RuntimeError):
    """A shipped documentation contract is invalid."""


def _markdown_files(root: Path) -> Iterable[Path]:
    yield root / "README.md"
    yield root / "CONTRIBUTING.md"
    yield from sorted((root / "docs").rglob("*.md"))


def validate_local_links(root: Path) -> int:
    """Require every relative Markdown link to resolve inside the repository."""

    root = root.resolve(strict=True)
    checked = 0
    failures: list[str] = []
    for document in _markdown_files(root):
        if not document.is_file():
            continue
        fenced = False
        for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            for match in _MARKDOWN_LINK.finditer(line):
                target = match.group("target").strip("<>")
                if not target or target.startswith("#") or target.startswith(_IGNORED_SCHEMES):
                    continue
                path_text = unquote(target.split("#", 1)[0])
                if not path_text:
                    continue
                candidate = (document.parent / path_text).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    failures.append(
                        f"{document.relative_to(root)}:{line_number}: link escapes repository: {target}"
                    )
                    continue
                checked += 1
                if not candidate.exists():
                    failures.append(
                        f"{document.relative_to(root)}:{line_number}: missing link target: {target}"
                    )
    if failures:
        raise DocsGateError("\n".join(failures))
    return checked


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DocsGateError(f"invalid JSON: {path}: {type(exc).__name__}") from exc


def validate_schemas(root: Path) -> tuple[int, int]:
    """Check every JSON schema plus the portable built-in benchmark catalog."""

    schema_dir = root / "docs" / "schemas"
    schemas: dict[str, dict] = {}
    for path in sorted(schema_dir.glob("*.schema.json")):
        payload = _load_json(path)
        if not isinstance(payload, dict):
            raise DocsGateError(f"schema root must be an object: {path}")
        try:
            Draft202012Validator.check_schema(payload)
        except SchemaError as exc:
            raise DocsGateError(f"invalid JSON schema {path}: {exc.message}") from exc
        schemas[path.name] = payload

    scenario_schema = schemas.get("benchmark-scenario-v1.schema.json")
    if scenario_schema is None:
        raise DocsGateError("benchmark scenario schema is missing")
    validator = Draft202012Validator(scenario_schema)
    instances = 0
    for path in sorted((root / "benchmarks" / "scenarios").glob("*.json")):
        try:
            validator.validate(_load_json(path))
        except ValidationError as exc:
            location = ".".join(str(item) for item in exc.absolute_path) or "<root>"
            raise DocsGateError(
                f"schema validation failed: {path}:{location}: {exc.message}"
            ) from exc
        instances += 1
    return len(schemas), instances


def validate_deprecations(root: Path) -> int:
    """Require every retirement target, symbol, and declared caller to exist."""

    manifest = root / "docs" / "deprecations.yaml"
    try:
        payload = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise DocsGateError("invalid deprecations manifest") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise DocsGateError("unsupported deprecations manifest")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise DocsGateError("deprecations manifest has no entries")
    failures: list[str] = []
    seen: set[str] = set()
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            failures.append(f"entries[{index}] is not a mapping")
            continue
        target = str(raw_entry.get("symbol_or_path") or "").strip()
        if not target or target in seen:
            failures.append(f"entries[{index}] has an empty or duplicate target")
            continue
        seen.add(target)
        path_text, separator, symbol = target.partition(":")
        target_path = root / path_text.rstrip("/")
        if not target_path.exists():
            failures.append(f"{target}: target path does not exist")
            continue
        if separator:
            if not target_path.is_file() or target_path.suffix != ".py":
                failures.append(f"{target}: symbol target is not a Python file")
            elif symbol not in _python_symbols(target_path):
                failures.append(f"{target}: symbol does not exist")
        callers = raw_entry.get("internal_callers")
        if not isinstance(callers, list):
            failures.append(f"{target}: internal_callers is not a list")
            continue
        reference_tokens = {
            Path(path_text.rstrip("/")).stem,
            *(part for part in symbol.split(".") if part),
        }
        for caller_text in callers:
            caller = root / str(caller_text)
            if not caller.is_file():
                failures.append(f"{target}: caller does not exist: {caller_text}")
                continue
            try:
                caller_source = caller.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                failures.append(f"{target}: caller is unreadable: {caller_text}")
                continue
            if reference_tokens and not any(
                token and token in caller_source for token in reference_tokens
            ):
                failures.append(
                    f"{target}: declared caller has no target reference: {caller_text}"
                )
    if failures:
        raise DocsGateError("\n".join(failures))
    return len(entries)


def _python_symbols(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise DocsGateError(f"cannot inspect deprecation symbol target: {path}") from exc
    symbols: set[str] = set()

    def visit(body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified = f"{prefix}.{node.name}" if prefix else node.name
                symbols.add(qualified)
                visit(node.body, qualified)
            elif not prefix and isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        symbols.add(target.id)

    visit(tree.body)
    return symbols


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _argument_parser().parse_args(argv)
    try:
        links = validate_local_links(args.root)
        schemas, instances = validate_schemas(args.root)
        deprecations = validate_deprecations(args.root)
    except (DocsGateError, OSError) as exc:
        print(f"docs gate failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"docs gate passed: {links} local links, {schemas} schemas, "
        f"{instances} instances, {deprecations} deprecations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
