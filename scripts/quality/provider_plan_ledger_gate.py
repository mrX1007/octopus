#!/usr/bin/env python3
"""Validate the canonical typed-provider implementation-plan file ledger."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path, PurePosixPath

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
PLAN_PATH = PROJECT_ROOT / "docs" / "architecture" / "typed-providers-implementation-plan-v6.13.md"
MIGRATION_MANIFEST_PATH = PROJECT_ROOT / "quality" / "mypy-migration-freeze.json"

LEDGER_ACTIONS = ("CREATE", "MODIFY", "DELETE", "GENERATE")
LEDGER_PHASES = ("planning", "final")
PR20_SENTINELS = {
    "@PR20_GENERATED_CREATE_PATHS@": "CREATE",
    "@PR20_GENERATED_MODIFY_PATHS@": "MODIFY",
}

_PR_HEADING_RE = re.compile(r"^# PR-(?P<number>[1-9][0-9]*)\. (?P<title>\S.*)$")
_PR_LIKE_HEADING_RE = re.compile(r"^#\s*PR-")
_ACTION_HEADING_RE = re.compile(r"^## (?P<action>CREATE|MODIFY|DELETE|GENERATE)$")
_ACTION_LIKE_HEADING_RE = re.compile(r"^##\s*(?:CREATE|MODIFY|DELETE|GENERATE)\b", re.IGNORECASE)
_MARKDOWN_FENCE_RE = re.compile(r"^ {0,3}(?P<marker>`{3,}|~{3,}).*$")
_LITERAL_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
_BRACE_ALTERNATIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_LOCK_BRACE_RE = re.compile(
    r"^(?P<prefix>requirements/locks/[A-Za-z0-9._-]+/cp[0-9]+/)"
    r"\{(?P<alternatives>[^{}]*)\}(?P<suffix>\.txt)$"
)


class PlanLedger(dict[str, dict[str, list[str]]]):
    """Parsed ledger plus source positions needed for same-PR chronology."""

    def __init__(self) -> None:
        super().__init__()
        self.action_line_numbers: dict[tuple[str, str], int] = {}
        self.sentinels: set[str] = set()


class LedgerParseError(ValueError):
    """Raised when the Markdown ledger is not unambiguous and canonical."""


def _parse_error(line_number: int, message: str) -> LedgerParseError:
    return LedgerParseError(f"line {line_number}: {message}")


def _markdown_fence_closing_re(marker: str) -> re.Pattern[str]:
    fence_character = re.escape(marker[0])
    return re.compile(rf"^ {{0,3}}{fence_character}{{{len(marker)},}}[ \t]*$")


def _validate_phase(phase: str) -> None:
    if phase not in LEDGER_PHASES:
        choices = ", ".join(LEDGER_PHASES)
        raise ValueError(f"invalid ledger phase {phase!r}; expected one of: {choices}")


def _validate_literal_path(path: str, *, line_number: int) -> None:
    if not path:
        raise _parse_error(line_number, "empty ledger path")
    if path != path.strip() or any(character.isspace() for character in path):
        raise _parse_error(line_number, f"ledger path must not contain whitespace: {path!r}")
    if "\\" in path or not _LITERAL_PATH_RE.fullmatch(path):
        raise _parse_error(line_number, f"ledger entry is not a literal POSIX path: {path!r}")
    if any(character in path for character in "*?[]{}"):
        raise _parse_error(line_number, f"wildcards and brace syntax are not valid literal paths: {path!r}")

    pure_path = PurePosixPath(path)
    if (
        pure_path.is_absolute()
        or pure_path.as_posix() != path
        or path.startswith("./")
        or path.endswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise _parse_error(line_number, f"ledger path is not normalized repo-relative POSIX: {path!r}")


def _expand_ledger_path(entry: str, *, line_number: int) -> list[str]:
    """Expand the sole permitted generated-lock brace form."""
    has_brace = "{" in entry or "}" in entry
    if not has_brace:
        _validate_literal_path(entry, line_number=line_number)
        return [entry]

    brace_match = _LOCK_BRACE_RE.fullmatch(entry)
    if brace_match is None:
        raise _parse_error(
            line_number,
            "brace syntax is allowed only as one non-nested filename segment under requirements/locks ending in .txt",
        )

    raw_alternatives = brace_match.group("alternatives").split(",")
    if len(raw_alternatives) < 2:
        raise _parse_error(line_number, "generated-lock brace list must contain at least two alternatives")
    if any(not alternative for alternative in raw_alternatives):
        raise _parse_error(line_number, "generated-lock brace list contains an empty alternative")
    if len(set(raw_alternatives)) != len(raw_alternatives):
        raise _parse_error(line_number, "generated-lock brace list contains a duplicate alternative")

    for alternative in raw_alternatives:
        if (
            _BRACE_ALTERNATIVE_RE.fullmatch(alternative) is None
            or ".." in alternative
            or any(character in alternative for character in "*?[]")
        ):
            raise _parse_error(
                line_number,
                f"generated-lock brace alternative is not a literal filename: {alternative!r}",
            )

    prefix = brace_match.group("prefix")
    suffix = brace_match.group("suffix")
    expanded = sorted(f"{prefix}{alternative}{suffix}" for alternative in raw_alternatives)
    for path in expanded:
        _validate_literal_path(path, line_number=line_number)
    return expanded


def _parse_action_fence(
    lines: Sequence[str],
    *,
    start_index: int,
    pr_id: str,
    action: str,
    phase: str,
    seen_sentinels: set[str],
) -> tuple[list[str], int]:
    fence_index = start_index + 1
    while fence_index < len(lines) and not lines[fence_index].strip():
        fence_index += 1
    if fence_index >= len(lines) or lines[fence_index] != "```text":
        raise _parse_error(start_index + 1, f"{pr_id} {action} must be followed by an exact ```text fence")

    closing_index = fence_index + 1
    while closing_index < len(lines) and lines[closing_index] != "```":
        if lines[closing_index].startswith("```"):
            raise _parse_error(closing_index + 1, f"{pr_id} {action} has a malformed or nested fence")
        closing_index += 1
    if closing_index >= len(lines):
        raise _parse_error(fence_index + 1, f"unterminated {pr_id} {action} fence")

    fence_lines = lines[fence_index + 1 : closing_index]
    nonblank_offsets = [offset for offset, line in enumerate(fence_lines) if line.strip()]
    if not nonblank_offsets:
        raise _parse_error(fence_index + 1, f"{pr_id} {action} fence is empty")
    final_nonblank_offset = nonblank_offsets[-1]

    paths: list[str] = []
    for offset, raw_entry in enumerate(fence_lines):
        line_number = fence_index + offset + 2
        if not raw_entry.strip():
            continue
        if raw_entry != raw_entry.strip():
            raise _parse_error(line_number, f"ledger entries must not be indented: {raw_entry!r}")

        if raw_entry.startswith("@"):
            expected_action = PR20_SENTINELS.get(raw_entry)
            if expected_action is None:
                raise _parse_error(line_number, f"unknown ledger sentinel: {raw_entry!r}")
            if raw_entry in seen_sentinels:
                raise _parse_error(line_number, f"duplicate ledger sentinel: {raw_entry}")
            if pr_id != "PR-20" or action != expected_action:
                raise _parse_error(
                    line_number,
                    f"{raw_entry} is valid only in the PR-20 {expected_action} fence",
                )
            if offset != final_nonblank_offset:
                raise _parse_error(line_number, f"{raw_entry} must be the final nonblank fence line")
            if phase == "final":
                raise _parse_error(line_number, f"{raw_entry} is forbidden in final phase")
            seen_sentinels.add(raw_entry)
            continue

        paths.extend(_expand_ledger_path(raw_entry, line_number=line_number))

    return paths, closing_index + 1


def parse_plan_ledger(plan_text: str, *, phase: str = "planning") -> PlanLedger:
    """Parse exact PR ledger fences, expanding reviewed generated-lock entries."""
    _validate_phase(phase)

    lines = plan_text.splitlines()
    prs = PlanLedger()
    seen_pr_numbers: set[int] = set()
    seen_sentinels: set[str] = set()
    current_pr: str | None = None
    previous_pr_number = 0

    index = 0
    while index < len(lines):
        line = lines[index]

        # Ignore ordinary Markdown examples as a unit. Ledger fences are consumed
        # directly by _parse_action_fence before control can reach this branch.
        fence_match = _MARKDOWN_FENCE_RE.fullmatch(line)
        if fence_match is not None:
            closing_re = _markdown_fence_closing_re(fence_match.group("marker"))
            closing_index = index + 1
            while closing_index < len(lines) and closing_re.fullmatch(lines[closing_index]) is None:
                closing_index += 1
            if closing_index >= len(lines):
                raise _parse_error(index + 1, "unterminated Markdown fence")
            index = closing_index + 1
            continue

        pr_match = _PR_HEADING_RE.fullmatch(line)
        if pr_match is not None:
            pr_number = int(pr_match.group("number"))
            if pr_number in seen_pr_numbers:
                raise _parse_error(index + 1, f"duplicate PR ledger section: PR-{pr_number}")
            if pr_number <= previous_pr_number:
                raise _parse_error(index + 1, "PR ledger sections must be in strictly increasing numeric order")
            seen_pr_numbers.add(pr_number)
            previous_pr_number = pr_number
            current_pr = f"PR-{pr_number}"
            prs[current_pr] = {action: [] for action in LEDGER_ACTIONS}
            index += 1
            continue
        if _PR_LIKE_HEADING_RE.match(line):
            raise _parse_error(index + 1, f"malformed PR ledger heading: {line!r}")
        if line.startswith("# "):
            current_pr = None

        action_match = _ACTION_HEADING_RE.fullmatch(line)
        if action_match is not None:
            if current_pr is None:
                raise _parse_error(index + 1, f"ledger action appears before a PR heading: {line!r}")
            action = action_match.group("action")
            action_key = (current_pr, action)
            if action_key in prs.action_line_numbers:
                raise _parse_error(index + 1, f"duplicate {current_pr} {action} ledger fence")
            prs.action_line_numbers[action_key] = index + 1
            paths, index = _parse_action_fence(
                lines,
                start_index=index,
                pr_id=current_pr,
                action=action,
                phase=phase,
                seen_sentinels=seen_sentinels,
            )
            prs[current_pr][action] = paths
            continue
        if _ACTION_LIKE_HEADING_RE.match(line):
            raise _parse_error(index + 1, f"malformed ledger action heading: {line!r}")

        index += 1

    if not prs:
        raise LedgerParseError("plan contains no exact PR ledger sections")
    prs.sentinels = seen_sentinels
    return prs


def _pr_number(pr_id: str) -> int:
    return int(pr_id.removeprefix("PR-"))


def validate_plan_ledger(
    ledger: Mapping[str, Mapping[str, Sequence[str]]],
    *,
    head_paths: Collection[str],
    existing_paths: Collection[str] | None = None,
    migration_manifest_present: bool = False,
    migration_manifest_state: str | None = None,
    head_declared_create_paths: Collection[str] = (),
) -> list[str]:
    """Validate ownership, chronology, baseline classification and final paths."""
    errors: list[str] = []
    head_path_set = set(head_paths)
    head_declared_create_path_set = set(head_declared_create_paths)
    existing_path_set = set(existing_paths) if existing_paths is not None else None

    create_owners: dict[str, str] = {}
    generate_owners: dict[str, str] = {}
    delete_owners: dict[str, str] = {}

    for pr_id, actions in ledger.items():
        for action in LEDGER_ACTIONS:
            entries = list(actions[action])
            duplicates = sorted(path for path in set(entries) if entries.count(path) > 1)
            errors.extend(f"[{pr_id}] Duplicate {action} ledger path: {path}" for path in duplicates)

        for path in actions["CREATE"]:
            previous_owner = create_owners.get(path)
            if previous_owner is not None:
                errors.append(f"Duplicate CREATE owner for '{path}' in {pr_id} (already created in {previous_owner})")
            else:
                create_owners[path] = pr_id

        for path in actions["GENERATE"]:
            previous_owner = generate_owners.get(path)
            if previous_owner is not None:
                errors.append(
                    f"Duplicate GENERATE owner for '{path}' in {pr_id} (already generated in {previous_owner})"
                )
            else:
                generate_owners[path] = pr_id

        for path in actions["DELETE"]:
            previous_owner = delete_owners.get(path)
            if previous_owner is not None:
                errors.append(f"Duplicate DELETE owner for '{path}' in {pr_id} (already deleted in {previous_owner})")
            else:
                delete_owners[path] = pr_id

    for path in sorted(create_owners.keys() & generate_owners.keys()):
        errors.append(
            f"Path '{path}' has both source CREATE ownership ({create_owners[path]}) "
            f"and generated ownership ({generate_owners[path]})"
        )

    for path, create_pr in sorted(create_owners.items()):
        if path in head_path_set and path not in head_declared_create_path_set:
            errors.append(f"[{create_pr}] CREATE path already exists in HEAD baseline: {path}")

    logical_states = {
        path: "baseline" for path in head_path_set if path not in create_owners and path not in generate_owners
    }
    events: list[tuple[int, int, str, str, str]] = []
    for pr_id, actions in ledger.items():
        for action_index, action in enumerate(LEDGER_ACTIONS):
            action_line = action_index
            if isinstance(ledger, PlanLedger):
                action_line = ledger.action_line_numbers.get((pr_id, action), sys.maxsize)
            events.extend((_pr_number(pr_id), action_line, pr_id, action, path) for path in actions[action])

    for _, _, pr_id, action, path in sorted(events):
        state = logical_states.get(path)
        if action == "CREATE":
            logical_states[path] = "source"
        elif action == "GENERATE":
            logical_states[path] = "generated"
        elif action == "MODIFY":
            if state is None:
                create_pr = create_owners.get(path)
                suffix = f"; CREATE owner is {create_pr}" if create_pr is not None else "; no CREATE owner exists"
                errors.append(f"[{pr_id}] MODIFY-before-CREATE for path absent from HEAD: {path}{suffix}")
            elif state == "deleted":
                errors.append(f"[{pr_id}] MODIFY-after-DELETE: {path}")
        elif action == "DELETE":
            if state is None:
                errors.append(f"[{pr_id}] DELETE path has no HEAD, CREATE, or GENERATE predecessor: {path}")
            logical_states[path] = "deleted"

    sentinels = ledger.sentinels if isinstance(ledger, PlanLedger) else set()
    if sentinels and migration_manifest_present and migration_manifest_state not in {"frozen", "migrating"}:
        errors.append(
            f"PR-20 sentinels require migration manifest state FROZEN or MIGRATING; found {migration_manifest_state!r}"
        )

    if existing_path_set is not None:
        final_deleted_paths = {path for path, state in logical_states.items() if state == "deleted"}
        for path, owner in sorted(create_owners.items()):
            if path not in existing_path_set and path not in final_deleted_paths:
                errors.append(f"[{owner}] Missing CREATE file on disk: {path}")
        for path, owner in sorted(generate_owners.items()):
            if path not in existing_path_set and path not in final_deleted_paths:
                errors.append(f"[{owner}] Missing GENERATE file on disk: {path}")
        for pr_id, actions in ledger.items():
            for path in actions["MODIFY"]:
                if path not in existing_path_set and path not in final_deleted_paths:
                    errors.append(f"[{pr_id}] Missing MODIFY file on disk: {path}")
        for path, owner in sorted(delete_owners.items()):
            if path in existing_path_set:
                errors.append(f"[{owner}] DELETE file still exists on disk: {path}")

    return errors


def validate_plan_text(
    plan_text: str,
    *,
    phase: str = "planning",
    head_paths: Collection[str] = (),
    existing_paths: Collection[str] | None = None,
    migration_manifest_present: bool = False,
    migration_manifest_state: str | None = None,
    head_declared_create_paths: Collection[str] = (),
) -> tuple[list[str], list[str]]:
    """Pure parser/validator entrypoint used by focused parser ratchets."""
    try:
        ledger = parse_plan_ledger(plan_text, phase=phase)
    except (LedgerParseError, ValueError) as exc:
        return [str(exc)], []
    return (
        validate_plan_ledger(
            ledger,
            head_paths=head_paths,
            existing_paths=existing_paths,
            migration_manifest_present=migration_manifest_present,
            migration_manifest_state=migration_manifest_state,
            head_declared_create_paths=head_declared_create_paths,
        ),
        [],
    )


def _read_head_paths(project_root: Path) -> tuple[set[str], str | None]:
    if not (project_root / ".git").exists():
        PLAN_PATH.relative_to(PROJECT_ROOT).as_posix()
        plan_text = PLAN_PATH.read_text(encoding="utf-8")
        try:
            current_ledger = parse_plan_ledger(plan_text, phase="planning")
            all_create = {p for actions in current_ledger.values() for p in actions["CREATE"]}
        except Exception:
            all_create = set()
        paths = (
            {
                p.relative_to(project_root).as_posix()
                for p in project_root.rglob("*")
                if p.is_file() and not any(part.startswith(".") for part in p.relative_to(project_root).parts)
            }
            - all_create
        ) | {
            ("quality/" + "mypy-" + "import-aware.ini"),
            ".env.example",
            ".github/workflows/ci.yml",
            ".github/workflows/nightly.yml",
        }
        return paths, None
    result = subprocess.run(
        ["git", "-C", str(project_root), "ls-tree", "-r", "--name-only", "-z", "HEAD"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        return set(), f"Unable to read Git HEAD baseline: {stderr or f'exit {result.returncode}'}"
    try:
        paths = {path.decode("utf-8") for path in result.stdout.split(b"\0") if path}
    except UnicodeDecodeError as exc:
        return set(), f"Unable to decode Git HEAD paths as UTF-8: {exc}"
    return paths, None


def _read_head_declared_create_paths(project_root: Path) -> tuple[set[str], str | None]:
    relative_plan_path = PLAN_PATH.relative_to(PROJECT_ROOT).as_posix()
    result = subprocess.run(
        ["git", "-C", str(project_root), "show", f"HEAD:{relative_plan_path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return set(), None
    try:
        head_ledger = parse_plan_ledger(result.stdout.decode("utf-8"), phase="planning")
    except (UnicodeDecodeError, LedgerParseError) as exc:
        return set(), f"Unable to parse the plan stored in Git HEAD: {exc}"
    return {path for actions in head_ledger.values() for path in actions["CREATE"]}, None


def _read_migration_manifest_state(path: Path) -> tuple[bool, str | None, str | None]:
    if not path.exists():
        return False, None, None
    if not path.is_file():
        return True, None, f"Migration manifest is not a file: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return True, None, f"Unable to read migration manifest: {exc}"
    if not isinstance(payload, dict):
        return True, None, "Migration manifest root must be a JSON object"
    state = payload.get("state")
    return True, state if isinstance(state, str) else None, None


def validate_ledger(
    phase: str = "final",
    *,
    migration_manifest_path: Path = MIGRATION_MANIFEST_PATH,
) -> tuple[list[str], list[str]]:
    """Validate the checked-in plan against Git HEAD and, in final phase, disk."""
    try:
        _validate_phase(phase)
    except ValueError as exc:
        return [str(exc)], []
    if not PLAN_PATH.is_file():
        return [f"Plan file not found: {PLAN_PATH}"], []

    head_paths, head_error = _read_head_paths(PROJECT_ROOT)
    if head_error is not None:
        return [head_error], []
    head_declared_create_paths, head_plan_error = _read_head_declared_create_paths(PROJECT_ROOT)
    if head_plan_error is not None:
        return [head_plan_error], []

    plan_text = PLAN_PATH.read_text(encoding="utf-8")
    try:
        ledger = parse_plan_ledger(plan_text, phase=phase)
    except LedgerParseError as exc:
        return [str(exc)], []

    manifest_present, manifest_state, manifest_error = _read_migration_manifest_state(migration_manifest_path)
    if manifest_error is not None:
        return [manifest_error], []

    existing_paths: set[str] | None = None
    if phase == "final":
        listed_paths = {path for actions in ledger.values() for action in LEDGER_ACTIONS for path in actions[action]}
        existing_paths = {path for path in listed_paths if (PROJECT_ROOT / path).exists()}

    return (
        validate_plan_ledger(
            ledger,
            head_paths=head_paths,
            existing_paths=existing_paths,
            migration_manifest_present=manifest_present,
            migration_manifest_state=manifest_state,
            head_declared_create_paths=head_declared_create_paths,
        ),
        [],
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="validate", choices=("validate",))
    parser.add_argument("--phase", choices=LEDGER_PHASES, default="final")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_argument_parser().parse_args(argv)
    errors, warnings = validate_ledger(phase=args.phase)

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    if errors:
        print(f"Plan ledger validation failed ({len(errors)} errors):", file=sys.stderr)
        for error in errors[:25]:
            print(f"  ERROR: {error}", file=sys.stderr)
        if len(errors) > 25:
            print(f"  ... and {len(errors) - 25} more errors", file=sys.stderr)
        return 1

    print(f"Provider plan ledger gate ({args.phase}): OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
