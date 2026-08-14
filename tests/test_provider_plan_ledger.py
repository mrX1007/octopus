"""Ratchets for the canonical typed-provider plan ledger."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from scripts.quality.provider_plan_ledger_gate import (
    PLAN_PATH,
    LedgerParseError,
    parse_plan_ledger,
    validate_ledger,
    validate_plan_text,
)

pytestmark = pytest.mark.unit


def _plan(*sections: str) -> str:
    return "\n\n".join(dedent(section).strip() for section in sections) + "\n"


def _single_entry_plan(entry: str, *, action: str = "MODIFY", pr_number: int = 6) -> str:
    return _plan(
        f"""
        # PR-{pr_number}. Parser fixture

        ## {action}

        ```text
        {entry}
        ```
        """
    )


def test_pr_file_ledger_has_single_create_owner(tmp_path: Path) -> None:
    errors, warnings = validate_ledger(
        phase="planning",
        migration_manifest_path=tmp_path / "manifest-does-not-exist.json",
    )
    assert warnings == []
    assert errors == []


def test_plan_path_has_pr1_create_owner_and_no_modify_before_create() -> None:
    plan_path = "docs/architecture/typed-providers-implementation-plan-v6.13.md"
    ledger = parse_plan_ledger(PLAN_PATH.read_text(encoding="utf-8"), phase="planning")

    assert ledger["PR-1"]["CREATE"].count(plan_path) == 1
    assert plan_path not in ledger["PR-1"]["MODIFY"]
    modifying_prs = [pr_id for pr_id, actions in ledger.items() if plan_path in actions["MODIFY"]]
    assert modifying_prs == ["PR-20"]


def test_ledger_expands_single_generated_lock_brace_list_exactly() -> None:
    ledger = parse_plan_ledger(
        _single_entry_plan(
            "requirements/locks/linux-x86_64/cp310/{runtime,c2,full}.txt",
        )
    )

    assert ledger["PR-6"]["MODIFY"] == [
        "requirements/locks/linux-x86_64/cp310/c2.txt",
        "requirements/locks/linux-x86_64/cp310/full.txt",
        "requirements/locks/linux-x86_64/cp310/runtime.txt",
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "requirements/locks/linux-x86_64/cp310/{{runtime,c2},full}.txt",
        "requirements/locks/linux-x86_64/cp310/{runtime..full}.txt",
        "requirements/locks/linux-x86_64/cp310/{runtime,fu*ll}.txt",
        "requirements/locks/linux-x86_64/cp310/{runtime,,full}.txt",
        "requirements/locks/linux-x86_64/cp310/{runtime,runtime}.txt",
        "requirements/locks/{cp310,cp311}/{runtime,full}.txt",
        "requirements/locks/linux-x86_64/cp310/*.txt",
        "requirements/locks/linux-x86_64/cp310/lock[0-9].txt",
    ],
)
def test_ledger_rejects_nested_braces_ranges_wildcards_empty_and_duplicate_alternatives(entry: str) -> None:
    with pytest.raises(LedgerParseError):
        parse_plan_ledger(_single_entry_plan(entry))


@pytest.mark.parametrize(
    "entry",
    [
        "requirements/{runtime,full}.txt",
        "quality/{runtime,full}.txt",
        "requirements/locks/{runtime,full}.txt",
        "requirements/locks/custom/{runtime,full}.txt",
        "requirements/locks/linux-x86_64/{cp310,cp311}/full.txt",
    ],
)
def test_ledger_rejects_braces_outside_requirements_locks(entry: str) -> None:
    with pytest.raises(LedgerParseError, match="brace syntax is allowed only"):
        parse_plan_ledger(_single_entry_plan(entry))


def test_expanded_lock_paths_participate_in_duplicate_and_existence_checks() -> None:
    compact_path = "requirements/locks/linux-x86_64/cp310/{runtime,full}.txt"
    runtime_path = "requirements/locks/linux-x86_64/cp310/runtime.txt"
    full_path = "requirements/locks/linux-x86_64/cp310/full.txt"
    duplicate_plan = _plan(
        f"""
        # PR-1. Compact owner

        ## CREATE

        ```text
        {compact_path}
        ```
        """,
        f"""
        # PR-2. Duplicate exact owner

        ## CREATE

        ```text
        {runtime_path}
        ```
        """,
    )
    errors, _ = validate_plan_text(duplicate_plan, phase="planning")
    assert any("Duplicate CREATE owner" in error and runtime_path in error for error in errors)

    existence_plan = _single_entry_plan(compact_path, action="MODIFY")
    errors, _ = validate_plan_text(
        existence_plan,
        phase="final",
        head_paths={runtime_path, full_path},
        existing_paths={runtime_path},
    )
    assert any("Missing MODIFY file on disk" in error and full_path in error for error in errors)


def test_pr20_sentinels_only_final_in_pr20_create_modify_and_contribute_zero_paths() -> None:
    plan = _plan(
        """
        # PR-20. Typing migration

        ## CREATE

        ```text
        scripts/quality/mypy_gate.py
        @PR20_GENERATED_CREATE_PATHS@
        ```

        ## MODIFY

        ```text
        pyproject.toml
        @PR20_GENERATED_MODIFY_PATHS@
        ```
        """
    )
    ledger = parse_plan_ledger(plan, phase="planning")

    assert ledger["PR-20"]["CREATE"] == ["scripts/quality/mypy_gate.py"]
    assert ledger["PR-20"]["MODIFY"] == ["pyproject.toml"]


@pytest.mark.parametrize(
    "plan",
    [
        _plan(
            """
            # PR-19. Wrong PR

            ## CREATE

            ```text
            @PR20_GENERATED_CREATE_PATHS@
            ```
            """
        ),
        _plan(
            """
            # PR-20. Wrong fence

            ## MODIFY

            ```text
            @PR20_GENERATED_CREATE_PATHS@
            ```
            """
        ),
        _plan(
            """
            # PR-20. Path after sentinel

            ## CREATE

            ```text
            @PR20_GENERATED_CREATE_PATHS@
            typings/package.pyi
            ```
            """
        ),
        _plan(
            """
            # PR-20. Duplicate sentinel

            ## CREATE

            ```text
            @PR20_GENERATED_CREATE_PATHS@
            @PR20_GENERATED_CREATE_PATHS@
            ```
            """
        ),
        _plan(
            """
            # PR-20. Unknown sentinel

            ## CREATE

            ```text
            @PR20_GENERATED_OTHER_PATHS@
            ```
            """
        ),
    ],
)
def test_ledger_rejects_duplicate_or_misplaced_pr20_sentinel(plan: str) -> None:
    with pytest.raises(LedgerParseError):
        parse_plan_ledger(plan, phase="planning")


def test_final_ledger_rejects_pr20_sentinel() -> None:
    plan = _plan(
        """
        # PR-20. Final phase fixture

        ## CREATE

        ```text
        scripts/quality/mypy_gate.py
        @PR20_GENERATED_CREATE_PATHS@
        ```
        """
    )

    with pytest.raises(LedgerParseError, match="forbidden in final phase"):
        parse_plan_ledger(plan, phase="final")


@pytest.mark.parametrize(
    ("present", "state", "has_error"),
    [
        (False, None, False),
        (True, "frozen", False),
        (True, "migrating", False),
        (True, None, True),
        (True, "complete", True),
        (True, "unknown", True),
    ],
)
def test_planning_sentinel_requires_valid_migration_manifest_state(
    present: bool,
    state: str | None,
    has_error: bool,
) -> None:
    plan = _plan(
        """
        # PR-20. Manifest state fixture

        ## CREATE

        ```text
        scripts/quality/mypy_gate.py
        @PR20_GENERATED_CREATE_PATHS@
        ```
        """
    )
    errors, _ = validate_plan_text(
        plan,
        migration_manifest_present=present,
        migration_manifest_state=state,
    )
    assert bool(errors) is has_error


@pytest.mark.parametrize(
    "heading",
    [
        "# PR-01. Leading zero",
        "# PR-1: Wrong separator",
        "#PR-1. Missing space",
    ],
)
def test_ledger_requires_exact_pr_headings(heading: str) -> None:
    plan = _single_entry_plan("core/actions/new.py", action="CREATE").replace(
        "# PR-6. Parser fixture",
        heading,
    )
    with pytest.raises(LedgerParseError):
        parse_plan_ledger(plan)


@pytest.mark.parametrize("heading", ["## create", "## CREATE ", "## CREATE paths"])
def test_ledger_requires_exact_action_headings(heading: str) -> None:
    plan = _single_entry_plan("core/actions/new.py", action="CREATE").replace("## CREATE", heading)
    with pytest.raises(LedgerParseError, match="malformed ledger action heading"):
        parse_plan_ledger(plan)


@pytest.mark.parametrize(
    "entry",
    [
        "core/actions/new.py because it is needed",
        "`core/actions/new.py`",
        "../core/actions/new.py",
        "./core/actions/new.py",
        "core//actions/new.py",
        "core\\actions\\new.py",
    ],
)
def test_ledger_rejects_ambiguous_or_noncanonical_path_entries(entry: str) -> None:
    with pytest.raises(LedgerParseError):
        parse_plan_ledger(_single_entry_plan(entry, action="CREATE"))


def test_ledger_ignores_headings_inside_tilde_fences_and_resets_at_top_level_heading() -> None:
    plan = _plan(
        """
        ~~~text
        # PR-1. Fake fenced PR
        ## CREATE
        ```text
        fake.py
        ```
        ~~~

        # PR-2. Real PR

        ## CREATE

        ```text
        real.py
        ```

        # Appendix

        ## MODIFY

        ```text
        must-not-be-attributed.py
        ```
        """
    )
    with pytest.raises(LedgerParseError, match="before a PR heading"):
        parse_plan_ledger(plan)


def test_ledger_rejects_duplicate_create_owner() -> None:
    path = "core/actions/new.py"
    plan = _plan(
        f"""
        # PR-1. First owner

        ## CREATE

        ```text
        {path}
        ```
        """,
        f"""
        # PR-2. Second owner

        ## CREATE

        ```text
        {path}
        ```
        """,
    )
    errors, _ = validate_plan_text(plan, phase="planning")

    assert any("Duplicate CREATE owner" in error and path in error for error in errors)


@pytest.mark.parametrize(
    "plan",
    [
        _plan(
            """
            # PR-1. Premature modify

            ## MODIFY

            ```text
            core/actions/new.py
            ```
            """,
            """
            # PR-2. Later owner

            ## CREATE

            ```text
            core/actions/new.py
            ```
            """,
        ),
        _plan(
            """
            # PR-1. Wrong same-PR order

            ## MODIFY

            ```text
            core/actions/new.py
            ```

            ## CREATE

            ```text
            core/actions/new.py
            ```
            """,
        ),
    ],
)
def test_ledger_rejects_modify_before_create(plan: str) -> None:
    errors, _ = validate_plan_text(plan, phase="planning")
    assert any("MODIFY-before-CREATE" in error for error in errors)


def test_ledger_allows_same_pr_modify_after_create() -> None:
    plan = _plan(
        """
        # PR-1. Ordered same-PR ownership

        ## CREATE

        ```text
        core/actions/new.py
        ```

        ## MODIFY

        ```text
        core/actions/new.py
        ```
        """
    )
    errors, _ = validate_plan_text(plan, phase="planning")
    assert errors == []


def test_ledger_rejects_modify_after_delete_and_accepts_generate_predecessor() -> None:
    deleted_plan = _plan(
        """
        # PR-1. Delete baseline

        ## DELETE

        ```text
        tracked.py
        ```
        """,
        """
        # PR-2. Invalid later modify

        ## MODIFY

        ```text
        tracked.py
        ```
        """,
    )
    errors, _ = validate_plan_text(deleted_plan, head_paths={"tracked.py"})
    assert any("MODIFY-after-DELETE" in error for error in errors)

    generated_plan = _plan(
        """
        # PR-1. Generate path

        ## GENERATE

        ```text
        quality/generated.json
        ```
        """,
        """
        # PR-2. Modify generated path

        ## MODIFY

        ```text
        quality/generated.json
        ```
        """,
    )
    errors, _ = validate_plan_text(generated_plan)
    assert errors == []


def test_ledger_rejects_create_path_present_in_head_baseline() -> None:
    path = "core/actions/already_tracked.py"
    errors, _ = validate_plan_text(
        _single_entry_plan(path, action="CREATE", pr_number=1),
        phase="planning",
        head_paths={path},
    )

    assert errors == [f"[PR-1] CREATE path already exists in HEAD baseline: {path}"]


def test_committed_create_declaration_is_not_reclassified_against_same_head() -> None:
    path = "core/actions/created_by_pr1.py"
    errors, _ = validate_plan_text(
        _single_entry_plan(path, action="CREATE", pr_number=1),
        head_paths={path},
        head_declared_create_paths={path},
    )
    assert errors == []


def test_generated_paths_have_separate_ownership_from_source_create_paths() -> None:
    generated_path = "quality/provider-mounts.json"
    actual_ledger = parse_plan_ledger(PLAN_PATH.read_text(encoding="utf-8"), phase="planning")
    assert actual_ledger["PR-1"]["GENERATE"] == [generated_path]
    assert all(generated_path not in actions["CREATE"] for actions in actual_ledger.values())

    conflicting_plan = _plan(
        f"""
        # PR-1. Conflicting ownership

        ## CREATE

        ```text
        {generated_path}
        ```

        ## GENERATE

        ```text
        {generated_path}
        ```
        """
    )
    errors, _ = validate_plan_text(conflicting_plan, phase="planning")
    assert any("both source CREATE ownership" in error and generated_path in error for error in errors)


def test_canonical_special_case_ledger_ownership_is_exact() -> None:
    ledger = parse_plan_ledger(PLAN_PATH.read_text(encoding="utf-8"), phase="planning")
    router_test = "tests/test_router_reentry_contract.py"
    process_module = "core/execution/processes.py"

    assert [
        (pr_id, action)
        for pr_id, actions in ledger.items()
        for action in ("CREATE", "MODIFY")
        if router_test in actions[action]
    ] == [
        ("PR-12", "CREATE"),
        ("PR-18", "MODIFY"),
    ]
    assert [
        (pr_id, action)
        for pr_id, actions in ledger.items()
        for action in ("CREATE", "MODIFY")
        if process_module in actions[action]
    ] == [
        ("PR-11", "CREATE"),
    ]


def test_final_existence_checks_create_generate_modify_and_delete() -> None:
    plan = _plan(
        """
        # PR-1. Final existence fixture

        ## CREATE

        ```text
        new.py
        ```

        ## MODIFY

        ```text
        tracked.py
        ```

        ## GENERATE

        ```text
        generated.json
        ```

        ## DELETE

        ```text
        removed.ini
        ```
        """
    )
    errors, _ = validate_plan_text(
        plan,
        phase="final",
        head_paths={"tracked.py", "removed.ini"},
        existing_paths={"removed.ini"},
    )

    assert sorted(errors) == sorted(
        [
            "[PR-1] Missing CREATE file on disk: new.py",
            "[PR-1] Missing GENERATE file on disk: generated.json",
            "[PR-1] Missing MODIFY file on disk: tracked.py",
            "[PR-1] DELETE file still exists on disk: removed.ini",
        ]
    )
