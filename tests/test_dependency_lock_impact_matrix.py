"""Dependency lock impact and source-digest ratchets."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.quality.dependency_lock_impact_gate import (
    DependencyLockImpactError,
    required_lock_paths_for_input,
    validate_changed_path_impact,
    validate_manifest_input_hashes,
)

pytestmark = pytest.mark.unit


def test_runtime_requirement_change_regenerates_all_nine_profiles_all_targets() -> None:
    expected = required_lock_paths_for_input("requirements/runtime.txt")
    assert len(expected) == 27
    changed = {
        "requirements/runtime.txt",
        "requirements/locks/manifest.json",
        *expected,
    }
    validate_changed_path_impact(changed)
    with pytest.raises(DependencyLockImpactError, match="missing generated lock impacts"):
        validate_changed_path_impact(changed - {expected[-1]})


def test_lock_manifest_input_hashes_match_requirement_sources() -> None:
    validate_manifest_input_hashes(Path(__file__).resolve().parents[1])


def test_non_requirement_change_has_no_lock_impact() -> None:
    validate_changed_path_impact(("core/actions/input_contracts.py",))
