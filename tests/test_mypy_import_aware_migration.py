"""Tests for the mypy configuration-consumer migration."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.quality.mypy_config_inventory import (
    CANONICAL_CI_ENTRYPOINT,
    LEGACY_CONFIG_PATH,
    PLAN_PATH,
    ReferenceClassification,
    ReferenceKind,
    inventory_repository,
)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _write_ci(root: Path, command: str = CANONICAL_CI_ENTRYPOINT) -> None:
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(f"jobs:\n  typing:\n    steps:\n      - run: {command}\n", encoding="utf-8")


def test_mypy_gate_file_exists() -> None:
    assert (ROOT / "scripts" / "quality" / "mypy_gate.py").is_file()


def test_current_consumer_inventory_complete() -> None:
    inventory = inventory_repository(ROOT)

    assert inventory.violations == ()
    ci_entries = [
        reference
        for reference in inventory.references
        if reference.path == ".github/workflows/ci.yml" and reference.kind is ReferenceKind.GATE_CHECK
    ]
    assert len(ci_entries) == 1


def test_no_stale_import_aware_live_consumer_after_finalization(tmp_path: Path) -> None:
    _write_ci(tmp_path)
    plan = tmp_path / PLAN_PATH
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text(f"DELETE evidence: {LEGACY_CONFIG_PATH}\n", encoding="utf-8")

    evidence_only = inventory_repository(tmp_path)
    assert evidence_only.violations == ()
    assert any(
        reference.kind is ReferenceKind.LEGACY_CONFIG
        and reference.classification is ReferenceClassification.NORMATIVE_EVIDENCE
        for reference in evidence_only.references
    )

    live_doc = tmp_path / "docs" / "quality" / "local.md"
    live_doc.parent.mkdir(parents=True, exist_ok=True)
    direct_command = "python " + "-m mypy"
    live_doc.write_text(f"{direct_command} --config-file {LEGACY_CONFIG_PATH}\n", encoding="utf-8")

    failed = inventory_repository(tmp_path)
    assert any("stale legacy mypy config consumer" in violation for violation in failed.violations)


def test_inventory_rejects_direct_mypy_and_duplicate_ci_entrypoints(tmp_path: Path) -> None:
    direct_command = "python " + "-m mypy"
    _write_ci(tmp_path, f"{CANONICAL_CI_ENTRYPOINT}\n      - run: {direct_command}")
    guide = tmp_path / "README.md"
    guide.write_text(f"```bash\n{direct_command}\n```\n", encoding="utf-8")

    inventory = inventory_repository(tmp_path)

    assert any("direct mypy consumer" in violation for violation in inventory.violations)

    _write_ci(tmp_path, f"{CANONICAL_CI_ENTRYPOINT}\n      - run: {CANONICAL_CI_ENTRYPOINT}")
    guide.unlink()
    duplicate = inventory_repository(tmp_path)
    assert any("found 2" in violation for violation in duplicate.violations)


def test_inventory_fails_closed_on_unreadable_text_candidate(tmp_path: Path) -> None:
    _write_ci(tmp_path)
    invalid = tmp_path / "quality" / "invalid.toml"
    invalid.parent.mkdir(parents=True, exist_ok=True)
    invalid.write_bytes(b"\xff")

    inventory = inventory_repository(tmp_path)

    assert any("cannot read inventory candidate quality/invalid.toml" in item for item in inventory.violations)
