"""Safety tests for incomplete mypy migration metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from scripts.quality.mypy_gate import (
    MypyMigrationStateV1,
    cmd_complete,
    cmd_finalization_ready,
)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def test_incomplete_migration_manifest_does_not_claim_complete() -> None:
    manifest_path = ROOT / "quality" / "mypy-migration-freeze.json"
    if not manifest_path.exists():
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest.get("state") != MypyMigrationStateV1.COMPLETE.value


def test_complete_fails_closed_without_strict_migration_proofs(tmp_path: Path) -> None:
    freeze = tmp_path / "quality" / "mypy-migration-freeze.json"
    freeze.parent.mkdir(parents=True)
    original = "{}\n"
    freeze.write_text(original, encoding="utf-8")

    assert cmd_complete(argparse.Namespace(rewrite_plan=True), tmp_path) == 1
    assert freeze.read_text(encoding="utf-8") == original


def test_finalization_ready_rejects_manifest_state_without_consumer_evidence(tmp_path: Path) -> None:
    freeze = tmp_path / "quality" / "mypy-migration-freeze.json"
    freeze.parent.mkdir(parents=True)
    freeze.write_text(json.dumps({"state": MypyMigrationStateV1.COMPLETE.value}), encoding="utf-8")

    assert cmd_finalization_ready(argparse.Namespace(), tmp_path) == 1
