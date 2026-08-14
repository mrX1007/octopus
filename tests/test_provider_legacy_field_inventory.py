"""Tests for provider legacy field inventory script."""

from __future__ import annotations

import pytest

from scripts.quality.provider_legacy_field_inventory import audit_repository

pytestmark = pytest.mark.unit


def test_provider_legacy_field_inventory_matches_reviewed_v1_allowlist() -> None:
    unallowed_reads, v2_violations = audit_repository()
    assert unallowed_reads == []
    assert v2_violations == []
