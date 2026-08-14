"""Tests for builder enrollment migration and absence of auto-issue tokens (§15.6)."""

from __future__ import annotations

import pytest

from scripts.quality.c2_builder_enrollment_inventory import inventory_builder_call_sites

pytestmark = pytest.mark.unit


def test_builder_enrollment_inventory_zero_violations():
    violations = inventory_builder_call_sites()
    assert violations == [], f"Expected zero builder auto-issue violations, got {violations}"
