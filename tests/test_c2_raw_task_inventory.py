"""Tests for zero V12 agent raw command inventory (§15.5)."""

from __future__ import annotations

import pytest

from scripts.quality.c2_raw_task_inventory import inventory_v12_raw_tasks

pytestmark = pytest.mark.unit


def test_raw_task_inventory_zero_violations():
    violations = inventory_v12_raw_tasks()
    assert violations == [], f"Expected zero raw command task violations in V12, got {violations}"
