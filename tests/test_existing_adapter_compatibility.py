"""Tests for existing adapter compatibility."""

from __future__ import annotations

import pytest

from core.actions.v1_compat import compat_v1

pytestmark = pytest.mark.unit


def test_v1_compat() -> None:
    res = compat_v1({"target_host": "192.168.1.1", "action": "test"})
    assert res["target"] == "192.168.1.1"
    assert res["action"] == "test"


def test_v1_compat_passthrough() -> None:
    res = compat_v1({"target": "10.0.0.1"})
    assert res["target"] == "10.0.0.1"
