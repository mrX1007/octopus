"""Tests for InvocationScope LIFO cleanup callbacks."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from core.actions.invocation_scope import InvocationScope


def test_invocation_scope_lifo_cleanup() -> None:
    events = []
    scope = InvocationScope("scope-1")

    scope.register_cleanup(lambda: events.append("first_registered"))
    scope.register_cleanup(lambda: events.append("second_registered"))

    scope.close()

    assert events == ["second_registered", "first_registered"]
