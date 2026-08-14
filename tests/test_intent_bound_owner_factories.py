"""Tests for intent bound owner factories."""

import pytest

from core.actions.intent_bound_owner_factories import IntentBoundOwnerFactory


@pytest.mark.unit
def test_owner_factory():
    factory = IntentBoundOwnerFactory()
    assert factory is not None
