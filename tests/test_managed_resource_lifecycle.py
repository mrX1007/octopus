"""Tests for ManagedResourceManagerV2."""
import pytest
from core.actions.managed_resources import ManagedResourceManagerV2, ManagedResourceStageRequestV2, ManagedResourceKind

@pytest.mark.unit
def test_managed_resource_lifecycle():
    mgr = ManagedResourceManagerV2()
    req = ManagedResourceStageRequestV2(
        resource_id="res-1",
        resource_kind=ManagedResourceKind.SESSION,
        descriptor={"host": "10.0.0.1"},
    )
    handle = mgr.register(req)
    assert handle.is_active
    assert mgr.get(handle.resource_ref) == handle
