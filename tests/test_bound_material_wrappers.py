from __future__ import annotations

import inspect
import json
import pickle
from dataclasses import fields

import pytest

import core.actions.materials as materials_module
from core.actions.checkout_models import ReferenceKind
from core.actions.materials import (
    ExecutorCheckoutHandleV2,
    ExecutorOpenedMaterialBundleV2,
    ExecutorOpenedMaterialV2,
)
from tests.checkout_test_support import FakeCheckoutHandle, build_fixture

pytestmark = pytest.mark.unit


def _opened() -> tuple[ExecutorOpenedMaterialV2, FakeCheckoutHandle]:
    fixture = build_fixture()
    metadata = fixture.reference_store.snapshots["credential://test/0"]
    handle = FakeCheckoutHandle("checkout://test-1", "super-secret-marker")
    return (
        ExecutorOpenedMaterialV2(
            reference=metadata.reference,
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="checkout://test-1",
            metadata=metadata,
            checkout_handle=handle,
        ),
        handle,
    )


def test_pr4_executor_opened_material_has_exact_private_fields() -> None:
    assert tuple(field.name for field in fields(ExecutorOpenedMaterialV2)) == (
        "reference",
        "reference_kind",
        "checkout_id",
        "metadata",
        "checkout_handle",
    )
    handle_field = fields(ExecutorOpenedMaterialV2)[-1]
    assert handle_field.repr is False
    assert handle_field.compare is False


def test_executor_checkout_handle_protocol_is_narrow() -> None:
    _, handle = _opened()
    assert isinstance(handle, ExecutorCheckoutHandleV2)
    protocol_members = {
        name
        for name, value in vars(ExecutorCheckoutHandleV2).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }
    assert protocol_members == {"checkout_id", "close_checkout"}


def test_opened_material_handle_is_excluded_from_repr_and_equality() -> None:
    opened, _ = _opened()
    other = ExecutorOpenedMaterialV2(
        reference=opened.reference,
        reference_kind=opened.reference_kind,
        checkout_id=opened.checkout_id,
        metadata=opened.metadata,
        checkout_handle=FakeCheckoutHandle(opened.checkout_id, "different-secret"),
    )
    assert "super-secret-marker" not in repr(opened)
    assert opened == other


def test_bound_material_handle_fields_are_private_and_non_serializable() -> None:
    opened, _ = _opened()
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(opened)
    with pytest.raises(TypeError):
        json.dumps(opened)


def test_opened_material_runtime_type_must_match_reference_kind() -> None:
    fixture = build_fixture()
    metadata = fixture.reference_store.snapshots["credential://test/0"]
    with pytest.raises(ValueError, match="opened_material_reference_kind_mismatch"):
        ExecutorOpenedMaterialV2(
            metadata.reference,
            ReferenceKind.ARTIFACT,
            "checkout://test-1",
            metadata,
            FakeCheckoutHandle("checkout://test-1"),
        )


def test_checkout_handle_must_be_bound_to_same_checkout() -> None:
    fixture = build_fixture()
    metadata = fixture.reference_store.snapshots["credential://test/0"]
    with pytest.raises(ValueError, match="checkout_handle_identity_mismatch"):
        ExecutorOpenedMaterialV2(
            metadata.reference,
            ReferenceKind.CREDENTIAL,
            "checkout://test-1",
            metadata,
            FakeCheckoutHandle("checkout://other"),
        )


def test_pr4_materials_has_no_future_invocation_scope_import() -> None:
    source = inspect.getsource(materials_module)
    assert "invocation_scope" not in source
    assert "ProviderExecutePhaseLeaseV2" not in source


def test_request_constructible_bound_material_placeholder_is_absent() -> None:
    assert not hasattr(materials_module, "BoundMaterialView")
    assert not hasattr(materials_module, "MaterialHandle")
    assert tuple(field.name for field in fields(ExecutorOpenedMaterialBundleV2)) == (
        "checkout_id",
        "materials",
    )
