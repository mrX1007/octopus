from __future__ import annotations

import pickle

import pytest

from core.actions.checkout_models import ExecutorCheckoutBundle, ReferenceKind
from core.actions.materials import ExecutorOpenedMaterialBundleV2, ExecutorOpenedMaterialV2
from tests.checkout_test_support import FakeCheckoutHandle, build_fixture

pytestmark = pytest.mark.unit


def _material(reference: str, checkout_id: str = "checkout://test-1") -> ExecutorOpenedMaterialV2:
    fixture = build_fixture()
    metadata = fixture.reference_store.snapshots[reference]
    return ExecutorOpenedMaterialV2(
        reference=reference,
        reference_kind=ReferenceKind.CREDENTIAL,
        checkout_id=checkout_id,
        metadata=metadata,
        checkout_handle=FakeCheckoutHandle(checkout_id),
    )


def test_bundle_requires_one_checkout_id_and_unique_references() -> None:
    first = _material("credential://test/0")
    with pytest.raises(ValueError, match="reference_duplicate"):
        ExecutorOpenedMaterialBundleV2("checkout://test-1", (first, first))


def test_bundle_rejects_material_from_another_checkout() -> None:
    material = _material("credential://test/0", "checkout://other")
    with pytest.raises(ValueError, match="checkout_identity_mismatch"):
        ExecutorOpenedMaterialBundleV2("checkout://test-1", (material,))


def test_bound_material_bundle_is_non_serializable() -> None:
    bundle = ExecutorOpenedMaterialBundleV2(
        "checkout://test-1",
        (_material("credential://test/0"),),
    )
    with pytest.raises(TypeError, match="non-serializable"):
        pickle.dumps(bundle)


def test_executor_checkout_bundle_has_no_open_or_reveal_method() -> None:
    forbidden = {
        "open",
        "open_material",
        "open_materials",
        "reveal",
        "store",
        "checkout_handle",
    }
    assert forbidden.isdisjoint(vars(ExecutorCheckoutBundle))


def test_empty_opened_bundle_is_closed_and_has_no_request_authority() -> None:
    bundle = ExecutorOpenedMaterialBundleV2("checkout://test-1", ())
    assert bundle.materials == ()
    assert not hasattr(bundle, "bind")
    assert not hasattr(bundle, "add")
    assert not hasattr(bundle, "open")
