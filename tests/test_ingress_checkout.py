from __future__ import annotations

from dataclasses import replace

import pytest

import core.actions.reference_checkout as reference_checkout
from core.actions.reference_checkout import ReferenceCheckoutError
from tests.checkout_test_support import build_fixture

pytestmark = pytest.mark.unit


def test_principal_checkout_requires_ingress_binding() -> None:
    fixture = build_fixture()
    fixture.authority.principal = replace(
        fixture.authority.principal,
        principal_ref="principal-2",
    )

    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_principal_identity_mismatch"):
        fixture.coordinator.checkout_many(fixture.request)


def test_transport_binding_mismatch_fails_before_reference_checkout() -> None:
    fixture = build_fixture()
    fixture.authority.ingress = replace(
        fixture.authority.ingress,
        transport_binding_digest="sha256:different-binding",
    )

    with pytest.raises(ReferenceCheckoutError, match="checkout_ingress_identity_mismatch"):
        fixture.coordinator.checkout_many(fixture.request)
    assert fixture.reference_store.receipts == {}


def test_global_reference_checkout_registry_is_absent() -> None:
    assert not hasattr(reference_checkout, "ReferenceCheckoutService")
    assert not hasattr(reference_checkout, "get_reference_resolver_registry")
