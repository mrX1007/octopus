"""PR-4 atomic snapshot checkout and post-readiness material-open tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from core.actions.checkout_models import CheckoutRecoveryRefV2, ReferenceAccessMode
from core.actions.reference_checkout import ReferenceCheckoutCoordinator, ReferenceCheckoutError
from tests.checkout_test_support import build_fixture

pytestmark = pytest.mark.unit


def test_checkout_many_returns_only_snapshots_and_fenced_leases() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)

    assert bundle.checkout_id == "checkout://test-1"
    assert bundle.ingress_session is fixture.authority.ingress
    assert bundle.principal is fixture.authority.principal
    assert bundle.mission is fixture.authority.mission
    assert len(bundle.references) == 1
    assert fixture.reference_store.open_calls == []
    bundle.assert_current()
    bundle.close()


def test_reference_checkout_uses_canonical_lock_order() -> None:
    events: list[str] = []
    fixture = build_fixture(events=events)
    bundle = fixture.coordinator.checkout_many(fixture.request)

    assert events[:2] == ["acquire:10:authority", "acquire:20:reference"]
    assert events[2:4] == ["release:20:reference", "release:10:authority"]
    bundle.close()


def test_reference_checkout_coordinator_opens_material_only_after_successful_final_readiness() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    assert fixture.reference_store.open_calls == []

    opened = fixture.coordinator.open_materials(bundle)
    assert tuple(item.reference for item in opened.materials) == ("credential://test/0",)
    assert fixture.reference_store.open_calls == ["credential://test/0"]
    bundle.close()


def test_metadata_only_reference_never_opens_material() -> None:
    fixture = build_fixture(access_modes=(ReferenceAccessMode.METADATA_ONLY,))
    bundle = fixture.coordinator.checkout_many(fixture.request)
    opened = fixture.coordinator.open_materials(bundle)

    assert opened.materials == ()
    assert fixture.reference_store.open_calls == []
    bundle.close()


def test_multi_checkout_all_or_release() -> None:
    fixture = build_fixture(reference_count=2)
    fixture.reference_store.fail_checkout_for = "credential://test/1"

    with pytest.raises(RuntimeError, match="test_checkout_failure"):
        fixture.coordinator.checkout_many(fixture.request)

    assert fixture.reference_store.release_counts == {"credential://test/0": 1}
    assert fixture.reference_store.receipts == {}
    assert fixture.reference_store.open_calls == []


def test_material_not_opened_on_partial_failure() -> None:
    fixture = build_fixture(reference_count=2)
    fixture.reference_store.fail_checkout_for = "credential://test/1"

    with pytest.raises(RuntimeError, match="test_checkout_failure"):
        fixture.coordinator.checkout_many(fixture.request)

    assert fixture.reference_store.open_calls == []
    assert fixture.reference_store.handles == []


def test_open_materials_revalidates_all_fences_atomically() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fixture.reference_store.advance_metadata_revision("credential://test/0")

    with pytest.raises(RuntimeError, match="reference_fence_invalid"):
        fixture.coordinator.open_materials(bundle)

    assert fixture.reference_store.open_calls == []
    bundle.close()


def test_metadata_revision_race_denied() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fixture.reference_store.advance_metadata_revision("credential://test/0")

    with pytest.raises(RuntimeError, match="reference_fence_invalid"):
        bundle.assert_current()
    bundle.close()


def test_acl_revision_race_denied() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    reference = "credential://test/0"
    snapshot = fixture.reference_store.snapshots[reference]
    fixture.reference_store.snapshots[reference] = replace(
        snapshot,
        authorization=replace(
            snapshot.authorization,
            authorization_revision=2,
        ),
    )

    with pytest.raises(RuntimeError, match="reference_fence_invalid"):
        bundle.assert_current()
    bundle.close()


def test_failed_open_materials_returns_no_partial_bundle() -> None:
    fixture = build_fixture(reference_count=2)
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fixture.reference_store.fail_open_for = "credential://test/1"

    with pytest.raises(RuntimeError, match="test_material_open_failure"):
        fixture.coordinator.open_materials(bundle)

    assert fixture.reference_store.open_calls == [
        "credential://test/0",
        "credential://test/1",
    ]
    assert len(fixture.reference_store.handles) == 1
    assert fixture.reference_store.handles[0].close_count == 1
    with pytest.raises(ReferenceCheckoutError, match="checkout_material_open_previously_failed"):
        fixture.coordinator.open_materials(bundle)
    bundle.close()
    assert fixture.reference_store.handles[0].close_count == 1


def test_checkout_close_closes_each_handle_and_fence_exactly_once() -> None:
    fixture = build_fixture(reference_count=2)
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fixture.coordinator.open_materials(bundle)

    bundle.close()
    bundle.close()

    assert [handle.close_count for handle in fixture.reference_store.handles] == [1, 1]
    assert fixture.reference_store.release_counts == {
        "credential://test/0": 1,
        "credential://test/1": 1,
    }
    with pytest.raises(ReferenceCheckoutError, match="checkout_bundle_closed"):
        bundle.assert_current()


def test_ingress_revision_race_denied() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fixture.authority.ingress = replace(fixture.authority.ingress, revision=2)

    with pytest.raises(RuntimeError, match="ingress_revision_mismatch"):
        bundle.assert_current()
    bundle.close()


def test_fact_revision_race_denied() -> None:
    fixture = build_fixture(include_fact=True)
    bundle = fixture.coordinator.checkout_many(fixture.request)
    fact_ref = fixture.request.facts[0].fact_ref
    fixture.authority.facts[fact_ref] = replace(
        fixture.authority.facts[fact_ref],
        revision=2,
    )

    with pytest.raises(RuntimeError, match="fact_revision_mismatch"):
        bundle.assert_current()
    bundle.close()


def test_approval_lease_revision_race_denied() -> None:
    fixture = build_fixture(include_approval=True)
    bundle = fixture.coordinator.checkout_many(fixture.request)
    assert fixture.approval_store is not None
    fixture.approval_store.revoke_approval(
        "approval://test/1",
        expected_revision=1,
    )

    with pytest.raises(RuntimeError, match="approval_revision_mismatch"):
        bundle.assert_current()
    bundle.close()


def test_reference_action_acl_mismatch_denied() -> None:
    fixture = build_fixture()
    reference = "credential://test/0"
    snapshot = fixture.reference_store.snapshots[reference]
    authorization = replace(
        snapshot.authorization,
        permitted_action_ids=("action:other",),
    )
    fixture.reference_store.snapshots[reference] = replace(
        snapshot,
        authorization=authorization,
    )

    with pytest.raises(ReferenceCheckoutError, match="reference_action_denied"):
        fixture.coordinator.checkout_many(fixture.request)
    assert fixture.reference_store.release_counts == {reference: 1}


def test_reference_scope_mismatch_denied() -> None:
    fixture = build_fixture()
    reference = "credential://test/0"
    snapshot = fixture.reference_store.snapshots[reference]
    authorization = replace(
        snapshot.authorization,
        authorization_scope=replace(snapshot.authorization.authorization_scope, rules=()),
    )
    fixture.reference_store.snapshots[reference] = replace(
        snapshot,
        authorization=authorization,
    )

    with pytest.raises(ReferenceCheckoutError, match="reference_scope_denied"):
        fixture.coordinator.checkout_many(fixture.request)
    assert fixture.reference_store.open_calls == []


def test_foreign_or_copied_bundle_has_no_checkout_authority() -> None:
    first = build_fixture()
    second = build_fixture()
    bundle = first.coordinator.checkout_many(first.request)

    with pytest.raises(ReferenceCheckoutError, match="checkout_bundle_not_canonical"):
        second.coordinator.open_materials(bundle)
    bundle.close()


def test_checkpoint_and_reopen_require_exact_fence_and_journal_identity() -> None:
    fixture = build_fixture()
    bundle = fixture.coordinator.checkout_many(fixture.request)
    recovery = CheckoutRecoveryRefV2(
        checkout_id=bundle.checkout_id,
        fence_generation=bundle.fence_generation,
        journal_ref="journal://checkout/1",
        journal_digest="sha256:journal-1",
    )

    assert fixture.coordinator.checkpoint_existing_recovery_state(bundle, recovery) is recovery
    assert fixture.coordinator.reopen_fenced(recovery) is bundle
    with pytest.raises(ReferenceCheckoutError, match="checkout_recovery_fence_mismatch"):
        fixture.coordinator.reopen_fenced(replace(recovery, fence_generation=2))
    bundle.close()


def test_ingress_checkout_required() -> None:
    fixture = build_fixture()
    with pytest.raises(TypeError, match="checkout_ingress_store_invalid"):
        ReferenceCheckoutCoordinator(
            ingress_store=None,  # type: ignore[arg-type]
            principal_store=fixture.authority,
            mission_store=fixture.authority,
            reference_stores={},
        )
