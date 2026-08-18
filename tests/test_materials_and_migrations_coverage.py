"""Comprehensive unit test coverage for materials, input_migrations, invocation_scope, sensitive_transactions, and schema_bindings."""

from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from core.actions.checkout_models import ReferenceKind
from core.actions.input_migrations import (
    LegacyInputMigrationRequiredV2,
    V1ToV2InputMigrator,
)
from core.actions.invocation_scope import InvocationScope
from core.actions.materials import (
    ExecutorCheckoutHandleV2,
    ExecutorOpenedMaterialBundleV2,
    ExecutorOpenedMaterialV2,
)
from core.actions.reference_authorization import (
    ReferenceAuthorizationSnapshot,
)
from core.actions.reference_snapshots import CredentialReferenceSnapshot
from core.actions.schema_bindings import (
    get_all_v2_schema_bindings,
    get_v2_schema_binding,
    get_v2_schema_binding_by_input_schema,
)
from core.actions.sensitive_transactions import SensitiveStagingTransactionV2
from core.actions.target_scope import (
    TargetKind,
    TargetScopeRule,
    TargetScopeSnapshot,
)
from core.auth.types import SubjectType
from core.credentials import CredentialAuthKind

pytestmark = pytest.mark.unit


def test_executor_opened_material_and_bundle():
    scope = TargetScopeSnapshot(
        schema_version="2.0",
        revision=1,
        rules=(TargetScopeRule(role=None, kind=TargetKind.IPV4, normalized_value="10.0.0.1"),),
    )
    auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="cred://1",
        authorization_revision=1,
        mission_id="m-1",
        owner_subject_id="s-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s-1",),
        permitted_action_ids=("act-1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req-1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )
    metadata = CredentialReferenceSnapshot(
        reference="cred://1",
        revision=1,
        authorization=auth,
        target="10.0.0.1",
        service="ssh",
        username="root",
        domain="",
        auth_kind=CredentialAuthKind.PASSWORD,
        port=22,
        verified=True,
        expires_at=2000.0,
    )

    class DummyHandle:
        @property
        def checkout_id(self) -> str:
            return "chk-1"

        def close_checkout(self) -> None:
            pass

    handle = DummyHandle()

    mat = ExecutorOpenedMaterialV2(
        reference="cred://1",
        reference_kind=ReferenceKind.CREDENTIAL,
        checkout_id="chk-1",
        metadata=metadata,
        checkout_handle=handle,
    )
    assert mat.reference == "cred://1"

    with pytest.raises(TypeError, match="non-serializable"):
        mat.__reduce__()

    bundle = ExecutorOpenedMaterialBundleV2(
        checkout_id="chk-1",
        materials=(mat,),
    )
    assert len(bundle.materials) == 1

    # Error conditions
    with pytest.raises(ValueError, match="opened_material_reference_identity_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://wrong",
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="chk-1",
            metadata=metadata,
            checkout_handle=handle,
        )

    with pytest.raises(ValueError, match="opened_material_reference_kind_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind=ReferenceKind.SESSION,
            checkout_id="chk-1",
            metadata=metadata,
            checkout_handle=handle,
        )

    with pytest.raises(TypeError, match="opened_material_checkout_handle_invalid"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="chk-1",
            metadata=metadata,
            checkout_handle="not_a_handle",  # type: ignore
        )

    class WrongHandle:
        @property
        def checkout_id(self) -> str:
            return "wrong_chk"

        def close_checkout(self) -> None:
            pass

    with pytest.raises(ValueError, match="opened_material_checkout_handle_identity_mismatch"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind=ReferenceKind.CREDENTIAL,
            checkout_id="chk-1",
            metadata=metadata,
            checkout_handle=WrongHandle(),
        )

    with pytest.raises(TypeError, match="non-serializable"):
        mat.__reduce_ex__(2)

    with pytest.raises(TypeError, match="non-serializable"):
        bundle.__reduce__()

    with pytest.raises(TypeError, match="non-serializable"):
        bundle.__reduce_ex__(2)

    # Error paths
    with pytest.raises(ValueError, match="opened_material_reference_kind_invalid"):
        ExecutorOpenedMaterialV2(
            reference="cred://1",
            reference_kind="not_a_kind",  # type: ignore
            checkout_id="chk-1",
            metadata=metadata,
            checkout_handle=handle,
        )

    # metadata reference authorization mismatch
    bad_auth = ReferenceAuthorizationSnapshot(
        schema_version="2.0",
        reference="cred://DIFFERENT",
        authorization_revision=1,
        mission_id="m-1",
        owner_subject_id="s-1",
        owner_subject_type=SubjectType.OPERATOR,
        permitted_subject_ids=("s-1",),
        permitted_action_ids=("act-1",),
        permitted_capabilities=("cap1",),
        authorization_scope=scope,
        created_by_request_id="req-1",
        delegated_by_subject_id=None,
        expires_at=2000.0,
    )
    with pytest.raises(ValueError, match="reference_authorization_identity_mismatch"):
        CredentialReferenceSnapshot(
            reference="cred://1",
            revision=1,
            authorization=bad_auth,
            target="10.0.0.1",
            service="ssh",
            username="root",
            domain="",
            auth_kind=CredentialAuthKind.PASSWORD,
            port=22,
            verified=True,
            expires_at=2000.0,
        )

    # _metadata_matches_kind branches
    from core.actions.materials import _metadata_matches_kind

    from core.actions.reference_snapshots import (
        PivotRouteReferenceSnapshot,
        C2ReferenceSnapshot,
        DeploymentReferenceSnapshot,
    )

    pivot_meta = object.__new__(PivotRouteReferenceSnapshot)
    assert _metadata_matches_kind(pivot_meta, ReferenceKind.PIVOT_ROUTE) is True
    c2_meta = object.__new__(C2ReferenceSnapshot)
    assert _metadata_matches_kind(c2_meta, ReferenceKind.C2_RESOURCE) is True
    dep_meta = object.__new__(DeploymentReferenceSnapshot)
    assert _metadata_matches_kind(dep_meta, ReferenceKind.DEPLOYMENT) is True
    assert _metadata_matches_kind(dep_meta, "unknown_kind") is False  # type: ignore

    with pytest.raises(ValueError, match="opened_material_bundle_items_invalid"):
        ExecutorOpenedMaterialBundleV2(checkout_id="chk-1", materials=["not_a_material"])  # type: ignore

    with pytest.raises(ValueError, match="opened_material_bundle_reference_duplicate"):
        ExecutorOpenedMaterialBundleV2(
            checkout_id="chk-1",
            materials=(mat, mat),
        )

    with pytest.raises(ValueError, match="opened_material_bundle_checkout_identity_mismatch"):
        ExecutorOpenedMaterialBundleV2(
            checkout_id="chk-OTHER",
            materials=(mat,),
        )


def test_v1_to_v2_input_migrator():
    migrator = V1ToV2InputMigrator()
    res = migrator.migrate(
        action_id="killchain:ssh_exec",
        v1_payload={"host": "10.0.0.1", "cmd": "whoami"},
    )
    assert res.disposition == "migration_required"
    assert res.reason_code == "explicit_action_migration_required"
    assert res.legacy_field_names == ("cmd", "host")

    # migrate_batch
    batch_res = migrator.migrate_batch(
        action_id="killchain:ssh_exec",
        v1_payloads=[{"host": "10.0.0.1"}],
    )
    assert len(batch_res) == 1

    # migrate_v1_to_v2
    from core.actions.input_migrations import migrate_v1_to_v2

    func_res = migrate_v1_to_v2(
        action_id="killchain:ssh_exec",
        v1_payload={"host": "10.0.0.1"},
    )
    assert func_res.disposition == "migration_required"


def test_invocation_scope_lifo_cleanup():
    scope = InvocationScope("scope-1")
    calls = []
    scope.register_cleanup(lambda: calls.append("first"))
    scope.register_cleanup(lambda: calls.append("second"))
    scope.close()

    assert calls == ["second", "first"]

    # Register after close raises
    with pytest.raises(RuntimeError, match="Cannot register cleanup on closed InvocationScope"):
        scope.register_cleanup(lambda: None)

    # Calling close again is idempotent
    scope.close()


def test_sensitive_staging_transaction():
    tx = SensitiveStagingTransactionV2(transaction_id="tx-1")
    assert tx.staging_active is True

    tx.add_draft("draft-1")
    assert len(tx.drafts) == 1

    tx.close()
    assert tx.staging_active is False

    with pytest.raises(RuntimeError, match="staging_transaction_inactive"):
        tx.add_draft("draft-2")


def test_schema_bindings_lookups():
    all_bindings = get_all_v2_schema_bindings()
    assert len(all_bindings) == 20

    first = all_bindings[0]
    by_action = get_v2_schema_binding(first.action_id)
    assert by_action == first

    by_schema = get_v2_schema_binding_by_input_schema(first.input_schema_id)
    assert by_schema == first

    with pytest.raises(KeyError, match="has no registered V2 schema binding"):
        get_v2_schema_binding("nonexistent:action")

    with pytest.raises(KeyError, match="has no registered V2 schema binding"):
        get_v2_schema_binding_by_input_schema("nonexistent:schema")
