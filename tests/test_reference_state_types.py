"""Canonical PR-4 state/kind ownership contracts."""

from __future__ import annotations

import pytest

import core.actions.reference_types as reference_types
from core.actions.provider_results import ArtifactKind as ProviderArtifactKind
from core.actions.reference_types import (
    ArtifactKind,
    C2ResourceKind,
    C2ResourceState,
    DeploymentState,
    RouteState,
    SessionState,
)
from core.artifacts import ArtifactKind as StoreArtifactKind
from core.c2.resources import C2ResourceKind as StoreC2ResourceKind
from core.c2.resources import C2ResourceState as StoreC2ResourceState
from core.credentials import CredentialAuthKind, CredentialRef, decode_credential_auth_kind
from core.pivot_routes import RouteState as StoreRouteState
from core.sessions import SessionState as StoreSessionState

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("enum_type", "values"),
    [
        (SessionState, ("active", "closing", "closed", "expired", "failed")),
        (
            ArtifactKind,
            (
                "generic",
                "payload",
                "payload_loader",
                "kerberos_ticket",
                "wordlist",
                "lsass_dump",
                "sam_hive",
                "system_hive",
                "security_hive",
                "c2_agent",
                "c2_rebind_manifest",
                "target_metadata",
            ),
        ),
        (RouteState, ("pending", "active", "closing", "closed", "expired", "failed")),
        (C2ResourceKind, ("channel", "agent", "task")),
        (
            C2ResourceState,
            ("pending", "active", "closed", "failed", "expired", "revoked", "consumed", "cancelled"),
        ),
        (
            DeploymentState,
            (
                "preallocated",
                "building",
                "staged",
                "uploading",
                "start_dispatching",
                "active",
                "in_doubt",
                "cleaning",
                "closed",
                "orphaned",
                "failed",
            ),
        ),
        (CredentialAuthKind, ("password", "nt_hash", "ssh_key")),
    ],
)
def test_reference_state_enums_have_exact_values(enum_type: type, values: tuple[str, ...]) -> None:
    assert tuple(item.value for item in enum_type) == values


def test_reference_state_enums_have_one_owner_and_are_only_reexported() -> None:
    assert StoreSessionState is SessionState
    assert StoreArtifactKind is ProviderArtifactKind is ArtifactKind
    assert StoreRouteState is RouteState
    assert StoreC2ResourceKind is C2ResourceKind
    assert StoreC2ResourceState is C2ResourceState
    assert not hasattr(reference_types, "ReferenceStateV2")
    assert not hasattr(reference_types, "ReferenceKindV2")


@pytest.mark.parametrize("value", ["password", "nt_hash", "ssh_key"])
def test_credential_auth_kind_legacy_decoder_is_closed(value: str) -> None:
    assert decode_credential_auth_kind(value).value == value


def test_unknown_credential_auth_kind_fails_closed() -> None:
    with pytest.raises(ValueError, match="credential_auth_kind_invalid"):
        CredentialRef(
            handle="credential://one",
            service="ssh",
            target="192.0.2.10",
            username="alice",
            auth_kind="plaintext",  # type: ignore[arg-type]
        )
