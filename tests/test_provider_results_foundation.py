"""PR-5/PR-7 provider-result foundation contract tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from core.actions.provider_results import (
    ManagedResourceDraftRefV2,
    ManagedResourceKind,
    ProviderOutcomeV2,
    ProviderProvenanceV2,
    ProviderResultFoundationV2,
    ProviderResultHeaderV2,
    SessionProviderResult,
)

pytestmark = pytest.mark.unit


def _header() -> ProviderResultHeaderV2:
    return ProviderResultHeaderV2(
        schema_version="2.0",
        provider_id="provider:test",
        outcome=ProviderOutcomeV2.SUCCEEDED,
        reason_codes=(),
        duration_ms=5,
        provenance=ProviderProvenanceV2(
            implementation_id="provider:test",
            implementation_version="1.0.0",
            request_digest="sha256:request",
            started_at=1.0,
            completed_at=1.005,
        ),
    )


def test_provider_result_foundation_is_structural_protocol() -> None:
    result = SessionProviderResult(
        header=_header(),
        session=ManagedResourceDraftRefV2(
            transaction_id="tx-1",
            draft_id="session-1",
            resource_kind=ManagedResourceKind.SESSION,
            target="host.example",
            lifecycle_owner="executor",
            close_action_id="session:close",
            expires_at=None,
        ),
    )
    assert isinstance(result, ProviderResultFoundationV2)
    assert tuple(field.name for field in fields(ProviderResultHeaderV2)) == (
        "schema_version",
        "provider_id",
        "outcome",
        "reason_codes",
        "duration_ms",
        "provenance",
    )


def test_provider_result_header_is_frozen_and_has_no_open_defaults() -> None:
    header = _header()
    with pytest.raises(FrozenInstanceError):
        header.duration_ms = 7  # type: ignore[misc]
    with pytest.raises(TypeError):
        ProviderResultHeaderV2()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"duration_ms": -1}, "duration"),
        ({"schema_version": "3.0"}, "schema_version"),
        ({"provider_id": ""}, "provider_id"),
    ],
)
def test_provider_result_header_rejects_invalid_foundation_fields(
    kwargs: dict[str, object],
    reason: str,
) -> None:
    values: dict[str, object] = {
        "schema_version": "2.0",
        "provider_id": "provider:test",
        "outcome": ProviderOutcomeV2.SUCCEEDED,
        "reason_codes": (),
        "duration_ms": 1,
        "provenance": _header().provenance,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=reason):
        ProviderResultHeaderV2(**values)  # type: ignore[arg-type]


def test_provider_provenance_rejects_completed_before_started() -> None:
    with pytest.raises(ValueError, match="timestamp"):
        ProviderProvenanceV2(
            implementation_id="provider:test",
            implementation_version="1.0.0",
            request_digest="sha256:request",
            started_at=2.0,
            completed_at=1.0,
        )
