from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import PayloadKeyingInputV2, PayloadKeyingProfileId
from core.actions.provider_results import ArtifactProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.c2.deployment_profiles import C2TargetArch, C2TargetOS
from core.providers.payload_keying import (
    PayloadKeyingAdapter,
    PayloadTargetMetadata,
    ProviderUnavailableError,
    key_payload,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "plugin:payload_keying") -> ActionRequestV2:
    return ActionRequestV2(
        "req-keying-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        PayloadKeyingInputV2(
            "artifact://payload/1",
            PayloadKeyingProfileId.HOSTNAME,
            "artifact://metadata/1",
        ),
    )


def _metadata() -> PayloadTargetMetadata:
    return PayloadTargetMetadata(
        target_os=C2TargetOS.WINDOWS,
        target_arch=C2TargetArch.AMD64,
        hostname="host.example",
        username=None,
        mac_address=None,
        machine_id=None,
        metadata_revision=1,
    )


def test_payload_keying_backend_is_explicitly_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="payload_keying_provider_unavailable"):
        key_payload(b"opaque", PayloadKeyingProfileId.HOSTNAME, _metadata())


def test_payload_keying_requires_canonical_action_identity() -> None:
    adapter = PayloadKeyingAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("payload_keying"))) is False


def test_payload_keying_never_fabricates_artifact_refs() -> None:
    adapter = PayloadKeyingAdapter()
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-keying-1")
    with pytest.raises(ProviderUnavailableError, match="staging_unavailable"):
        adapter.execute_bound(context)


def test_payload_keying_declares_exact_result_variant() -> None:
    assert get_type_hints(PayloadKeyingAdapter.execute_bound)["return"] is ArtifactProviderResult
