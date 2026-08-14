from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import PassTheHashInputV2
from core.actions.operation_catalog import RemoteExecOperationId
from core.actions.provider_results import RemoteAuthProviderResultV2
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_credentials import (
    PassTheHashAdapter,
    ProviderUnavailableError,
    execute_pass_the_hash,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:pass_the_hash") -> ActionRequestV2:
    return ActionRequestV2(
        "req-pth-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        PassTheHashInputV2(
            "credential://ntlm/1",
            "host.example",
            RemoteExecOperationId.IDENTITY,
        ),
    )


def test_pass_the_hash_direct_backend_is_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="pass_the_hash_provider_unavailable"):
        execute_pass_the_hash("credential://ntlm/1", "host.example")


def test_pass_the_hash_requires_canonical_identity() -> None:
    adapter = PassTheHashAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("pass_the_hash"))) is False


def test_pass_the_hash_never_fabricates_auth_receipt() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-pth-1")
    with pytest.raises(ProviderUnavailableError, match="effect_staging_unavailable"):
        PassTheHashAdapter().execute_bound(context)


def test_pass_the_hash_declares_closed_remote_auth_union() -> None:
    assert get_type_hints(PassTheHashAdapter.execute_bound)["return"] == RemoteAuthProviderResultV2
