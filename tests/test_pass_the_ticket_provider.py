from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import PassTheTicketInputV2
from core.actions.operation_catalog import RemoteExecOperationId
from core.actions.provider_results import RemoteAuthProviderResultV2
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_credentials import (
    PassTheTicketAdapter,
    ProviderUnavailableError,
    execute_pass_the_ticket,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:ad_pass_the_ticket") -> ActionRequestV2:
    return ActionRequestV2(
        "req-ptt-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        PassTheTicketInputV2(
            "artifact://ticket/1",
            "host.example",
            RemoteExecOperationId.IDENTITY,
        ),
    )


def test_pass_the_ticket_direct_backend_is_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="pass_the_ticket_provider_unavailable"):
        execute_pass_the_ticket("artifact://ticket/1", "cifs/host.example")


def test_pass_the_ticket_requires_canonical_identity() -> None:
    adapter = PassTheTicketAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("ad_pass_the_ticket"))) is False


def test_pass_the_ticket_never_fabricates_auth_receipt() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-ptt-1")
    with pytest.raises(ProviderUnavailableError, match="effect_staging_unavailable"):
        PassTheTicketAdapter().execute_bound(context)


def test_pass_the_ticket_declares_closed_remote_auth_union() -> None:
    assert get_type_hints(PassTheTicketAdapter.execute_bound)["return"] == RemoteAuthProviderResultV2
