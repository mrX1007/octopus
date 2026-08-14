from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import SSHChainHopInputV2, SSHChainInputV2
from core.actions.provider_results import SessionProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.pivot import (
    PivotSSHChainAdapter,
    ProviderUnavailableError,
    build_ssh_chain,
)

pytestmark = pytest.mark.unit


def _request() -> ActionRequestV2:
    return ActionRequestV2(
        "req-chain-1",
        "killchain:pivot_ssh_chain",
        "mission-1",
        None,
        (),
        None,
        SSHChainInputV2((SSHChainHopInputV2("jump.example", "credential://ssh/1"),)),
    )


def test_ssh_chain_helper_is_explicitly_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="ssh_chain_provider_unavailable"):
        build_ssh_chain(("jump.example",), "destination.example")


def test_ssh_chain_checks_exact_input() -> None:
    assert PivotSSHChainAdapter().check_bound(BoundProviderCheckContext(_request())) is True


def test_ssh_chain_never_fabricates_session() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-chain-1")
    with pytest.raises(ProviderUnavailableError, match="session_staging_unavailable"):
        PivotSSHChainAdapter().execute_bound(context)


def test_ssh_chain_declares_exact_session_result() -> None:
    assert get_type_hints(PivotSSHChainAdapter.execute_bound)["return"] is SessionProviderResult
