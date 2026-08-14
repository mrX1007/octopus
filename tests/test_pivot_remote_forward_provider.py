from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import RemoteForwardInputV2
from core.actions.provider_results import RouteProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.pivot import (
    PivotRemoteForwardAdapter,
    ProviderUnavailableError,
    setup_remote_forward,
)

pytestmark = pytest.mark.unit


def _request() -> ActionRequestV2:
    return ActionRequestV2(
        "req-forward-1",
        "killchain:pivot_remote_forward",
        "mission-1",
        None,
        (),
        None,
        RemoteForwardInputV2(
            "session://jump/1",
            "jump.example",
            8080,
            "destination.example",
            443,
        ),
    )


def test_remote_forward_helper_is_explicitly_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="remote_forward_provider_unavailable"):
        setup_remote_forward(8080, "127.0.0.1", "destination.example", 443)


def test_remote_forward_checks_exact_input() -> None:
    assert PivotRemoteForwardAdapter().check_bound(BoundProviderCheckContext(_request())) is True


def test_remote_forward_never_fabricates_live_route() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-forward-1")
    with pytest.raises(ProviderUnavailableError, match="route_staging_unavailable"):
        PivotRemoteForwardAdapter().execute_bound(context)


def test_remote_forward_declares_exact_route_result() -> None:
    assert get_type_hints(PivotRemoteForwardAdapter.execute_bound)["return"] is RouteProviderResult
