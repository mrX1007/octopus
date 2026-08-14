from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import PivotProxyScanInputV2
from core.actions.provider_results import OperationProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.pivot import (
    PivotProxyScanAdapter,
    ProviderUnavailableError,
    execute_proxy_scan,
)

pytestmark = pytest.mark.unit


def _request() -> ActionRequestV2:
    return ActionRequestV2(
        "req-scan-1",
        "killchain:pivot_proxy_scan",
        "mission-1",
        None,
        (),
        None,
        PivotProxyScanInputV2("route://proxy/1", "10.0.0.0/24", (80, 443), 10),
    )


def test_proxy_scan_helper_is_explicitly_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="proxy_scan_provider_unavailable"):
        execute_proxy_scan("route://proxy/1", "10.0.0.0/24", (80, 443))


def test_proxy_scan_checks_exact_input() -> None:
    assert PivotProxyScanAdapter().check_bound(BoundProviderCheckContext(_request())) is True


def test_proxy_scan_never_fabricates_observations() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-scan-1")
    with pytest.raises(ProviderUnavailableError, match="observation_staging_unavailable"):
        PivotProxyScanAdapter().execute_bound(context)


def test_proxy_scan_declares_exact_operation_result() -> None:
    assert get_type_hints(PivotProxyScanAdapter.execute_bound)["return"] is OperationProviderResult
