from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import RemoteExecInputV2
from core.actions.operation_catalog import RemoteExecOperationId, RemoteExecService
from core.actions.provider_results import OperationProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_lateral import ADWinRMExecAdapter, ProviderUnavailableError

pytestmark = pytest.mark.unit


def _request(service: RemoteExecService = RemoteExecService.WINRM) -> ActionRequestV2:
    return ActionRequestV2(
        "req-winrm-1",
        "killchain:ad_winrm_exec",
        "mission-1",
        None,
        (),
        None,
        RemoteExecInputV2(
            "credential://winrm/1",
            "host.example",
            RemoteExecOperationId.IDENTITY,
            service,
        ),
    )


def test_winrm_check_rejects_wrong_service() -> None:
    adapter = ADWinRMExecAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request(RemoteExecService.DCOM))) is False


def test_winrm_never_dispatches_without_effect_participant() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-winrm-1")
    with pytest.raises(ProviderUnavailableError, match="effect_participant_unavailable"):
        ADWinRMExecAdapter().execute_bound(context)


def test_winrm_declares_exact_operation_result() -> None:
    assert get_type_hints(ADWinRMExecAdapter.execute_bound)["return"] is OperationProviderResult
