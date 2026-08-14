from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import RemoteExecInputV2
from core.actions.operation_catalog import RemoteExecOperationId, RemoteExecService
from core.actions.provider_results import OperationProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_lateral import ADDComExecAdapter, ProviderUnavailableError

pytestmark = pytest.mark.unit


def _request(service: RemoteExecService = RemoteExecService.DCOM) -> ActionRequestV2:
    return ActionRequestV2(
        "req-dcom-1",
        "killchain:ad_dcom_exec",
        "mission-1",
        None,
        (),
        None,
        RemoteExecInputV2(
            "credential://dcom/1",
            "host.example",
            RemoteExecOperationId.IDENTITY,
            service,
        ),
    )


def test_dcom_check_rejects_wrong_service() -> None:
    adapter = ADDComExecAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request(RemoteExecService.SMB))) is False


def test_dcom_never_dispatches_without_effect_participant() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-dcom-1")
    with pytest.raises(ProviderUnavailableError, match="effect_participant_unavailable"):
        ADDComExecAdapter().execute_bound(context)


def test_dcom_declares_exact_operation_result() -> None:
    assert get_type_hints(ADDComExecAdapter.execute_bound)["return"] is OperationProviderResult
