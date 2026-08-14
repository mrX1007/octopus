from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import CredentialDumpInputV2
from core.actions.provider_results import SensitiveProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_credentials import (
    ProviderUnavailableError,
    SamDumpAdapter,
    execute_sam_dump,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:ad_sam_dump") -> ActionRequestV2:
    return ActionRequestV2(
        "req-sam-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        CredentialDumpInputV2("credential://admin/1", "host.example"),
    )


def test_sam_direct_backend_is_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="sam_dump_provider_unavailable"):
        execute_sam_dump("host.example")


def test_sam_requires_canonical_identity() -> None:
    adapter = SamDumpAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("ad_sam_dump"))) is False


def test_sam_never_fabricates_batch_or_artifact_refs() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-sam-1")
    with pytest.raises(ProviderUnavailableError, match="sensitive_staging_unavailable"):
        SamDumpAdapter().execute_bound(context)


def test_sam_declares_exact_sensitive_result() -> None:
    assert get_type_hints(SamDumpAdapter.execute_bound)["return"] is SensitiveProviderResult
