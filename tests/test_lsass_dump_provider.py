from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import CredentialDumpInputV2
from core.actions.provider_results import SensitiveProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.ad_credentials import (
    LsassDumpAdapter,
    ProviderUnavailableError,
    execute_lsass_dump,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:ad_dump_lsass") -> ActionRequestV2:
    return ActionRequestV2(
        "req-lsass-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        CredentialDumpInputV2("credential://admin/1", "host.example"),
    )


def test_lsass_direct_backend_is_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="lsass_dump_provider_unavailable"):
        execute_lsass_dump("host.example")


def test_lsass_requires_canonical_identity() -> None:
    adapter = LsassDumpAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("ad_dump_lsass"))) is False


def test_lsass_never_fabricates_batch_or_artifact_refs() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-lsass-1")
    with pytest.raises(ProviderUnavailableError, match="sensitive_staging_unavailable"):
        LsassDumpAdapter().execute_bound(context)


def test_lsass_declares_exact_sensitive_result() -> None:
    assert get_type_hints(LsassDumpAdapter.execute_bound)["return"] is SensitiveProviderResult
