from __future__ import annotations

from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import KerberosExtractInputV2
from core.actions.provider_results import ArtifactProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.kerberos import (
    KerberosExtractAdapter,
    ProviderUnavailableError,
    extract_kerberos_tickets,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:kerberos_extract_tickets") -> ActionRequestV2:
    return ActionRequestV2(
        "req-krb-extract-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        KerberosExtractInputV2("credential://krb/1", "dc.example"),
    )


def test_kerberos_extract_backend_is_explicitly_unavailable() -> None:
    with pytest.raises(ProviderUnavailableError, match="extract_provider_unavailable"):
        extract_kerberos_tickets("dc.example", "EXAMPLE")


def test_kerberos_extract_requires_canonical_identity() -> None:
    adapter = KerberosExtractAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    assert adapter.check_bound(BoundProviderCheckContext(_request("kerberos_extract_tickets"))) is False


def test_kerberos_extract_never_fabricates_ticket_artifact() -> None:
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-krb-extract")
    with pytest.raises(ProviderUnavailableError, match="staging_unavailable"):
        KerberosExtractAdapter().execute_bound(context)


def test_kerberos_extract_declares_exact_result_variant() -> None:
    assert get_type_hints(KerberosExtractAdapter.execute_bound)["return"] is ArtifactProviderResult
