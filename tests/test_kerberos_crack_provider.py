from __future__ import annotations

from dataclasses import fields
from typing import get_type_hints

import pytest

from core.actions.bound_adapters import BoundProviderCheckContext, BoundProviderInvocationContext
from core.actions.input_contracts import KerberosCrackInputV2, KerberosHashMode
from core.actions.provider_results import CredentialProviderResult
from core.actions.request_v2 import ActionRequestV2
from core.providers.kerberos import (
    KerberosCrackAdapter,
    KerberosCrackBackendResult,
    ProviderUnavailableError,
    crack_kerberos_tickets,
)

pytestmark = pytest.mark.unit


def _request(action_id: str = "killchain:kerberos_crack_tickets") -> ActionRequestV2:
    return ActionRequestV2(
        "req-krb-crack-1",
        action_id,
        "mission-1",
        None,
        (),
        None,
        KerberosCrackInputV2(
            "artifact://ticket/1",
            KerberosHashMode.KERBEROAST,
            "artifact://wordlist/1",
        ),
    )


def test_kerberos_crack_backend_accepts_refs_not_plaintext_candidates() -> None:
    with pytest.raises(ProviderUnavailableError, match="crack_provider_unavailable"):
        crack_kerberos_tickets("artifact://ticket/1", "artifact://wordlist/1")


def test_kerberos_crack_backend_result_has_no_plaintext_field() -> None:
    assert {item.name for item in fields(KerberosCrackBackendResult)} == {
        "credential_batch",
        "attempts",
        "backend_used",
    }


def test_kerberos_crack_never_fabricates_observations_or_credentials() -> None:
    adapter = KerberosCrackAdapter()
    assert adapter.check_bound(BoundProviderCheckContext(_request())) is True
    context = BoundProviderInvocationContext(_request(), transaction_id="tx-krb-crack")
    with pytest.raises(ProviderUnavailableError, match="sensitive_staging_unavailable"):
        adapter.execute_bound(context)


def test_kerberos_crack_declares_exact_result_variant() -> None:
    assert get_type_hints(KerberosCrackAdapter.execute_bound)["return"] is CredentialProviderResult
