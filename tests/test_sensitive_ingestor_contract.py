"""Reference-only ingestion contract for credential-shaped observations."""

from __future__ import annotations

import json

import pytest

from core.ai.fact_store import FactStore
from core.ai.sensitive_ingestor import (
    SensitiveField,
    SensitiveObservation,
    SensitiveObservationIngestor,
)
from core.credentials import CredentialStore
from core.secrets import SecretStore

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_secret_store_api_is_sufficient_for_canonical_sensitive_ingestion(tmp_path) -> None:
    plaintext = "credential-ingestion-canary"
    secret_store = SecretStore(":memory:")
    credential_store = CredentialStore(secret_store, hydrate=False)
    fact_store = FactStore(str(tmp_path / "facts.db"), secret_store=secret_store)
    ingestor = SensitiveObservationIngestor(
        secret_store,
        credential_store,
        fact_store,
    )

    result = ingestor.ingest(
        SensitiveObservation(
            target="192.0.2.10",
            source_tool="manual-gated-fixture",
            execution_id="execution-1",
            mission_id="mission-1",
            sensitive_fields=(
                SensitiveField(
                    field_name="password",
                    plaintext=plaintext,
                    subject="operator",
                    service="ssh",
                ),
            ),
            non_sensitive_facts={"kind": "credential_observation"},
        )
    )

    assert result.errors == ()
    assert len(result.secret_refs) == 1
    assert result.secret_refs[0].startswith("secret://")
    assert len(result.credential_refs) == 1
    assert result.credential_refs[0].startswith("credential://")

    stored = fact_store.get_facts("mission-1", "192.0.2.10")
    assert len(stored) == 1
    payload = json.loads(stored[0]["value"])
    assert payload["_secret_refs"] == list(result.secret_refs)
    assert payload["_credential_refs"] == list(result.credential_refs)
    assert plaintext not in json.dumps(stored)
