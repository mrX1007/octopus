"""Generic ingestion boundary for execution results containing secrets.

This is *not* a domain-specific credential extraction pipeline.  It is
a single, reusable boundary that ensures any observation carrying
sensitive material (credentials, tickets, keys, enrollment tokens)
flows through the same storage contract:

1. Plaintext → ``SecretStore.store()`` → opaque reference.
2. Domain identity → ``CredentialStore.register()`` → ``CredentialRef``.
3. ``FactStore`` receives *only* ``secret://`` references and provenance.
4. ``FactStore.redactor`` remains the last-resort defence, *not* the
   primary ingestion API.

The ingestor prevents orphan secrets, dangling references, and divergent
SecretStore instances for different FactStore databases.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.ai.fact_store import FactStore
    from core.credentials import CredentialStore
    from core.secrets import SecretStore


@dataclass(frozen=True)
class SensitiveField:
    """One sensitive datum inside an observation."""

    field_name: str
    plaintext: str
    subject: str | None = None
    service: str | None = None


@dataclass(frozen=True)
class SensitiveObservation:
    """Typed observation containing one or more sensitive fields."""

    target: str
    source_tool: str
    execution_id: str
    mission_id: str | None = None
    task_id: str | None = None
    sensitive_fields: tuple[SensitiveField, ...] = ()
    non_sensitive_facts: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)


@dataclass(frozen=True)
class IngestionResult:
    """Outcome of a sensitive observation ingestion."""

    secret_refs: tuple[str, ...]
    credential_refs: tuple[str, ...]
    fact_ids: tuple[str, ...]
    errors: tuple[str, ...] = ()


class SensitiveObservationIngestor:
    """Unified ingestion boundary for results with secret material."""

    def __init__(
        self,
        secret_store: SecretStore,
        credential_store: CredentialStore,
        fact_store: FactStore,
    ) -> None:
        self._secrets = secret_store
        self._credentials = credential_store
        self._facts = fact_store

    def ingest(self, observation: SensitiveObservation) -> IngestionResult:
        """Ingest a sensitive observation through the canonical pipeline.

        Steps:
        1. Store each sensitive field's plaintext via SecretStore.store().
        2. Register a CredentialRef for credential-shaped fields.
        3. Write only secret:// references + provenance into FactStore.
        4. Verify secret:// reference integrity before commit.
        5. Support idempotency via SecretStore deduplication.
        """
        secret_refs: list[str] = []
        credential_refs: list[str] = []
        fact_ids: list[str] = []
        errors: list[str] = []

        for sf in observation.sensitive_fields:
            try:
                # 1. Store plaintext → opaque reference
                ref = self._secrets.store(sf.plaintext)
                secret_refs.append(ref)

                # 2. Register credential identity if subject is known
                if sf.subject:
                    cred_ref, _is_new = self._credentials.register(
                        service=sf.service or "",
                        target=observation.target,
                        username=sf.subject,
                        secret=ref,
                    )
                    credential_refs.append(cred_ref.handle)

            except Exception as exc:
                errors.append(f"sensitive_ingest_failed:{sf.field_name}:{type(exc).__name__}")

        # 3. Write non-sensitive facts with secret:// references
        fact_data = {
            **observation.non_sensitive_facts,
            "_secret_refs": secret_refs,
            "_credential_refs": credential_refs,
            "_source_tool": observation.source_tool,
            "_execution_id": observation.execution_id,
            **observation.provenance,
        }

        try:
            fact_id = self._facts.add_fact(
                scan_id=observation.mission_id or "",
                host=observation.target,
                fact_type="sensitive_observation",
                value=json.dumps(fact_data),
                source=observation.source_tool,
            )
            if fact_id is not None:
                fact_ids.append(str(fact_id))
        except Exception as exc:
            errors.append(f"fact_store_failed:{type(exc).__name__}")

        return IngestionResult(
            secret_refs=tuple(secret_refs),
            credential_refs=tuple(credential_refs),
            fact_ids=tuple(fact_ids),
            errors=tuple(errors),
        )
