"""Participant execution authority factory and binding contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

@dataclass(frozen=True)
class ParticipantExecutionAuthorityBindingV2:
    authority_id: str
    transaction_id: str
    creation_ref: str
    intent_ref: str
    checkout_ref: str
    coordinator_ref: str
    authority_digest: str

def canonical_participant_authority_digest(binding: ParticipantExecutionAuthorityBindingV2) -> str:
    payload = {
        "authority_id": binding.authority_id,
        "transaction_id": binding.transaction_id,
        "creation_ref": binding.creation_ref,
        "intent_ref": binding.intent_ref,
        "checkout_ref": binding.checkout_ref,
        "coordinator_ref": binding.coordinator_ref,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"

@runtime_checkable
class ParticipantExecutionAuthorityFactoryV2(Protocol):
    def issue(
        self,
        *,
        creation_ref: str,
        transaction_id: str,
        intent_ref: str,
        checkout_ref: str,
        coordinator_ref: str,
    ) -> ParticipantExecutionAuthorityBindingV2: ...

class DefaultParticipantExecutionAuthorityFactoryV2:
    """Concrete production factory issuing ParticipantExecutionAuthorityBindingV2 instances."""

    def issue(
        self,
        *,
        creation_ref: str,
        transaction_id: str,
        intent_ref: str,
        checkout_ref: str,
        coordinator_ref: str,
    ) -> ParticipantExecutionAuthorityBindingV2:
        auth_id = f"auth:{transaction_id}:{hashlib.sha256(creation_ref.encode()).hexdigest()[:8]}"
        dummy = ParticipantExecutionAuthorityBindingV2(
            authority_id=auth_id,
            transaction_id=transaction_id,
            creation_ref=creation_ref,
            intent_ref=intent_ref,
            checkout_ref=checkout_ref,
            coordinator_ref=coordinator_ref,
            authority_digest="",
        )
        digest = canonical_participant_authority_digest(dummy)
        return ParticipantExecutionAuthorityBindingV2(
            authority_id=auth_id,
            transaction_id=transaction_id,
            creation_ref=creation_ref,
            intent_ref=intent_ref,
            checkout_ref=checkout_ref,
            coordinator_ref=coordinator_ref,
            authority_digest=digest,
        )
