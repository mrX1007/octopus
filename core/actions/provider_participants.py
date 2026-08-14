"""PR-5 Module: Provider participant registration facade and restricted interfaces (§8.2, §8.9)."""

from __future__ import annotations

from dataclasses import dataclass

from core.actions.execution_commit_participants import ExecutionCommitParticipant, ParticipantKindV2


@dataclass(frozen=True)
class ParticipantRegistrationRefV2:
    registration_id: str
    participant_id: str
    kind: ParticipantKindV2
    registration_digest: str


class ProviderParticipantRegistrationFacade:
    """Restricted facade for provider registration of transient and staging participants."""

    def __init__(self, transaction_id: str) -> None:
        self._transaction_id = transaction_id
        self._participants: list[ExecutionCommitParticipant] = []
        self._is_sealed = False

    def register_participant(self, participant: ExecutionCommitParticipant) -> ParticipantRegistrationRefV2:
        if self._is_sealed:
            raise RuntimeError("Registration facade is sealed; cannot register new participants")
        self._participants.append(participant)
        return ParticipantRegistrationRefV2(
            registration_id=f"reg-{len(self._participants)}",
            participant_id=participant.participant_id,
            kind=participant.kind,
            registration_digest=f"digest-{participant.participant_id}",
        )

    def seal(self) -> tuple[ExecutionCommitParticipant, ...]:
        self._is_sealed = True
        return tuple(self._participants)


__all__ = [
    "ParticipantRegistrationRefV2",
    "ProviderParticipantRegistrationFacade",
]
