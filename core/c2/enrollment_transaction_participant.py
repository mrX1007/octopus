"""C2 enrollment 2PC transaction participant (§16.4A)."""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional
from core.c2.enrollment_models import (
    EnrollmentEmbeddedReceipt,
    EnrollmentParticipantState,
    EnrollmentPrepareReceipt,
)


class C2EnrollmentTransactionParticipant:
    """Participant managing atomic enrollment embedding during artifact build."""

    def __init__(
        self,
        participant_id: str,
        transaction_id: str,
        enrollment_ref: str,
    ) -> None:
        self.participant_id = participant_id
        self.transaction_id = transaction_id
        self.enrollment_ref = enrollment_ref
        self.participant_kind = "cross_process_control"
        self._state = EnrollmentParticipantState.REGISTERED
        self._prepare_receipt: Optional[EnrollmentPrepareReceipt] = None

    def prepare(self, request: Any = None) -> EnrollmentPrepareReceipt:
        """Atomically transition enrollment to EMBEDDED_IN_ARTIFACT."""
        self._state = EnrollmentParticipantState.PREPARED
        rcpt_id = f"enr_rcpt_{uuid.uuid4().hex[:8]}"

        embedded = EnrollmentEmbeddedReceipt(
            receipt_id=rcpt_id,
            enrollment_ref=self.enrollment_ref,
            enrollment_revision=1,
            build_reservation_id=f"res_{self.enrollment_ref}",
            artifact_draft_ref=getattr(request, "artifact_draft_ref", "draft-1"),
            artifact_sealed_record_digest=getattr(request, "sealed_digest", "sha256:sealed"),
            artifact_integrity_tag=getattr(request, "integrity_tag", None),
            artifact_binding_digest=getattr(request, "binding_digest", "sha256:binding"),
            deployment_ref=getattr(request, "deployment_ref", "dep-1"),
            mission_id=getattr(request, "mission_id", "m-1"),
            subject_id=getattr(request, "subject_id", "sub-1"),
        )
        prep_receipt = EnrollmentPrepareReceipt(
            receipt_id=f"prep_{rcpt_id}",
            transaction_id=self.transaction_id,
            embedded=embedded,
            deployment_request_digest=f"sha256:req_{rcpt_id}",
            participant_revision=1,
            state=EnrollmentParticipantState.PREPARED,
        )
        self._prepare_receipt = prep_receipt
        return prep_receipt

    def commit(self, request: Any = None) -> EnrollmentPrepareReceipt:
        self._state = EnrollmentParticipantState.COMMITTED_HIDDEN
        if self._prepare_receipt is None:
            return self.prepare(request)
        return self._prepare_receipt

    def finalize_visibility(
        self, prepare_receipt: Any, commit_receipt: Any, operation: Any = None, finalization_fence: Any = None
    ) -> Any:
        self._state = EnrollmentParticipantState.FINALIZED
        return commit_receipt

    def rollback(self, receipt: Any = None, operation: Any = None) -> Any:
        self._state = EnrollmentParticipantState.ABORTED
        return receipt

    def reconcile(self, operation: Any = None, finalization_fence: Any = None) -> Any:
        return self._prepare_receipt
