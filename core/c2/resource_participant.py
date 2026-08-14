"""Resource participant."""
from __future__ import annotations

import uuid
from typing import Any, Dict, Optional
from core.c2.control_commands import (
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlRequestV1,
    ParticipantControlReceiptV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlPhaseV1,
    BoundedControlErrorV1,
)
from core.c2.control_models import calculate_receipt_digest, calculate_snapshot_digest


class C2DaemonResourceParticipant:
    """Resource participant managing transactions for C2 daemon resources."""

    def __init__(
        self,
        participant_id: str = "daemon_resource_participant",
        daemon_instance_id: str = "daemon_inst_0",
    ) -> None:
        self.participant_id = participant_id
        self.daemon_instance_id = daemon_instance_id
        self.participant_kind = "cross_process_resource"
        self._pending_transactions: Dict[str, Dict[str, Any]] = {}
        self._committed_resources: Dict[str, Dict[str, Any]] = {}
        self._revisions: Dict[str, int] = {}

    def prepare(
        self, request: ParticipantControlRequestV1
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Prepare phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{request.authorization.participant_id}"

        # Check expected revision if specified
        current_rev = self._revisions.get(res_ref, 0)
        if (
            request.expected_resource_revision is not None
            and request.expected_resource_revision != current_rev
        ):
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                retryable=True,
                detail_ref=f"Revision mismatch: expected {request.expected_resource_revision}, current {current_rev}",
            )

        rcpt_ref = f"rcpt_prep_{uuid.uuid4().hex[:8]}"
        rcpt_digest = calculate_receipt_digest(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            receipt_ref=rcpt_ref,
            result_payload_digest=request.payload_digest,
        )

        self._pending_transactions[tx_id] = {
            "request": request,
            "phase": ParticipantControlPhaseV1.PENDING,
            "resource_ref": res_ref,
            "prepare_receipt_ref": rcpt_ref,
            "prepare_receipt_digest": rcpt_digest,
        }

        return ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            action=request.action,
            resource_ref=res_ref,
            resource_revision=current_rev,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_digest,
            daemon_instance_id=self.daemon_instance_id,
            result_payload_schema_id=request.payload_schema_id,
            result_payload_digest=request.payload_digest,
            result_payload_b64u=request.canonical_payload_b64u,
        )

    def commit(
        self, request: ParticipantControlRequestV1
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Commit phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        if tx_id in self._committed_resources:
            return self._committed_resources[tx_id]["receipt"]

        pending = self._pending_transactions.pop(tx_id, None)

        if pending is None:
            return BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                retryable=False,
                detail_ref=f"No pending transaction found for tx {tx_id}",
            )

        res_ref = pending["resource_ref"]
        new_rev = self._revisions.get(res_ref, 0) + 1
        self._revisions[res_ref] = new_rev

        rcpt_ref = f"rcpt_commit_{uuid.uuid4().hex[:8]}"
        rcpt_digest = calculate_receipt_digest(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            receipt_ref=rcpt_ref,
            result_payload_digest=request.payload_digest,
        )

        receipt = ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            action=request.action,
            resource_ref=res_ref,
            resource_revision=new_rev,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_digest,
            daemon_instance_id=self.daemon_instance_id,
            result_payload_schema_id=request.payload_schema_id,
            result_payload_digest=request.payload_digest,
            result_payload_b64u=request.canonical_payload_b64u,
        )

        pending["phase"] = ParticipantControlPhaseV1.COMMITTED_HIDDEN
        pending["receipt"] = receipt
        self._committed_resources[tx_id] = pending

        return receipt

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantControlReceiptV1,
        commit_receipt: ParticipantControlReceiptV1,
        operation: Any = None,
        finalization_fence: Any = None,
    ) -> ParticipantControlReceiptV1:
        """Finalize visibility of committed resource."""
        tx_id = commit_receipt.transaction_id
        pending = self._committed_resources.get(tx_id)
        if pending is not None:
            pending["phase"] = ParticipantControlPhaseV1.FINALIZED_VISIBLE

        return commit_receipt

    def rollback(
        self, receipt: ParticipantControlReceiptV1, operation: Any = None
    ) -> ParticipantControlReceiptV1:
        """Abort/rollback a transaction."""
        tx_id = receipt.transaction_id
        self._pending_transactions.pop(tx_id, None)
        committed = self._committed_resources.get(tx_id)
        if committed is not None:
            committed["phase"] = ParticipantControlPhaseV1.ABORTED

        rcpt_ref = f"rcpt_abort_{uuid.uuid4().hex[:8]}"
        rcpt_digest = calculate_receipt_digest(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            receipt_ref=rcpt_ref,
            result_payload_digest=receipt.result_payload_digest,
        )

        return ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            action=receipt.action,
            resource_ref=receipt.resource_ref,
            resource_revision=receipt.resource_revision,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_digest,
            daemon_instance_id=self.daemon_instance_id,
            result_payload_schema_id=receipt.result_payload_schema_id,
            result_payload_digest=receipt.result_payload_digest,
            result_payload_b64u=receipt.result_payload_b64u,
        )

    def reconcile(
        self, operation: Any = None, finalization_fence: Any = None
    ) -> ParticipantControlQuerySnapshotV1:
        """Query current state snapshot of the resource participant."""
        tx_id = getattr(operation, "transaction_id", "tx_reconcile")
        res_ref = f"resource:{self.participant_id}"
        rev = self._revisions.get(res_ref, 0)
        phase = ParticipantControlPhaseV1.FINALIZED_VISIBLE

        snap_digest = calculate_snapshot_digest(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            phase=phase.value,
        )

        return ParticipantControlQuerySnapshotV1(
            transaction_id=tx_id,
            participant_id=self.participant_id,
            resource_ref=res_ref,
            resource_revision=rev,
            phase=phase,
            receipt_ref=None,
            receipt_digest=None,
            snapshot_digest=snap_digest,
            result_payload_schema_id=None,
            result_payload_digest=None,
            result_payload_b64u=None,
        )

