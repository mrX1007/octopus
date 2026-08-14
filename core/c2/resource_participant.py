from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from core.c2.control_auth import AuthenticatedControlPrincipal
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlErrorCodeV1,
    ParticipantControlPhaseV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.control_migrations import apply_control_migrations
from core.c2.control_models import (
    calculate_receipt_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
)


class C2DaemonResourceParticipant:
    """Resource participant managing transactions for C2 daemon resources with durable SQLite persistence."""

    def __init__(
        self,
        participant_id: str = "daemon_resource_participant",
        daemon_instance_id: str = "daemon_inst_0",
        db_path: str = ":memory:",
    ) -> None:
        self.participant_id = participant_id
        self.daemon_instance_id = daemon_instance_id
        self.participant_kind = "cross_process_resource"
        self.db_path = db_path
        self._lock = threading.RLock()
        self._pending_transactions: dict[str, Any] = {}
        self._committed_resources: dict[str, Any] = {}
        if self.db_path == ":memory:":
            self._conn_uri = f"file:mem_res_{id(self)}?mode=memory&cache=shared"
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(
                self._conn_uri, uri=True, check_same_thread=False
            )
        else:
            self._conn_uri = self.db_path
            self._shared_conn = None
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._connection() as conn:
            apply_control_migrations(conn)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self._shared_conn is not None:
            conn = sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def close(self) -> None:
        with self._lock:
            if self._shared_conn is not None:
                self._shared_conn.close()
                self._shared_conn = None

    def _get_resource_revision(self, conn: sqlite3.Connection, resource_ref: str) -> int:
        cur = conn.execute("SELECT revision FROM control_resource_revisions WHERE resource_ref = ?", (resource_ref,))
        row = cur.fetchone()
        return row[0] if row else 0

    def prepare(
        self,
        request: ParticipantControlRequestV1,
        principal: AuthenticatedControlPrincipal | None = None,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Prepare phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)
        operator_id = principal.operator_id if principal else ""

        intent_digest = calculate_transaction_intent_digest(
            participant_id=self.participant_id,
            resource_ref=res_ref,
            mission_id=request.authorization.mission_id,
            subject_id=request.authorization.subject_id,
            operation_kind=request.action.value,
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
        )

        with self._lock, self._connection() as conn:
            try:
                # 1. Query existing transaction FIRST
                cur = conn.execute(
                    """
                    SELECT phase, prepare_receipt_ref, prepare_receipt_digest, payload_digest,
                           operator_id, subject_id, mission_id, prepared_base_revision
                    FROM control_2pc_transactions
                    WHERE participant_id = ? AND transaction_id = ?
                    """,
                    (self.participant_id, tx_id),
                )
                existing = cur.fetchone()

                if existing is not None:
                    phase, prep_ref, prep_dig, p_dig, _op_id, subj_id, mis_id, base_rev = existing
                    if (
                        p_dig != request.payload_digest
                        or subj_id != request.authorization.subject_id
                        or mis_id != request.authorization.mission_id
                    ):
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                            retryable=False,
                            detail_ref="transaction_identity_or_payload_mismatch",
                        )

                    if phase != ParticipantControlPhaseV1.PENDING.value:
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"Transaction already in phase {phase}",
                        )

                    # Idempotent prepare receipt return
                    return ParticipantControlReceiptV1(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        action=request.action,
                        resource_ref=res_ref,
                        resource_revision=base_rev,
                        receipt_ref=prep_ref,
                        receipt_digest=prep_dig,
                        daemon_instance_id=self.daemon_instance_id,
                        result_payload_schema_id=request.payload_schema_id,
                        result_payload_digest=request.payload_digest,
                        result_payload_b64u=request.canonical_payload_b64u,
                    )

                # 2. If new: validate expected revision
                current_rev = self._get_resource_revision(conn, res_ref)
                if request.expected_resource_revision is not None and request.expected_resource_revision != current_rev:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                        retryable=True,
                        detail_ref=f"Revision mismatch: expected {request.expected_resource_revision}, current {current_rev}",
                    )

                # Ensure resource revision row exists
                conn.execute(
                    "INSERT OR IGNORE INTO control_resource_revisions (resource_ref, revision) VALUES (?, ?)",
                    (res_ref, current_rev),
                )

                rcpt_ref = f"rcpt_prep_{uuid.uuid4().hex[:8]}"
                rcpt_digest = calculate_receipt_digest(
                    transaction_id=tx_id,
                    participant_id=self.participant_id,
                    action=request.action.value,
                    resource_ref=res_ref,
                    resource_revision=current_rev,
                    receipt_ref=rcpt_ref,
                    daemon_instance_id=self.daemon_instance_id,
                    result_payload_schema_id=request.payload_schema_id,
                    result_payload_digest=request.payload_digest,
                )

                conn.execute(
                    """
                    INSERT INTO control_2pc_transactions (
                        participant_id, transaction_id, operator_id, key_id, key_revision,
                        subject_id, mission_id, operation_kind, transaction_intent_digest,
                        resource_ref, resource_revision, phase, action, payload_schema_id,
                        payload_digest, canonical_payload_b64u, prepared_request_digest,
                        prepared_base_revision, prepare_receipt_ref, prepare_receipt_digest,
                        created_at_ms, updated_at_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.participant_id,
                        tx_id,
                        operator_id,
                        request.authorization.key_id,
                        request.authorization.coordinator_revision,
                        request.authorization.subject_id,
                        request.authorization.mission_id,
                        request.action.value,
                        intent_digest,
                        res_ref,
                        current_rev,
                        ParticipantControlPhaseV1.PENDING.value,
                        request.action.value,
                        request.payload_schema_id,
                        request.payload_digest,
                        request.canonical_payload_b64u,
                        request.authorization.request_digest,
                        current_rev,
                        rcpt_ref,
                        rcpt_digest,
                        now_ms,
                        now_ms,
                    ),
                )

                res = ParticipantControlReceiptV1(
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
                self._pending_transactions[tx_id] = {
                    "phase": ParticipantControlPhaseV1.PENDING,
                    "request": request,
                    "receipt": res,
                }
                return res
            except Exception as exc:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"prepare_failed:{exc}",
                )

    def commit(
        self,
        request: ParticipantControlRequestV1,
        principal: AuthenticatedControlPrincipal | None = None,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Commit phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock, self._connection() as conn:
            try:
                cur = conn.execute(
                    """
                    SELECT phase, resource_revision, payload_digest, commit_receipt_ref,
                           commit_receipt_digest, canonical_payload_b64u, prepare_receipt_ref,
                           prepare_receipt_digest, prepared_base_revision
                    FROM control_2pc_transactions
                    WHERE participant_id = ? AND transaction_id = ?
                    """,
                    (self.participant_id, tx_id),
                )
                row = cur.fetchone()
                if row is None:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                        retryable=False,
                        detail_ref=f"transaction_not_found:{tx_id}",
                    )

                (
                    phase_val,
                    stored_rev,
                    _prep_pdig,
                    comm_ref,
                    comm_dig,
                    stored_b64,
                    prep_ref,
                    prep_dig,
                    base_rev,
                ) = row

                if phase_val in (
                    ParticipantControlPhaseV1.COMMITTED_HIDDEN.value,
                    ParticipantControlPhaseV1.FINALIZED_VISIBLE.value,
                ):
                    # Idempotent commit return
                    res = ParticipantControlReceiptV1(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        action=request.action,
                        resource_ref=res_ref,
                        resource_revision=stored_rev,
                        receipt_ref=comm_ref,
                        receipt_digest=comm_dig,
                        daemon_instance_id=self.daemon_instance_id,
                        result_payload_schema_id=request.payload_schema_id,
                        result_payload_digest=request.payload_digest,
                        result_payload_b64u=stored_b64,
                    )
                    self._pending_transactions.pop(tx_id, None)
                    if tx_id not in self._committed_resources:
                        self._committed_resources[tx_id] = {
                            "phase": ParticipantControlPhaseV1.COMMITTED_HIDDEN,
                            "request": request,
                            "receipt": res,
                        }
                    return res

                if phase_val != ParticipantControlPhaseV1.PENDING.value:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                        retryable=False,
                        detail_ref=f"Transaction in phase {phase_val} cannot be committed",
                    )

                # Validate prepare receipt chain
                if request.prior_receipt_ref and request.prior_receipt_ref != prep_ref:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                        retryable=False,
                        detail_ref="prior_receipt_ref_mismatch",
                    )
                if request.prior_receipt_digest and request.prior_receipt_digest != prep_dig:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                        retryable=False,
                        detail_ref="prior_receipt_digest_mismatch",
                    )

                # Perform atomic CAS on resource revision
                new_rev = base_rev + 1
                cas_cur = conn.execute(
                    "UPDATE control_resource_revisions SET revision = ? WHERE resource_ref = ? AND revision = ?",
                    (new_rev, res_ref, base_rev),
                )
                if cas_cur.rowcount != 1:
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                        retryable=True,
                        detail_ref="concurrent_revision_conflict",
                    )

                rcpt_ref = f"rcpt_commit_{uuid.uuid4().hex[:8]}"
                rcpt_digest = calculate_receipt_digest(
                    transaction_id=tx_id,
                    participant_id=self.participant_id,
                    action=request.action.value,
                    resource_ref=res_ref,
                    resource_revision=new_rev,
                    receipt_ref=rcpt_ref,
                    daemon_instance_id=self.daemon_instance_id,
                    result_payload_schema_id=request.payload_schema_id,
                    result_payload_digest=request.payload_digest,
                )

                conn.execute(
                    """
                    UPDATE control_2pc_transactions
                    SET phase = ?, resource_revision = ?, commit_receipt_ref = ?,
                        commit_receipt_digest = ?, commit_request_digest = ?, updated_at_ms = ?
                    WHERE participant_id = ? AND transaction_id = ?
                    """,
                    (
                        ParticipantControlPhaseV1.COMMITTED_HIDDEN.value,
                        new_rev,
                        rcpt_ref,
                        rcpt_digest,
                        request.authorization.request_digest,
                        now_ms,
                        self.participant_id,
                        tx_id,
                    ),
                )

                res = ParticipantControlReceiptV1(
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
                self._pending_transactions.pop(tx_id, None)
                self._committed_resources[tx_id] = {
                    "phase": ParticipantControlPhaseV1.COMMITTED_HIDDEN,
                    "request": request,
                    "receipt": res,
                }
                return res
            except Exception as exc:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"commit_failed:{exc}",
                )

    def finalize_visibility(
        self,
        request_or_receipt: ParticipantControlRequestV1 | ParticipantControlReceiptV1,
        principal: AuthenticatedControlPrincipal | None = None,
        operation: Any = None,
        finalization_fence: Any = None,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Finalize visibility of committed resource."""
        if isinstance(request_or_receipt, ParticipantControlRequestV1):
            tx_id = request_or_receipt.authorization.transaction_id
            prior_ref = request_or_receipt.prior_receipt_ref
            prior_dig = request_or_receipt.prior_receipt_digest
            req_dig = request_or_receipt.authorization.request_digest
            action = request_or_receipt.action
        else:
            if isinstance(principal, ParticipantControlReceiptV1):
                tx_id = principal.transaction_id
                prior_ref = principal.receipt_ref
                prior_dig = principal.receipt_digest
                req_dig = ""
                action = principal.action
            elif isinstance(operation, ParticipantControlReceiptV1):
                tx_id = operation.transaction_id
                prior_ref = operation.receipt_ref
                prior_dig = operation.receipt_digest
                req_dig = ""
                action = operation.action
            else:
                tx_id = request_or_receipt.transaction_id
                prior_ref = request_or_receipt.receipt_ref
                prior_dig = request_or_receipt.receipt_digest
                req_dig = ""
                action = request_or_receipt.action

        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock, self._connection() as conn:
            cur = conn.execute(
                """
                SELECT phase, resource_revision, commit_receipt_ref, commit_receipt_digest,
                       payload_schema_id, payload_digest, canonical_payload_b64u,
                       finalize_receipt_ref, finalize_receipt_digest
                FROM control_2pc_transactions
                WHERE participant_id = ? AND transaction_id = ?
                """,
                (self.participant_id, tx_id),
            )
            row = cur.fetchone()
            if row is None:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                    retryable=False,
                    detail_ref=f"transaction_not_found:{tx_id}",
                )

            (
                phase,
                rev,
                comm_ref,
                comm_dig,
                sch_id,
                p_dig,
                b64u,
                fin_ref,
                fin_dig,
            ) = row

            if phase == ParticipantControlPhaseV1.FINALIZED_VISIBLE.value:
                # Idempotent return
                res = ParticipantControlReceiptV1(
                    transaction_id=tx_id,
                    participant_id=self.participant_id,
                    action=action,
                    resource_ref=res_ref,
                    resource_revision=rev,
                    receipt_ref=fin_ref or comm_ref,
                    receipt_digest=fin_dig or comm_dig,
                    daemon_instance_id=self.daemon_instance_id,
                    result_payload_schema_id=sch_id,
                    result_payload_digest=p_dig,
                    result_payload_b64u=b64u,
                )
                if tx_id in self._committed_resources:
                    self._committed_resources[tx_id]["phase"] = ParticipantControlPhaseV1.FINALIZED_VISIBLE
                return res

            if phase != ParticipantControlPhaseV1.COMMITTED_HIDDEN.value:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                    retryable=False,
                    detail_ref=f"Cannot finalize transaction in phase {phase}",
                )

            if prior_ref and prior_ref != comm_ref:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                    retryable=False,
                    detail_ref="prior_receipt_ref_mismatch",
                )
            if prior_dig and prior_dig != comm_dig:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                    retryable=False,
                    detail_ref="prior_receipt_digest_mismatch",
                )

            rcpt_ref = f"rcpt_fin_{uuid.uuid4().hex[:8]}"
            rcpt_digest = calculate_receipt_digest(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                action=action.value if hasattr(action, "value") else str(action),
                resource_ref=res_ref,
                resource_revision=rev,
                receipt_ref=rcpt_ref,
                daemon_instance_id=self.daemon_instance_id,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
            )

            conn.execute(
                """
                UPDATE control_2pc_transactions
                SET phase = ?, finalize_receipt_ref = ?, finalize_receipt_digest = ?,
                    finalize_request_digest = ?, updated_at_ms = ?
                WHERE participant_id = ? AND transaction_id = ?
                """,
                (
                    ParticipantControlPhaseV1.FINALIZED_VISIBLE.value,
                    rcpt_ref,
                    rcpt_digest,
                    req_dig,
                    now_ms,
                    self.participant_id,
                    tx_id,
                ),
            )

            res = ParticipantControlReceiptV1(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                action=action,
                resource_ref=res_ref,
                resource_revision=rev,
                receipt_ref=rcpt_ref,
                receipt_digest=rcpt_digest,
                daemon_instance_id=self.daemon_instance_id,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
                result_payload_b64u=b64u,
            )
            if tx_id in self._committed_resources:
                self._committed_resources[tx_id]["phase"] = ParticipantControlPhaseV1.FINALIZED_VISIBLE
            return res

    def rollback(
        self,
        request_or_receipt: ParticipantControlRequestV1 | ParticipantControlReceiptV1,
        principal: AuthenticatedControlPrincipal | None = None,
        operation: Any = None,
    ) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Abort/rollback a transaction."""
        if isinstance(request_or_receipt, ParticipantControlRequestV1):
            tx_id = request_or_receipt.authorization.transaction_id
            action = request_or_receipt.action
        else:
            tx_id = request_or_receipt.transaction_id
            action = request_or_receipt.action

        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock, self._connection() as conn:
            cur = conn.execute(
                """
                SELECT phase, resource_revision, payload_schema_id, payload_digest, canonical_payload_b64u
                FROM control_2pc_transactions
                WHERE participant_id = ? AND transaction_id = ?
                """,
                (self.participant_id, tx_id),
            )
            row = cur.fetchone()
            if row is None:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                    retryable=False,
                    detail_ref=f"transaction_not_found:{tx_id}",
                )

            _phase, rev, sch_id, p_dig, b64u = row

            rcpt_ref = f"rcpt_abort_{uuid.uuid4().hex[:8]}"
            rcpt_digest = calculate_receipt_digest(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                action=action.value if hasattr(action, "value") else str(action),
                resource_ref=res_ref,
                resource_revision=rev,
                receipt_ref=rcpt_ref,
                daemon_instance_id=self.daemon_instance_id,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
            )

            conn.execute(
                """
                UPDATE control_2pc_transactions
                SET phase = ?, updated_at_ms = ?
                WHERE participant_id = ? AND transaction_id = ?
                """,
                (ParticipantControlPhaseV1.ABORTED.value, now_ms, self.participant_id, tx_id),
            )

            self._pending_transactions.pop(tx_id, None)
            self._committed_resources.pop(tx_id, None)

            return ParticipantControlReceiptV1(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                action=action,
                resource_ref=res_ref,
                resource_revision=rev,
                receipt_ref=rcpt_ref,
                receipt_digest=rcpt_digest,
                daemon_instance_id=self.daemon_instance_id,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
                result_payload_b64u=b64u,
            )

    def reconcile(
        self,
        operation: Any = None,
        finalization_fence: Any = None,
    ) -> ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Query current state snapshot of the resource participant."""
        tx_id = getattr(operation, "transaction_id", None)
        if isinstance(operation, ParticipantControlRequestV1):
            tx_id = operation.authorization.transaction_id

        if not tx_id:
            with self._lock, self._connection() as conn:
                current_rev = self._get_resource_revision(conn, f"resource:{self.participant_id}")
            snap_digest = calculate_snapshot_digest(
                transaction_id="query",
                participant_id=self.participant_id,
                phase=ParticipantControlPhaseV1.FINALIZED_VISIBLE.value,
                receipt_digest="none",
                resource_ref=f"resource:{self.participant_id}",
                resource_revision=current_rev,
            )
            return ParticipantControlQuerySnapshotV1(
                transaction_id="query",
                participant_id=self.participant_id,
                resource_ref=f"resource:{self.participant_id}",
                resource_revision=current_rev,
                phase=ParticipantControlPhaseV1.FINALIZED_VISIBLE,
                snapshot_digest=snap_digest,
                receipt_ref=None,
                receipt_digest=None,
                result_payload_schema_id=None,
                result_payload_digest=None,
            )

        with self._lock, self._connection() as conn:
            cur = conn.execute(
                """
                SELECT resource_ref, resource_revision, phase, commit_receipt_ref,
                       commit_receipt_digest, prepare_receipt_ref, prepare_receipt_digest,
                       finalize_receipt_ref, finalize_receipt_digest,
                       payload_schema_id, payload_digest, canonical_payload_b64u
                FROM control_2pc_transactions
                WHERE participant_id = ? AND transaction_id = ?
                """,
                (self.participant_id, tx_id),
            )

            row = cur.fetchone()
            if row is None:
                return BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
                    retryable=False,
                    detail_ref=f"transaction_not_found:{tx_id}",
                )

            (
                res_ref,
                rev,
                phase_str,
                comm_ref,
                comm_dig,
                prep_ref,
                prep_dig,
                fin_ref,
                fin_dig,
                sch_id,
                p_dig,
                b64u,
            ) = row
            phase = ParticipantControlPhaseV1(phase_str)
            receipt_ref = fin_ref or comm_ref or prep_ref
            receipt_digest = fin_dig or comm_dig or prep_dig

            snap_digest = calculate_snapshot_digest(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                phase=phase.value,
                receipt_digest=receipt_digest,
                receipt_ref=receipt_ref,
                resource_ref=res_ref,
                resource_revision=rev,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
            )

            return ParticipantControlQuerySnapshotV1(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                resource_ref=res_ref,
                resource_revision=rev,
                phase=phase,
                receipt_ref=receipt_ref,
                receipt_digest=receipt_digest,
                snapshot_digest=snap_digest,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
                result_payload_b64u=b64u,
            )


__all__ = [
    "C2DaemonResourceParticipant",
]
