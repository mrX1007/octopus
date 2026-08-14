from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from typing import Any


from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlErrorCodeV1,
    ParticipantControlPhaseV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
)
from core.c2.control_models import calculate_receipt_digest, calculate_snapshot_digest


class C2DaemonResourceParticipant:
    """Resource participant managing transactions for C2 daemon resources with SQLite persistence."""

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
        if self.db_path == ":memory:":
            self._conn_uri = f"file:mem_res_{id(self)}?mode=memory&cache=shared"
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(
                self._conn_uri, uri=True, check_same_thread=False
            )
        else:
            self._conn_uri = self.db_path
            self._shared_conn = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn


    def _init_db(self) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS control_2pc_transactions (
                        participant_id TEXT NOT NULL,
                        transaction_id TEXT NOT NULL,
                        resource_ref TEXT NOT NULL,
                        resource_revision INTEGER NOT NULL,
                        phase TEXT NOT NULL,
                        action TEXT NOT NULL,
                        payload_schema_id TEXT,
                        payload_digest TEXT,
                        canonical_payload_b64u TEXT,
                        prepare_receipt_ref TEXT,
                        prepare_receipt_digest TEXT,
                        commit_receipt_ref TEXT,
                        commit_receipt_digest TEXT,
                        created_at_ms INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (participant_id, transaction_id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS control_resource_revisions (
                        resource_ref TEXT PRIMARY KEY,
                        revision INTEGER NOT NULL
                    )
                    """
                )

    def _get_resource_revision(self, conn: sqlite3.Connection, resource_ref: str) -> int:
        cur = conn.execute("SELECT revision FROM control_resource_revisions WHERE resource_ref = ?", (resource_ref,))
        row = cur.fetchone()
        return row[0] if row else 0

    def _set_resource_revision(self, conn: sqlite3.Connection, resource_ref: str, revision: int) -> None:
        conn.execute(
            """
            INSERT INTO control_resource_revisions (resource_ref, revision)
            VALUES (?, ?)
            ON CONFLICT(resource_ref) DO UPDATE SET revision = excluded.revision
            """,
            (resource_ref, revision),
        )

    def prepare(self, request: ParticipantControlRequestV1) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Prepare phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    current_rev = self._get_resource_revision(conn, res_ref)

                    if request.expected_resource_revision is not None and request.expected_resource_revision != current_rev:
                        conn.rollback()
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                            retryable=True,
                            detail_ref=f"Revision mismatch: expected {request.expected_resource_revision}, current {current_rev}",
                        )

                    cur = conn.execute(
                        "SELECT phase, prepare_receipt_ref, prepare_receipt_digest, payload_digest FROM control_2pc_transactions WHERE participant_id = ? AND transaction_id = ?",
                        (self.participant_id, tx_id),
                    )
                    existing = cur.fetchone()
                    if existing is not None:
                        phase, prep_ref, prep_dig, p_dig = existing
                        if p_dig != request.payload_digest:
                            conn.rollback()
                            return BoundedControlErrorV1(
                                reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                                retryable=False,
                                detail_ref="transaction_payload_mismatch",
                            )
                        # Idempotent prepare return
                        conn.rollback()
                        return ParticipantControlReceiptV1(
                            transaction_id=tx_id,
                            participant_id=self.participant_id,
                            action=request.action,
                            resource_ref=res_ref,
                            resource_revision=current_rev,
                            receipt_ref=prep_ref,
                            receipt_digest=prep_dig,
                            daemon_instance_id=self.daemon_instance_id,
                            result_payload_schema_id=request.payload_schema_id,
                            result_payload_digest=request.payload_digest,
                            result_payload_b64u=request.canonical_payload_b64u,
                        )

                    rcpt_ref = f"rcpt_prep_{uuid.uuid4().hex[:8]}"
                    rcpt_digest = calculate_receipt_digest(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        receipt_ref=rcpt_ref,
                        result_payload_digest=request.payload_digest,
                    )

                    conn.execute(
                        """
                        INSERT INTO control_2pc_transactions (
                            participant_id, transaction_id, resource_ref, resource_revision,
                            phase, action, payload_schema_id, payload_digest, canonical_payload_b64u,
                            prepare_receipt_ref, prepare_receipt_digest,
                            created_at_ms, updated_at_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self.participant_id,
                            tx_id,
                            res_ref,
                            current_rev,
                            ParticipantControlPhaseV1.PENDING.value,
                            request.action.value if hasattr(request.action, "value") else str(request.action),
                            request.payload_schema_id,
                            request.payload_digest,
                            request.canonical_payload_b64u,
                            rcpt_ref,
                            rcpt_digest,
                            now_ms,
                            now_ms,
                        ),
                    )
                    conn.commit()

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
                except Exception as exc:
                    conn.rollback()
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.INTERNAL_FAILURE,
                        retryable=False,
                        detail_ref=f"prepare_failed:{exc}",
                    )

    def commit(self, request: ParticipantControlRequestV1) -> ParticipantControlReceiptV1 | BoundedControlErrorV1:
        """Commit phase of 2PC transaction."""
        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    cur = conn.execute(
                        """
                        SELECT phase, resource_revision, payload_digest, commit_receipt_ref, commit_receipt_digest, canonical_payload_b64u
                        FROM control_2pc_transactions
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (self.participant_id, tx_id),
                    )
                    row = cur.fetchone()
                    if row is None:
                        conn.rollback()
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"No pending transaction found for tx {tx_id}",
                        )

                    phase_val, stored_rev, prep_pdig, comm_ref, comm_dig, stored_b64 = row
                    if phase_val in (ParticipantControlPhaseV1.COMMITTED_HIDDEN.value, ParticipantControlPhaseV1.FINALIZED_VISIBLE.value):
                        # Idempotent commit return
                        conn.rollback()
                        return ParticipantControlReceiptV1(
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

                    if phase_val != ParticipantControlPhaseV1.PENDING.value:
                        conn.rollback()
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"Transaction in phase {phase_val} cannot be committed",
                        )

                    if prep_pdig != request.payload_digest:
                        conn.rollback()
                        return BoundedControlErrorV1(
                            reason_code=C2ControlErrorCodeV1.IDEMPOTENCY_CONFLICT,
                            retryable=False,
                            detail_ref="commit_payload_mismatch",
                        )

                    current_rev = self._get_resource_revision(conn, res_ref)
                    new_rev = current_rev + 1
                    self._set_resource_revision(conn, res_ref, new_rev)

                    rcpt_ref = f"rcpt_commit_{uuid.uuid4().hex[:8]}"
                    rcpt_digest = calculate_receipt_digest(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        receipt_ref=rcpt_ref,
                        result_payload_digest=request.payload_digest,
                    )

                    conn.execute(
                        """
                        UPDATE control_2pc_transactions
                        SET phase = ?, resource_revision = ?, commit_receipt_ref = ?, commit_receipt_digest = ?, updated_at_ms = ?
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (
                            ParticipantControlPhaseV1.COMMITTED_HIDDEN.value,
                            new_rev,
                            rcpt_ref,
                            rcpt_digest,
                            now_ms,
                            self.participant_id,
                            tx_id,
                        ),
                    )
                    conn.commit()

                    return ParticipantControlReceiptV1(
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
                except Exception as exc:
                    conn.rollback()
                    return BoundedControlErrorV1(
                        reason_code=C2ControlErrorCodeV1.INTERNAL_FAILURE,
                        retryable=False,
                        detail_ref=f"commit_failed:{exc}",
                    )

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantControlReceiptV1,
        commit_receipt: ParticipantControlReceiptV1,
        operation: Any = None,
        finalization_fence: Any = None,
    ) -> ParticipantControlReceiptV1:
        """Finalize visibility of committed resource."""
        tx_id = commit_receipt.transaction_id
        now_ms = int(time.time() * 1000)

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE control_2pc_transactions
                    SET phase = ?, updated_at_ms = ?
                    WHERE participant_id = ? AND transaction_id = ?
                    """,
                    (ParticipantControlPhaseV1.FINALIZED_VISIBLE.value, now_ms, self.participant_id, tx_id),
                )
                conn.commit()

        return commit_receipt

    def rollback(self, receipt: ParticipantControlReceiptV1, operation: Any = None) -> ParticipantControlReceiptV1:
        """Abort/rollback a transaction."""
        tx_id = receipt.transaction_id
        now_ms = int(time.time() * 1000)

        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE control_2pc_transactions
                    SET phase = ?, updated_at_ms = ?
                    WHERE participant_id = ? AND transaction_id = ?
                    """,
                    (ParticipantControlPhaseV1.ABORTED.value, now_ms, self.participant_id, tx_id),
                )
                conn.commit()

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

    @property
    def _committed_resources(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT transaction_id, resource_ref, resource_revision, phase FROM control_2pc_transactions WHERE phase IN (?, ?)",
                    (ParticipantControlPhaseV1.COMMITTED_HIDDEN.value, ParticipantControlPhaseV1.FINALIZED_VISIBLE.value),
                ).fetchall()
                return {
                    row[0]: {
                        "resource_ref": row[1],
                        "revision": row[2],
                        "phase": ParticipantControlPhaseV1(row[3]),
                    }
                    for row in rows
                }

    @property
    def _pending_transactions(self) -> dict[str, Any]:
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT transaction_id, resource_ref, resource_revision, phase FROM control_2pc_transactions WHERE phase = ?",
                    (ParticipantControlPhaseV1.PENDING.value,),
                ).fetchall()
                return {
                    row[0]: {
                        "resource_ref": row[1],
                        "revision": row[2],
                        "phase": ParticipantControlPhaseV1(row[3]),
                    }
                    for row in rows
                }

    def reconcile(
        self, operation: Any = None, finalization_fence: Any = None
    ) -> ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
        """Query current state snapshot of the resource participant."""
        tx_id = getattr(operation, "transaction_id", None)
        if isinstance(operation, ParticipantControlRequestV1):
            tx_id = operation.authorization.transaction_id

        if not tx_id:
            snap_digest = calculate_snapshot_digest(
                transaction_id="query",
                participant_id=self.participant_id,
                phase=ParticipantControlPhaseV1.FINALIZED_VISIBLE.value,
                receipt_digest="none",
            )
            return ParticipantControlQuerySnapshotV1(
                transaction_id="query",
                participant_id=self.participant_id,
                resource_ref=f"resource:{self.participant_id}",
                resource_revision=0,
                phase=ParticipantControlPhaseV1.FINALIZED_VISIBLE,
                snapshot_digest=snap_digest,
                receipt_ref=None,
                receipt_digest=None,
                result_payload_schema_id=None,
                result_payload_digest=None,
            )


        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    SELECT resource_ref, resource_revision, phase, commit_receipt_ref, commit_receipt_digest,
                           prepare_receipt_ref, prepare_receipt_digest, payload_schema_id, payload_digest, canonical_payload_b64u
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

                res_ref, rev, phase_str, comm_ref, comm_dig, prep_ref, prep_dig, sch_id, p_dig, b64u = row
                phase = ParticipantControlPhaseV1(phase_str)
                receipt_ref = comm_ref or prep_ref
                receipt_digest = comm_dig or prep_dig

                snap_digest = calculate_snapshot_digest(
                    transaction_id=tx_id,
                    participant_id=self.participant_id,
                    phase=phase.value,
                    receipt_digest=receipt_digest,
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

