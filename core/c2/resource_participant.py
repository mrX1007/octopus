"""Deterministic 2PC resource participant with durable SQLite persistence and failpoints (§14.4-§14.6)."""

from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum
from typing import Any

from core.c2.control_auth import (
    AuthorityFence,
    VerifiedMutationAuthority,
)
from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlPhaseV2,
    ParticipantControlQuerySnapshotV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
)
from core.c2.control_migrations import apply_control_migrations
from core.c2.control_models import (
    calculate_receipt_digest,
    calculate_snapshot_digest,
    calculate_transaction_intent_digest,
)


class TransactionFailpoint(str, Enum):
    AFTER_BEGIN = "after_begin"
    AFTER_CAS = "after_cas"
    AFTER_PHASE_PERSIST = "after_phase_persist"
    AFTER_RECEIPT_PERSIST = "after_receipt_persist"


def _extract_and_validate_authority(
    authority: Any,
    request_or_receipt: Any,
    participant_id: str,
) -> tuple[VerifiedMutationAuthority | None, BoundedControlErrorV2 | None]:
    if authority is None or (
        type(authority) is not VerifiedMutationAuthority and not isinstance(authority, VerifiedMutationAuthority)
    ):
        return None, BoundedControlErrorV2(
            reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
            retryable=False,
            detail_ref="mandatory_verified_mutation_authority_required",
        )

    if isinstance(request_or_receipt, ParticipantControlRequestV2):
        tx_id = request_or_receipt.authorization.transaction_id
        if authority.transaction_id and authority.transaction_id != tx_id:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_transaction_mismatch",
            )
        if authority.participant_id and authority.participant_id != participant_id:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_participant_mismatch",
            )
        req_act = getattr(request_or_receipt.action, "value", str(request_or_receipt.action))
        if authority.action_id and authority.action_id != req_act:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_action_mismatch",
            )
        if (
            authority.mission_id != request_or_receipt.authorization.mission_id
            or authority.subject_id != request_or_receipt.authorization.subject_id
        ):
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_scope_mismatch",
            )
        if authority.request_digest != request_or_receipt.authorization.request_digest:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_request_digest_mismatch",
            )
    elif isinstance(request_or_receipt, ParticipantControlReceiptV2):
        tx_id = request_or_receipt.transaction_id
        if authority.transaction_id and authority.transaction_id != tx_id:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_transaction_mismatch",
            )
        if authority.participant_id and authority.participant_id != participant_id:
            return None, BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                retryable=False,
                detail_ref="authority_participant_mismatch",
            )

    return authority, None


class C2DaemonResourceParticipant:
    """Resource participant managing transactions for C2 daemon resources with atomic 2PC state machine."""

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
        self._active_failpoint: TransactionFailpoint | None = None
        self._failpoint_exception: Exception | None = None

        if self.db_path == ":memory:":
            self._conn_uri = f"file:mem_res_{id(self)}?mode=memory&cache=shared"
            self._shared_conn: sqlite3.Connection | None = sqlite3.connect(
                self._conn_uri, uri=True, check_same_thread=False
            )
        else:
            self._conn_uri = self.db_path
            self._shared_conn = None
        self._init_db()

    def set_failpoint(
        self,
        failpoint: TransactionFailpoint | None,
        exception: Exception | None = None,
    ) -> None:
        """Inject a deterministic failpoint for rollback/crash recovery testing."""
        self._active_failpoint = failpoint
        self._failpoint_exception = exception or RuntimeError(f"failpoint_triggered:{failpoint}")

    def clear_failpoints(self) -> None:
        """Clear all active failpoints."""
        self._active_failpoint = None
        self._failpoint_exception = None

    def _trigger_failpoint(self, failpoint: TransactionFailpoint) -> None:
        if self._active_failpoint == failpoint:
            exc = self._failpoint_exception or RuntimeError(f"failpoint_triggered:{failpoint}")
            raise exc

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

    @contextmanager
    def _immediate_transaction(self) -> Iterator[sqlite3.Connection]:
        """Open a connection and issue BEGIN IMMEDIATE for atomic 2PC mutations."""
        if self._shared_conn is not None:
            conn = sqlite3.connect(self._conn_uri, uri=True, timeout=30.0, check_same_thread=False)
        else:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.isolation_level = None
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(Exception):
                conn.execute("ROLLBACK")
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

    def recover_startup_state(self) -> list[str]:
        """Scan and quarantine any ambiguous unfinalized transactions at startup without guessing."""
        quarantined: list[str] = []
        now_ms = int(time.time() * 1000)
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                """
                SELECT transaction_id, phase FROM control_2pc_transactions
                WHERE participant_id = ? AND phase IN ('prepared', 'pending', 'committed_hidden', 'recovery_required')
                """,
                (self.participant_id,),
            ).fetchall()
            for tx_id, phase in rows:
                if phase in ("prepared", "pending", "committed_hidden"):
                    conn.execute(
                        """
                        UPDATE control_2pc_transactions
                        SET phase = ?, updated_at_ms = ?
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (
                            ParticipantControlPhaseV2.RECOVERY_REQUIRED.value,
                            now_ms,
                            self.participant_id,
                            tx_id,
                        ),
                    )
                    quarantined.append(tx_id)
                elif phase == "recovery_required":
                    quarantined.append(tx_id)
        return quarantined

    def prepare(
        self,
        request: ParticipantControlRequestV2,
        authority_or_principal: Any = None,
        resolved_key: Any = None,
        authority: Any = None,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Prepare phase of 2PC transaction."""
        passed_auth = authority if authority is not None else authority_or_principal
        auth, auth_err = _extract_and_validate_authority(passed_auth, request, self.participant_id)
        if auth_err is not None:
            return auth_err
        assert auth is not None

        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)
        operator_id = auth.operator_id

        intent_digest = calculate_transaction_intent_digest(
            participant_id=self.participant_id,
            resource_ref=res_ref,
            mission_id=request.authorization.mission_id,
            subject_id=request.authorization.subject_id,
            operation_kind="c2_resource",
            payload_schema_id=request.payload_schema_id,
            payload_digest=request.payload_digest,
        )

        with self._lock:
            try:
                with self._immediate_transaction() as conn:
                    self._trigger_failpoint(TransactionFailpoint.AFTER_BEGIN)

                    # TOCTOU Authority Fence
                    try:
                        AuthorityFence.verify_current(conn, auth)
                    except PermissionError as exc:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                            retryable=False,
                            detail_ref=f"authority_fence_failed:{exc}",
                        )

                    # 1. Query existing transaction FIRST
                    cur = conn.execute(
                        """
                        SELECT phase, prepare_receipt_ref, prepare_receipt_digest, payload_digest,
                               operator_id, subject_id, mission_id, prepared_base_revision,
                               prepare_request_digest, transaction_intent_digest
                        FROM control_2pc_transactions
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (self.participant_id, tx_id),
                    )
                    existing = cur.fetchone()

                    if existing is not None:
                        (
                            phase,
                            prep_ref,
                            prep_dig,
                            p_dig,
                            op_id,
                            subj_id,
                            mis_id,
                            base_rev,
                            prep_req_dig,
                            stored_intent_dig,
                        ) = existing

                        # Idempotency check: same request digest and same intent digest
                        if (
                            prep_req_dig != request.authorization.request_digest
                            or stored_intent_dig != intent_digest
                            or p_dig != request.payload_digest
                            or subj_id != request.authorization.subject_id
                            or mis_id != request.authorization.mission_id
                            or (operator_id and op_id != operator_id)
                        ):
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                                retryable=False,
                                detail_ref="transaction_identity_or_payload_mismatch",
                            )

                        if phase not in (
                            ParticipantControlPhaseV2.PREPARED.value,
                            "pending",
                        ):
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                                retryable=False,
                                detail_ref=f"Transaction already in phase {phase}",
                            )

                        # Idempotent prepare receipt return
                        return ParticipantControlReceiptV2(
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
                    if (
                        request.expected_resource_revision is not None
                        and request.expected_resource_revision != current_rev
                    ):
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                            retryable=True,
                            detail_ref=f"revision_mismatch: expected {request.expected_resource_revision}, current {current_rev}",
                        )

                    # Ensure resource revision row exists
                    conn.execute(
                        """
                        INSERT INTO control_resource_revisions (resource_ref, revision, updated_at_ms)
                        VALUES (?, ?, ?)
                        ON CONFLICT(resource_ref) DO NOTHING
                        """,
                        (res_ref, current_rev, now_ms),
                    )

                    rcpt_ref = f"rcpt_prep_{uuid.uuid4().hex[:8]}"
                    rcpt_digest = calculate_receipt_digest(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        action=request.action.value if hasattr(request.action, "value") else str(request.action),
                        resource_ref=res_ref,
                        resource_revision=current_rev,
                        receipt_ref=rcpt_ref,
                        daemon_instance_id=self.daemon_instance_id,
                        result_payload_schema_id=request.payload_schema_id,
                        result_payload_digest=request.payload_digest,
                    )

                    key_rev = auth.key_revision

                    conn.execute(
                        """
                        INSERT INTO control_2pc_transactions (
                            transaction_id, participant_id, operator_id, key_id, key_revision,
                            subject_id, mission_id, action, resource_ref, resource_revision,
                            phase, payload_schema_id, payload_digest, canonical_payload_b64u,
                            transaction_intent_digest, prepared_base_revision,
                            prepare_request_digest, prepare_receipt_ref, prepare_receipt_digest,
                            created_at_ms, updated_at_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tx_id,
                            self.participant_id,
                            operator_id,
                            request.authorization.key_id,
                            key_rev,
                            request.authorization.subject_id,
                            request.authorization.mission_id,
                            request.action.value if hasattr(request.action, "value") else str(request.action),
                            res_ref,
                            current_rev,
                            ParticipantControlPhaseV2.PREPARED.value,
                            request.payload_schema_id,
                            request.payload_digest,
                            request.canonical_payload_b64u,
                            intent_digest,
                            current_rev,
                            request.authorization.request_digest,
                            rcpt_ref,
                            rcpt_digest,
                            now_ms,
                            now_ms,
                        ),
                    )

                    self._trigger_failpoint(TransactionFailpoint.AFTER_RECEIPT_PERSIST)

                    res = ParticipantControlReceiptV2(
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
                        "phase": ParticipantControlPhaseV2.PREPARED,
                        "request": request,
                        "receipt": res,
                    }
                    return res
            except Exception as exc:
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"prepare_failed:{exc}",
                )

    def commit(
        self,
        request: ParticipantControlRequestV2,
        authority_or_principal: Any = None,
        resolved_key: Any = None,
        authority: Any = None,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Commit phase of 2PC transaction."""
        passed_auth = authority if authority is not None else authority_or_principal
        auth, auth_err = _extract_and_validate_authority(passed_auth, request, self.participant_id)
        if auth_err is not None:
            return auth_err
        assert auth is not None

        tx_id = request.authorization.transaction_id
        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        # Mandatory caller-provided receipt chaining
        prior_ref = request.prior_receipt_ref
        prior_dig = request.prior_receipt_digest
        if not prior_ref or not prior_dig:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                retryable=False,
                detail_ref="prior_receipt_required_for_commit",
            )

        with self._lock:
            try:
                with self._immediate_transaction() as conn:
                    self._trigger_failpoint(TransactionFailpoint.AFTER_BEGIN)

                    # TOCTOU Authority Fence
                    try:
                        AuthorityFence.verify_current(conn, auth)
                    except PermissionError as exc:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                            retryable=False,
                            detail_ref=f"authority_fence_failed:{exc}",
                        )

                    cur = conn.execute(
                        """
                        SELECT phase, resource_revision, payload_digest, commit_receipt_ref,
                               commit_receipt_digest, canonical_payload_b64u, prepare_receipt_ref,
                               prepare_receipt_digest, prepared_base_revision, commit_request_digest,
                               operator_id, subject_id, mission_id, transaction_intent_digest
                        FROM control_2pc_transactions
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (self.participant_id, tx_id),
                    )
                    row = cur.fetchone()
                    if row is None:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"transaction_not_found:{tx_id}",
                        )

                    (
                        phase_val,
                        stored_rev,
                        prep_pdig,
                        comm_ref,
                        comm_dig,
                        stored_b64,
                        prep_ref,
                        prep_dig,
                        base_rev,
                        stored_comm_req_dig,
                        _op_id,
                        subj_id,
                        mis_id,
                        _stored_intent_dig,
                    ) = row

                    if phase_val in (
                        ParticipantControlPhaseV2.COMMITTED_HIDDEN.value,
                        ParticipantControlPhaseV2.FINALIZED_VISIBLE.value,
                        "committed_hidden",
                        "finalized_visible",
                    ):
                        # Idempotency validation
                        if stored_comm_req_dig and stored_comm_req_dig != request.authorization.request_digest:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                                retryable=False,
                                detail_ref="commit_request_digest_mismatch",
                            )

                        res = ParticipantControlReceiptV2(
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
                                "phase": ParticipantControlPhaseV2.COMMITTED_HIDDEN,
                                "request": request,
                                "receipt": res,
                            }
                        return res

                    if phase_val not in (
                        ParticipantControlPhaseV2.PREPARED.value,
                        "pending",
                        "prepared",
                    ):
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"Transaction in phase {phase_val} cannot be committed",
                        )

                    # Validate prepare receipt chain
                    if prior_ref != prep_ref or prior_dig != prep_dig:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref="prior_receipt_chain_validation_failed",
                        )

                    # Intent validation across phases
                    if (
                        request.payload_digest != prep_pdig
                        or request.authorization.subject_id != subj_id
                        or request.authorization.mission_id != mis_id
                    ):
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                            retryable=False,
                            detail_ref="intent_mismatch_across_phases",
                        )

                    # Perform atomic CAS on resource revision
                    new_rev = base_rev + 1
                    cas_cur = conn.execute(
                        "UPDATE control_resource_revisions SET revision = ?, updated_at_ms = ? WHERE resource_ref = ? AND revision = ?",
                        (new_rev, now_ms, res_ref, base_rev),
                    )
                    if cas_cur.rowcount != 1:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                            retryable=True,
                            detail_ref="concurrent_revision_conflict",
                        )

                    self._trigger_failpoint(TransactionFailpoint.AFTER_CAS)

                    rcpt_ref = f"rcpt_commit_{uuid.uuid4().hex[:8]}"
                    rcpt_digest = calculate_receipt_digest(
                        transaction_id=tx_id,
                        participant_id=self.participant_id,
                        action=request.action.value if hasattr(request.action, "value") else str(request.action),
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
                            ParticipantControlPhaseV2.COMMITTED_HIDDEN.value,
                            new_rev,
                            rcpt_ref,
                            rcpt_digest,
                            request.authorization.request_digest,
                            now_ms,
                            self.participant_id,
                            tx_id,
                        ),
                    )

                    self._trigger_failpoint(TransactionFailpoint.AFTER_RECEIPT_PERSIST)

                    res = ParticipantControlReceiptV2(
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
                        "phase": ParticipantControlPhaseV2.COMMITTED_HIDDEN,
                        "request": request,
                        "receipt": res,
                    }
                    return res
            except Exception as exc:
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"commit_failed:{exc}",
                )

    def finalize_visibility(
        self,
        request_or_receipt: Any,
        commit_receipt_or_authority: Any = None,
        resolved_key: Any = None,
        authority: Any = None,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Finalize visibility of committed resource."""
        passed_auth = (
            authority
            if authority is not None
            else (
                commit_receipt_or_authority
                if isinstance(commit_receipt_or_authority, VerifiedMutationAuthority)
                else None
            )
        )
        auth, auth_err = _extract_and_validate_authority(passed_auth, request_or_receipt, self.participant_id)
        if auth_err is not None:
            return auth_err
        assert auth is not None

        commit_receipt = (
            commit_receipt_or_authority
            if isinstance(commit_receipt_or_authority, ParticipantControlReceiptV2)
            else None
        )

        if isinstance(request_or_receipt, ParticipantControlRequestV2):
            tx_id = request_or_receipt.authorization.transaction_id
            prior_ref = request_or_receipt.prior_receipt_ref
            prior_dig = request_or_receipt.prior_receipt_digest
            req_dig = request_or_receipt.authorization.request_digest
            action = request_or_receipt.action
        else:
            tx_id = getattr(request_or_receipt, "transaction_id", "")
            if commit_receipt is not None:
                prior_ref = commit_receipt.receipt_ref
                prior_dig = commit_receipt.receipt_digest
            else:
                prior_ref = getattr(request_or_receipt, "receipt_ref", None)
                prior_dig = getattr(request_or_receipt, "receipt_digest", None)
            req_dig = ""
            action = getattr(request_or_receipt, "action", C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY)

        # Mandatory caller-provided receipt chaining
        if not prior_ref or not prior_dig:
            return BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                retryable=False,
                detail_ref="prior_receipt_required_for_finalize",
            )

        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock:
            try:
                with self._immediate_transaction() as conn:
                    self._trigger_failpoint(TransactionFailpoint.AFTER_BEGIN)

                    # TOCTOU Authority Fence
                    try:
                        AuthorityFence.verify_current(conn, auth)
                    except PermissionError as exc:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                            retryable=False,
                            detail_ref=f"authority_fence_failed:{exc}",
                        )

                    cur = conn.execute(
                        """
                        SELECT phase, resource_revision, commit_receipt_ref, commit_receipt_digest,
                               payload_schema_id, payload_digest, canonical_payload_b64u,
                               finalize_receipt_ref, finalize_receipt_digest, finalize_request_digest
                        FROM control_2pc_transactions
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (self.participant_id, tx_id),
                    )
                    row = cur.fetchone()
                    if row is None:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
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
                        stored_fin_req_dig,
                    ) = row

                    if phase in (
                        ParticipantControlPhaseV2.FINALIZED_VISIBLE.value,
                        "finalized_visible",
                    ):
                        # Idempotency check
                        if req_dig and stored_fin_req_dig and stored_fin_req_dig != req_dig:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                                retryable=False,
                                detail_ref="finalize_request_digest_mismatch",
                            )

                        res = ParticipantControlReceiptV2(
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
                            self._committed_resources[tx_id]["phase"] = ParticipantControlPhaseV2.FINALIZED_VISIBLE
                        return res

                    if phase not in (
                        ParticipantControlPhaseV2.COMMITTED_HIDDEN.value,
                        "committed_hidden",
                    ):
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"Cannot finalize transaction in phase {phase}",
                        )

                    if prior_ref != comm_ref or prior_dig != comm_dig:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref="prior_receipt_chain_validation_failed",
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
                            ParticipantControlPhaseV2.FINALIZED_VISIBLE.value,
                            rcpt_ref,
                            rcpt_digest,
                            req_dig,
                            now_ms,
                            self.participant_id,
                            tx_id,
                        ),
                    )

                    self._trigger_failpoint(TransactionFailpoint.AFTER_RECEIPT_PERSIST)

                    res = ParticipantControlReceiptV2(
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
                        self._committed_resources[tx_id]["phase"] = ParticipantControlPhaseV2.FINALIZED_VISIBLE
                    return res
            except Exception as exc:
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"finalize_failed:{exc}",
                )

    def rollback(
        self,
        request_or_receipt: Any,
        authority_or_principal: Any = None,
        resolved_key: Any = None,
        authority: Any = None,
    ) -> ParticipantControlReceiptV2 | BoundedControlErrorV2:
        """Abort/rollback a transaction with compensation validation."""
        passed_auth = authority if authority is not None else authority_or_principal
        auth, auth_err = _extract_and_validate_authority(passed_auth, request_or_receipt, self.participant_id)
        if auth_err is not None:
            return auth_err
        assert auth is not None

        if isinstance(request_or_receipt, ParticipantControlRequestV2):
            tx_id = request_or_receipt.authorization.transaction_id
            prior_ref = request_or_receipt.prior_receipt_ref
            prior_dig = request_or_receipt.prior_receipt_digest
            req_dig = request_or_receipt.authorization.request_digest
            action = request_or_receipt.action
        else:
            tx_id = getattr(request_or_receipt, "transaction_id", "")
            prior_ref = getattr(request_or_receipt, "receipt_ref", None)
            prior_dig = getattr(request_or_receipt, "receipt_digest", None)
            req_dig = ""
            action = getattr(request_or_receipt, "action", C2ControlAction.ABORT_C2_RESOURCE)

        res_ref = f"resource:{self.participant_id}"
        now_ms = int(time.time() * 1000)

        with self._lock:
            try:
                with self._immediate_transaction() as conn:
                    self._trigger_failpoint(TransactionFailpoint.AFTER_BEGIN)

                    # TOCTOU Authority Fence
                    try:
                        AuthorityFence.verify_current(conn, auth)
                    except PermissionError as exc:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.NOT_AUTHORIZED,
                            retryable=False,
                            detail_ref=f"authority_fence_failed:{exc}",
                        )

                    cur = conn.execute(
                        """
                        SELECT phase, resource_revision, payload_schema_id, payload_digest,
                               canonical_payload_b64u, prepare_receipt_ref, prepare_receipt_digest,
                               commit_receipt_ref, commit_receipt_digest, abort_receipt_ref,
                               abort_receipt_digest, abort_request_digest
                        FROM control_2pc_transactions
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (self.participant_id, tx_id),
                    )
                    row = cur.fetchone()
                    if row is None:
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref=f"transaction_not_found:{tx_id}",
                        )

                    (
                        phase,
                        rev,
                        sch_id,
                        p_dig,
                        b64u,
                        prep_ref,
                        prep_dig,
                        comm_ref,
                        comm_dig,
                        ab_ref,
                        ab_dig,
                        stored_ab_req_dig,
                    ) = row

                    if phase in (
                        ParticipantControlPhaseV2.ABORTED.value,
                        "aborted",
                    ):
                        if req_dig and stored_ab_req_dig and stored_ab_req_dig != req_dig:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.IDEMPOTENCY_CONFLICT,
                                retryable=False,
                                detail_ref="abort_request_digest_mismatch",
                            )

                        return ParticipantControlReceiptV2(
                            transaction_id=tx_id,
                            participant_id=self.participant_id,
                            action=action,
                            resource_ref=res_ref,
                            resource_revision=rev,
                            receipt_ref=ab_ref or f"rcpt_abort_{tx_id[:8]}",
                            receipt_digest=ab_dig or "abort_receipt_digest",
                            daemon_instance_id=self.daemon_instance_id,
                            result_payload_schema_id=sch_id,
                            result_payload_digest=p_dig,
                            result_payload_b64u=b64u,
                        )

                    if phase in (
                        ParticipantControlPhaseV2.FINALIZED_VISIBLE.value,
                        "finalized_visible",
                    ):
                        return BoundedControlErrorV2(
                            reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                            retryable=False,
                            detail_ref="cannot_abort_finalized_transaction",
                        )

                    # Validate receipt chain for abort
                    if phase in (ParticipantControlPhaseV2.PREPARED.value, "pending", "prepared"):
                        if prior_ref and prior_ref != prep_ref:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                                retryable=False,
                                detail_ref="prepare_receipt_mismatch_for_abort",
                            )
                        if prior_dig and prior_dig != prep_dig:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                                retryable=False,
                                detail_ref="prepare_receipt_digest_mismatch_for_abort",
                            )
                    elif phase in (
                        ParticipantControlPhaseV2.COMMITTED_HIDDEN.value,
                        "committed_hidden",
                    ):
                        if prior_ref and prior_ref != comm_ref:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                                retryable=False,
                                detail_ref="commit_receipt_mismatch_for_abort",
                            )
                        if prior_dig and prior_dig != comm_dig:
                            return BoundedControlErrorV2(
                                reason_code=C2ControlErrorCodeV2.WRONG_PHASE,
                                retryable=False,
                                detail_ref="commit_receipt_digest_mismatch_for_abort",
                            )

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
                        SET phase = ?, abort_receipt_ref = ?, abort_receipt_digest = ?,
                            abort_request_digest = ?, updated_at_ms = ?
                        WHERE participant_id = ? AND transaction_id = ?
                        """,
                        (
                            ParticipantControlPhaseV2.ABORTED.value,
                            rcpt_ref,
                            rcpt_digest,
                            req_dig,
                            now_ms,
                            self.participant_id,
                            tx_id,
                        ),
                    )

                    self._pending_transactions.pop(tx_id, None)
                    self._committed_resources.pop(tx_id, None)

                    return ParticipantControlReceiptV2(
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
            except Exception as exc:
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref=f"abort_failed:{exc}",
                )

    abort = rollback

    def reconcile(
        self,
        operation: Any = None,
        finalization_fence: Any = None,
    ) -> ParticipantControlQuerySnapshotV2 | BoundedControlErrorV2:
        """Query current state snapshot of the resource participant."""
        tx_id = getattr(operation, "transaction_id", None)
        if isinstance(operation, ParticipantControlRequestV2):
            tx_id = operation.authorization.transaction_id

        if not tx_id or tx_id == "query":
            res_ref = f"resource:{self.participant_id}"
            with self._lock, self._connection() as conn:
                cur_rev = self._get_resource_revision(conn, res_ref)
                snap_dig = calculate_snapshot_digest(
                    transaction_id="query",
                    participant_id=self.participant_id,
                    phase=ParticipantControlPhaseV2.FINALIZED_VISIBLE.value,
                    resource_ref=res_ref,
                )
                return ParticipantControlQuerySnapshotV2(
                    transaction_id="query",
                    participant_id=self.participant_id,
                    resource_ref=res_ref,
                    resource_revision=cur_rev,
                    phase=ParticipantControlPhaseV2.FINALIZED_VISIBLE,
                    receipt_ref="rcpt_0",
                    receipt_digest="0" * 64,
                    snapshot_digest=snap_dig,
                    result_payload_schema_id="schema:c2_control_v2",
                    result_payload_digest="0" * 64,
                    result_payload_b64u="",
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
                return BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
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
            phase: ParticipantControlPhaseV2
            try:
                phase = ParticipantControlPhaseV2(phase_str)
            except ValueError:
                phase = (
                    ParticipantControlPhaseV2.PREPARED
                    if phase_str == "pending"
                    else ParticipantControlPhaseV2.RECOVERY_REQUIRED
                )

            receipt_ref = fin_ref or comm_ref or prep_ref
            receipt_digest = fin_dig or comm_dig or prep_dig

            snap_digest = calculate_snapshot_digest(
                transaction_id=tx_id,
                participant_id=self.participant_id,
                phase=phase.value if hasattr(phase, "value") else str(phase),
                receipt_digest=receipt_digest,
                receipt_ref=receipt_ref,
                resource_ref=res_ref,
                resource_revision=rev,
                result_payload_schema_id=sch_id,
                result_payload_digest=p_dig,
            )

            return ParticipantControlQuerySnapshotV2(
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
    "TransactionFailpoint",
]
