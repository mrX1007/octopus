"""Tests for C2 control plane idempotency contracts (§14.6)."""

from __future__ import annotations

import pytest

from core.c2.control_idempotency import (
    IdempotencyConflictError,
    IdempotencyStateV1,
    IdempotencyStoreV1,
    compute_idempotency_fingerprint,
)

pytestmark = pytest.mark.unit


def test_idempotency_reservation_and_commit():
    store = IdempotencyStoreV1()
    rec = store.reserve(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
        action="prepare_c2_resource",
        idempotency_key="idem-key-1",
        request_id="req-1",
        payload_schema_id="schema:resource",
        payload_digest="sha256:digest1",
    )
    assert rec.state == IdempotencyStateV1.PENDING
    assert rec.operator_id == "op-1"
    assert rec.idempotency_key == "idem-key-1"

    # Same reservation returns existing record
    rec2 = store.reserve(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
        action="prepare_c2_resource",
        idempotency_key="idem-key-1",
        request_id="req-1",
        payload_schema_id="schema:resource",
        payload_digest="sha256:digest1",
    )
    assert rec2 == rec

    # Commit outcome
    committed = store.commit(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
        action="prepare_c2_resource",
        idempotency_key="idem-key-1",
        response_data={"status": "ok", "resource_ref": "res-123"},
    )
    assert committed.state == IdempotencyStateV1.COMMITTED
    assert committed.response_json is not None


def test_idempotency_conflict_on_mismatched_payload():
    store = IdempotencyStoreV1()
    store.reserve(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
        action="prepare_c2_resource",
        idempotency_key="idem-key-1",
        request_id="req-1",
        payload_schema_id="schema:resource",
        payload_digest="sha256:digest1",
    )

    # Reusing same key with different payload digest fails
    with pytest.raises(IdempotencyConflictError, match="different payload"):
        store.reserve(
            operator_id="op-1",
            subject_id="sub-1",
            mission_id="m-1",
            action="prepare_c2_resource",
            idempotency_key="idem-key-1",
            request_id="req-1",
            payload_schema_id="schema:resource",
            payload_digest="sha256:DIFFERENT_DIGEST",
        )


def test_idempotency_conflict_on_mismatched_mission():
    store = IdempotencyStoreV1()
    store.reserve(
        operator_id="op-1",
        subject_id="sub-1",
        mission_id="m-1",
        action="prepare_c2_resource",
        idempotency_key="idem-key-1",
        request_id="req-1",
        payload_schema_id="schema:resource",
        payload_digest="sha256:digest1",
    )

    with pytest.raises(IdempotencyConflictError):
        store.reserve(
            operator_id="op-1",
            subject_id="sub-1",
            mission_id="m-2-different",
            action="prepare_c2_resource",
            idempotency_key="idem-key-1",
            request_id="req-1",
            payload_schema_id="schema:resource",
            payload_digest="sha256:digest1",
        )


def test_compute_fingerprint_deterministic():
    fp1 = compute_idempotency_fingerprint("op", "sub", "m", "act", "s_id", "sha256:abc")
    fp2 = compute_idempotency_fingerprint("op", "sub", "m", "act", "s_id", "sha256:abc")
    fp3 = compute_idempotency_fingerprint("op2", "sub", "m", "act", "s_id", "sha256:abc")
    assert fp1 == fp2
    assert fp1 != fp3
