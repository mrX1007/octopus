"""Focused edge-case contracts for :mod:`core.ai.fact_store`."""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any

import pytest

import core.ai.fact_store as fact_store_module
from core.ai.fact_store import (
    CommandCompletionClaim,
    CommandCompletionConflictError,
    CommandCompletionInProgressError,
    FactStore,
)

pytestmark = pytest.mark.unit


def _claim_args(
    idempotency_key: str,
    *,
    scan_id: str = "scan",
    host: str = "host.example",
) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "host": host,
        "command_key": "probe",
        "command": "probe host.example",
        "output_hash": "a" * 64,
        "status": "succeeded",
        "failed": False,
        "partial": False,
        "execution_id": "",
        "idempotency_key": idempotency_key,
    }


def _add_result(
    store: FactStore,
    idempotency_key: str = "",
    *,
    scan_id: str = "scan",
    host: str = "host.example",
    output_hash: str = "a" * 64,
    **kwargs: Any,
) -> tuple[int, bool]:
    return store.add_command_result(
        scan_id,
        host,
        "probe",
        "probe host.example",
        output_hash,
        status="succeeded",
        idempotency_key=idempotency_key,
        **kwargs,
    )


def test_constructor_projection_and_input_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        fact_store_module,
        "default_secret_store_path",
        lambda: str(tmp_path / "default-secrets.db"),
    )
    default_store = FactStore()
    assert default_store.secret_store.db_path == str((tmp_path / "default-secrets.db").resolve())

    with pytest.raises(ValueError, match="finite and positive"):
        FactStore(str(tmp_path / "invalid-lease.db"), completion_lease_seconds=0)

    # The constructor has an explicit in-memory secret-store selection. Stub
    # the independently connection-scoped fact DB so this assertion is about
    # that selection alone.
    class StubAssessmentStore:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

    with monkeypatch.context() as patch:
        patch.setattr(FactStore, "_init_db", lambda _self: None)
        patch.setattr(fact_store_module, "FactAssessmentStore", StubAssessmentStore)
        memory_store = FactStore(":memory:")
    assert memory_store.secret_store.db_path == ":memory:"

    store = FactStore(str(tmp_path / "projection.db"))
    with pytest.raises(TypeError, match="must be callable"):
        store.register_assessment_projection_handler(None)  # type: ignore[arg-type]

    handler_calls: list[tuple[int, ...]] = []

    def handler(fact_ids: tuple[int, ...]) -> None:
        handler_calls.append(fact_ids)

    store.register_assessment_projection_handler(handler)
    store.register_assessment_projection_handler(handler)
    assert len(store._assessment_projection_handlers) == 1
    assert store._normalized_projection_fact_ids([1, 1, 0, "bad", 2]) == (1, 2)
    assert store.pending_assessment_projections(limit=object()) == []
    assert store.pending_assessment_projections(limit=0) == []
    assert store.pending_assessment_projections(["bad"]) == []
    assert store.pending_assessment_projections([1]) == []

    event = {
        "fact_id": 1,
        "assessment_id": "assessment",
    }
    attempts: list[tuple[tuple[int, str], ...]] = []
    with monkeypatch.context() as patch:
        patch.setattr(fact_store_module, "_PROJECTION_OUTBOX_MAX_BATCHES", 1)
        patch.setattr(
            store,
            "pending_assessment_projections",
            lambda *_args, **_kwargs: [event],
        )
        patch.setattr(
            store,
            "_mark_assessment_projection_attempts",
            attempts.append,
        )
        patch.setattr(
            store,
            "_ack_assessment_projection_events",
            lambda _events: 1,
        )
        assert store.drain_assessment_projection_outbox() == 1
    assert attempts == [((1, "assessment"),)]
    assert handler_calls == [(1,)]


def test_migration_and_serialization_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FactStore(str(tmp_path / "migration-helpers.db"))
    hypothesis_id = store.add_hypothesis(
        "scan",
        "host.example",
        "service is reachable",
        ["independent observation"],
        "analyst",
    )
    assert hypothesis_id > 0
    assert store.get_hypotheses("scan")[0]["id"] == hypothesis_id

    result_id, _ = _add_result(store, execution_id="legacy-execution")
    with store._get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE migration_probe (id INTEGER)")
        store._ensure_column(cursor, "migration_probe", "label", "TEXT")
        assert {row[1] for row in cursor.execute("PRAGMA table_info(migration_probe)")} == {
            "id",
            "label",
        }

        cursor.execute(
            "UPDATE command_results SET execution_key = '' WHERE id = ?",
            (result_id,),
        )
        store._backfill_command_execution_keys(cursor)
        execution_key = cursor.execute(
            "SELECT execution_key FROM command_results WHERE id = ?",
            (result_id,),
        ).fetchone()[0]
        assert execution_key

        # Already-safe hypotheses exercise the no-op migration path.
        store._redact_existing_rows(cursor)

    assert store._load_json_list(object()) == []
    assert store._load_json_value(object()) == {}
    assert json.loads(store._metadata_json({"blob": "x" * 70_000})) == {
        "metadata_original_bytes": 70_011,
        "metadata_truncated": True,
    }
    assert store._bounded_count(object()) == 0
    assert store._canonical_source_identity(None) == ""
    assert store._canonical_observation_method("", source_identity="browser-session") == "application_observation"

    with monkeypatch.context() as patch:
        patch.setattr(
            store.redactor,
            "redact_text",
            lambda value, *, kind="": "same" if kind == "execution_metadata_key" else f"safe:{value}",
        )
        protected = store._redact_metadata_keys(
            {
                "first": (1,),
                "second": {2},
                "third": object(),
            }
        )
    assert protected["same"] == [1]
    assert protected["same#2"] == [2]
    assert protected["same#3"].startswith("safe:")

    fact_id = store.add_fact(
        "scan",
        "host.example",
        "service",
        "https",
        "browser",
        session_id="session-1",
    )
    assert store.get_facts("scan", session_id="session-1")[0]["id"] == fact_id
    assert store.get_facts_by_ids(["bad", fact_id, fact_id, 0])[0]["id"] == fact_id
    assert store.get_facts_by_ids(["bad", 0]) == []


class _ShrinkingDuplicateCursor:
    """Model a duplicate group that disappears between defensive reads."""

    def __init__(self) -> None:
        self._fetch_count = 0

    def execute(self, _query: str, _params: Any = ()) -> _ShrinkingDuplicateCursor:
        return self

    def fetchall(self) -> list[tuple[Any, ...]]:
        self._fetch_count += 1
        if self._fetch_count == 1:
            return [("scan", "host", "service", "https")]
        return [(1, 100, 1.0, "[]", "[]")]


def test_duplicate_fact_migration_repairs_all_references(tmp_path: Path) -> None:
    store = FactStore(str(tmp_path / "duplicate-migration.db"))
    keeper_id = store.add_fact(
        "scan",
        "host",
        "service",
        "https",
        "probe",
    )

    with store._get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("DROP INDEX idx_fact_identity_unique")
        cursor.execute(
            """
            INSERT INTO facts(
                scan_id, host, type, value, confidence, source, session_id,
                derived_from, evidence_hash, timestamp, secret_refs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan",
                "host",
                "service",
                "https",
                80,
                "second-probe",
                "none",
                "[]",
                "duplicate",
                2.0,
                "[]",
            ),
        )
        duplicate_id = int(cursor.lastrowid)
        cursor.execute(
            """
            INSERT INTO facts(
                scan_id, host, type, value, confidence, source, session_id,
                derived_from, evidence_hash, timestamp, secret_refs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "scan",
                "host",
                "relationship",
                "derived",
                90,
                "analysis",
                "none",
                "[]",
                "derived",
                3.0,
                "[]",
            ),
        )
        derived_id = int(cursor.lastrowid)
        cursor.execute(
            "UPDATE facts SET derived_from = ? WHERE id = ?",
            (json.dumps(["bad", duplicate_id, -1, derived_id]), derived_id),
        )
        cursor.execute(
            """
            CREATE TABLE mission_task_attempts(
                attempt_id TEXT PRIMARY KEY,
                fact_ids_json TEXT NOT NULL
            )
            """
        )
        cursor.executemany(
            "INSERT INTO mission_task_attempts VALUES (?, ?)",
            (
                (
                    "changed",
                    json.dumps([duplicate_id, "bad", -1, duplicate_id], separators=(",", ":")),
                ),
                ("same", json.dumps([keeper_id], separators=(",", ":"))),
                ("empty", "[]"),
            ),
        )

        store._merge_duplicate_facts(cursor)

        assert cursor.execute("SELECT COUNT(*) FROM facts WHERE type = 'service'").fetchone()[0] == 1
        assert json.loads(
            cursor.execute("SELECT derived_from FROM facts WHERE id = ?", (derived_id,)).fetchone()[0]
        ) == [keeper_id]
        assert cursor.execute(
            "SELECT fact_ids_json FROM mission_task_attempts WHERE attempt_id = 'changed'"
        ).fetchone()[0] == json.dumps([keeper_id], separators=(",", ":"))

        cursor.execute(
            "DELETE FROM fact_assessment_heads WHERE fact_id IN (?, ?)",
            (keeper_id, duplicate_id),
        )
        store._merge_duplicate_assessments(cursor, keeper_id, duplicate_id)

    with sqlite3.connect(":memory:") as conn:
        cursor = conn.cursor()
        store._merge_duplicate_assessments(cursor, 1, 2)
        cursor.execute("CREATE TABLE fact_assessments(assessment_id TEXT, fact_id INTEGER)")
        store._merge_duplicate_assessments(cursor, 1, 2)

    store._merge_duplicate_facts(_ShrinkingDuplicateCursor())  # type: ignore[arg-type]


def test_completion_claim_boundary_states(tmp_path: Path) -> None:
    store = FactStore(
        str(tmp_path / "completion-claims.db"),
        completion_clock=lambda: "not-a-number",  # type: ignore[return-value]
    )
    assert math.isfinite(store._completion_now())
    assert store._completion_fact_ids("not-json") == ()
    assert store._completion_fact_ids("{}") == ()
    assert store._completion_fact_ids(json.dumps([{}, "bad", 1, 1, 0])) == (1,)

    invalid_status = _claim_args("invalid-status")
    invalid_status["status"] = "unsupported"
    with pytest.raises(ValueError, match="Unsupported"):
        store.claim_command_completion(**invalid_status)

    fence = store.capture_scan_completion_fence("scan")
    with pytest.raises(CommandCompletionConflictError, match="inputs disagree"):
        store.claim_command_completion(
            **_claim_args("fence-disagreement"),
            completion_fence=fence,
            scan_generation=fence.scan_generation + 1,
        )

    generation_args = _claim_args("generation-conflict")
    generation_claim = store.claim_command_completion(**generation_args)
    with store._get_conn() as conn:
        conn.execute(
            """
            UPDATE command_completion_claims SET scan_generation = ?
            WHERE idempotency_key = ?
            """,
            (generation_claim.scan_generation + 1, generation_claim.idempotency_key),
        )
    with pytest.raises(CommandCompletionConflictError, match="scan generation"):
        store.claim_command_completion(**generation_args)
    with pytest.raises(CommandCompletionConflictError, match="scan generation"):
        _add_result(store, "generation-conflict")

    lease_args = _claim_args("invalid-lease")
    lease_claim = store.claim_command_completion(**lease_args)
    with store._get_conn() as conn:
        conn.execute(
            """
            UPDATE command_completion_claims SET lease_expires_at = 'invalid'
            WHERE idempotency_key = ?
            """,
            (lease_claim.idempotency_key,),
        )
    replacement_claim = store.claim_command_completion(**lease_args)
    assert replacement_claim.owner_token != lease_claim.owner_token

    missing_result_args = _claim_args("completed-without-result")
    missing_result_claim = store.claim_command_completion(**missing_result_args)
    with store._get_conn() as conn:
        conn.execute(
            """
            UPDATE command_completion_claims
            SET state = 'completed', owner_token = '', command_result_id = NULL
            WHERE idempotency_key = ?
            """,
            (missing_result_claim.idempotency_key,),
        )
    with pytest.raises(RuntimeError, match="has no command result"):
        store.claim_command_completion(**missing_result_args)

    store.release_command_completion_claim(CommandCompletionClaim())
    store.renew_command_completion_claim(CommandCompletionClaim(replayed=True))

    current_result_id, _ = _add_result(store, "current-result")
    with store._get_conn() as conn:
        conn.execute(
            "DELETE FROM command_completion_claims WHERE idempotency_key = ?",
            (store._idempotency_digest("current-result"),),
        )
    adopted = store.claim_command_completion(**_claim_args("current-result"))
    assert adopted.replayed is True
    assert adopted.command_result_id == current_result_id


def test_command_result_boundary_states_and_views(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FactStore(str(tmp_path / "command-results.db"))

    with pytest.raises(ValueError, match="Unsupported"):
        store.add_command_result(
            "scan",
            "host.example",
            "probe",
            "probe host.example",
            "bad-status",
            status="unsupported",
        )
    _add_result(
        store,
        output_hash="invalid-numbers",
        duration="bad",  # type: ignore[arg-type]
        exit_code="bad",  # type: ignore[arg-type]
    )
    _add_result(store, output_hash="negative-duration", duration=-1)

    wrong_scan_claim = CommandCompletionClaim(scan_key="wrong", scan_generation=0)
    with pytest.raises(CommandCompletionConflictError, match="different scan"):
        _add_result(
            store,
            output_hash="wrong-scan-claim",
            completion_claim=wrong_scan_claim,
        )

    pending_args = _claim_args("pending-result")
    store.claim_command_completion(**pending_args)
    with pytest.raises(CommandCompletionInProgressError, match="already in progress"):
        _add_result(store, "pending-result")

    generation_args = _claim_args("result-generation")
    generation_claim = store.claim_command_completion(**generation_args)
    with store._get_conn() as conn:
        conn.execute(
            """
            UPDATE command_completion_claims SET scan_generation = 1
            WHERE idempotency_key = ?
            """,
            (generation_claim.idempotency_key,),
        )
    with pytest.raises(CommandCompletionConflictError, match="scan generation"):
        _add_result(store, "result-generation")

    claim_without_ownership = CommandCompletionClaim(
        scan_key=store._completion_scan_key("scan"),
        scan_generation=0,
    )
    with pytest.raises(RuntimeError, match="claim was lost"):
        _add_result(
            store,
            "lost-result-claim",
            completion_claim=claim_without_ownership,
        )

    fingerprint_result_id, _ = _add_result(store, "fingerprinted-result")
    with store._get_conn() as conn:
        conn.execute(
            "DELETE FROM command_completion_claims WHERE idempotency_key = ?",
            (store._idempotency_digest("fingerprinted-result"),),
        )
    assert _add_result(store, "fingerprinted-result") == (
        fingerprint_result_id,
        False,
    )

    legacy_result_id, _ = _add_result(store, "legacy-result")
    with store._get_conn() as conn:
        conn.execute(
            "DELETE FROM command_completion_claims WHERE idempotency_key = ?",
            (store._idempotency_digest("legacy-result"),),
        )
        conn.execute(
            "UPDATE command_results SET completion_fingerprint = '' WHERE id = ?",
            (legacy_result_id,),
        )
    assert _add_result(store, "legacy-result") == (legacy_result_id, False)

    finalization_args = _claim_args("lost-finalization")
    finalization_claim = store.claim_command_completion(**finalization_args)

    def steal_finalization(conn: sqlite3.Connection, **_kwargs: Any) -> None:
        conn.execute(
            """
            UPDATE command_completion_claims SET state = 'completed'
            WHERE idempotency_key = ?
            """,
            (finalization_claim.idempotency_key,),
        )

    with monkeypatch.context() as patch:
        patch.setattr(
            store.assessments,
            "apply_automatic_rules_for_execution_in_connection",
            steal_finalization,
        )
        with pytest.raises(RuntimeError, match="could not be finalized"):
            _add_result(
                store,
                "lost-finalization",
                completion_claim=finalization_claim,
            )

    fact_id = store.add_fact(
        "scan",
        "host.example",
        "service",
        "https",
        "browser",
    )
    assert store.get_command_results("scan")
    assert json.loads(store.get_all_facts_for_llm("scan", "host.example"))[0]["type"] == "service"
    assert json.loads(store.get_all_facts_for_llm("empty", "host.example")) == []
    assert store.get_history("scan")[0]["id"] == fact_id
