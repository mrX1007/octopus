#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import time
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable
from uuid import uuid4

from core.ai.fact_assessment import FactAssessment, FactAssessmentStore, FreshnessPolicy
from core.execution.results import ExecutionResult, ExecutionStatus
from core.secrets import Redactor, SecretStore, default_secret_store_path

_COMMAND_RESULT_STATUSES = {status.value for status in ExecutionStatus} | {"legacy"}
_FAILED_STATUSES = {
    ExecutionStatus.FAILED.value,
    ExecutionStatus.TIMEOUT.value,
    ExecutionStatus.UNAVAILABLE.value,
    ExecutionStatus.CANCELLED.value,
}
_MAX_COMMAND_BYTES = 16 * 1024
_MAX_IDENTIFIER_BYTES = 4096
_MAX_METADATA_BYTES = 64 * 1024
_MAX_RECORDED_OUTPUT_BYTES = 100_000_000
_MAX_PROVENANCE_IDENTITY_BYTES = 512
_PROJECTION_OUTBOX_BATCH_SIZE = 256
_PROJECTION_OUTBOX_MAX_BATCHES = 64
_COMMAND_COMPLETION_LEASE_SECONDS = 5 * 60.0
logger = logging.getLogger("octopus.fact_store")


class CommandCompletionConflictError(ValueError):
    """An idempotency key was reused for a different completion payload."""


class CommandCompletionInProgressError(RuntimeError):
    """Another writer currently owns the same execution completion."""


@dataclass(frozen=True)
class CommandCompletionClaim:
    """Durable reservation or completed replay for one execution ingress."""

    scan_key: str = ""
    scan_generation: int = 0
    idempotency_key: str = ""
    owner_token: str = ""
    replayed: bool = False
    command_result_id: int | None = None
    fact_ids: tuple[int, ...] = ()
    parsed_facts: int = 0
    new_facts: int = 0


class FactStore:
    def __init__(
        self,
        db_path: str = "data/facts.db",
        secret_store: SecretStore | None = None,
        *,
        assessment_policy: FreshnessPolicy | None = None,
        assessment_clock: Callable[[], float] | None = None,
        completion_clock: Callable[[], float] | None = None,
        completion_lease_seconds: float = _COMMAND_COMPLETION_LEASE_SECONDS,
    ):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        if secret_store is None:
            if os.path.normpath(db_path) == os.path.normpath("data/facts.db"):
                secret_path = default_secret_store_path()
            elif db_path == ":memory:":
                secret_path = ":memory:"
            else:
                secret_path = f"{db_path}.secrets"
            secret_store = SecretStore(secret_path)
        self.secret_store = secret_store
        self.redactor = Redactor(secret_store)
        self._assessment_clock = assessment_clock or time.time
        self._completion_clock = completion_clock or time.time
        self._completion_lease_seconds = float(completion_lease_seconds)
        if (
            not math.isfinite(self._completion_lease_seconds)
            or self._completion_lease_seconds <= 0
        ):
            raise ValueError("completion_lease_seconds must be finite and positive")
        self._assessment_projection_handlers: list[
            Callable[[Sequence[int]], Any]
        ] = []
        self._init_db()
        self.assessments = FactAssessmentStore(
            self.db_path,
            secret_store=self.secret_store,
            redactor=self.redactor,
            freshness_policy=assessment_policy,
            clock=self._assessment_clock,
            transition_hook=self._enqueue_assessment_projections_in_connection,
            post_commit_hook=self._refresh_assessment_projections,
        )

    def register_assessment_projection_handler(
        self,
        handler: Callable[[Sequence[int]], Any],
    ) -> None:
        """Register an idempotent post-commit current-assessment projector."""

        if not callable(handler):
            raise TypeError("Assessment projection handler must be callable")
        if handler not in self._assessment_projection_handlers:
            self._assessment_projection_handlers.append(handler)

    @staticmethod
    def _normalized_projection_fact_ids(fact_ids: Iterable[Any]) -> tuple[int, ...]:
        normalized_ids: list[int] = []
        for item in fact_ids:
            try:
                fact_id = int(item)
            except (TypeError, ValueError):
                continue
            if fact_id > 0 and fact_id not in normalized_ids:
                normalized_ids.append(fact_id)
        return tuple(normalized_ids)

    def _enqueue_assessment_projections_in_connection(
        self,
        conn: sqlite3.Connection,
        fact_ids: Sequence[int],
    ) -> tuple[tuple[int, str], ...]:
        """Coalesce current assessment heads into the transactional outbox."""

        normalized = self._normalized_projection_fact_ids(fact_ids)
        if not normalized:
            return ()
        placeholders = ",".join("?" for _ in normalized)
        rows = conn.execute(
            f"""
            SELECT h.fact_id, h.assessment_id
            FROM fact_assessment_heads AS h
            WHERE h.fact_id IN ({placeholders})
            ORDER BY h.fact_id
            """,
            normalized,
        ).fetchall()
        enqueued_at = time.time()
        events: list[tuple[int, str]] = []
        for fact_id, assessment_id in rows:
            event = (int(fact_id), str(assessment_id))
            conn.execute(
                """
                INSERT INTO fact_assessment_projection_outbox(
                    fact_id, assessment_id, enqueued_at,
                    attempt_count, last_attempt_at
                ) VALUES (?, ?, ?, 0, NULL)
                ON CONFLICT(fact_id) DO UPDATE SET
                    assessment_id = excluded.assessment_id,
                    enqueued_at = CASE
                        WHEN fact_assessment_projection_outbox.assessment_id =
                             excluded.assessment_id
                        THEN fact_assessment_projection_outbox.enqueued_at
                        ELSE excluded.enqueued_at
                    END,
                    attempt_count = CASE
                        WHEN fact_assessment_projection_outbox.assessment_id =
                             excluded.assessment_id
                        THEN fact_assessment_projection_outbox.attempt_count
                        ELSE 0
                    END,
                    last_attempt_at = CASE
                        WHEN fact_assessment_projection_outbox.assessment_id =
                             excluded.assessment_id
                        THEN fact_assessment_projection_outbox.last_attempt_at
                        ELSE NULL
                    END
                """,
                (event[0], event[1], enqueued_at),
            )
            events.append(event)
        return tuple(events)

    def pending_assessment_projections(
        self,
        fact_ids: Sequence[int] | None = None,
        *,
        limit: int = _PROJECTION_OUTBOX_BATCH_SIZE,
    ) -> list[dict[str, Any]]:
        """Return durable current-assessment projection work in FIFO order."""

        try:
            bounded_limit = min(4096, max(0, int(limit)))
        except (TypeError, ValueError):
            bounded_limit = _PROJECTION_OUTBOX_BATCH_SIZE
        if bounded_limit == 0:
            return []
        query = """
            SELECT fact_id, assessment_id, enqueued_at,
                   attempt_count, last_attempt_at
            FROM fact_assessment_projection_outbox
        """
        params: list[Any] = []
        if fact_ids is not None:
            normalized = self._normalized_projection_fact_ids(fact_ids)
            if not normalized:
                return []
            placeholders = ",".join("?" for _ in normalized)
            query += f" WHERE fact_id IN ({placeholders})"
            params.extend(normalized)
        query += " ORDER BY enqueued_at, fact_id LIMIT ?"
        params.append(bounded_limit)
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "fact_id": int(row[0]),
                "assessment_id": str(row[1]),
                "enqueued_at": float(row[2]),
                "attempt_count": int(row[3]),
                "last_attempt_at": (
                    None if row[4] is None else float(row[4])
                ),
            }
            for row in rows
        ]

    def _mark_assessment_projection_attempts(
        self,
        events: Sequence[tuple[int, str]],
    ) -> None:
        attempted_at = time.time()
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                """
                UPDATE fact_assessment_projection_outbox
                SET attempt_count = attempt_count + 1, last_attempt_at = ?
                WHERE fact_id = ? AND assessment_id = ?
                """,
                (
                    (attempted_at, int(fact_id), str(assessment_id))
                    for fact_id, assessment_id in events
                ),
            )
            conn.commit()

    def _ack_assessment_projection_events(
        self,
        events: Sequence[tuple[int, str]],
    ) -> int:
        acknowledged = 0
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for fact_id, assessment_id in events:
                cursor = conn.execute(
                    """
                    DELETE FROM fact_assessment_projection_outbox
                    WHERE fact_id = ? AND assessment_id = ?
                    """,
                    (int(fact_id), str(assessment_id)),
                )
                acknowledged += max(0, int(cursor.rowcount or 0))
            conn.commit()
        return acknowledged

    def drain_assessment_projection_outbox(
        self,
        fact_ids: Sequence[int] | None = None,
        *,
        limit: int = _PROJECTION_OUTBOX_BATCH_SIZE,
    ) -> int:
        """Project and ACK durable work; failures remain pending for repair."""

        handlers = tuple(self._assessment_projection_handlers)
        if not handlers:
            return 0
        drained = 0
        for _batch in range(_PROJECTION_OUTBOX_MAX_BATCHES):
            pending = self.pending_assessment_projections(
                fact_ids,
                limit=limit,
            )
            if not pending:
                break
            events = tuple(
                (int(item["fact_id"]), str(item["assessment_id"]))
                for item in pending
            )
            self._mark_assessment_projection_attempts(events)
            projected = True
            event_fact_ids = tuple(dict.fromkeys(item[0] for item in events))
            for handler in handlers:
                try:
                    handler(event_fact_ids)
                except Exception as exc:
                    projected = False
                    logger.warning(
                        "Assessment projection deferred; outbox retained (%s)",
                        type(exc).__name__,
                    )
            if not projected:
                break
            drained += self._ack_assessment_projection_events(events)
        return drained

    def _refresh_assessment_projections(self, _fact_ids: Sequence[int]) -> None:
        # Drain the whole queue so any older crash residue is repaired by the
        # next safe ingress, not only by a process restart.
        self.drain_assessment_projection_outbox()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            # Facts Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 100,
                    source TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT 'none',
                    derived_from TEXT DEFAULT '[]',
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    secret_refs TEXT NOT NULL DEFAULT '[]'
                )
            ''')
            # Hypotheses Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    required_evidence TEXT DEFAULT '[]',
                    source TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fact_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fact_id INTEGER NOT NULL,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 100,
                    source TEXT NOT NULL,
                    source_identity TEXT NOT NULL DEFAULT '',
                    observation_method TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL DEFAULT 'none',
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    secret_refs TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY(fact_id) REFERENCES facts(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fact_observation_executions (
                    observation_id INTEGER NOT NULL,
                    execution_key TEXT NOT NULL,
                    PRIMARY KEY(observation_id, execution_key),
                    FOREIGN KEY(observation_id)
                        REFERENCES fact_observations(id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    command_key TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output_hash TEXT NOT NULL,
                    output_bytes INTEGER NOT NULL DEFAULT 0,
                    parsed_facts INTEGER NOT NULL DEFAULT 0,
                    new_facts INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    schema_version TEXT NOT NULL DEFAULT '0',
                    status TEXT NOT NULL DEFAULT 'legacy',
                    partial INTEGER NOT NULL DEFAULT 0,
                    execution_id TEXT NOT NULL DEFAULT '',
                    execution_key TEXT NOT NULL DEFAULT '',
                    request_id TEXT NOT NULL DEFAULT '',
                    policy_decision_ref TEXT NOT NULL DEFAULT '',
                    exit_code INTEGER,
                    duration REAL NOT NULL DEFAULT 0.0,
                    stderr_bytes INTEGER NOT NULL DEFAULT 0,
                    error_class TEXT NOT NULL DEFAULT '',
                    artifact_count INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    idempotency_key TEXT NOT NULL DEFAULT '',
                    completion_fingerprint TEXT NOT NULL DEFAULT '',
                    timestamp REAL NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_completion_generations (
                    scan_key TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL DEFAULT 0,
                    updated_at REAL NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_completion_claims (
                    idempotency_key TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    scan_generation INTEGER NOT NULL DEFAULT 0,
                    host_key TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    owner_token TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
                    command_result_id INTEGER,
                    fact_ids_json TEXT NOT NULL DEFAULT '[]',
                    parsed_facts INTEGER NOT NULL DEFAULT 0,
                    new_facts INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    lease_expires_at REAL,
                    completed_at REAL,
                    FOREIGN KEY(command_result_id)
                        REFERENCES command_results(id) ON DELETE SET NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fact_assessment_projection_outbox (
                    fact_id INTEGER PRIMARY KEY,
                    assessment_id TEXT NOT NULL,
                    enqueued_at REAL NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    last_attempt_at REAL,
                    FOREIGN KEY(fact_id) REFERENCES facts(id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_host ON facts (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON facts (type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_fact ON fact_observations (fact_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_scan_host ON fact_observations (scan_id, host)')
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_obs_execution_key
                ON fact_observation_executions(execution_key, observation_id)
                """
            )
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_hash ON command_results (scan_id, host, output_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_key ON command_results (scan_id, host, command_key)')
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_assessment_projection_outbox_order
                ON fact_assessment_projection_outbox(enqueued_at, fact_id)
                """
            )
            self._ensure_column(cursor, "facts", "secret_refs", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(cursor, "fact_observations", "secret_refs", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(
                cursor,
                "fact_observations",
                "source_identity",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                cursor,
                "fact_observations",
                "observation_method",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(cursor, "command_results", "schema_version", "TEXT NOT NULL DEFAULT '0'")
            self._ensure_column(cursor, "command_results", "status", "TEXT NOT NULL DEFAULT 'legacy'")
            self._ensure_column(cursor, "command_results", "partial", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(cursor, "command_results", "execution_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                cursor,
                "command_results",
                "execution_key",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(cursor, "command_results", "request_id", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                cursor,
                "command_results",
                "policy_decision_ref",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(cursor, "command_results", "exit_code", "INTEGER")
            self._ensure_column(cursor, "command_results", "duration", "REAL NOT NULL DEFAULT 0.0")
            self._ensure_column(cursor, "command_results", "stderr_bytes", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(cursor, "command_results", "error_class", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(cursor, "command_results", "artifact_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(cursor, "command_results", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(
                cursor,
                "command_results",
                "idempotency_key",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                cursor,
                "command_results",
                "completion_fingerprint",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                cursor,
                "command_completion_claims",
                "scan_generation",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                cursor,
                "command_completion_claims",
                "lease_expires_at",
                "REAL",
            )
            cursor.execute(
                """
                UPDATE command_results
                SET status = CASE WHEN failed = 1 THEN 'failed' ELSE 'succeeded' END
                WHERE status = 'legacy'
                """
            )
            self._backfill_command_execution_keys(cursor)
            self._redact_existing_rows(cursor)
            self._backfill_observation_provenance(cursor)
            self._merge_duplicate_facts(cursor)
            cursor.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_fact_identity_unique
                ON facts(scan_id, host, type, value)
                """
            )
            cursor.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_command_result_idempotency
                ON command_results(idempotency_key)
                WHERE idempotency_key <> ''
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_command_result_execution
                ON command_results(execution_key, scan_id, host, timestamp)
                WHERE execution_key <> ''
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_command_completion_scope
                ON command_completion_claims(scan_id, host_key, state)
                """
            )
            conn.commit()

    def _ensure_column(self, cursor, table: str, column: str, definition: str) -> None:
        columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _backfill_command_execution_keys(self, cursor: sqlite3.Cursor) -> None:
        """Key legacy execution IDs before their display values are redacted."""

        for row_id, execution_id in cursor.execute(
            """
            SELECT id, execution_id
            FROM command_results
            WHERE execution_key = '' AND execution_id <> ''
            """
        ).fetchall():
            cursor.execute(
                "UPDATE command_results SET execution_key = ? WHERE id = ?",
                (
                    self.secret_store.keyed_digest(
                        str(execution_id),
                        kind="fact_assessment:execution",
                    ),
                    int(row_id),
                ),
            )

    def _backfill_observation_provenance(self, cursor: sqlite3.Cursor) -> None:
        """Give legacy observations stable source/method identities.

        Legacy rows cannot be safely linked to a particular execution after
        the fact, so only the non-secret observation provenance is backfilled.
        This keeps migration conservative: old execution cardinality alone can
        never create a new automatic verification.
        """

        for row_id, source, source_identity, observation_method in cursor.execute(
            """
            SELECT id, source, source_identity, observation_method
            FROM fact_observations
            """
        ).fetchall():
            if source_identity:
                identity = self._canonical_source_identity(
                    self.redactor.redact_text(
                        source_identity,
                        kind="fact_source_identity",
                    )
                )
            else:
                identity = self._source_identity_from_source(source)
            method = self._canonical_observation_method(
                self.redactor.redact_text(
                    observation_method or "",
                    kind="fact_observation_method",
                ),
                source_identity=identity,
            )
            if identity != source_identity or method != observation_method:
                cursor.execute(
                    """
                    UPDATE fact_observations
                    SET source_identity = ?, observation_method = ?
                    WHERE id = ?
                    """,
                    (identity, method, int(row_id)),
                )

    def _redact_existing_rows(self, cursor) -> None:
        """One-way migrate legacy plaintext rows before any caller can read them."""
        for row_id, fact_type, value, source, refs_json in cursor.execute(
            "SELECT id, type, value, source, secret_refs FROM facts"
        ).fetchall():
            safe_value, refs = self.redactor.redact_fact(fact_type, value)
            safe_source = self.redactor.redact_text(source, kind="fact_source")
            merged = tuple(dict.fromkeys(self._load_refs(refs_json) + refs))
            if safe_value != value or safe_source != source or merged != self._load_refs(refs_json):
                cursor.execute(
                    "UPDATE facts SET value = ?, source = ?, secret_refs = ? WHERE id = ?",
                    (safe_value, safe_source, json.dumps(merged), row_id),
                )
        for row_id, fact_type, value, source, refs_json in cursor.execute(
            "SELECT id, type, value, source, secret_refs FROM fact_observations"
        ).fetchall():
            safe_value, refs = self.redactor.redact_fact(fact_type, value)
            safe_source = self.redactor.redact_text(source, kind="fact_source")
            merged = tuple(dict.fromkeys(self._load_refs(refs_json) + refs))
            if safe_value != value or safe_source != source or merged != self._load_refs(refs_json):
                cursor.execute(
                    "UPDATE fact_observations SET value = ?, source = ?, secret_refs = ? WHERE id = ?",
                    (safe_value, safe_source, json.dumps(merged), row_id),
                )
        for (
            row_id,
            command,
            command_key,
            execution_id,
            request_id,
            policy_ref,
            error_class,
            metadata_json,
            output_hash,
        ) in cursor.execute(
            """
            SELECT id, command, command_key, execution_id, request_id,
                   policy_decision_ref, error_class, metadata_json, output_hash
            FROM command_results
            """
        ).fetchall():
            safe_command = self.redactor.redact_text(command, kind="command")
            safe_command_key = self.redactor.redact_text(command_key, kind="command_key")
            safe_execution_id = self.redactor.redact_text(execution_id, kind="execution_id")
            safe_request_id = self.redactor.redact_text(request_id, kind="request_id")
            safe_policy_ref = self.redactor.redact_text(policy_ref, kind="policy_decision_ref")
            safe_error_class = self.redactor.redact_text(error_class, kind="execution_error_class")
            safe_metadata = self._metadata_json(self._load_json_value(metadata_json))
            safe_output_hash = self._safe_output_hash(output_hash)
            cursor.execute(
                """
                UPDATE command_results
                SET command = ?, command_key = ?, execution_id = ?, request_id = ?,
                    policy_decision_ref = ?, error_class = ?, metadata_json = ?,
                    output_hash = ?
                WHERE id = ?
                """,
                (
                    self._bounded_text(safe_command, _MAX_COMMAND_BYTES),
                    self._bounded_text(safe_command_key, _MAX_IDENTIFIER_BYTES),
                    self._bounded_text(safe_execution_id, _MAX_IDENTIFIER_BYTES),
                    self._bounded_text(safe_request_id, _MAX_IDENTIFIER_BYTES),
                    self._bounded_text(safe_policy_ref, _MAX_IDENTIFIER_BYTES),
                    self._bounded_text(safe_error_class, 256),
                    safe_metadata,
                    safe_output_hash,
                    row_id,
                ),
            )
        for row_id, claim, required, source in cursor.execute(
            "SELECT id, claim, required_evidence, source FROM hypotheses"
        ).fetchall():
            safe_claim = self.redactor.redact_text(claim, kind="hypothesis")
            safe_required = self.redactor.redact_data(self._load_json_list(required))
            safe_source = self.redactor.redact_text(source, kind="hypothesis_source")
            required_json = json.dumps(safe_required)
            if safe_claim != claim or required_json != required or safe_source != source:
                cursor.execute(
                    "UPDATE hypotheses SET claim = ?, required_evidence = ?, source = ? WHERE id = ?",
                    (safe_claim, required_json, safe_source, row_id),
                )

    def _merge_duplicate_facts(self, cursor: sqlite3.Cursor) -> None:
        """One-way migration to the database-enforced canonical fact identity."""

        groups = cursor.execute(
            """
            SELECT scan_id, host, type, value
            FROM facts
            GROUP BY scan_id, host, type, value
            HAVING COUNT(*) > 1
            """
        ).fetchall()
        replacements: dict[int, int] = {}
        for scan_id, host, fact_type, value in groups:
            rows = cursor.execute(
                """
                SELECT id, confidence, timestamp, derived_from, secret_refs
                FROM facts
                WHERE scan_id = ? AND host = ? AND type = ? AND value = ?
                ORDER BY id
                """,
                (scan_id, host, fact_type, value),
            ).fetchall()
            if len(rows) < 2:
                continue
            keeper_id = int(rows[0][0])
            merged_confidence = max(int(row[1] or 0) for row in rows)
            merged_timestamp = max(float(row[2] or 0.0) for row in rows)
            merged_refs = tuple(
                dict.fromkeys(
                    ref
                    for row in rows
                    for ref in self._load_refs(row[4])
                )
            )
            for row in rows[1:]:
                duplicate_id = int(row[0])
                replacements[duplicate_id] = keeper_id
                cursor.execute(
                    "UPDATE fact_observations SET fact_id = ? WHERE fact_id = ?",
                    (keeper_id, duplicate_id),
                )
                self._merge_duplicate_assessments(cursor, keeper_id, duplicate_id)
                cursor.execute("DELETE FROM facts WHERE id = ?", (duplicate_id,))
            cursor.execute(
                """
                UPDATE facts
                SET confidence = ?, timestamp = ?, secret_refs = ?
                WHERE id = ?
                """,
                (
                    merged_confidence,
                    merged_timestamp,
                    json.dumps(merged_refs),
                    keeper_id,
                ),
            )

        if not replacements:
            return
        for fact_id, derived_json in cursor.execute(
            "SELECT id, derived_from FROM facts"
        ).fetchall():
            derived = []
            for raw_id in self._load_json_list(derived_json):
                try:
                    source_id = int(raw_id)
                except (TypeError, ValueError):
                    continue
                canonical_id = replacements.get(source_id, source_id)
                if canonical_id > 0 and canonical_id != int(fact_id):
                    derived.append(canonical_id)
            canonical = list(dict.fromkeys(derived))
            encoded = json.dumps(canonical)
            if encoded != str(derived_json or "[]"):
                cursor.execute(
                    "UPDATE facts SET derived_from = ? WHERE id = ?",
                    (encoded, int(fact_id)),
                )
        if self._table_exists(cursor, "mission_task_attempts"):
            for attempt_id, fact_ids_json in cursor.execute(
                "SELECT attempt_id, fact_ids_json FROM mission_task_attempts"
            ).fetchall():
                canonical_ids = []
                for raw_id in self._load_json_list(fact_ids_json):
                    try:
                        fact_id = int(raw_id)
                    except (TypeError, ValueError):
                        continue
                    canonical_ids.append(replacements.get(fact_id, fact_id))
                encoded = json.dumps(
                    list(dict.fromkeys(item for item in canonical_ids if item > 0)),
                    separators=(",", ":"),
                )
                if encoded != str(fact_ids_json or "[]"):
                    cursor.execute(
                        """
                        UPDATE mission_task_attempts SET fact_ids_json = ?
                        WHERE attempt_id = ?
                        """,
                        (encoded, attempt_id),
                    )

    def _merge_duplicate_assessments(
        self,
        cursor: sqlite3.Cursor,
        keeper_id: int,
        duplicate_id: int,
    ) -> None:
        if not self._table_exists(cursor, "fact_assessments"):
            return
        if self._table_exists(cursor, "fact_assessment_evidence"):
            cursor.execute(
                """
                DELETE FROM fact_assessment_evidence AS duplicate_ref
                WHERE duplicate_ref.evidence_fact_id = ?
                  AND EXISTS (
                      SELECT 1 FROM fact_assessment_evidence AS keeper_ref
                      WHERE keeper_ref.assessment_id = duplicate_ref.assessment_id
                        AND keeper_ref.evidence_fact_id = ?
                  )
                """,
                (duplicate_id, keeper_id),
            )
            cursor.execute(
                """
                UPDATE fact_assessment_evidence
                SET evidence_fact_id = ?
                WHERE evidence_fact_id = ?
                """,
                (keeper_id, duplicate_id),
            )
        chosen_head = None
        if self._table_exists(cursor, "fact_assessment_heads"):
            heads = cursor.execute(
                """
                SELECT assessment_id, updated_at
                FROM fact_assessment_heads
                WHERE fact_id IN (?, ?)
                ORDER BY updated_at DESC, assessment_id DESC
                """,
                (keeper_id, duplicate_id),
            ).fetchall()
            if heads:
                chosen_head = (str(heads[0][0]), float(heads[0][1]))
            cursor.execute(
                "DELETE FROM fact_assessment_heads WHERE fact_id IN (?, ?)",
                (keeper_id, duplicate_id),
            )
        cursor.execute(
            "UPDATE fact_assessments SET fact_id = ? WHERE fact_id = ?",
            (keeper_id, duplicate_id),
        )
        if chosen_head is not None:
            cursor.execute(
                """
                INSERT INTO fact_assessment_heads(fact_id, assessment_id, updated_at)
                VALUES (?, ?, ?)
                """,
                (keeper_id, chosen_head[0], chosen_head[1]),
            )

    @staticmethod
    def _table_exists(cursor: sqlite3.Cursor, table: str) -> bool:
        return cursor.execute(
            """
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = ?
            """,
            (table,),
        ).fetchone() is not None

    @staticmethod
    def _load_json_list(value: Any) -> list[Any]:
        try:
            loaded = json.loads(value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        return loaded if isinstance(loaded, list) else []

    @staticmethod
    def _load_json_value(value: Any) -> Any:
        try:
            return json.loads(value or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _bounded_text(value: Any, limit: int) -> str:
        text = "" if value is None else str(value)
        raw = text.encode("utf-8", "replace")
        if len(raw) <= limit:
            return text
        return raw[:limit].decode("utf-8", "ignore")

    def _metadata_json(self, value: Any) -> str:
        safe = self.redactor.redact_data(value if isinstance(value, dict) else {"value": value})
        safe = self._redact_metadata_keys(safe)
        encoded = json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        encoded_bytes = encoded.encode("utf-8", "replace")
        if len(encoded_bytes) <= _MAX_METADATA_BYTES:
            return encoded
        return json.dumps(
            {
                "metadata_original_bytes": len(encoded_bytes),
                "metadata_truncated": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def _safe_output_hash(self, value: Any) -> str:
        safe = self.redactor.redact_text(value, kind="output_hash").strip().lower()
        if len(safe) == 64 and all(character in "0123456789abcdef" for character in safe):
            return safe
        return hashlib.sha256(safe.encode("utf-8", "replace")).hexdigest()

    def _redact_metadata_keys(self, value: Any) -> Any:
        """Make metadata JSON-safe while protecting keys without raw-key hashes."""

        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for raw_key, item in value.items():
                safe_key = self._bounded_text(
                    self.redactor.redact_text(raw_key, kind="execution_metadata_key"),
                    512,
                )
                candidate = safe_key
                ordinal = 2
                while candidate in result:
                    candidate = f"{safe_key}#{ordinal}"
                    ordinal += 1
                result[candidate] = self._redact_metadata_keys(item)
            return result
        if isinstance(value, (list, tuple)):
            return [self._redact_metadata_keys(item) for item in value]
        if isinstance(value, (set, frozenset)):
            return [self._redact_metadata_keys(item) for item in sorted(value, key=repr)]
        if value is None or isinstance(value, (str, bool, int, float)):
            return value if not isinstance(value, float) or math.isfinite(value) else None
        return self.redactor.redact_text(value, kind="execution_metadata")

    @staticmethod
    def _bounded_count(value: Any) -> int:
        try:
            parsed = int(value or 0)
        except (TypeError, ValueError):
            return 0
        return min(_MAX_RECORDED_OUTPUT_BYTES, max(0, parsed))

    @classmethod
    def _load_refs(cls, value: Any) -> tuple[str, ...]:
        return tuple(str(item) for item in cls._load_json_list(value) if item)

    @staticmethod
    def _canonical_source_identity(value: Any) -> str:
        text = str(value or "").strip().casefold()
        if not text:
            return ""
        identity = re.sub(r"[^a-z0-9_.:/-]+", "_", text).strip("_")
        return FactStore._bounded_text(identity, _MAX_PROVENANCE_IDENTITY_BYTES)

    @classmethod
    def _source_identity_from_source(cls, value: Any) -> str:
        first = re.split(r"\s+", str(value or "").strip(), maxsplit=1)[0]
        return cls._canonical_source_identity(first)

    @staticmethod
    def _canonical_observation_method(
        value: Any,
        *,
        source_identity: str,
    ) -> str:
        explicit = str(value or "").strip().casefold()
        if explicit:
            method = re.sub(r"[^a-z0-9_.:/-]+", "_", explicit).strip("_")
            return FactStore._bounded_text(method, _MAX_PROVENANCE_IDENTITY_BYTES)
        identity = source_identity.casefold()
        if any(marker in identity for marker in ("check", "verify")):
            return "verification_check"
        if any(marker in identity for marker in ("browser", "curl", "http", "web")):
            return "application_observation"
        if any(marker in identity for marker in ("nmap", "scan", "probe")):
            return "network_observation"
        if any(marker in identity for marker in ("inventory", "session", "ssh")):
            return "authenticated_observation"
        return "reported_observation"

    def add_fact(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                 confidence: int = 100, session_id: str = 'none',
                 derived_from: list[int] | None = None, evidence_hash: str = "",
                 source_execution_ids: Sequence[str] | None = None,
                 source_identity: str | None = None,
                 observation_method: str | None = None) -> int:
        """Add a fact and return its row id.

        For backward compatibility this returns the existing id when the fact is
        already present. New callers that need to distinguish inserts from
        duplicates should use add_fact_with_status().
        """
        fact_id, _created = self.add_fact_with_status(
            scan_id=scan_id,
            host=host,
            fact_type=fact_type,
            value=value,
            source=source,
            confidence=confidence,
            session_id=session_id,
            derived_from=derived_from,
            evidence_hash=evidence_hash,
            source_execution_ids=source_execution_ids,
            source_identity=source_identity,
            observation_method=observation_method,
        )
        return fact_id

    def add_fact_with_status(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                             confidence: int = 100, session_id: str = 'none',
                             derived_from: list[int] | None = None, evidence_hash: str = "",
                             source_execution_ids: Sequence[str] | None = None,
                             source_identity: str | None = None,
                             observation_method: str | None = None,
                             completion_claim: CommandCompletionClaim | None = None,
                             ) -> tuple[int, bool]:
        """Add a fact and return (row_id, created).

        The AI pipeline uses the created flag for anti-loop accounting. Without
        it, duplicates look like new facts because add_fact() returns an id for
        both new and existing rows.
        """
        if derived_from is None:
            derived_from = []
        value, secret_refs = self.redactor.redact_fact(fact_type, value)
        source = self.redactor.redact_text(source, kind="fact_source")
        if source_identity is None:
            canonical_source_identity = self._source_identity_from_source(source)
        else:
            raw_source_identity = self.redactor.redact_text(
                source_identity,
                kind="fact_source_identity",
            )
            canonical_source_identity = self._canonical_source_identity(
                raw_source_identity
            )
        raw_observation_method = self.redactor.redact_text(
            observation_method or "",
            kind="fact_observation_method",
        )
        canonical_observation_method = self._canonical_observation_method(
            raw_observation_method,
            source_identity=canonical_source_identity,
        )
        session_id = self.redactor.redact_text(session_id, kind="session_id")
        derived_json = json.dumps(derived_from)
        refs_json = json.dumps(secret_refs)
        now = time.time()
        evidence_hash = evidence_hash or self._evidence_hash(
            scan_id, host, fact_type, value, source, session_id
        )

        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if (
                completion_claim is not None
                and completion_claim.scan_key != self._completion_scan_key(scan_id)
            ):
                raise CommandCompletionConflictError(
                    "Execution completion claim belongs to a different scan"
                )
            self._renew_command_completion_claim_in_connection(
                conn,
                completion_claim,
            )
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, confidence FROM facts
                WHERE scan_id = ? AND host = ? AND type = ? AND value = ?
                LIMIT 1
            ''', (scan_id, host, fact_type, value))
            existing = cursor.fetchone()
            if existing:
                fact_id, old_confidence = existing
                if self._observation_already_recorded(
                    cursor,
                    int(fact_id),
                    canonical_source_identity,
                    canonical_observation_method,
                    evidence_hash,
                    source_execution_ids or (),
                ):
                    # A durable execution replay is not a new observation and
                    # must not refresh fact age or inflate observation counts.
                    self.assessments.ensure_initial_in_connection(
                        conn,
                        fact_id=int(fact_id),
                        confidence=max(
                            int(old_confidence or 0),
                            int(confidence or 0),
                        ),
                        derived_from=derived_from,
                        source_execution_ids=source_execution_ids or (),
                    )
                    conn.commit()
                    return fact_id, False
                cursor.execute('''
                    UPDATE facts
                    SET confidence = ?, timestamp = ?
                    WHERE id = ?
                ''', (max(int(old_confidence or 0), int(confidence or 0)), now, fact_id))
                self._insert_observation(
                    cursor, fact_id, scan_id, host, fact_type, value,
                    confidence, source, session_id, evidence_hash, now, secret_refs,
                    canonical_source_identity, canonical_observation_method,
                    source_execution_ids or (),
                )
                self.assessments.ensure_initial_in_connection(
                    conn,
                    fact_id=int(fact_id),
                    confidence=max(int(old_confidence or 0), int(confidence or 0)),
                    derived_from=derived_from,
                    source_execution_ids=source_execution_ids or (),
                )
                conn.commit()
                return fact_id, False

            cursor.execute('''
                INSERT INTO facts (
                    scan_id, host, type, value, confidence, source, session_id,
                    derived_from, evidence_hash, timestamp, secret_refs
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, host, fact_type, value, confidence, source, session_id,
                derived_json, evidence_hash, now, refs_json,
            ))
            fact_id = cursor.lastrowid
            self._insert_observation(
                cursor, fact_id, scan_id, host, fact_type, value,
                confidence, source, session_id, evidence_hash, now, secret_refs,
                canonical_source_identity, canonical_observation_method,
                source_execution_ids or (),
            )
            self.assessments.ensure_initial_in_connection(
                conn,
                fact_id=int(fact_id),
                confidence=confidence,
                derived_from=derived_from,
                source_execution_ids=source_execution_ids or (),
            )
            conn.commit()
            return fact_id, True

    def _observation_already_recorded(
        self,
        cursor: sqlite3.Cursor,
        fact_id: int,
        source_identity: str,
        observation_method: str,
        evidence_hash: str,
        source_execution_ids: Sequence[str],
    ) -> bool:
        """Return whether this exact execution-backed observation is durable."""

        execution_keys = tuple(
            dict.fromkeys(
                self.secret_store.keyed_digest(
                    str(item or "").strip(),
                    kind="fact_assessment:execution",
                )
                for item in source_execution_ids
                if str(item or "").strip()
            )
        )
        if not execution_keys:
            return False
        placeholders = ",".join("?" for _ in execution_keys)
        row = cursor.execute(
            f"""
            SELECT o.id
            FROM fact_observations AS o
            JOIN fact_observation_executions AS foe
              ON foe.observation_id = o.id
            WHERE o.fact_id = ?
              AND o.source_identity = ?
              AND o.observation_method = ?
              AND o.evidence_hash = ?
              AND foe.execution_key IN ({placeholders})
            GROUP BY o.id
            HAVING COUNT(DISTINCT foe.execution_key) = ?
            LIMIT 1
            """,
            (
                int(fact_id),
                source_identity,
                observation_method,
                evidence_hash,
                *execution_keys,
                len(execution_keys),
            ),
        ).fetchone()
        return row is not None

    def _insert_observation(self, cursor, fact_id: int, scan_id: str, host: str,
                            fact_type: str, value: str, confidence: int, source: str,
                            session_id: str, evidence_hash: str, timestamp: float,
                            secret_refs: tuple[str, ...], source_identity: str,
                            observation_method: str,
                            source_execution_ids: Sequence[str]) -> None:
        cursor.execute('''
            INSERT INTO fact_observations (
                fact_id, scan_id, host, type, value, confidence, source,
                source_identity, observation_method, session_id, evidence_hash,
                timestamp, secret_refs
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fact_id, scan_id, host, fact_type, value, confidence, source,
            source_identity, observation_method, session_id, evidence_hash,
            timestamp, json.dumps(secret_refs),
        ))
        observation_id = int(cursor.lastrowid)
        execution_ids = tuple(
            dict.fromkeys(
                str(item or "").strip()
                for item in source_execution_ids
                if str(item or "").strip()
            )
        )
        cursor.executemany(
            """
            INSERT OR IGNORE INTO fact_observation_executions(
                observation_id, execution_key
            ) VALUES (?, ?)
            """,
            (
                (
                    observation_id,
                    self.secret_store.keyed_digest(
                        execution_id,
                        kind="fact_assessment:execution",
                    ),
                )
                for execution_id in execution_ids
            ),
        )

    def _evidence_hash(self, scan_id: str, host: str, fact_type: str, value: str,
                       source: str, session_id: str) -> str:
        payload = "\x1f".join(str(part or "") for part in (
            scan_id, host, fact_type, value, source, session_id,
        ))
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
            
    def add_hypothesis(self, scan_id: str, host: str, claim: str, required_evidence: list[str], source: str) -> int:
        """Add a hypothesis to the hypotheses table."""
        claim = self.redactor.redact_text(claim, kind="hypothesis")
        required_evidence = self.redactor.redact_data(required_evidence)
        source = self.redactor.redact_text(source, kind="hypothesis_source")
        req_json = json.dumps(required_evidence)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hypotheses (scan_id, host, claim, required_evidence, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, host, claim, req_json, source, time.time()))
            conn.commit()
            return cursor.lastrowid

    def get_facts(self, scan_id: str, host: str | None = None, fact_type: str | None = None, session_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve facts matching the given criteria."""
        query = "SELECT id, scan_id, host, type, value, confidence, source, session_id, derived_from, evidence_hash, timestamp, secret_refs FROM facts WHERE scan_id = ?"
        params = [scan_id]

        if host:
            query += " AND host = ?"
            params.append(host)
        if fact_type:
            query += " AND type = ?"
            params.append(fact_type)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY timestamp ASC, id ASC"

        with self._get_conn() as conn:
            conn.execute("BEGIN")
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            evaluated_at = self.assessments.freshness_evaluation_time()
            fact_ids = [row[0] for row in rows]
            observations_by_fact = self._get_observations_for_facts(cursor, fact_ids)
            return self._serialize_fact_rows(
                conn,
                rows,
                observations_by_fact,
                evaluated_at=evaluated_at,
            )

    def get_facts_by_ids(self, fact_ids: Sequence[int]) -> list[dict[str, Any]]:
        """Read a bounded fact set for projection without bypassing this store."""

        ids = []
        for item in fact_ids:
            try:
                fact_id = int(item)
            except (TypeError, ValueError):
                continue
            if fact_id > 0 and fact_id not in ids:
                ids.append(fact_id)
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self._get_conn() as conn:
            conn.execute("BEGIN")
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT id, scan_id, host, type, value, confidence, source,
                       session_id, derived_from, evidence_hash, timestamp,
                       secret_refs
                FROM facts WHERE id IN ({placeholders}) ORDER BY timestamp, id
                """,
                ids,
            )
            rows = cursor.fetchall()
            evaluated_at = self.assessments.freshness_evaluation_time()
            observations_by_fact = self._get_observations_for_facts(cursor, ids)
            return self._serialize_fact_rows(
                conn,
                rows,
                observations_by_fact,
                evaluated_at=evaluated_at,
            )

    def _serialize_fact_rows(
        self,
        conn: sqlite3.Connection,
        rows: Sequence[Sequence[Any]],
        observations_by_fact: dict[int, list[dict[str, Any]]],
        *,
        evaluated_at: float,
    ) -> list[dict[str, Any]]:
        fact_ids = [int(row[0]) for row in rows]
        assessments_by_fact = self.assessments.current_for_facts_in_connection(
            conn,
            fact_ids,
        )
        latest_execution_statuses = self._latest_execution_statuses_for_assessments(
            conn,
            assessments_by_fact.values(),
        )
        results = []
        for row in rows:
            observations = observations_by_fact.get(row[0], [])
            assessment = assessments_by_fact.get(int(row[0]))
            latest_execution_status = latest_execution_statuses.get(int(row[0]))
            freshness = self.assessments.freshness_for(
                str(row[3]),
                row[10],
                execution_statuses=(
                    (latest_execution_status,) if latest_execution_status else ()
                ),
                now=evaluated_at,
            )
            if not observations:
                observations = [{
                    "id": None,
                    "confidence": row[5],
                    "source": row[6],
                    "source_identity": self._source_identity_from_source(row[6]),
                    "observation_method": self._canonical_observation_method(
                        "",
                        source_identity=self._source_identity_from_source(row[6]),
                    ),
                    "session_id": row[7],
                    "evidence_hash": row[9],
                    "timestamp": row[10],
                    "secret_refs": list(self._load_refs(row[11])),
                }]
            sources = sorted({obs["source"] for obs in observations if obs.get("source")})
            sessions = sorted({obs["session_id"] for obs in observations if obs.get("session_id")})
            results.append({
                "id": row[0],
                "scan_id": row[1],
                "host": row[2],
                "type": row[3],
                "value": row[4],
                "confidence": row[5],
                "source": row[6],
                "session_id": row[7],
                "derived_from": json.loads(row[8]),
                "evidence_hash": row[9],
                "timestamp": row[10],
                "secret_refs": list(self._load_refs(row[11])),
                "observations": observations,
                "sources": sources,
                "sessions": sessions,
                "assessment": assessment.to_dict() if assessment else None,
                "assessment_id": assessment.assessment_id if assessment else None,
                "assessment_status": assessment.status.value if assessment else "observed",
                "assessment_rule_id": assessment.rule_id if assessment else None,
                "freshness": freshness.to_dict(),
                "freshness_status": freshness.status.value,
                "coverage_status": freshness.coverage.value,
            })
        return results

    def _latest_execution_statuses_for_assessments(
        self,
        conn: sqlite3.Connection,
        assessments: Iterable[FactAssessment],
    ) -> dict[int, str]:
        assessment_ids = tuple(
            assessment.assessment_id for assessment in assessments
        )
        if not assessment_ids:
            return {}
        placeholders = ",".join("?" for _ in assessment_ids)
        rows = conn.execute(
            f"""
            SELECT a.fact_id, cr.status, cr.timestamp, cr.id
            FROM fact_assessment_executions AS ae
            JOIN fact_assessments AS a
              ON a.assessment_id = ae.assessment_id
            JOIN facts AS f ON f.id = a.fact_id
            JOIN command_results AS cr
              ON cr.execution_key = ae.execution_key
             AND cr.scan_id = f.scan_id
             AND LOWER(RTRIM(TRIM(cr.host), '.')) =
                 LOWER(RTRIM(TRIM(f.host), '.'))
            WHERE ae.assessment_id IN ({placeholders})
            ORDER BY cr.timestamp, cr.id
            """,
            assessment_ids,
        ).fetchall()
        return {
            int(fact_id): str(status)
            for fact_id, status, _timestamp, _result_id in rows
        }

    def _get_observations_for_facts(self, cursor, fact_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        if not fact_ids:
            return {}
        placeholders = ",".join("?" for _ in fact_ids)
        cursor.execute(f'''
            SELECT id, fact_id, confidence, source, source_identity,
                   observation_method, session_id, evidence_hash, timestamp,
                   secret_refs
            FROM fact_observations
            WHERE fact_id IN ({placeholders})
            ORDER BY timestamp ASC
        ''', fact_ids)
        grouped: dict[int, list[dict[str, Any]]] = {}
        for row in cursor.fetchall():
            grouped.setdefault(row[1], []).append({
                "id": row[0],
                "confidence": row[2],
                "source": row[3],
                "source_identity": row[4],
                "observation_method": row[5],
                "session_id": row[6],
                "evidence_hash": row[7],
                "timestamp": row[8],
                "secret_refs": list(self._load_refs(row[9])),
            })
        return grouped

    @staticmethod
    def _completion_host_key(host: Any) -> str:
        return str(host or "").strip().casefold().rstrip(".")

    @staticmethod
    def _scan_completion_generation_in_connection(
        conn: sqlite3.Connection,
        scan_key: str,
    ) -> int:
        row = conn.execute(
            """
            SELECT generation FROM scan_completion_generations
            WHERE scan_key = ?
            """,
            (str(scan_key),),
        ).fetchone()
        return max(0, int(row[0])) if row is not None else 0

    def _completion_scan_key(self, scan_id: str) -> str:
        return self.secret_store.keyed_digest(
            str(scan_id or ""),
            kind="command_completion:scan",
        )

    def scan_completion_generation(self, scan_id: str) -> int:
        """Return the durable generation fencing execution completion writes."""

        scan_key = self._completion_scan_key(scan_id)
        with self._get_conn() as conn:
            conn.execute("BEGIN")
            return self._scan_completion_generation_in_connection(conn, scan_key)

    def capture_scan_completion_fence(
        self,
        scan_id: str,
    ) -> CommandCompletionClaim:
        """Capture a generation-only token before dispatch or replay work."""

        scan_key = self._completion_scan_key(scan_id)
        with self._get_conn() as conn:
            conn.execute("BEGIN")
            generation = self._scan_completion_generation_in_connection(
                conn,
                scan_key,
            )
        return CommandCompletionClaim(
            scan_key=scan_key,
            scan_generation=generation,
        )

    def _validate_scan_completion_generation_in_connection(
        self,
        conn: sqlite3.Connection,
        *,
        scan_key: str,
        expected_generation: int,
    ) -> None:
        current = self._scan_completion_generation_in_connection(conn, scan_key)
        if current != int(expected_generation):
            raise CommandCompletionConflictError(
                "Scan generation changed before execution completion"
            )

    def _completion_now(self) -> float:
        try:
            value = float(self._completion_clock())
        except (TypeError, ValueError):
            value = time.time()
        return value if math.isfinite(value) else time.time()

    @staticmethod
    def _completion_fact_ids(value: Any) -> tuple[int, ...]:
        try:
            items = json.loads(str(value or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        if not isinstance(items, list):
            return ()
        normalized: list[int] = []
        for item in items:
            try:
                fact_id = int(item)
            except (TypeError, ValueError):
                continue
            if fact_id > 0 and fact_id not in normalized:
                normalized.append(fact_id)
        return tuple(normalized)

    @staticmethod
    def _idempotency_digest(idempotency_key: str) -> str:
        return (
            hashlib.sha256(
                str(idempotency_key).encode("utf-8", "replace")
            ).hexdigest()
            if idempotency_key
            else ""
        )

    def _completion_request_fingerprint(
        self,
        *,
        command_key: str,
        command: str,
        output_hash: str,
        status: str,
        failed: bool,
        partial: bool,
        execution_key: str,
        schema_version: str,
        request_id: str,
        policy_decision_ref: str,
        exit_code: int | None,
        error_class: str,
        artifact_count: int,
    ) -> str:
        payload = json.dumps(
            {
                "command": str(command or ""),
                "command_key": str(command_key or ""),
                "execution_key": str(execution_key or ""),
                "failed": bool(failed),
                "output_hash": str(output_hash or ""),
                "partial": bool(partial),
                "schema_version": str(schema_version or ""),
                "status": str(status or ""),
                "request_id": str(request_id or ""),
                "policy_decision_ref": str(policy_decision_ref or ""),
                "exit_code": exit_code,
                "error_class": str(error_class or ""),
                "artifact_count": self._bounded_count(artifact_count),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return self.secret_store.keyed_digest(
            payload,
            kind="command_completion:request",
        )

    @staticmethod
    def _validate_completion_identity(
        *,
        existing_scan_id: str,
        existing_host_key: str,
        existing_fingerprint: str,
        scan_id: str,
        host_key: str,
        request_fingerprint: str,
    ) -> None:
        if existing_scan_id != scan_id or existing_host_key != host_key:
            raise CommandCompletionConflictError(
                "Execution completion idempotency key belongs to a different scope"
            )
        if existing_fingerprint != request_fingerprint:
            raise CommandCompletionConflictError(
                "Execution completion idempotency key was reused with a different payload"
            )

    @staticmethod
    def _validate_legacy_completion_payload(
        *,
        existing_output_hash: str,
        existing_status: str,
        existing_failed: bool,
        existing_partial: bool,
        existing_execution_key: str,
        existing_schema_version: str,
        existing_command_key: str,
        existing_command: str,
        existing_request_id: str,
        existing_policy_decision_ref: str,
        existing_exit_code: int | None,
        existing_error_class: str,
        existing_artifact_count: int,
        output_hash: str,
        status: str,
        failed: bool,
        partial: bool,
        execution_key: str,
        schema_version: str,
        command_key: str,
        command: str,
        request_id: str,
        policy_decision_ref: str,
        exit_code: int | None,
        error_class: str,
        artifact_count: int,
    ) -> None:
        existing = (
            existing_output_hash,
            existing_status,
            existing_failed,
            existing_partial,
            existing_execution_key,
            existing_schema_version,
            existing_command_key,
            existing_command,
            existing_request_id,
            existing_policy_decision_ref,
            existing_exit_code,
            existing_error_class,
            existing_artifact_count,
        )
        incoming = (
            output_hash,
            status,
            failed,
            partial,
            execution_key,
            schema_version,
            command_key,
            command,
            request_id,
            policy_decision_ref,
            exit_code,
            error_class,
            artifact_count,
        )
        if existing != incoming:
            raise CommandCompletionConflictError(
                "Execution completion idempotency key was reused with a different payload"
            )

    def _fact_ids_for_execution_in_connection(
        self,
        conn: sqlite3.Connection,
        *,
        execution_key: str,
        scan_id: str,
        host_key: str,
    ) -> tuple[int, ...]:
        if not execution_key:
            return ()
        rows = conn.execute(
            """
            SELECT fact_id FROM (
                SELECT o.fact_id AS fact_id
                FROM fact_observation_executions AS oe
                JOIN fact_observations AS o ON o.id = oe.observation_id
                WHERE oe.execution_key = ? AND o.scan_id = ?
                  AND LOWER(RTRIM(TRIM(o.host), '.')) = ?
                UNION
                SELECT a.fact_id AS fact_id
                FROM fact_assessment_executions AS ae
                JOIN fact_assessments AS a
                  ON a.assessment_id = ae.assessment_id
                JOIN facts AS f ON f.id = a.fact_id
                WHERE ae.execution_key = ? AND f.scan_id = ?
                  AND LOWER(RTRIM(TRIM(f.host), '.')) = ?
            )
            ORDER BY fact_id
            """,
            (
                execution_key,
                scan_id,
                host_key,
                execution_key,
                scan_id,
                host_key,
            ),
        ).fetchall()
        return tuple(int(row[0]) for row in rows)

    def claim_command_completion(
        self,
        *,
        scan_id: str,
        host: str,
        command_key: str,
        command: str,
        output_hash: str,
        status: str | ExecutionStatus,
        failed: bool,
        partial: bool,
        execution_id: str,
        idempotency_key: str,
        schema_version: str = "0",
        request_id: str = "",
        policy_decision_ref: str = "",
        exit_code: int | None = None,
        error_class: str = "",
        artifact_count: int = 0,
        scan_generation: int | None = None,
        completion_fence: CommandCompletionClaim | None = None,
    ) -> CommandCompletionClaim:
        """Reserve an idempotent completion before parsing or evidence writes."""

        safe_idempotency_key = self._idempotency_digest(idempotency_key)
        normalized_status = (
            status.value if isinstance(status, ExecutionStatus) else str(status).lower()
        )
        if normalized_status not in _COMMAND_RESULT_STATUSES:
            raise ValueError(f"Unsupported command result status: {normalized_status}")
        effective_failed = bool(failed) or normalized_status in _FAILED_STATUSES
        safe_output_hash = self._safe_output_hash(output_hash)
        raw_execution_id = str(execution_id or "")
        execution_key = (
            self.secret_store.keyed_digest(
                raw_execution_id,
                kind="fact_assessment:execution",
            )
            if raw_execution_id
            else ""
        )
        scan_key = self._completion_scan_key(scan_id)
        host_key = self._completion_host_key(host)
        request_fingerprint = self._completion_request_fingerprint(
            command_key=command_key,
            command=command,
            output_hash=safe_output_hash,
            status=normalized_status,
            failed=effective_failed,
            partial=partial,
            execution_key=execution_key,
            schema_version=schema_version,
            request_id=request_id,
            policy_decision_ref=policy_decision_ref,
            exit_code=exit_code,
            error_class=error_class,
            artifact_count=artifact_count,
        )
        owner_token = uuid4().hex
        claimed_at = self._completion_now()
        lease_expires_at = claimed_at + self._completion_lease_seconds
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if completion_fence is not None:
                if completion_fence.scan_key != scan_key:
                    raise CommandCompletionConflictError(
                        "Execution completion fence belongs to a different scan"
                    )
                expected_generation = int(completion_fence.scan_generation)
                if (
                    scan_generation is not None
                    and int(scan_generation) != expected_generation
                ):
                    raise CommandCompletionConflictError(
                        "Execution completion generation inputs disagree"
                    )
            else:
                expected_generation = (
                    self._scan_completion_generation_in_connection(conn, scan_key)
                    if scan_generation is None
                    else int(scan_generation)
                )
            self._validate_scan_completion_generation_in_connection(
                conn,
                scan_key=scan_key,
                expected_generation=expected_generation,
            )
            if not safe_idempotency_key:
                return CommandCompletionClaim(
                    scan_key=scan_key,
                    scan_generation=expected_generation,
                )
            claim_row = conn.execute(
                """
                SELECT scan_id, scan_generation, host_key, request_fingerprint,
                       owner_token, state, lease_expires_at, command_result_id,
                       fact_ids_json, parsed_facts, new_facts
                FROM command_completion_claims
                WHERE idempotency_key = ?
                """,
                (safe_idempotency_key,),
            ).fetchone()
            if claim_row is not None and int(claim_row[1]) != expected_generation:
                raise CommandCompletionConflictError(
                    "Execution completion belongs to a different scan generation"
                )
            if claim_row is None:
                existing = conn.execute(
                    """
                    SELECT id, scan_id, host, command_key, command, output_hash,
                           status, failed, partial, execution_key,
                           parsed_facts, new_facts, schema_version, request_id,
                           policy_decision_ref, exit_code, error_class,
                           artifact_count, completion_fingerprint
                    FROM command_results
                    WHERE idempotency_key = ?
                    LIMIT 1
                    """,
                    (safe_idempotency_key,),
                ).fetchone()
                if existing is not None:
                    existing_host_key = self._completion_host_key(existing[2])
                    existing_fingerprint = str(existing[18] or "")
                    self._validate_completion_identity(
                        existing_scan_id=str(existing[1]),
                        existing_host_key=existing_host_key,
                        existing_fingerprint=(
                            existing_fingerprint or request_fingerprint
                        ),
                        scan_id=str(scan_id),
                        host_key=host_key,
                        request_fingerprint=request_fingerprint,
                    )
                    if not existing_fingerprint:
                        self._validate_legacy_completion_payload(
                            existing_output_hash=str(existing[5]),
                            existing_status=str(existing[6]),
                            existing_failed=bool(existing[7]),
                            existing_partial=bool(existing[8]),
                            existing_execution_key=str(existing[9] or ""),
                            existing_schema_version=str(existing[12]),
                            existing_command_key=str(existing[3]),
                            existing_command=str(existing[4]),
                            existing_request_id=str(existing[13]),
                            existing_policy_decision_ref=str(existing[14]),
                            existing_exit_code=(
                                int(existing[15])
                                if existing[15] is not None
                                else None
                            ),
                            existing_error_class=str(existing[16]),
                            existing_artifact_count=self._bounded_count(existing[17]),
                            output_hash=safe_output_hash,
                            status=normalized_status,
                            failed=effective_failed,
                            partial=bool(partial),
                            execution_key=execution_key,
                            schema_version=self._bounded_text(schema_version, 32),
                            command_key=self._bounded_text(
                                self.redactor.redact_text(
                                    command_key,
                                    kind="command_key",
                                ),
                                _MAX_IDENTIFIER_BYTES,
                            ),
                            command=self._bounded_text(
                                self.redactor.redact_text(command, kind="command"),
                                _MAX_COMMAND_BYTES,
                            ),
                            request_id=self._bounded_text(
                                self.redactor.redact_text(
                                    request_id,
                                    kind="request_id",
                                ),
                                _MAX_IDENTIFIER_BYTES,
                            ),
                            policy_decision_ref=self._bounded_text(
                                self.redactor.redact_text(
                                    policy_decision_ref,
                                    kind="policy_decision_ref",
                                ),
                                _MAX_IDENTIFIER_BYTES,
                            ),
                            exit_code=(int(exit_code) if exit_code is not None else None),
                            error_class=self._bounded_text(
                                self.redactor.redact_text(
                                    error_class,
                                    kind="execution_error_class",
                                ),
                                256,
                            ),
                            artifact_count=self._bounded_count(artifact_count),
                        )
                    fact_ids = self._fact_ids_for_execution_in_connection(
                        conn,
                        execution_key=str(existing[9] or ""),
                        scan_id=str(scan_id),
                        host_key=host_key,
                    )
                    conn.execute(
                        """
                        INSERT INTO command_completion_claims(
                            idempotency_key, scan_id, scan_generation, host_key,
                            request_fingerprint, state, command_result_id,
                            fact_ids_json, parsed_facts, new_facts,
                            created_at, completed_at
                        ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            safe_idempotency_key,
                            str(scan_id),
                            expected_generation,
                            host_key,
                            request_fingerprint,
                            int(existing[0]),
                            json.dumps(list(fact_ids)),
                            self._bounded_count(existing[10]),
                            self._bounded_count(existing[11]),
                            claimed_at,
                            claimed_at,
                        ),
                    )
                    return CommandCompletionClaim(
                        scan_key=scan_key,
                        scan_generation=expected_generation,
                        idempotency_key=safe_idempotency_key,
                        replayed=True,
                        command_result_id=int(existing[0]),
                        fact_ids=fact_ids,
                        parsed_facts=self._bounded_count(existing[10]),
                        new_facts=self._bounded_count(existing[11]),
                    )
                conn.execute(
                    """
                    INSERT INTO command_completion_claims(
                        idempotency_key, scan_id, scan_generation, host_key,
                        request_fingerprint, owner_token, state, created_at,
                        lease_expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        safe_idempotency_key,
                        str(scan_id),
                        expected_generation,
                        host_key,
                        request_fingerprint,
                        owner_token,
                        claimed_at,
                        lease_expires_at,
                    ),
                )
                return CommandCompletionClaim(
                    scan_key=scan_key,
                    scan_generation=expected_generation,
                    idempotency_key=safe_idempotency_key,
                    owner_token=owner_token,
                )

            self._validate_completion_identity(
                existing_scan_id=str(claim_row[0]),
                existing_host_key=str(claim_row[2]),
                existing_fingerprint=str(claim_row[3]),
                scan_id=str(scan_id),
                host_key=host_key,
                request_fingerprint=request_fingerprint,
            )
            if str(claim_row[5]) != "completed":
                try:
                    existing_lease = float(claim_row[6] or 0.0)
                except (TypeError, ValueError):
                    existing_lease = 0.0
                if existing_lease > claimed_at:
                    raise CommandCompletionInProgressError(
                        "Execution completion is already in progress"
                    )
                conn.execute(
                    """
                    UPDATE command_completion_claims
                    SET owner_token = ?, lease_expires_at = ?
                    WHERE idempotency_key = ? AND scan_generation = ?
                      AND state = 'pending'
                    """,
                    (
                        owner_token,
                        lease_expires_at,
                        safe_idempotency_key,
                        expected_generation,
                    ),
                )
                return CommandCompletionClaim(
                    scan_key=scan_key,
                    scan_generation=expected_generation,
                    idempotency_key=safe_idempotency_key,
                    owner_token=owner_token,
                )
            result_id = int(claim_row[7]) if claim_row[7] is not None else None
            if result_id is None:
                raise RuntimeError("Completed execution claim has no command result")
            return CommandCompletionClaim(
                scan_key=scan_key,
                scan_generation=expected_generation,
                idempotency_key=safe_idempotency_key,
                replayed=True,
                command_result_id=result_id,
                fact_ids=self._completion_fact_ids(claim_row[8]),
                parsed_facts=self._bounded_count(claim_row[9]),
                new_facts=self._bounded_count(claim_row[10]),
            )

    def release_command_completion_claim(
        self,
        claim: CommandCompletionClaim,
    ) -> None:
        """Release a reservation when completion failed before side effects."""

        if not claim.idempotency_key or not claim.owner_token or claim.replayed:
            return
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                DELETE FROM command_completion_claims
                WHERE idempotency_key = ? AND owner_token = ?
                  AND scan_generation = ?
                  AND state = 'pending'
                """,
                (
                    claim.idempotency_key,
                    claim.owner_token,
                    claim.scan_generation,
                ),
            )

    def renew_command_completion_claim(
        self,
        claim: CommandCompletionClaim,
    ) -> None:
        """Fence each completion side effect with a renewed ownership lease."""

        if claim.replayed:
            return
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._renew_command_completion_claim_in_connection(conn, claim)

    def _renew_command_completion_claim_in_connection(
        self,
        conn: sqlite3.Connection,
        claim: CommandCompletionClaim | None,
    ) -> None:
        if (
            claim is None
            or claim.replayed
        ):
            return
        self._validate_scan_completion_generation_in_connection(
            conn,
            scan_key=claim.scan_key,
            expected_generation=claim.scan_generation,
        )
        if not claim.idempotency_key or not claim.owner_token:
            return
        lease_expires_at = self._completion_now() + self._completion_lease_seconds
        updated = conn.execute(
            """
            UPDATE command_completion_claims
            SET lease_expires_at = ?
            WHERE idempotency_key = ? AND owner_token = ?
              AND scan_generation = ?
              AND state = 'pending'
            """,
            (
                lease_expires_at,
                claim.idempotency_key,
                claim.owner_token,
                claim.scan_generation,
            ),
        )
        if updated.rowcount != 1:
            raise CommandCompletionInProgressError(
                "Execution completion lease ownership was lost"
            )

    def get_hypotheses(self, scan_id: str, host: str | None = None) -> list[dict[str, Any]]:
        """Retrieve hypotheses matching criteria."""
        query = "SELECT id, scan_id, host, claim, required_evidence, source, timestamp FROM hypotheses WHERE scan_id = ?"
        params = [scan_id]

        if host:
            query += " AND host = ?"
            params.append(host)
            
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "scan_id": row[1],
                "host": row[2],
                "claim": row[3],
                "required_evidence": json.loads(row[4]),
                "source": row[5],
                "timestamp": row[6]
            })
        return results

    def add_command_result(
        self,
        scan_id: str,
        host: str,
        command_key: str,
        command: str,
        output_hash: str,
        output_bytes: int = 0,
        parsed_facts: int = 0,
        new_facts: int = 0,
        failed: bool = False,
        *,
        execution_result: ExecutionResult | None = None,
        schema_version: str = "0",
        status: str | None = None,
        partial: bool = False,
        execution_id: str = "",
        request_id: str = "",
        policy_decision_ref: str = "",
        exit_code: int | None = None,
        duration: float = 0.0,
        stderr_bytes: int = 0,
        error_class: str = "",
        artifact_count: int = 0,
        metadata: dict[str, Any] | None = None,
        idempotency_key: str = "",
        fact_ids: Iterable[int] = (),
        completion_claim: CommandCompletionClaim | None = None,
    ) -> tuple[int, bool]:
        now = time.time()
        raw_command_key = str(command_key or "")
        raw_command = str(command or "")
        legacy_failed = bool(failed)
        if execution_result is not None:
            schema_version = execution_result.schema_version
            status = execution_result.status.value
            partial = execution_result.partial
            execution_id = execution_result.execution_id
            request_id = execution_result.request_id
            policy_decision_ref = execution_result.policy_decision_ref
            exit_code = execution_result.exit_code
            duration = execution_result.duration
            output_bytes = len(execution_result.stdout.encode("utf-8", "ignore"))
            stderr_bytes = len(execution_result.stderr.encode("utf-8", "ignore"))
            error_class = execution_result.error_class
            artifact_count = len(execution_result.artifact_refs)
            metadata = execution_result.metadata
        normalized_status = (
            status.value
            if isinstance(status, ExecutionStatus)
            else str(status or ("failed" if failed else "succeeded")).lower()
        )
        if normalized_status not in _COMMAND_RESULT_STATUSES:
            raise ValueError(f"Unsupported command result status: {normalized_status}")
        # ``failed`` is the legacy content/adapter projection. Preserve it in
        # addition to canonical terminal statuses so an error-shaped legacy
        # stdout cannot become successful corroboration merely because it was
        # adapted to a schema-1.0 ``succeeded`` transport result.
        failed = legacy_failed or normalized_status in _FAILED_STATUSES
        try:
            safe_duration = float(duration or 0.0)
        except (TypeError, ValueError):
            safe_duration = 0.0
        if not math.isfinite(safe_duration) or safe_duration < 0:
            safe_duration = 0.0
        safe_exit_code: int | None
        try:
            safe_exit_code = None if exit_code is None else int(exit_code)
        except (TypeError, ValueError):
            safe_exit_code = None
        raw_schema_version = str(schema_version or "")
        raw_request_id = str(request_id or "")
        raw_policy_decision_ref = str(policy_decision_ref or "")
        raw_error_class = str(error_class or "")
        safe_artifact_count = self._bounded_count(artifact_count)
        command = self._bounded_text(
            self.redactor.redact_text(command, kind="command"),
            _MAX_COMMAND_BYTES,
        )
        command_key = self._bounded_text(
            self.redactor.redact_text(command_key, kind="command_key"),
            _MAX_IDENTIFIER_BYTES,
        )
        output_hash = self._safe_output_hash(output_hash)
        schema_version = self._bounded_text(schema_version, 32)
        raw_execution_id = str(execution_id or "")
        execution_key = (
            self.secret_store.keyed_digest(
                raw_execution_id,
                kind="fact_assessment:execution",
            )
            if raw_execution_id
            else ""
        )
        execution_id = self._bounded_text(
            self.redactor.redact_text(raw_execution_id, kind="execution_id"),
            _MAX_IDENTIFIER_BYTES,
        )
        request_id = self._bounded_text(
            self.redactor.redact_text(request_id, kind="request_id"),
            _MAX_IDENTIFIER_BYTES,
        )
        policy_decision_ref = self._bounded_text(
            self.redactor.redact_text(policy_decision_ref, kind="policy_decision_ref"),
            _MAX_IDENTIFIER_BYTES,
        )
        error_class = self._bounded_text(
            self.redactor.redact_text(error_class, kind="execution_error_class"),
            256,
        )
        metadata_json = self._metadata_json(metadata or {})
        safe_idempotency_key = self._idempotency_digest(idempotency_key)
        request_fingerprint = self._completion_request_fingerprint(
            command_key=raw_command_key,
            command=raw_command,
            output_hash=output_hash,
            status=normalized_status,
            failed=failed,
            partial=partial,
            execution_key=execution_key,
            schema_version=raw_schema_version,
            request_id=raw_request_id,
            policy_decision_ref=raw_policy_decision_ref,
            exit_code=safe_exit_code,
            error_class=raw_error_class,
            artifact_count=safe_artifact_count,
        )
        normalized_fact_ids = self._normalized_projection_fact_ids(fact_ids)
        projection_fact_ids: tuple[int, ...] = ()
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            scan_key = self._completion_scan_key(scan_id)
            if completion_claim is not None:
                if completion_claim.scan_key != scan_key:
                    raise CommandCompletionConflictError(
                        "Execution completion claim belongs to a different scan"
                    )
                self._renew_command_completion_claim_in_connection(
                    conn,
                    completion_claim,
                )
                result_generation = completion_claim.scan_generation
            else:
                result_generation = self._scan_completion_generation_in_connection(
                    conn,
                    scan_key,
                )
            claim_row = None
            if safe_idempotency_key:
                claim_row = cursor.execute(
                    """
                    SELECT scan_id, scan_generation, host_key,
                           request_fingerprint, owner_token, state,
                           command_result_id
                    FROM command_completion_claims
                    WHERE idempotency_key = ?
                    """,
                    (safe_idempotency_key,),
                ).fetchone()
                if claim_row is not None:
                    if int(claim_row[1]) != result_generation:
                        raise CommandCompletionConflictError(
                            "Execution completion belongs to a different scan generation"
                        )
                    self._validate_completion_identity(
                        existing_scan_id=str(claim_row[0]),
                        existing_host_key=str(claim_row[2]),
                        existing_fingerprint=str(claim_row[3]),
                        scan_id=str(scan_id),
                        host_key=self._completion_host_key(host),
                        request_fingerprint=request_fingerprint,
                    )
                    if str(claim_row[5]) == "pending" and (
                        completion_claim is None
                        or completion_claim.idempotency_key != safe_idempotency_key
                        or completion_claim.owner_token != str(claim_row[4])
                    ):
                        raise CommandCompletionInProgressError(
                            "Execution completion is already in progress"
                        )
                elif completion_claim is not None:
                    raise RuntimeError("Execution completion claim was lost")
            idempotent = None
            if safe_idempotency_key:
                cursor.execute(
                    """
                    SELECT id, scan_id, host, command_key, command,
                           output_hash, status, failed, partial, execution_key,
                           schema_version, request_id, policy_decision_ref,
                           exit_code, error_class, artifact_count,
                           completion_fingerprint
                    FROM command_results
                    WHERE idempotency_key = ? LIMIT 1
                    """,
                    (safe_idempotency_key,),
                )
                idempotent = cursor.fetchone()
            if idempotent is not None:
                if claim_row is None:
                    existing_fingerprint = str(idempotent[16] or "")
                    self._validate_completion_identity(
                        existing_scan_id=str(idempotent[1]),
                        existing_host_key=self._completion_host_key(idempotent[2]),
                        existing_fingerprint=(
                            existing_fingerprint or request_fingerprint
                        ),
                        scan_id=str(scan_id),
                        host_key=self._completion_host_key(host),
                        request_fingerprint=request_fingerprint,
                    )
                    if not existing_fingerprint:
                        self._validate_legacy_completion_payload(
                            existing_output_hash=str(idempotent[5]),
                            existing_status=str(idempotent[6]),
                            existing_failed=bool(idempotent[7]),
                            existing_partial=bool(idempotent[8]),
                            existing_execution_key=str(idempotent[9] or ""),
                            existing_schema_version=str(idempotent[10]),
                            existing_command_key=str(idempotent[3]),
                            existing_command=str(idempotent[4]),
                            existing_request_id=str(idempotent[11]),
                            existing_policy_decision_ref=str(idempotent[12]),
                            existing_exit_code=(
                                int(idempotent[13])
                                if idempotent[13] is not None
                                else None
                            ),
                            existing_error_class=str(idempotent[14]),
                            existing_artifact_count=self._bounded_count(idempotent[15]),
                            output_hash=output_hash,
                            status=normalized_status,
                            failed=failed,
                            partial=bool(partial),
                            execution_key=execution_key,
                            schema_version=schema_version,
                            command_key=command_key,
                            command=command,
                            request_id=request_id,
                            policy_decision_ref=policy_decision_ref,
                            exit_code=safe_exit_code,
                            error_class=error_class,
                            artifact_count=safe_artifact_count,
                        )
                result_id = int(idempotent[0])
                result_is_unique = False
                projection_execution_key = str(idempotent[9] or "")
            else:
                cursor.execute('''
                    SELECT id FROM command_results
                    WHERE scan_id = ? AND host = ? AND output_hash = ?
                    LIMIT 1
                ''', (scan_id, host, output_hash))
                existing = cursor.fetchone()
                cursor.execute('''
                    INSERT INTO command_results (
                        scan_id, host, command_key, command, output_hash, output_bytes,
                        parsed_facts, new_facts, failed, schema_version, status, partial,
                        execution_id, execution_key, request_id, policy_decision_ref,
                        exit_code, duration,
                        stderr_bytes, error_class, artifact_count, metadata_json,
                        idempotency_key, completion_fingerprint, timestamp
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    host,
                    command_key,
                    command,
                    output_hash,
                    self._bounded_count(output_bytes),
                    self._bounded_count(parsed_facts),
                    self._bounded_count(new_facts),
                    1 if failed else 0,
                    schema_version,
                    normalized_status,
                    1 if partial else 0,
                    execution_id,
                    execution_key,
                    request_id,
                    policy_decision_ref,
                    safe_exit_code,
                    safe_duration,
                    self._bounded_count(stderr_bytes),
                    error_class,
                    safe_artifact_count,
                    metadata_json,
                    safe_idempotency_key,
                    request_fingerprint,
                    now,
                ))
                result_id = int(cursor.lastrowid)
                result_is_unique = existing is None
                projection_execution_key = execution_key
            self.assessments.apply_automatic_rules_for_execution_in_connection(
                conn,
                execution_key=projection_execution_key,
                scan_id=scan_id,
                host=host,
            )
            projection_fact_ids = (
                self.assessments.automatic_rule_fact_ids_for_execution_in_connection(
                    conn,
                    execution_key=projection_execution_key,
                    scan_id=scan_id,
                    host=host,
                )
            )
            self._enqueue_assessment_projections_in_connection(
                conn,
                projection_fact_ids,
            )
            if safe_idempotency_key:
                fact_ids_json = json.dumps(list(normalized_fact_ids))
                if completion_claim is not None and completion_claim.owner_token:
                    updated = cursor.execute(
                        """
                        UPDATE command_completion_claims
                        SET owner_token = '', state = 'completed',
                            command_result_id = ?, fact_ids_json = ?,
                            parsed_facts = ?, new_facts = ?,
                            lease_expires_at = NULL, completed_at = ?
                        WHERE idempotency_key = ? AND owner_token = ?
                          AND scan_generation = ? AND state = 'pending'
                        """,
                        (
                            result_id,
                            fact_ids_json,
                            self._bounded_count(parsed_facts),
                            self._bounded_count(new_facts),
                            now,
                            safe_idempotency_key,
                            completion_claim.owner_token,
                            result_generation,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise RuntimeError("Execution completion claim could not be finalized")
                elif claim_row is None:
                    cursor.execute(
                        """
                        INSERT INTO command_completion_claims(
                            idempotency_key, scan_id, scan_generation, host_key,
                            request_fingerprint, state, command_result_id,
                            fact_ids_json, parsed_facts, new_facts,
                            created_at, completed_at
                        ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            safe_idempotency_key,
                            str(scan_id),
                            result_generation,
                            self._completion_host_key(host),
                            request_fingerprint,
                            result_id,
                            fact_ids_json,
                            self._bounded_count(parsed_facts),
                            self._bounded_count(new_facts),
                            now,
                            now,
                        ),
                    )
            conn.commit()
        self._refresh_assessment_projections(projection_fact_ids)
        return result_id, result_is_unique

    def get_command_results(self, scan_id: str, host: str | None = None) -> list[dict[str, Any]]:
        query = '''
            SELECT id, scan_id, host, command_key, command, output_hash, output_bytes,
                   parsed_facts, new_facts, failed, timestamp, schema_version, status,
                   partial, execution_id, request_id, policy_decision_ref, exit_code,
                   duration, stderr_bytes, error_class, artifact_count, metadata_json,
                   idempotency_key
            FROM command_results
            WHERE scan_id = ?
        '''
        params = [scan_id]
        if host:
            query += " AND host = ?"
            params.append(host)
        query += " ORDER BY timestamp ASC, id ASC"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return [self._command_result_from_row(row) for row in rows]

    def get_command_result_by_id(self, result_id: int) -> dict[str, Any] | None:
        """Load one persisted command result for an idempotent replay."""

        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT id, scan_id, host, command_key, command, output_hash,
                       output_bytes, parsed_facts, new_facts, failed, timestamp,
                       schema_version, status, partial, execution_id, request_id,
                       policy_decision_ref, exit_code, duration, stderr_bytes,
                       error_class, artifact_count, metadata_json, idempotency_key
                FROM command_results WHERE id = ?
                """,
                (int(result_id),),
            ).fetchone()
        return self._command_result_from_row(row) if row is not None else None

    def _command_result_from_row(self, row: Sequence[Any]) -> dict[str, Any]:
        return {
            "id": row[0],
            "scan_id": row[1],
            "host": row[2],
            "command_key": row[3],
            "command": row[4],
            "output_hash": row[5],
            "output_bytes": row[6],
            "parsed_facts": row[7],
            "new_facts": row[8],
            "failed": bool(row[9]),
            "timestamp": row[10],
            "schema_version": row[11],
            "status": row[12],
            "partial": bool(row[13]),
            "execution_id": row[14],
            "request_id": row[15],
            "policy_decision_ref": row[16],
            "exit_code": row[17],
            "duration": row[18],
            "stderr_bytes": row[19],
            "error_class": row[20],
            "artifact_count": row[21],
            "metadata_json": row[22],
            "metadata": self._load_json_value(row[22]),
            "idempotency_key": row[23],
        }

    def get_all_facts_for_llm(self, scan_id: str, host: str) -> str:
        """Format facts as a JSON string for LLM ingestion. Use ContextBuilder instead for Director."""
        facts = self.get_facts(scan_id, host)
        # Strip internal DB fields to save tokens
        clean_facts = []
        for f in facts:
            clean_facts.append({
                "type": f["type"],
                "value": f["value"],
                "source": f["source"],
                "sources": f.get("sources", []),
                "observations": len(f.get("observations", [])),
                "session_id": f["session_id"],
                "confidence": f["confidence"],
                "assessment_id": f.get("assessment_id"),
                "assessment_status": f.get("assessment_status", "observed"),
            })
        return json.dumps(clean_facts, indent=2)

    def get_history(self, scan_id: str) -> list[dict[str, Any]]:
        """Retrieve chronological history of facts for anti-loop and replay."""
        return self.get_facts(scan_id)

    def clear_scan(self, scan_id: str):
        """Remove evidence and durable mission state for a clean scan restart."""
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            live_claim = cursor.execute(
                """
                SELECT 1 FROM command_completion_claims
                WHERE scan_id = ? AND state = 'pending'
                  AND COALESCE(lease_expires_at, 0) > ?
                LIMIT 1
                """,
                (scan_id, self._completion_now()),
            ).fetchone()
            if live_claim is not None:
                raise CommandCompletionInProgressError(
                    "Cannot clear a scan with an active execution completion"
                )
            cursor.execute(
                """
                INSERT INTO scan_completion_generations(
                    scan_key, generation, updated_at
                ) VALUES (?, 1, ?)
                ON CONFLICT(scan_key) DO UPDATE SET
                    generation = scan_completion_generations.generation + 1,
                    updated_at = excluded.updated_at
                """,
                (self._completion_scan_key(scan_id), time.time()),
            )
            has_missions = cursor.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'missions'
                """
            ).fetchone()
            if has_missions:
                cursor.execute(
                    "DELETE FROM missions WHERE scan_key = ?",
                    (
                        self.secret_store.keyed_digest(
                            str(scan_id or ""),
                            kind="mission:scan",
                        ),
                    ),
                )
            cursor.execute("DELETE FROM fact_observations WHERE scan_id = ?", (scan_id,))
            cursor.execute(
                "DELETE FROM command_completion_claims WHERE scan_id = ?",
                (scan_id,),
            )
            cursor.execute("DELETE FROM command_results WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM hypotheses WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM facts WHERE scan_id = ?", (scan_id,))
            conn.commit()
