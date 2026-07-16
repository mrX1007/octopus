#!/usr/bin/env python3

import hashlib
import json
import math
import os
import sqlite3
import time
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from typing import Any, Callable, Optional

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


class FactStore:
    def __init__(
        self,
        db_path: str = "data/facts.db",
        secret_store: Optional[SecretStore] = None,
        *,
        assessment_policy: Optional[FreshnessPolicy] = None,
        assessment_clock: Optional[Callable[[], float]] = None,
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
        self._init_db()
        self.assessments = FactAssessmentStore(
            self.db_path,
            secret_store=self.secret_store,
            redactor=self.redactor,
            freshness_policy=assessment_policy,
            clock=assessment_clock,
        )

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
                    session_id TEXT NOT NULL DEFAULT 'none',
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    secret_refs TEXT NOT NULL DEFAULT '[]',
                    FOREIGN KEY(fact_id) REFERENCES facts(id)
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
                    timestamp REAL NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_host ON facts (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON facts (type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_fact ON fact_observations (fact_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_scan_host ON fact_observations (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_hash ON command_results (scan_id, host, output_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_key ON command_results (scan_id, host, command_key)')
            self._ensure_column(cursor, "facts", "secret_refs", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(cursor, "fact_observations", "secret_refs", "TEXT NOT NULL DEFAULT '[]'")
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
            cursor.execute(
                """
                UPDATE command_results
                SET status = CASE WHEN failed = 1 THEN 'failed' ELSE 'succeeded' END
                WHERE status = 'legacy'
                """
            )
            self._backfill_command_execution_keys(cursor)
            self._redact_existing_rows(cursor)
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

    def add_fact(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                 confidence: int = 100, session_id: str = 'none',
                 derived_from: Optional[list[int]] = None, evidence_hash: str = "",
                 source_execution_ids: Optional[Sequence[str]] = None) -> int:
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
        )
        return fact_id

    def add_fact_with_status(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                             confidence: int = 100, session_id: str = 'none',
                             derived_from: Optional[list[int]] = None, evidence_hash: str = "",
                             source_execution_ids: Optional[Sequence[str]] = None) -> tuple[int, bool]:
        """Add a fact and return (row_id, created).

        The AI pipeline uses the created flag for anti-loop accounting. Without
        it, duplicates look like new facts because add_fact() returns an id for
        both new and existing rows.
        """
        if derived_from is None:
            derived_from = []
        value, secret_refs = self.redactor.redact_fact(fact_type, value)
        source = self.redactor.redact_text(source, kind="fact_source")
        session_id = self.redactor.redact_text(session_id, kind="session_id")
        derived_json = json.dumps(derived_from)
        refs_json = json.dumps(secret_refs)
        now = time.time()
        evidence_hash = evidence_hash or self._evidence_hash(
            scan_id, host, fact_type, value, source, session_id
        )

        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, confidence FROM facts
                WHERE scan_id = ? AND host = ? AND type = ? AND value = ?
                LIMIT 1
            ''', (scan_id, host, fact_type, value))
            existing = cursor.fetchone()
            if existing:
                fact_id, old_confidence = existing
                cursor.execute('''
                    UPDATE facts
                    SET confidence = ?, timestamp = ?
                    WHERE id = ?
                ''', (max(int(old_confidence or 0), int(confidence or 0)), now, fact_id))
                self._insert_observation(
                    cursor, fact_id, scan_id, host, fact_type, value,
                    confidence, source, session_id, evidence_hash, now, secret_refs,
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

    def _insert_observation(self, cursor, fact_id: int, scan_id: str, host: str,
                            fact_type: str, value: str, confidence: int, source: str,
                            session_id: str, evidence_hash: str, timestamp: float,
                            secret_refs: tuple[str, ...]) -> None:
        cursor.execute('''
            INSERT INTO fact_observations (
                fact_id, scan_id, host, type, value, confidence, source,
                session_id, evidence_hash, timestamp, secret_refs
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fact_id, scan_id, host, fact_type, value, confidence, source,
            session_id, evidence_hash, timestamp, json.dumps(secret_refs),
        ))

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

    def get_facts(self, scan_id: str, host: Optional[str] = None, fact_type: Optional[str] = None, session_id: Optional[str] = None) -> list[dict[str, Any]]:
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

        query += " ORDER BY timestamp ASC"

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            fact_ids = [row[0] for row in rows]
            observations_by_fact = self._get_observations_for_facts(cursor, fact_ids)
        return self._serialize_fact_rows(rows, observations_by_fact)

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
            observations_by_fact = self._get_observations_for_facts(cursor, ids)
        return self._serialize_fact_rows(rows, observations_by_fact)

    def _serialize_fact_rows(
        self,
        rows: Sequence[Sequence[Any]],
        observations_by_fact: dict[int, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        fact_ids = [int(row[0]) for row in rows]
        assessments_by_fact = self.assessments.current_for_facts(fact_ids)
        latest_execution_statuses = self._latest_execution_statuses_for_assessments(
            assessments_by_fact.values()
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
            )
            if not observations:
                observations = [{
                    "id": None,
                    "confidence": row[5],
                    "source": row[6],
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
        assessments: Iterable[FactAssessment],
    ) -> dict[int, str]:
        assessment_ids = tuple(
            assessment.assessment_id for assessment in assessments
        )
        if not assessment_ids:
            return {}
        placeholders = ",".join("?" for _ in assessment_ids)
        with self._get_conn() as conn:
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
            SELECT id, fact_id, confidence, source, session_id, evidence_hash, timestamp, secret_refs
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
                "session_id": row[4],
                "evidence_hash": row[5],
                "timestamp": row[6],
                "secret_refs": list(self._load_refs(row[7])),
            })
        return grouped

    def get_hypotheses(self, scan_id: str, host: Optional[str] = None) -> list[dict[str, Any]]:
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
        execution_result: Optional[ExecutionResult] = None,
        schema_version: str = "0",
        status: Optional[str] = None,
        partial: bool = False,
        execution_id: str = "",
        request_id: str = "",
        policy_decision_ref: str = "",
        exit_code: Optional[int] = None,
        duration: float = 0.0,
        stderr_bytes: int = 0,
        error_class: str = "",
        artifact_count: int = 0,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: str = "",
    ) -> tuple[int, bool]:
        now = time.time()
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
        failed = normalized_status in _FAILED_STATUSES
        try:
            safe_duration = float(duration or 0.0)
        except (TypeError, ValueError):
            safe_duration = 0.0
        if not math.isfinite(safe_duration) or safe_duration < 0:
            safe_duration = 0.0
        safe_exit_code: Optional[int]
        try:
            safe_exit_code = None if exit_code is None else int(exit_code)
        except (TypeError, ValueError):
            safe_exit_code = None
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
        safe_idempotency_key = (
            hashlib.sha256(str(idempotency_key).encode("utf-8", "replace")).hexdigest()
            if idempotency_key
            else ""
        )
        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            if safe_idempotency_key:
                cursor.execute(
                    """
                    SELECT id, execution_key FROM command_results
                    WHERE idempotency_key = ? LIMIT 1
                    """,
                    (safe_idempotency_key,),
                )
                idempotent = cursor.fetchone()
                if idempotent is not None:
                    self.assessments.apply_automatic_rules_for_execution_in_connection(
                        conn,
                        execution_key=str(idempotent[1] or ""),
                        scan_id=scan_id,
                        host=host,
                    )
                    return int(idempotent[0]), False
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
                    idempotency_key, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                self._bounded_count(artifact_count),
                metadata_json,
                safe_idempotency_key,
                now,
            ))
            self.assessments.apply_automatic_rules_for_execution_in_connection(
                conn,
                execution_key=execution_key,
                scan_id=scan_id,
                host=host,
            )
            conn.commit()
            return cursor.lastrowid, existing is None

    def get_command_results(self, scan_id: str, host: Optional[str] = None) -> list[dict[str, Any]]:
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
        return [
            {
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
            for row in rows
        ]

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
            cursor = conn.cursor()
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
            cursor.execute("DELETE FROM command_results WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM hypotheses WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM facts WHERE scan_id = ?", (scan_id,))
            conn.commit()
