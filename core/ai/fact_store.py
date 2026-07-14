#!/usr/bin/env python3

import hashlib
import json
import math
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Optional

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
    def __init__(self, db_path: str = "data/facts.db", secret_store: Optional[SecretStore] = None):
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

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys=ON")
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
                    request_id TEXT NOT NULL DEFAULT '',
                    policy_decision_ref TEXT NOT NULL DEFAULT '',
                    exit_code INTEGER,
                    duration REAL NOT NULL DEFAULT 0.0,
                    stderr_bytes INTEGER NOT NULL DEFAULT 0,
                    error_class TEXT NOT NULL DEFAULT '',
                    artifact_count INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
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
            cursor.execute(
                """
                UPDATE command_results
                SET status = CASE WHEN failed = 1 THEN 'failed' ELSE 'succeeded' END
                WHERE status = 'legacy'
                """
            )
            self._redact_existing_rows(cursor)
            conn.commit()

    def _ensure_column(self, cursor, table: str, column: str, definition: str) -> None:
        columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

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
                 derived_from: Optional[list[int]] = None, evidence_hash: str = "") -> int:
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
        )
        return fact_id

    def add_fact_with_status(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                             confidence: int = 100, session_id: str = 'none',
                             derived_from: Optional[list[int]] = None, evidence_hash: str = "") -> tuple[int, bool]:
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

        results = []
        for row in rows:
            observations = observations_by_fact.get(row[0], [])
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
            })
        return results

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
        execution_id = self._bounded_text(
            self.redactor.redact_text(execution_id, kind="execution_id"),
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
        with self._get_conn() as conn:
            cursor = conn.cursor()
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
                    execution_id, request_id, policy_decision_ref, exit_code, duration,
                    stderr_bytes, error_class, artifact_count, metadata_json, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                request_id,
                policy_decision_ref,
                safe_exit_code,
                safe_duration,
                self._bounded_count(stderr_bytes),
                error_class,
                self._bounded_count(artifact_count),
                metadata_json,
                now,
            ))
            conn.commit()
            return cursor.lastrowid, existing is None

    def get_command_results(self, scan_id: str, host: Optional[str] = None) -> list[dict[str, Any]]:
        query = '''
            SELECT id, scan_id, host, command_key, command, output_hash, output_bytes,
                   parsed_facts, new_facts, failed, timestamp, schema_version, status,
                   partial, execution_id, request_id, policy_decision_ref, exit_code,
                   duration, stderr_bytes, error_class, artifact_count, metadata_json
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
                "confidence": f["confidence"]
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
