#!/usr/bin/env python3
"""Durable, append-only assessments for facts.

Facts remain observations owned by :mod:`core.ai.fact_store`.  This module
owns the separate judgement about what an observation means: whether it is
observed, inferred, verified, or contradicted.  Assessments never rewrite the
fact row; a new judgement supersedes the previous head while preserving the
history and its evidence chain.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, ClassVar

from core.secrets import Redactor, SecretStore

FACT_ASSESSMENT_SCHEMA_VERSION = "1.1"
FACT_FRESHNESS_POLICY_VERSION = "1.0"
_SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS = {"1.0", FACT_ASSESSMENT_SCHEMA_VERSION}
_MAX_REASON_BYTES = 4096
_MAX_ASSESSOR_BYTES = 256
_MAX_EXECUTION_ID_BYTES = 4096
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")


class FactFreshnessStatus(str, Enum):
    """Time validity of an observation under a named policy version."""

    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class EvidenceCoverageStatus(str, Enum):
    """Whether the producing executions provide usable evidence coverage."""

    COMPLETE = "complete"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FreshnessAssessment:
    """Pure read-time freshness judgement; it never mutates the fact row."""

    status: FactFreshnessStatus
    coverage: EvidenceCoverageStatus
    policy_version: str
    rule_id: str
    observed_at: float | None
    evaluated_at: float
    max_age_seconds: float
    age_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "coverage": self.coverage.value,
            "policy_version": self.policy_version,
            "rule_id": self.rule_id,
            "observed_at": self.observed_at,
            "evaluated_at": self.evaluated_at,
            "max_age_seconds": self.max_age_seconds,
            "age_seconds": self.age_seconds,
        }


@dataclass(frozen=True)
class FreshnessPolicy:
    """Versioned bounds for freshness and scoped multi-source rules.

    Type-specific bounds are represented as a sorted tuple rather than mutable
    configuration so the policy is deterministic and safe to share across
    resolver instances. Callers may inject a policy for a deployment or test;
    facts retain their original confidence regardless of this read-time view.
    """

    policy_version: str = FACT_FRESHNESS_POLICY_VERSION
    default_max_age_seconds: float = 24 * 60 * 60
    corroboration_window_seconds: float = 60 * 60
    max_age_by_type: tuple[tuple[str, float], ...] = field(
        default_factory=lambda: (
            ("application_access", 15 * 60),
            ("service_status", 30 * 60),
            ("system_access", 15 * 60),
            ("vulnerability", 6 * 60 * 60),
        )
    )

    def __post_init__(self) -> None:
        if not str(self.policy_version or "").strip():
            raise ValueError("Freshness policy version must not be empty")
        for name, value in (
            ("default_max_age_seconds", self.default_max_age_seconds),
            ("corroboration_window_seconds", self.corroboration_window_seconds),
        ):
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        normalized: list[tuple[str, float]] = []
        for fact_type, raw_seconds in self.max_age_by_type:
            key = str(fact_type or "").strip().casefold()
            seconds = float(raw_seconds)
            if not key or not math.isfinite(seconds) or seconds <= 0:
                raise ValueError("Freshness type bounds require a name and positive seconds")
            normalized.append((key, seconds))
        object.__setattr__(self, "max_age_by_type", tuple(sorted(dict(normalized).items())))

    def max_age_for(self, fact_type: str) -> float:
        bounds = dict(self.max_age_by_type)
        return float(bounds.get(str(fact_type or "").strip().casefold(), self.default_max_age_seconds))

    def evaluate(
        self,
        fact_type: str,
        *,
        observed_at: Any,
        now: float | None = None,
        execution_statuses: Iterable[Any] = (),
    ) -> FreshnessAssessment:
        evaluated_at = float(time.time() if now is None else now)
        max_age = self.max_age_for(fact_type)
        statuses = {
            str(status.value if isinstance(status, Enum) else status or "").strip().casefold()
            for status in execution_statuses or ()
        }
        statuses.discard("")
        successful = bool(statuses.intersection({"succeeded", "success", "completed"}))
        if "timeout" in statuses and not successful:
            return FreshnessAssessment(
                status=FactFreshnessStatus.UNKNOWN,
                coverage=EvidenceCoverageStatus.DEGRADED,
                policy_version=self.policy_version,
                rule_id="fact.coverage.timeout.v1",
                observed_at=self._timestamp(observed_at),
                evaluated_at=evaluated_at,
                max_age_seconds=max_age,
            )
        if statuses and not successful and statuses.intersection(
            {"failed", "partial", "cancelled", "unavailable", "blocked"}
        ):
            return FreshnessAssessment(
                status=FactFreshnessStatus.UNKNOWN,
                coverage=EvidenceCoverageStatus.DEGRADED,
                policy_version=self.policy_version,
                rule_id="fact.coverage.incomplete_execution.v1",
                observed_at=self._timestamp(observed_at),
                evaluated_at=evaluated_at,
                max_age_seconds=max_age,
            )

        timestamp = self._timestamp(observed_at)
        coverage = (
            EvidenceCoverageStatus.COMPLETE
            if successful
            else EvidenceCoverageStatus.UNKNOWN
        )
        if timestamp is None:
            return FreshnessAssessment(
                status=FactFreshnessStatus.UNKNOWN,
                coverage=coverage,
                policy_version=self.policy_version,
                rule_id="fact.freshness.timestamp_missing.v1",
                observed_at=None,
                evaluated_at=evaluated_at,
                max_age_seconds=max_age,
            )
        age = max(0.0, evaluated_at - timestamp)
        status = (
            FactFreshnessStatus.STALE
            if age > max_age
            else FactFreshnessStatus.FRESH
        )
        return FreshnessAssessment(
            status=status,
            coverage=coverage,
            policy_version=self.policy_version,
            rule_id=(
                "fact.freshness.max_age.v1"
                if status is FactFreshnessStatus.STALE
                else "fact.freshness.within_age.v1"
            ),
            observed_at=timestamp,
            evaluated_at=evaluated_at,
            max_age_seconds=max_age,
            age_seconds=age,
        )

    @staticmethod
    def _timestamp(value: Any) -> float | None:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        return parsed if math.isfinite(parsed) and parsed >= 0 else None


class AssessmentStatus(str, Enum):
    """Canonical fact judgement, independent from execution/task status."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    VERIFIED = "verified"
    CONTRADICTED = "contradicted"


@dataclass(frozen=True)
class FactAssessment:
    assessment_id: str
    fact_id: int
    status: AssessmentStatus
    confidence: int
    rule_id: str
    reason: str
    assessor: str
    evidence_fact_ids: tuple[int, ...]
    source_execution_ids: tuple[str, ...]
    supersedes_assessment_id: str | None
    created_at: float
    schema_version: str = FACT_ASSESSMENT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "fact_id": self.fact_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "assessor": self.assessor,
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "source_execution_ids": list(self.source_execution_ids),
            "supersedes_assessment_id": self.supersedes_assessment_id,
            "created_at": self.created_at,
        }


class FactAssessmentStore:
    """SQLite authority for immutable fact-assessment transitions."""

    _POSITIVE_ASSERTIONS: ClassVar[set[str]] = {
        "affected",
        "confirmed_present",
        "enabled",
        "found",
        "open",
        "positive",
        "present",
        "success",
        "succeeded",
        "true",
        "vulnerable",
    }
    _NEGATIVE_ASSERTIONS: ClassVar[set[str]] = {
        "absent",
        "closed",
        "confirmed_absent",
        "disabled",
        "failed",
        "false",
        "negative",
        "not_affected",
        "not_found",
        "not_vulnerable",
        "patched",
    }

    def __init__(
        self,
        db_path: str,
        *,
        secret_store: SecretStore,
        redactor: Redactor,
        freshness_policy: FreshnessPolicy | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.db_path = db_path
        self.secret_store = secret_store
        self.redactor = redactor
        self.freshness_policy = freshness_policy or FreshnessPolicy()
        self._clock = clock or time.time
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
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

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS fact_assessment_schema (
                    schema_version TEXT PRIMARY KEY,
                    applied_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fact_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    fact_id INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('observed', 'inferred', 'verified', 'contradicted')
                    ),
                    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
                    rule_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    assessor TEXT NOT NULL,
                    semantic_key TEXT NOT NULL,
                    transition_key TEXT NOT NULL UNIQUE,
                    supersedes_assessment_id TEXT,
                    schema_version TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(fact_id) REFERENCES facts(id) ON DELETE CASCADE,
                    FOREIGN KEY(supersedes_assessment_id)
                        REFERENCES fact_assessments(assessment_id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS fact_assessment_evidence (
                    assessment_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    evidence_fact_id INTEGER NOT NULL,
                    PRIMARY KEY(assessment_id, ordinal),
                    UNIQUE(assessment_id, evidence_fact_id),
                    FOREIGN KEY(assessment_id)
                        REFERENCES fact_assessments(assessment_id) ON DELETE CASCADE,
                    FOREIGN KEY(evidence_fact_id) REFERENCES facts(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS fact_assessment_executions (
                    assessment_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    execution_id TEXT NOT NULL,
                    execution_key TEXT NOT NULL,
                    PRIMARY KEY(assessment_id, ordinal),
                    UNIQUE(assessment_id, execution_key),
                    FOREIGN KEY(assessment_id)
                        REFERENCES fact_assessments(assessment_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS fact_assessment_heads (
                    fact_id INTEGER PRIMARY KEY,
                    assessment_id TEXT NOT NULL UNIQUE,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY(fact_id) REFERENCES facts(id) ON DELETE CASCADE,
                    FOREIGN KEY(assessment_id)
                        REFERENCES fact_assessments(assessment_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_fact_assessments_fact
                    ON fact_assessments(fact_id, created_at, assessment_id);
                CREATE INDEX IF NOT EXISTS idx_fact_assessments_status
                    ON fact_assessments(status);
                CREATE INDEX IF NOT EXISTS idx_fact_assessment_evidence_fact
                    ON fact_assessment_evidence(evidence_fact_id);
                """
            )
            # ``executescript`` owns its schema transaction. Serialize the
            # version check, redaction migration, and legacy backfill after it.
            conn.execute("BEGIN IMMEDIATE")
            self._ensure_column(
                conn,
                "fact_assessments",
                "rule_id",
                "TEXT NOT NULL DEFAULT 'fact.assessment.legacy.v1'",
            )
            versions = {
                str(row[0])
                for row in conn.execute(
                    "SELECT schema_version FROM fact_assessment_schema"
                ).fetchall()
            }
            unsupported = versions - _SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS
            if unsupported:
                raise RuntimeError(
                    "Unsupported fact-assessment schema version(s): "
                    + ", ".join(sorted(unsupported))
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO fact_assessment_schema(schema_version, applied_at)
                VALUES (?, ?)
                """,
                (FACT_ASSESSMENT_SCHEMA_VERSION, time.time()),
            )
            self._redact_existing_rows(conn)
            self._backfill_legacy_facts(conn)

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _redact_existing_rows(self, conn: sqlite3.Connection) -> None:
        for assessment_id, reason, assessor in conn.execute(
            "SELECT assessment_id, reason, assessor FROM fact_assessments"
        ).fetchall():
            safe_reason = self._bounded(
                self.redactor.redact_text(reason, kind="fact_assessment_reason"),
                _MAX_REASON_BYTES,
            )
            safe_assessor = self._bounded(
                self.redactor.redact_text(assessor, kind="fact_assessor"),
                _MAX_ASSESSOR_BYTES,
            )
            if safe_reason != reason or safe_assessor != assessor:
                conn.execute(
                    """
                    UPDATE fact_assessments SET reason = ?, assessor = ?
                    WHERE assessment_id = ?
                    """,
                    (safe_reason, safe_assessor, assessment_id),
                )
        for assessment_id, ordinal, execution_id in conn.execute(
            """
            SELECT assessment_id, ordinal, execution_id
            FROM fact_assessment_executions
            """
        ).fetchall():
            safe_execution_id = self._bounded(
                self.redactor.redact_text(execution_id, kind="execution_id"),
                _MAX_EXECUTION_ID_BYTES,
            )
            if safe_execution_id != execution_id:
                conn.execute(
                    """
                    UPDATE fact_assessment_executions SET execution_id = ?
                    WHERE assessment_id = ? AND ordinal = ?
                    """,
                    (safe_execution_id, assessment_id, ordinal),
                )

    def _backfill_legacy_facts(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT f.id, f.confidence, f.derived_from
            FROM facts AS f
            LEFT JOIN fact_assessment_heads AS h ON h.fact_id = f.id
            WHERE h.fact_id IS NULL
            ORDER BY f.id
            """
        ).fetchall()
        for fact_id, confidence, derived_json in rows:
            evidence_ids = self._valid_derived_ids(conn, fact_id, derived_json)
            if evidence_ids:
                status = AssessmentStatus.INFERRED
                reason = "Legacy derived fact backfilled from derived_from provenance."
            else:
                status = AssessmentStatus.OBSERVED
                evidence_ids = (int(fact_id),)
                reason = "Legacy fact backfilled as an observation."
            self._insert_transition(
                conn,
                fact_id=int(fact_id),
                status=status,
                confidence=self._confidence(confidence),
                rule_id=(
                    "fact.migration.derived_inferred.v1"
                    if status is AssessmentStatus.INFERRED
                    else "fact.migration.observed.v1"
                ),
                reason=reason,
                assessor="fact_store.migration",
                evidence_fact_ids=evidence_ids,
                source_execution_ids=(),
                previous_id=None,
            )

    def _valid_derived_ids(
        self,
        conn: sqlite3.Connection,
        fact_id: int,
        raw_value: Any,
    ) -> tuple[int, ...]:
        try:
            loaded = json.loads(raw_value or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ()
        if not isinstance(loaded, list):
            return ()
        candidates = self._positive_ids(loaded)
        if not candidates:
            return ()
        subject = conn.execute(
            "SELECT scan_id FROM facts WHERE id = ?",
            (int(fact_id),),
        ).fetchone()
        if not subject:
            return ()
        placeholders = ",".join("?" for _ in candidates)
        rows = conn.execute(
            f"SELECT id FROM facts WHERE scan_id = ? AND id IN ({placeholders})",
            (subject[0], *candidates),
        ).fetchall()
        valid = {int(row[0]) for row in rows}
        return tuple(item for item in candidates if item in valid)

    def ensure_initial_in_connection(
        self,
        conn: sqlite3.Connection,
        *,
        fact_id: int,
        confidence: Any,
        derived_from: Sequence[int] = (),
        source_execution_ids: Sequence[str] = (),
    ) -> FactAssessment:
        """Create the first assessment inside the fact insertion transaction."""

        current = self._current_in_connection(conn, int(fact_id))
        if current is not None:
            current = self._refresh_display_redaction(conn, current)
            merged_execution_ids = tuple(
                dict.fromkeys((*current.source_execution_ids, *self._raw_texts(source_execution_ids)))
            )
            merged_confidence = max(current.confidence, self._confidence(confidence))
            if (
                merged_execution_ids == current.source_execution_ids
                and merged_confidence == current.confidence
            ):
                return self._apply_automatic_rules_in_connection(conn, int(fact_id), current)
            updated = self._assess_in_connection(
                    conn,
                    fact_id=int(fact_id),
                    status=current.status,
                    confidence=merged_confidence,
                    rule_id=current.rule_id,
                    reason=current.reason,
                    assessor=current.assessor,
                    evidence_fact_ids=current.evidence_fact_ids,
                    source_execution_ids=merged_execution_ids,
                )[0]
            return self._apply_automatic_rules_in_connection(conn, int(fact_id), updated)

        evidence_ids = self._positive_ids(derived_from)
        if evidence_ids:
            status = AssessmentStatus.INFERRED
            reason = "Derived from persisted source facts."
        else:
            status = AssessmentStatus.OBSERVED
            evidence_ids = (int(fact_id),)
            reason = "Recorded by the canonical fact ingress."
        assessment, _created = self._assess_in_connection(
            conn,
            fact_id=int(fact_id),
            status=status,
            confidence=self._confidence(confidence),
            rule_id=(
                "fact.ingress.derived_inferred.v1"
                if status is AssessmentStatus.INFERRED
                else "fact.ingress.observed.v1"
            ),
            reason=reason,
            assessor="fact_store.ingress",
            evidence_fact_ids=evidence_ids,
            source_execution_ids=source_execution_ids,
        )
        return self._apply_automatic_rules_in_connection(conn, int(fact_id), assessment)

    def _apply_automatic_rules_in_connection(
        self,
        conn: sqlite3.Connection,
        fact_id: int,
        current: FactAssessment | None = None,
    ) -> FactAssessment:
        """Apply conservative corroboration and contradiction rules atomically.

        Independence is based on keyed execution provenance, never provider
        labels. Contradiction is intentionally limited to recognized opposite
        assertions with the same scan, canonical target, type, subject, and
        configured time window. The later assertion supersedes only the older
        assertion's assessment; neither base fact confidence is rewritten.
        """

        row = conn.execute(
            "SELECT scan_id, host, type, value, timestamp FROM facts WHERE id = ?",
            (int(fact_id),),
        ).fetchone()
        if row is None:
            raise KeyError(f"Unknown fact_id: {fact_id}")
        current = current or self._current_in_connection(conn, int(fact_id))
        if current is None:
            raise KeyError(f"Unassessed fact_id: {fact_id}")
        if current.status is AssessmentStatus.CONTRADICTED:
            # Repeated provenance is retained, but a contradicted head is not
            # live evidence and must never promote or contradict another fact.
            return current

        execution_keys = self._successful_execution_keys(
            conn,
            current.assessment_id,
        )
        if (
            len(execution_keys) >= 2
            and current.status in {AssessmentStatus.OBSERVED, AssessmentStatus.INFERRED}
            and self._corroboration_within_window(conn, current)
        ):
            current, _created = self._assess_in_connection(
                conn,
                fact_id=int(fact_id),
                status=AssessmentStatus.VERIFIED,
                confidence=current.confidence,
                rule_id="fact.corroborated.independent_execution.v1",
                reason=(
                    "Independent execution provenance corroborated the same "
                    "target-scoped fact within the policy window."
                ),
                assessor="fact_assessment.rules",
                evidence_fact_ids=current.evidence_fact_ids or (int(fact_id),),
                source_execution_ids=current.source_execution_ids,
            )
            execution_keys = self._successful_execution_keys(
                conn,
                current.assessment_id,
            )

        claim = self._scoped_claim(str(row[2]), str(row[3]))
        if claim is None or not execution_keys:
            return current
        scan_id, host, fact_type, _value, observed_at = row
        try:
            observed = float(observed_at)
        except (TypeError, ValueError):
            return current
        lower_bound = observed - float(self.freshness_policy.corroboration_window_seconds)
        candidates = conn.execute(
            """
            SELECT id, host, type, value, timestamp
            FROM facts
            WHERE scan_id = ? AND type = ? AND id <> ?
              AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC, id DESC
            """,
            (str(scan_id), str(fact_type), int(fact_id), lower_bound, observed),
        ).fetchall()
        target_key = self._target_key(host)
        for candidate_id, candidate_host, candidate_type, candidate_value, candidate_at in candidates:
            try:
                candidate_order = (float(candidate_at), int(candidate_id))
            except (TypeError, ValueError):
                continue
            if candidate_order >= (observed, int(fact_id)):
                continue
            if self._target_key(candidate_host) != target_key:
                continue
            candidate_claim = self._scoped_claim(str(candidate_type), str(candidate_value))
            if (
                candidate_claim is None
                or candidate_claim[0] != claim[0]
                or candidate_claim[1] == claim[1]
            ):
                continue
            candidate_assessment = self._current_in_connection(conn, int(candidate_id))
            if candidate_assessment is None or candidate_assessment.status is AssessmentStatus.CONTRADICTED:
                continue
            candidate_keys = self._successful_execution_keys(
                conn,
                candidate_assessment.assessment_id,
            )
            if not candidate_keys or not execution_keys.isdisjoint(candidate_keys):
                continue
            self._assess_in_connection(
                conn,
                fact_id=int(candidate_id),
                status=AssessmentStatus.CONTRADICTED,
                confidence=candidate_assessment.confidence,
                rule_id="fact.contradicted.scoped_opposite.v1",
                reason=(
                    "A later independent execution produced an opposite assertion "
                    "for the same target, subject, and policy time window."
                ),
                assessor="fact_assessment.rules",
                evidence_fact_ids=(int(fact_id),),
                # The opposing execution belongs to the evidence fact, not to
                # the older same-claim fact's producing provenance.
                source_execution_ids=candidate_assessment.source_execution_ids,
            )
        return current

    @staticmethod
    def _target_key(value: Any) -> str:
        return str(value or "").strip().casefold().rstrip(".")

    @classmethod
    def _scoped_claim(cls, fact_type: str, value: str) -> tuple[str, str] | None:
        normalized_type = re.sub(r"[^a-z0-9]+", "_", fact_type.casefold()).strip("_")
        normalized_value = re.sub(r"\s+", "_", value.strip().casefold())
        if not normalized_type or not normalized_value:
            return None
        markers = cls._POSITIVE_ASSERTIONS | cls._NEGATIVE_ASSERTIONS
        subject = normalized_type
        marker = normalized_value
        if marker not in markers:
            match = re.fullmatch(r"(.+?)(?::|=)([a-z_]+)", normalized_value)
            if match and match.group(2) in markers:
                subject, marker = match.groups()
            else:
                match = re.fullmatch(r"([a-z_]+)(?::|=)(.+)", normalized_value)
                if not match or match.group(1) not in markers:
                    return None
                marker, subject = match.groups()
        polarity = "positive" if marker in cls._POSITIVE_ASSERTIONS else "negative"
        subject_key = re.sub(r"[^a-z0-9]+", "_", subject).strip("_")
        if not subject_key:
            return None
        return f"{normalized_type}:{subject_key}", polarity

    @staticmethod
    def _successful_execution_keys(
        conn: sqlite3.Connection,
        assessment_id: str,
    ) -> set[str]:
        """Return producing executions whose latest persisted outcome succeeded."""

        return {
            str(row[0])
            for row in conn.execute(
                """
                SELECT ae.execution_key
                FROM fact_assessment_executions AS ae
                JOIN fact_assessments AS a
                  ON a.assessment_id = ae.assessment_id
                JOIN facts AS f ON f.id = a.fact_id
                JOIN command_results AS cr
                  ON cr.id = (
                      SELECT latest.id
                      FROM command_results AS latest
                      WHERE latest.execution_key = ae.execution_key
                        AND latest.scan_id = f.scan_id
                        AND LOWER(RTRIM(TRIM(latest.host), '.')) =
                            LOWER(RTRIM(TRIM(f.host), '.'))
                      ORDER BY latest.timestamp DESC, latest.id DESC
                      LIMIT 1
                  )
                WHERE ae.assessment_id = ?
                  AND ae.execution_key <> ''
                  AND cr.status = 'succeeded'
                  AND cr.failed = 0
                  AND cr.partial = 0
                """,
                (assessment_id,),
            ).fetchall()
        }

    def apply_automatic_rules_for_execution_in_connection(
        self,
        conn: sqlite3.Connection,
        *,
        execution_key: str,
        scan_id: str,
        host: str,
    ) -> tuple[FactAssessment, ...]:
        """Re-evaluate impacted facts after an outcome is persisted.

        The caller owns the command-result transaction. Re-evaluating here
        makes the outcome and any resulting assessment transitions visible as
        one atomic commit, regardless of whether opposing outcomes arrived in
        chronological order.
        """

        if not str(execution_key or ""):
            return ()
        direct_rows = conn.execute(
            """
            SELECT DISTINCT f.id, f.scan_id, f.host, f.type, f.timestamp
            FROM fact_assessment_heads AS h
            JOIN fact_assessments AS a ON a.assessment_id = h.assessment_id
            JOIN fact_assessment_executions AS ae
              ON ae.assessment_id = a.assessment_id
            JOIN facts AS f ON f.id = a.fact_id
            WHERE ae.execution_key = ? AND f.scan_id = ?
            ORDER BY f.timestamp, f.id
            """,
            (str(execution_key), str(scan_id)),
        ).fetchall()
        target_key = self._target_key(host)
        direct_rows = [
            row for row in direct_rows if self._target_key(row[2]) == target_key
        ]
        if not direct_rows:
            return ()

        impacted: dict[int, tuple[float, int]] = {}
        window = float(self.freshness_policy.corroboration_window_seconds)
        for fact_id, fact_scan_id, fact_host, fact_type, observed_at in direct_rows:
            try:
                observed = float(observed_at)
            except (TypeError, ValueError):
                continue
            for candidate_id, candidate_host, candidate_at in conn.execute(
                """
                SELECT id, host, timestamp
                FROM facts
                WHERE scan_id = ? AND type = ?
                  AND timestamp BETWEEN ? AND ?
                """,
                (
                    str(fact_scan_id),
                    str(fact_type),
                    observed - window,
                    observed + window,
                ),
            ).fetchall():
                if self._target_key(candidate_host) != self._target_key(fact_host):
                    continue
                try:
                    candidate_order = (float(candidate_at), int(candidate_id))
                except (TypeError, ValueError):
                    continue
                impacted[int(candidate_id)] = candidate_order
            impacted[int(fact_id)] = (observed, int(fact_id))

        transitions: list[FactAssessment] = []
        for fact_id in sorted(impacted, key=impacted.__getitem__):
            before = self._current_in_connection(conn, fact_id)
            if before is None:
                continue
            after = self._apply_automatic_rules_in_connection(conn, fact_id, before)
            if after.assessment_id != before.assessment_id:
                transitions.append(after)
        return tuple(transitions)

    def _corroboration_within_window(
        self,
        conn: sqlite3.Connection,
        assessment: FactAssessment,
    ) -> bool:
        previous_id = assessment.supersedes_assessment_id
        if not previous_id:
            # Multiple provenance IDs supplied by one atomic ingress are one
            # time-scoped observation set.
            return True
        row = conn.execute(
            "SELECT created_at FROM fact_assessments WHERE assessment_id = ?",
            (previous_id,),
        ).fetchone()
        if row is None:
            return False
        return (
            0.0
            <= assessment.created_at - float(row[0])
            <= float(self.freshness_policy.corroboration_window_seconds)
        )

    def freshness_for(
        self,
        fact_type: str,
        observed_at: Any,
        *,
        execution_statuses: Iterable[Any] = (),
        now: float | None = None,
    ) -> FreshnessAssessment:
        return self.freshness_policy.evaluate(
            fact_type,
            observed_at=observed_at,
            now=float(self._clock()) if now is None else now,
            execution_statuses=execution_statuses,
        )

    def assess_fact(
        self,
        fact_id: int,
        status: AssessmentStatus | str,
        *,
        confidence: int,
        reason: str,
        assessor: str,
        rule_id: str | None = None,
        evidence_fact_ids: Sequence[int] = (),
        source_execution_ids: Sequence[str] = (),
    ) -> tuple[FactAssessment, bool]:
        """Append an assessment and atomically make it the fact's current head.

        Repeating the exact current judgement is idempotent.  Re-applying a
        prior judgement after another transition creates a new history record,
        which preserves the actual state transition instead of resurrecting an
        old row.
        """

        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self._assess_in_connection(
                conn,
                fact_id=int(fact_id),
                status=self._status(status),
                confidence=self._confidence(confidence),
                rule_id=self._rule_id(rule_id, self._status(status)),
                reason=str(reason or ""),
                assessor=str(assessor or ""),
                evidence_fact_ids=evidence_fact_ids,
                source_execution_ids=source_execution_ids,
            )

    def _assess_in_connection(
        self,
        conn: sqlite3.Connection,
        *,
        fact_id: int,
        status: AssessmentStatus,
        confidence: int,
        rule_id: str,
        reason: str,
        assessor: str,
        evidence_fact_ids: Sequence[int],
        source_execution_ids: Sequence[str],
    ) -> tuple[FactAssessment, bool]:
        subject = conn.execute(
            "SELECT scan_id FROM facts WHERE id = ?",
            (int(fact_id),),
        ).fetchone()
        if subject is None:
            raise KeyError(f"Unknown fact_id: {fact_id}")
        if not str(reason or "").strip():
            raise ValueError("Fact assessment reason must not be empty")
        if not str(assessor or "").strip():
            raise ValueError("Fact assessment assessor must not be empty")
        rule_id = self._rule_id(rule_id, status)

        evidence_ids = self._positive_ids(evidence_fact_ids)
        if status in {AssessmentStatus.VERIFIED, AssessmentStatus.CONTRADICTED} and not evidence_ids:
            raise ValueError(f"{status.value} assessment requires an evidence chain")
        if evidence_ids:
            placeholders = ",".join("?" for _ in evidence_ids)
            rows = conn.execute(
                f"SELECT id, scan_id FROM facts WHERE id IN ({placeholders})",
                evidence_ids,
            ).fetchall()
            found = {int(row[0]): str(row[1]) for row in rows}
            missing = [item for item in evidence_ids if item not in found]
            if missing:
                raise KeyError(f"Unknown evidence fact_id(s): {missing}")
            wrong_scan = [item for item in evidence_ids if found[item] != str(subject[0])]
            if wrong_scan:
                raise ValueError(
                    "Evidence facts must belong to the assessed fact's scan: "
                    + ", ".join(str(item) for item in wrong_scan)
                )

        raw_execution_ids = self._raw_texts(source_execution_ids)
        semantic_key = self._semantic_key(
            fact_id=fact_id,
            status=status,
            confidence=confidence,
            rule_id=rule_id,
            reason=reason,
            assessor=assessor,
            evidence_fact_ids=evidence_ids,
            source_execution_ids=raw_execution_ids,
        )
        current = self._current_in_connection(conn, fact_id)
        if current is not None:
            current = self._refresh_display_redaction(conn, current)
            row = conn.execute(
                "SELECT semantic_key FROM fact_assessments WHERE assessment_id = ?",
                (current.assessment_id,),
            ).fetchone()
            if row and str(row[0]) == semantic_key:
                return current, False
        assessment = self._insert_transition(
            conn,
            fact_id=fact_id,
            status=status,
            confidence=confidence,
            rule_id=rule_id,
            reason=reason,
            assessor=assessor,
            evidence_fact_ids=evidence_ids,
            source_execution_ids=raw_execution_ids,
            previous_id=current.assessment_id if current else None,
            semantic_key=semantic_key,
        )
        return assessment, True

    def _refresh_display_redaction(
        self,
        conn: sqlite3.Connection,
        assessment: FactAssessment,
    ) -> FactAssessment:
        """Apply one-way redaction learned after an immutable record was written."""

        safe_reason = self._bounded(
            self.redactor.redact_text(
                assessment.reason,
                kind="fact_assessment_reason",
            ),
            _MAX_REASON_BYTES,
        )
        safe_assessor = self._bounded(
            self.redactor.redact_text(assessment.assessor, kind="fact_assessor"),
            _MAX_ASSESSOR_BYTES,
        )
        changed = safe_reason != assessment.reason or safe_assessor != assessment.assessor
        if changed:
            conn.execute(
                """
                UPDATE fact_assessments SET reason = ?, assessor = ?
                WHERE assessment_id = ?
                """,
                (safe_reason, safe_assessor, assessment.assessment_id),
            )
        for ordinal, execution_id in enumerate(assessment.source_execution_ids):
            safe_execution_id = self._bounded(
                self.redactor.redact_text(execution_id, kind="execution_id"),
                _MAX_EXECUTION_ID_BYTES,
            )
            if safe_execution_id == execution_id:
                continue
            changed = True
            conn.execute(
                """
                UPDATE fact_assessment_executions SET execution_id = ?
                WHERE assessment_id = ? AND ordinal = ?
                """,
                (safe_execution_id, assessment.assessment_id, ordinal),
            )
        if not changed:
            return assessment
        refreshed = self._current_in_connection(conn, assessment.fact_id)
        return refreshed or assessment

    def _insert_transition(
        self,
        conn: sqlite3.Connection,
        *,
        fact_id: int,
        status: AssessmentStatus,
        confidence: int,
        rule_id: str,
        reason: str,
        assessor: str,
        evidence_fact_ids: Sequence[int],
        source_execution_ids: Sequence[str],
        previous_id: str | None,
        semantic_key: str | None = None,
    ) -> FactAssessment:
        evidence_ids = self._positive_ids(evidence_fact_ids)
        raw_execution_ids = self._raw_texts(source_execution_ids)
        semantic_key = semantic_key or self._semantic_key(
            fact_id=fact_id,
            status=status,
            confidence=confidence,
            rule_id=rule_id,
            reason=reason,
            assessor=assessor,
            evidence_fact_ids=evidence_ids,
            source_execution_ids=raw_execution_ids,
        )
        transition_payload = json.dumps(
            {"semantic_key": semantic_key, "previous": previous_id or ""},
            sort_keys=True,
            separators=(",", ":"),
        )
        transition_key = self.secret_store.keyed_digest(
            transition_payload,
            kind="fact_assessment:transition",
        )
        assessment_id = f"fa_{transition_key[:32]}"
        created_at = time.time()
        safe_reason = self._bounded(
            self.redactor.redact_text(reason, kind="fact_assessment_reason"),
            _MAX_REASON_BYTES,
        )
        safe_assessor = self._bounded(
            self.redactor.redact_text(assessor, kind="fact_assessor"),
            _MAX_ASSESSOR_BYTES,
        )
        conn.execute(
            """
            INSERT INTO fact_assessments(
                assessment_id, fact_id, status, confidence, rule_id, reason, assessor,
                semantic_key, transition_key, supersedes_assessment_id,
                schema_version, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                int(fact_id),
                status.value,
                int(confidence),
                rule_id,
                safe_reason,
                safe_assessor,
                semantic_key,
                transition_key,
                previous_id,
                FACT_ASSESSMENT_SCHEMA_VERSION,
                created_at,
            ),
        )
        for ordinal, evidence_id in enumerate(evidence_ids):
            conn.execute(
                """
                INSERT INTO fact_assessment_evidence(
                    assessment_id, ordinal, evidence_fact_id
                ) VALUES (?, ?, ?)
                """,
                (assessment_id, ordinal, evidence_id),
            )
        safe_execution_ids = []
        for ordinal, execution_id in enumerate(raw_execution_ids):
            safe_execution_id = self._bounded(
                self.redactor.redact_text(execution_id, kind="execution_id"),
                _MAX_EXECUTION_ID_BYTES,
            )
            safe_execution_ids.append(safe_execution_id)
            conn.execute(
                """
                INSERT INTO fact_assessment_executions(
                    assessment_id, ordinal, execution_id, execution_key
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    ordinal,
                    safe_execution_id,
                    self.secret_store.keyed_digest(
                        execution_id,
                        kind="fact_assessment:execution",
                    ),
                ),
            )
        conn.execute(
            """
            INSERT INTO fact_assessment_heads(fact_id, assessment_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(fact_id) DO UPDATE SET
                assessment_id = excluded.assessment_id,
                updated_at = excluded.updated_at
            """,
            (int(fact_id), assessment_id, created_at),
        )
        return FactAssessment(
            assessment_id=assessment_id,
            fact_id=int(fact_id),
            status=status,
            confidence=int(confidence),
            rule_id=rule_id,
            reason=safe_reason,
            assessor=safe_assessor,
            evidence_fact_ids=tuple(evidence_ids),
            source_execution_ids=tuple(safe_execution_ids),
            supersedes_assessment_id=previous_id,
            created_at=created_at,
        )

    def current_for_fact(self, fact_id: int) -> FactAssessment | None:
        with self._get_conn() as conn:
            return self._current_in_connection(conn, int(fact_id))

    def attach_source_executions(
        self,
        fact_id: int,
        source_execution_ids: Sequence[str],
    ) -> tuple[FactAssessment, bool]:
        """Append execution provenance without changing the current judgement."""

        with self._get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = self._current_in_connection(conn, int(fact_id))
            if current is None:
                raise KeyError(f"Unknown or unassessed fact_id: {fact_id}")
            merged = tuple(
                dict.fromkeys(
                    (*current.source_execution_ids, *self._raw_texts(source_execution_ids))
                )
            )
            if merged == current.source_execution_ids:
                refreshed = self._apply_automatic_rules_in_connection(
                    conn,
                    int(fact_id),
                    current,
                )
                return refreshed, refreshed.assessment_id != current.assessment_id
            updated, created = self._assess_in_connection(
                conn,
                fact_id=current.fact_id,
                status=current.status,
                confidence=current.confidence,
                rule_id=current.rule_id,
                reason=current.reason,
                assessor=current.assessor,
                evidence_fact_ids=current.evidence_fact_ids,
                source_execution_ids=merged,
            )
            refreshed = self._apply_automatic_rules_in_connection(
                conn,
                int(fact_id),
                updated,
            )
            return refreshed, created or refreshed.assessment_id != updated.assessment_id

    def current_for_facts(
        self,
        fact_ids: Iterable[int],
    ) -> dict[int, FactAssessment]:
        ids = self._positive_ids(fact_ids)
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        with self._get_conn() as conn:
            rows = conn.execute(
                f"""
                SELECT a.assessment_id, a.fact_id, a.status, a.confidence,
                       a.rule_id, a.reason, a.assessor,
                       a.supersedes_assessment_id, a.created_at, a.schema_version
                FROM fact_assessment_heads AS h
                JOIN fact_assessments AS a ON a.assessment_id = h.assessment_id
                WHERE h.fact_id IN ({placeholders})
                """,
                ids,
            ).fetchall()
            assessments = self._hydrate(conn, rows)
        return {item.fact_id: item for item in assessments}

    def history(self, fact_id: int) -> tuple[FactAssessment, ...]:
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT assessment_id, fact_id, status, confidence, rule_id,
                       reason, assessor, supersedes_assessment_id,
                       created_at, schema_version
                FROM fact_assessments
                WHERE fact_id = ?
                ORDER BY created_at, assessment_id
                """,
                (int(fact_id),),
            ).fetchall()
            return tuple(self._hydrate(conn, rows))

    def list_for_scan(
        self,
        scan_id: str,
        *,
        host: str | None = None,
        status: AssessmentStatus | str | None = None,
        current_only: bool = True,
    ) -> tuple[FactAssessment, ...]:
        join = (
            "JOIN fact_assessment_heads AS h ON h.assessment_id = a.assessment_id"
            if current_only
            else ""
        )
        query = f"""
            SELECT a.assessment_id, a.fact_id, a.status, a.confidence,
                   a.rule_id, a.reason, a.assessor,
                   a.supersedes_assessment_id, a.created_at, a.schema_version
            FROM fact_assessments AS a
            {join}
            JOIN facts AS f ON f.id = a.fact_id
            WHERE f.scan_id = ?
        """
        params: list[Any] = [scan_id]
        if host is not None:
            query += " AND f.host = ?"
            params.append(host)
        if status is not None:
            query += " AND a.status = ?"
            params.append(self._status(status).value)
        query += " ORDER BY a.created_at, a.assessment_id"
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return tuple(self._hydrate(conn, rows))

    def _current_in_connection(
        self,
        conn: sqlite3.Connection,
        fact_id: int,
    ) -> FactAssessment | None:
        row = conn.execute(
            """
            SELECT a.assessment_id, a.fact_id, a.status, a.confidence,
                   a.rule_id, a.reason, a.assessor,
                   a.supersedes_assessment_id, a.created_at, a.schema_version
            FROM fact_assessment_heads AS h
            JOIN fact_assessments AS a ON a.assessment_id = h.assessment_id
            WHERE h.fact_id = ?
            """,
            (int(fact_id),),
        ).fetchone()
        if row is None:
            return None
        return self._hydrate(conn, [row])[0]

    def _hydrate(
        self,
        conn: sqlite3.Connection,
        rows: Sequence[Sequence[Any]],
    ) -> list[FactAssessment]:
        if not rows:
            return []
        ids = [str(row[0]) for row in rows]
        placeholders = ",".join("?" for _ in ids)
        evidence: dict[str, list[int]] = {}
        for assessment_id, evidence_fact_id in conn.execute(
            f"""
            SELECT assessment_id, evidence_fact_id
            FROM fact_assessment_evidence
            WHERE assessment_id IN ({placeholders})
            ORDER BY assessment_id, ordinal
            """,
            ids,
        ).fetchall():
            evidence.setdefault(str(assessment_id), []).append(int(evidence_fact_id))
        executions: dict[str, list[str]] = {}
        for assessment_id, execution_id in conn.execute(
            f"""
            SELECT assessment_id, execution_id
            FROM fact_assessment_executions
            WHERE assessment_id IN ({placeholders})
            ORDER BY assessment_id, ordinal
            """,
            ids,
        ).fetchall():
            executions.setdefault(str(assessment_id), []).append(str(execution_id))
        return [
            FactAssessment(
                assessment_id=str(row[0]),
                fact_id=int(row[1]),
                status=AssessmentStatus(str(row[2])),
                confidence=int(row[3]),
                rule_id=str(row[4]),
                reason=str(row[5]),
                assessor=str(row[6]),
                evidence_fact_ids=tuple(evidence.get(str(row[0]), [])),
                source_execution_ids=tuple(executions.get(str(row[0]), [])),
                supersedes_assessment_id=(str(row[7]) if row[7] else None),
                created_at=float(row[8]),
                schema_version=str(row[9]),
            )
            for row in rows
        ]

    def _semantic_key(
        self,
        *,
        fact_id: int,
        status: AssessmentStatus,
        confidence: int,
        rule_id: str,
        reason: str,
        assessor: str,
        evidence_fact_ids: Sequence[int],
        source_execution_ids: Sequence[str],
    ) -> str:
        payload = json.dumps(
            {
                "fact_id": int(fact_id),
                "status": status.value,
                "confidence": int(confidence),
                "rule_id": rule_id,
                "reason": str(reason),
                "assessor": str(assessor),
                "evidence_fact_ids": list(evidence_fact_ids),
                "source_execution_ids": list(source_execution_ids),
                "schema_version": FACT_ASSESSMENT_SCHEMA_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return self.secret_store.keyed_digest(payload, kind="fact_assessment:semantic")

    @staticmethod
    def _rule_id(value: str | None, status: AssessmentStatus) -> str:
        normalized = str(value or f"fact.assessment.manual_{status.value}.v1").strip().casefold()
        if not _RULE_ID_RE.fullmatch(normalized):
            raise ValueError(
                "Fact assessment rule_id must be a stable lowercase dotted identifier"
            )
        return normalized

    @staticmethod
    def _status(value: AssessmentStatus | str) -> AssessmentStatus:
        if isinstance(value, AssessmentStatus):
            return value
        try:
            return AssessmentStatus(str(value or "").strip().lower())
        except ValueError as exc:
            allowed = ", ".join(item.value for item in AssessmentStatus)
            raise ValueError(f"Unsupported fact assessment status; expected one of: {allowed}") from exc

    @staticmethod
    def _confidence(value: Any) -> int:
        if isinstance(value, bool):
            raise ValueError("Fact assessment confidence must be an integer from 0 to 100")
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Fact assessment confidence must be an integer from 0 to 100") from exc
        if not math.isfinite(parsed) or not parsed.is_integer() or not 0 <= parsed <= 100:
            raise ValueError("Fact assessment confidence must be an integer from 0 to 100")
        return int(parsed)

    @staticmethod
    def _positive_ids(values: Iterable[Any]) -> tuple[int, ...]:
        output: list[int] = []
        seen: set[int] = set()
        for value in values or ():
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            if parsed <= 0 or parsed in seen:
                continue
            seen.add(parsed)
            output.append(parsed)
        return tuple(output)

    @staticmethod
    def _raw_texts(values: Iterable[Any]) -> tuple[str, ...]:
        output: list[str] = []
        seen: set[str] = set()
        for value in values or ():
            text = str(value or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            output.append(text)
        return tuple(output)

    @staticmethod
    def _bounded(value: Any, limit: int) -> str:
        text = str(value or "")
        raw = text.encode("utf-8", "replace")
        if len(raw) <= limit:
            return text
        return raw[:limit].decode("utf-8", "ignore")


__all__ = [
    "FACT_ASSESSMENT_SCHEMA_VERSION",
    "FACT_FRESHNESS_POLICY_VERSION",
    "AssessmentStatus",
    "EvidenceCoverageStatus",
    "FactAssessment",
    "FactAssessmentStore",
    "FactFreshnessStatus",
    "FreshnessAssessment",
    "FreshnessPolicy",
]
