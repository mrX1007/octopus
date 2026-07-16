"""Bounded, durable decision events and evidence-quality metrics."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

DECISION_TRACE_SCHEMA_VERSION = "1.0"
DECISION_METRICS_SCHEMA_VERSION = "1.0"

_MAX_TEXT_BYTES = 4_096
_MAX_COLLECTION_ITEMS = 64
_MAX_SUPPORTING_FACTS = 256
_MAX_JSON_BYTES = 64 * 1_024
_INTERNAL_FACT_TYPES = frozenset(
    {
        "check_result",
        "external_url",
        "llm_health",
        "network_edge",
        "network_node",
    }
)
_CANDIDATE_FACT_TYPES = frozenset(
    {
        "cve_candidate",
        "exploit_candidate",
        "potential_vulnerability",
        "vulnerability",
        "vulnerability_candidate",
        "vulnerability_endpoint",
        "vulnerability_hypothesis",
    }
)


@dataclass(frozen=True)
class DecisionEvent:
    """Canonical decision record; payloads contain summaries, never tool output."""

    event_type: str
    event_id: str = ""
    mission_id: str = ""
    scan_id: str = ""
    task_id: str = ""
    task: str = ""
    goal: str = ""
    candidates: tuple[str, ...] = ()
    rejected: tuple[dict[str, Any], ...] = ()
    chosen_action: str = ""
    capability_ref: str = ""
    policy_refs: tuple[str, ...] = ()
    supporting_fact_ids: tuple[int, ...] = ()
    expected_outcome: dict[str, Any] = field(default_factory=dict)
    actual_outcome: dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    cost: dict[str, Any] = field(default_factory=dict)
    state_from: str = ""
    state_to: str = ""
    retry_count: int = 0
    fallback_count: int = 0
    occurred_at: float = 0.0
    schema_version: str = DECISION_TRACE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "mission_id": self.mission_id,
            "scan_id": self.scan_id,
            "task_id": self.task_id,
            "task": self.task,
            "goal": self.goal,
            "candidates": list(self.candidates),
            "rejected": [dict(item) for item in self.rejected],
            "chosen_action": self.chosen_action,
            "capability_ref": self.capability_ref,
            "policy_refs": list(self.policy_refs),
            "supporting_fact_ids": list(self.supporting_fact_ids),
            "expected_outcome": dict(self.expected_outcome),
            "actual_outcome": dict(self.actual_outcome),
            "duration": self.duration,
            "cost": dict(self.cost),
            "state_transition": {"from": self.state_from, "to": self.state_to},
            "retry_count": self.retry_count,
            "fallback_count": self.fallback_count,
            "occurred_at": self.occurred_at,
        }


class DecisionTraceStore:
    """SQLite-backed observability projection with deterministic retention."""

    def __init__(
        self,
        db_path: str,
        *,
        redactor: Any,
        max_events_per_scope: int = 2_000,
        max_total_events: int = 50_000,
    ) -> None:
        self.db_path = db_path
        self.redactor = redactor
        self.max_events_per_scope = max(5, min(int(max_events_per_scope), 20_000))
        self.max_total_events = max(
            self.max_events_per_scope,
            min(int(max_total_events), 1_000_000),
        )
        self._persistent_conn: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(
                ":memory:", timeout=10.0, check_same_thread=False
            )
            self._persistent_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def close(self) -> None:
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None

    def __del__(self):
        with suppress(Exception):
            self.close()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if self._persistent_conn is not None:
            conn = self._persistent_conn
        else:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if conn is not self._persistent_conn:
                conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS decision_trace_schema (
                    schema_version TEXT PRIMARY KEY,
                    applied_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decision_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    scope_key TEXT NOT NULL,
                    mission_id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    task TEXT NOT NULL,
                    goal TEXT NOT NULL,
                    chosen_action TEXT NOT NULL,
                    capability_ref TEXT NOT NULL,
                    duration REAL NOT NULL,
                    retry_count INTEGER NOT NULL,
                    fallback_count INTEGER NOT NULL,
                    occurred_at REAL NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_decision_events_scope
                    ON decision_events(scope_key, occurred_at DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_decision_events_scan
                    ON decision_events(scan_id, occurred_at DESC, id DESC);
                CREATE INDEX IF NOT EXISTS idx_decision_events_mission
                    ON decision_events(mission_id, occurred_at DESC, id DESC);
                """
            )
            versions = {
                str(row[0])
                for row in conn.execute(
                    "SELECT schema_version FROM decision_trace_schema"
                ).fetchall()
            }
            unsupported = versions - {DECISION_TRACE_SCHEMA_VERSION}
            if unsupported:
                raise RuntimeError(
                    "Unsupported decision-trace schema version(s): "
                    + ", ".join(sorted(unsupported))
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO decision_trace_schema(schema_version, applied_at)
                VALUES (?, ?)
                """,
                (DECISION_TRACE_SCHEMA_VERSION, time.time()),
            )

    def record(self, event: DecisionEvent | Mapping[str, Any]) -> tuple[str, bool]:
        """Persist one event idempotently and enforce both retention bounds."""

        raw = event.to_dict() if isinstance(event, DecisionEvent) else dict(event)
        normalized = self._normalize_event(raw)
        payload_json = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if len(payload_json.encode("utf-8", "replace")) > _MAX_JSON_BYTES:
            normalized["expected_outcome"] = {"truncated": True}
            normalized["actual_outcome"] = {"truncated": True}
            normalized["rejected"] = normalized["rejected"][:8]
            payload_json = json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO decision_events(
                    event_id, scope_key, mission_id, scan_id, event_type,
                    task_id, task, goal, chosen_action, capability_ref,
                    duration, retry_count, fallback_count, occurred_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized["event_id"],
                    normalized["scope_key"],
                    normalized["mission_id"],
                    normalized["scan_id"],
                    normalized["event_type"],
                    normalized["task_id"],
                    normalized["task"],
                    normalized["goal"],
                    normalized["chosen_action"],
                    normalized["capability_ref"],
                    normalized["duration"],
                    normalized["retry_count"],
                    normalized["fallback_count"],
                    normalized["occurred_at"],
                    payload_json,
                ),
            )
            created = cursor.rowcount > 0
            self._prune(conn, normalized["scope_key"])
        return normalized["event_id"], created

    def list_events(
        self,
        *,
        scan_id: str = "",
        mission_id: str = "",
        event_type: str = "",
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(self._safe_text(scan_id, "decision_scan_id", 512))
        if mission_id:
            clauses.append("mission_id = ?")
            params.append(self._safe_text(mission_id, "decision_mission_id", 512))
        if event_type:
            clauses.append("event_type = ?")
            params.append(self._safe_text(event_type, "decision_event_type", 256))
        query = "SELECT payload_json FROM decision_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        bounded_limit = max(1, min(int(limit), 20_000))
        query += " ORDER BY occurred_at DESC, id DESC LIMIT ?"
        params.append(bounded_limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        events = [json.loads(str(row[0])) for row in rows]
        events.reverse()
        return events

    def count(self, *, scan_id: str = "", mission_id: str = "") -> int:
        clauses: list[str] = []
        params: list[str] = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(self._safe_text(scan_id, "decision_scan_id", 512))
        if mission_id:
            clauses.append("mission_id = ?")
            params.append(self._safe_text(mission_id, "decision_mission_id", 512))
        query = "SELECT COUNT(*) FROM decision_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    def _normalize_event(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        safe = self.redactor.redact_data(dict(raw))
        if not isinstance(safe, Mapping):
            safe = {}
        event_type = self._safe_text(
            safe.get("event_type") or "decision",
            "decision_event_type",
            256,
        )
        mission_id = self._safe_text(
            safe.get("mission_id"), "decision_mission_id", 512
        )
        scan_id = self._safe_text(safe.get("scan_id"), "decision_scan_id", 512)
        state = safe.get("state_transition") or {}
        if not isinstance(state, Mapping):
            state = {}
        if not state:
            state = {
                "from": safe.get("state_from"),
                "to": safe.get("state_to"),
            }
        candidates = self._text_list(safe.get("candidates"), "decision_candidate")
        rejected = self._rejected(safe.get("rejected"))
        policy_refs = self._text_list(safe.get("policy_refs"), "decision_policy_ref")
        supporting_fact_ids = _positive_ints(safe.get("supporting_fact_ids"))[
            :_MAX_SUPPORTING_FACTS
        ]
        normalized = {
            "schema_version": DECISION_TRACE_SCHEMA_VERSION,
            "event_type": event_type,
            "mission_id": mission_id,
            "scan_id": scan_id,
            "task_id": self._safe_text(safe.get("task_id"), "decision_task_id", 512),
            "task": self._safe_text(safe.get("task"), "decision_task", 512),
            "goal": self._safe_text(safe.get("goal"), "decision_goal", _MAX_TEXT_BYTES),
            "candidates": candidates,
            "rejected": rejected,
            "chosen_action": self._safe_text(
                safe.get("chosen_action"), "decision_action", 1_024
            ),
            "capability_ref": self._safe_text(
                safe.get("capability_ref"), "decision_capability_ref", 1_024
            ),
            "policy_refs": policy_refs,
            "supporting_fact_ids": supporting_fact_ids,
            "expected_outcome": _bounded_value(safe.get("expected_outcome") or {}),
            "actual_outcome": _bounded_value(safe.get("actual_outcome") or {}),
            "duration": _nonnegative_float(safe.get("duration")),
            "cost": _bounded_value(safe.get("cost") or {}),
            "state_transition": {
                "from": self._safe_text(state.get("from"), "decision_state", 256),
                "to": self._safe_text(state.get("to"), "decision_state", 256),
            },
            "retry_count": _bounded_count(safe.get("retry_count")),
            "fallback_count": _bounded_count(safe.get("fallback_count")),
            "occurred_at": _timestamp(safe.get("occurred_at")),
        }
        semantic_identity = {
            key: value
            for key, value in normalized.items()
            if key not in {"occurred_at", "schema_version"}
        }
        explicit_event_id = self._safe_text(
            safe.get("event_id"), "decision_event_id", 1_024
        )
        normalized["event_id"] = _stable_id(
            "decision", explicit_event_id or semantic_identity
        )
        normalized["scope_key"] = _stable_id(
            "decision-scope", mission_id or scan_id or "global"
        )
        return normalized

    def _safe_text(self, value: Any, kind: str, max_bytes: int) -> str:
        safe = self.redactor.redact_text(value or "", kind=kind)
        return _bounded_text(safe, max_bytes)

    def _text_list(self, values: Any, kind: str) -> list[str]:
        if values is None:
            return []
        if isinstance(values, (str, bytes)):
            values = [values]
        result: list[str] = []
        for value in values:
            safe = self._safe_text(value, kind, 1_024)
            if safe and safe not in result:
                result.append(safe)
            if len(result) >= _MAX_COLLECTION_ITEMS:
                break
        return result

    def _rejected(self, values: Any) -> list[dict[str, str]]:
        if isinstance(values, Mapping):
            values = [values]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            return []
        result: list[dict[str, str]] = []
        for value in values[:_MAX_COLLECTION_ITEMS]:
            if isinstance(value, Mapping):
                candidate = self._safe_text(
                    value.get("candidate") or value.get("action_id"),
                    "decision_candidate",
                    1_024,
                )
                reason = self._safe_text(
                    value.get("reason") or value.get("reasons"),
                    "decision_rejection_reason",
                    _MAX_TEXT_BYTES,
                )
            else:
                candidate = ""
                reason = self._safe_text(
                    value, "decision_rejection_reason", _MAX_TEXT_BYTES
                )
            result.append({"candidate": candidate, "reason": reason})
        return result

    def _prune(self, conn: sqlite3.Connection, scope_key: str) -> None:
        conn.execute(
            """
            DELETE FROM decision_events
            WHERE id IN (
                SELECT id FROM decision_events
                WHERE scope_key = ?
                ORDER BY occurred_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (scope_key, self.max_events_per_scope),
        )
        conn.execute(
            """
            DELETE FROM decision_events
            WHERE id IN (
                SELECT id FROM decision_events
                ORDER BY occurred_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_total_events,),
        )


def build_decision_metrics(
    facts: Sequence[Mapping[str, Any]],
    command_results: Sequence[Mapping[str, Any]],
    *,
    decision_events: Sequence[Mapping[str, Any]] = (),
    task_outcomes: Sequence[Mapping[str, Any]] = (),
    machine_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute stable, denominator-explicit quality metrics for one snapshot."""

    fact_list = [item for item in facts if isinstance(item, Mapping)]
    result_list = [item for item in command_results if isinstance(item, Mapping)]
    event_list = [item for item in decision_events if isinstance(item, Mapping)]
    outcome_list = [item for item in task_outcomes if isinstance(item, Mapping)]
    timestamps = [
        value
        for value in (
            *(_positive_timestamp(item.get("timestamp")) for item in fact_list),
            *(_positive_timestamp(item.get("timestamp")) for item in result_list),
            *(_positive_timestamp(item.get("occurred_at")) for item in event_list),
        )
        if value is not None
    ]
    baseline = min(timestamps, default=None)
    useful_facts = [item for item in fact_list if _useful_fact(item)]
    verified_facts = [
        item for item in fact_list if _assessment_status(item) == "verified"
    ]
    first_useful = _first_delay(useful_facts, baseline)
    first_verified = _first_delay(verified_facts, baseline)

    executed_results = [
        item for item in result_list if str(item.get("status") or "") != "blocked"
    ]
    useful_fact_count = sum(_bounded_count(item.get("new_facts")) for item in executed_results)
    parsed_fact_count = sum(
        _bounded_count(item.get("parsed_facts")) for item in executed_results
    )
    output_hashes: set[str] = set()
    duplicate_results = 0
    for item in executed_results:
        output_hash = str(item.get("output_hash") or "")
        if output_hash and output_hash in output_hashes:
            duplicate_results += 1
        if output_hash:
            output_hashes.add(output_hash)
    no_op_results = sum(
        1 for item in executed_results if _bounded_count(item.get("new_facts")) == 0
    )
    candidate_facts = [
        item
        for item in fact_list
        if str(item.get("type") or "").lower() in _CANDIDATE_FACT_TYPES
    ]
    verified_candidates = [
        item for item in candidate_facts if _assessment_status(item) == "verified"
    ]
    planner_events = [
        item for item in event_list if str(item.get("event_type") or "") == "goal_selection"
    ]
    invalid_planner_events = sum(
        1
        for item in planner_events
        if str((item.get("actual_outcome") or {}).get("status") or "").lower()
        in {"empty", "invalid", "rejected"}
    )
    invalid_task_outcomes = sum(
        1
        for item in outcome_list
        if str(item.get("reason") or "").lower().startswith(
            ("invalid", "unknown_agent", "planner_")
        )
    )
    planner_denominator = len(planner_events) + len(outcome_list)
    provider_events = [
        item
        for item in event_list
        if str(item.get("event_type") or "") == "provider_selection"
    ]
    fallback_events = sum(
        1 for item in provider_events if _bounded_count(item.get("fallback_count")) > 0
    )
    retry_events = sum(
        1 for item in provider_events if _bounded_count(item.get("retry_count")) > 0
    )
    timeout_results = sum(
        1 for item in executed_results if str(item.get("status") or "") == "timeout"
    )
    resume_outcomes = [
        item
        for item in event_list
        if str(item.get("event_type") or "") == "mission_resume_outcome"
    ]
    successful_resumes = sum(
        1
        for item in resume_outcomes
        if str((item.get("actual_outcome") or {}).get("status") or "") == "succeeded"
    )
    report_summary = (machine_report or {}).get("summary") or {}
    evidence_completeness = report_summary.get("evidence_completeness")
    if not isinstance(evidence_completeness, (int, float)):
        evidence_complete = sum(1 for fact in verified_facts if _verified_fact_complete(fact))
        evidence_completeness = _rate(evidence_complete, len(verified_facts), empty=1.0)

    counts = {
        "facts": len(fact_list),
        "useful_facts": len(useful_facts),
        "verified_facts": len(verified_facts),
        "candidate_facts": len(candidate_facts),
        "verified_candidates": len(verified_candidates),
        "commands": len(result_list),
        "executed_commands": len(executed_results),
        "duplicate_results": duplicate_results,
        "no_op_results": no_op_results,
        "parsed_facts": parsed_fact_count,
        "new_facts": useful_fact_count,
        "decision_events": len(event_list),
        "provider_decisions": len(provider_events),
        "fallback_events": fallback_events,
        "retry_events": retry_events,
        "timeout_results": timeout_results,
        "resume_outcomes": len(resume_outcomes),
        "successful_resumes": successful_resumes,
    }
    metrics = {
        "time_to_first_useful_evidence_seconds": first_useful,
        "time_to_first_verified_evidence_seconds": first_verified,
        "useful_facts_per_tool": _rate(useful_fact_count, len(executed_results)),
        "duplicate_rate": _rate(duplicate_results, len(executed_results)),
        "no_op_rate": _rate(no_op_results, len(executed_results)),
        "parser_yield": _rate(useful_fact_count, parsed_fact_count),
        "parsed_facts_per_tool": _rate(parsed_fact_count, len(executed_results)),
        "verification_conversion_rate": _rate(
            len(verified_candidates), len(candidate_facts)
        ),
        "invalid_planner_rate": _rate(
            invalid_planner_events + invalid_task_outcomes,
            planner_denominator,
        ),
        "fallback_rate": _rate(fallback_events, len(provider_events)),
        "retry_rate": _rate(retry_events, len(provider_events)),
        "timeout_rate": _rate(timeout_results, len(executed_results)),
        "resume_success_rate": _rate(successful_resumes, len(resume_outcomes)),
        "evidence_completeness": round(float(evidence_completeness), 6),
        "decision_duration_seconds": round(
            sum(_nonnegative_float(item.get("duration")) for item in event_list),
            6,
        ),
        "estimated_cost_units": round(
            sum(
                _nonnegative_float((item.get("cost") or {}).get("estimated_units"))
                for item in event_list
                if isinstance(item.get("cost") or {}, Mapping)
            ),
            6,
        ),
    }
    return {
        "schema_version": DECISION_METRICS_SCHEMA_VERSION,
        "metrics": metrics,
        "counts": counts,
        "definitions": {
            "useful_fact": "Non-internal fact whose current assessment is not contradicted.",
            "duplicate_rate": "Repeated non-empty output hashes / executed commands.",
            "no_op_rate": "Executed commands that added zero canonical facts / executed commands.",
            "parser_yield": "New canonical facts / parsed facts.",
            "verification_conversion_rate": "Currently verified candidate facts / candidate facts.",
            "invalid_planner_rate": "Invalid goal decisions and planner/task rejections / planner-related decisions.",
            "fallback_rate": "Provider decisions taking at least one fallback / provider decisions.",
            "retry_rate": "Provider decisions containing a retryable attempt / provider decisions.",
            "resume_success_rate": "Successful durable resume outcomes / durable resume outcomes.",
            "null_rate": "A null rate means that the snapshot has no applicable denominator.",
        },
    }


def _first_delay(
    facts: Sequence[Mapping[str, Any]], baseline: float | None
) -> float | None:
    if baseline is None:
        return None
    timestamps = [
        value
        for value in (_positive_timestamp(item.get("timestamp")) for item in facts)
        if value is not None
    ]
    if not timestamps:
        return None
    return round(max(0.0, min(timestamps) - baseline), 6)


def _useful_fact(fact: Mapping[str, Any]) -> bool:
    fact_type = str(fact.get("type") or "").lower()
    return fact_type not in _INTERNAL_FACT_TYPES and _assessment_status(fact) != "contradicted"


def _verified_fact_complete(fact: Mapping[str, Any]) -> bool:
    assessment = fact.get("assessment") or {}
    if not isinstance(assessment, Mapping):
        return False
    return bool(
        assessment.get("reason")
        and assessment.get("evidence_fact_ids")
        and assessment.get("source_execution_ids")
    )


def _assessment_status(fact: Mapping[str, Any]) -> str:
    assessment = fact.get("assessment") or {}
    if not isinstance(assessment, Mapping):
        assessment = {}
    return str(
        assessment.get("status") or fact.get("assessment_status") or "observed"
    ).lower()


def _rate(numerator: int | float, denominator: int, *, empty: float | None = None):
    if denominator <= 0:
        return empty
    return round(float(numerator) / float(denominator), 6)


def _bounded_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 4:
        return "[depth-bounded]"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value, key=lambda item: str(item))[:_MAX_COLLECTION_ITEMS]:
            result[_bounded_text(key, 256)] = _bounded_value(value[key], depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [
            _bounded_value(item, depth=depth + 1)
            for item in value[:_MAX_COLLECTION_ITEMS]
        ]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value if isinstance(value, int) or math.isfinite(value) else 0.0
    return _bounded_text(value, _MAX_TEXT_BYTES)


def _stable_id(namespace: str, payload: Any) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8", "replace")
    return f"{namespace}://sha256/{hashlib.sha256(encoded).hexdigest()}"


def _bounded_text(value: Any, max_bytes: int) -> str:
    raw = str(value or "")
    encoded = raw.encode("utf-8", "replace")
    if len(encoded) <= max_bytes:
        return raw
    return encoded[:max_bytes].decode("utf-8", "ignore")


def _positive_ints(values: Any) -> list[int]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, int)):
        values = [values]
    result: list[int] = []
    for value in values:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0 and parsed not in result:
            result.append(parsed)
    return result


def _bounded_count(value: Any) -> int:
    try:
        parsed = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(parsed, 1_000_000))


def _nonnegative_float(value: Any) -> float:
    try:
        parsed = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return parsed if math.isfinite(parsed) and parsed >= 0 else 0.0


def _positive_timestamp(value: Any) -> float | None:
    parsed = _nonnegative_float(value)
    return parsed if parsed > 0 else None


def _timestamp(value: Any) -> float:
    parsed = _positive_timestamp(value)
    return parsed if parsed is not None else time.time()


__all__ = [
    "DECISION_METRICS_SCHEMA_VERSION",
    "DECISION_TRACE_SCHEMA_VERSION",
    "DecisionEvent",
    "DecisionTraceStore",
    "build_decision_metrics",
]
