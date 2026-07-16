"""Bounded, secret-free provider telemetry for explainable selection."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

PROVIDER_TELEMETRY_SCHEMA_VERSION = "1.0"
_SAFE_LABEL = re.compile(r"[^a-zA-Z0-9_.:/-]+")


def target_class(value: str) -> str:
    """Classify a target without retaining its address or hostname."""

    raw = str(value or "").strip()
    if not raw:
        return "none"
    if "://" in raw:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        prefix = f"url_{parsed.scheme.lower()}"
    else:
        host = raw.strip("[]")
        prefix = ""
    if "/" in host:
        try:
            network = ipaddress.ip_network(host, strict=False)
            scope = "private" if network.is_private else "public"
            return f"network_{network.version}_{scope}"
        except ValueError:
            pass
    if host.count(":") == 1 and not prefix:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
    try:
        address = ipaddress.ip_address(host)
        scope = "private" if address.is_private else "public"
        base = f"ip{address.version}_{scope}"
    except ValueError:
        lowered = host.rstrip(".").lower()
        if lowered in {"localhost", "127.0.0.1", "::1"}:
            base = "local"
        elif "." in lowered and not any(char.isspace() for char in lowered):
            base = "dns"
        else:
            base = "opaque"
    return f"{prefix}_{base}" if prefix else base


@dataclass(frozen=True)
class ProviderTelemetryEvent:
    provider_id: str
    capability: str
    target_class: str
    status: str
    dependency_available: bool
    scope_compatible: bool
    active_risk: float
    duration: float = 0.0
    useful_facts: int = 0
    duplicate_facts: int = 0
    parser_items: int = 0
    parser_errors: int = 0
    partial_output_ingested: bool = False
    retryable: bool = False
    execution_id: str = ""
    observed_at: float = 0.0


@dataclass(frozen=True)
class ProviderTelemetrySummary:
    provider_id: str
    capability: str
    target_class: str
    samples: int = 0
    dependency_availability_rate: float = 0.0
    average_duration: float = 0.0
    timeout_rate: float = 0.0
    failure_rate: float = 0.0
    unavailable_rate: float = 0.0
    success_rate: float = 0.0
    useful_fact_yield: float = 0.0
    duplicate_yield_rate: float = 0.0
    parser_quality: float = 0.0
    scope_compatibility_rate: float = 0.0
    active_risk: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "capability": self.capability,
            "target_class": self.target_class,
            "samples": self.samples,
            "dependency_availability_rate": self.dependency_availability_rate,
            "average_duration": self.average_duration,
            "timeout_rate": self.timeout_rate,
            "failure_rate": self.failure_rate,
            "unavailable_rate": self.unavailable_rate,
            "success_rate": self.success_rate,
            "useful_fact_yield": self.useful_fact_yield,
            "duplicate_yield_rate": self.duplicate_yield_rate,
            "parser_quality": self.parser_quality,
            "scope_compatibility_rate": self.scope_compatibility_rate,
            "active_risk": self.active_risk,
        }


class ProviderTelemetryStore:
    def __init__(
        self,
        db_path: str,
        *,
        max_events_per_key: int = 100,
        max_total_events: int = 10_000,
    ) -> None:
        self.db_path = db_path
        self.max_events_per_key = max(5, min(int(max_events_per_key), 1_000))
        self.max_total_events = max(
            self.max_events_per_key,
            min(int(max_total_events), 1_000_000),
        )
        self._persistent_conn: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:", timeout=10.0)
            self._persistent_conn.row_factory = sqlite3.Row
        else:
            directory = os.path.dirname(os.path.abspath(db_path))
            os.makedirs(directory, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if conn is not self._persistent_conn:
                conn.close()

    def close(self) -> None:
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None

    def __del__(self):
        with suppress(Exception):
            self.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS provider_telemetry_schema (
                    schema_version TEXT PRIMARY KEY,
                    applied_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT NOT NULL UNIQUE,
                    provider_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    target_class TEXT NOT NULL,
                    status TEXT NOT NULL,
                    dependency_available INTEGER NOT NULL,
                    scope_compatible INTEGER NOT NULL,
                    active_risk REAL NOT NULL,
                    duration REAL NOT NULL,
                    useful_facts INTEGER NOT NULL,
                    duplicate_facts INTEGER NOT NULL,
                    parser_items INTEGER NOT NULL,
                    parser_errors INTEGER NOT NULL,
                    partial_output_ingested INTEGER NOT NULL,
                    retryable INTEGER NOT NULL,
                    observed_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_provider_telemetry_key
                    ON provider_telemetry_events(
                        provider_id, capability, target_class, observed_at DESC, id DESC
                    );
                CREATE INDEX IF NOT EXISTS idx_provider_telemetry_observed
                    ON provider_telemetry_events(observed_at DESC, id DESC);
                """
            )
            versions = {
                str(row[0])
                for row in conn.execute(
                    "SELECT schema_version FROM provider_telemetry_schema"
                ).fetchall()
            }
            unsupported = versions - {PROVIDER_TELEMETRY_SCHEMA_VERSION}
            if unsupported:
                raise RuntimeError(
                    "Unsupported provider-telemetry schema version(s): "
                    + ", ".join(sorted(unsupported))
                )
            conn.execute(
                """
                INSERT OR IGNORE INTO provider_telemetry_schema(schema_version, applied_at)
                VALUES (?, ?)
                """,
                (PROVIDER_TELEMETRY_SCHEMA_VERSION, time.time()),
            )

    @staticmethod
    def _label(value: str, *, limit: int = 256) -> str:
        label = _SAFE_LABEL.sub("_", str(value or "").strip())[:limit]
        if not label:
            raise ValueError("Provider telemetry labels must not be empty")
        return label

    @staticmethod
    def _count(value: Any) -> int:
        try:
            parsed = int(value or 0)
        except (TypeError, ValueError):
            return 0
        return max(0, min(parsed, 1_000_000))

    @staticmethod
    def _finite(value: Any, *, maximum: float) -> float:
        try:
            parsed = float(value or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(parsed, maximum)) if math.isfinite(parsed) else 0.0

    def record(self, event: ProviderTelemetryEvent) -> bool:
        provider_id = self._label(event.provider_id)
        capability = self._label(event.capability)
        target_kind = self._label(event.target_class, limit=64)
        status = self._label(event.status, limit=64).lower()
        observed_at = self._finite(event.observed_at or time.time(), maximum=4_102_444_800.0)
        identity_parts = [provider_id, capability, target_kind]
        if event.execution_id:
            identity_parts.append(f"execution:{event.execution_id}")
        else:
            identity_parts.extend((status, f"observed:{observed_at:.6f}"))
        identity = "\x1f".join(identity_parts)
        event_key = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
        values = (
            event_key,
            provider_id,
            capability,
            target_kind,
            status,
            int(bool(event.dependency_available)),
            int(bool(event.scope_compatible)),
            self._finite(event.active_risk, maximum=1.0),
            self._finite(event.duration, maximum=86_400.0),
            self._count(event.useful_facts),
            self._count(event.duplicate_facts),
            self._count(event.parser_items),
            self._count(event.parser_errors),
            int(bool(event.partial_output_ingested)),
            int(bool(event.retryable)),
            observed_at,
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO provider_telemetry_events(
                    event_key, provider_id, capability, target_class, status,
                    dependency_available, scope_compatible, active_risk,
                    duration, useful_facts, duplicate_facts, parser_items,
                    parser_errors, partial_output_ingested, retryable, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            created = cursor.rowcount > 0
            self._prune(conn, provider_id, capability, target_kind)
        return created

    def _prune(
        self,
        conn: sqlite3.Connection,
        provider_id: str,
        capability: str,
        target_kind: str,
    ) -> None:
        conn.execute(
            """
            DELETE FROM provider_telemetry_events WHERE id IN (
                SELECT id FROM provider_telemetry_events
                WHERE provider_id = ? AND capability = ? AND target_class = ?
                ORDER BY observed_at DESC, id DESC LIMIT -1 OFFSET ?
            )
            """,
            (provider_id, capability, target_kind, self.max_events_per_key),
        )
        conn.execute(
            """
            DELETE FROM provider_telemetry_events WHERE id IN (
                SELECT id FROM provider_telemetry_events
                ORDER BY observed_at DESC, id DESC LIMIT -1 OFFSET ?
            )
            """,
            (self.max_total_events,),
        )

    def summary(
        self,
        provider_id: str,
        capability: str,
        target_kind: str,
    ) -> ProviderTelemetrySummary:
        provider_id = self._label(provider_id)
        capability = self._label(capability)
        target_kind = self._label(target_kind, limit=64)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT status, dependency_available, scope_compatible,
                       active_risk, duration, useful_facts, duplicate_facts,
                       parser_items, parser_errors
                FROM provider_telemetry_events
                WHERE provider_id = ? AND capability = ? AND target_class = ?
                ORDER BY observed_at DESC, id DESC LIMIT ?
                """,
                (provider_id, capability, target_kind, self.max_events_per_key),
            ).fetchall()
        samples = len(rows)
        if not samples:
            return ProviderTelemetrySummary(provider_id, capability, target_kind)
        statuses = [str(row["status"]) for row in rows]
        useful = sum(int(row["useful_facts"]) for row in rows)
        duplicate = sum(int(row["duplicate_facts"]) for row in rows)
        parser_items = sum(int(row["parser_items"]) for row in rows)
        parser_errors = sum(int(row["parser_errors"]) for row in rows)
        return ProviderTelemetrySummary(
            provider_id=provider_id,
            capability=capability,
            target_class=target_kind,
            samples=samples,
            dependency_availability_rate=(
                sum(int(row["dependency_available"]) for row in rows) / samples
            ),
            average_duration=sum(float(row["duration"]) for row in rows) / samples,
            timeout_rate=statuses.count("timeout") / samples,
            failure_rate=statuses.count("failed") / samples,
            unavailable_rate=statuses.count("unavailable") / samples,
            success_rate=statuses.count("succeeded") / samples,
            useful_fact_yield=useful / samples,
            duplicate_yield_rate=(duplicate / (useful + duplicate) if useful + duplicate else 0.0),
            parser_quality=(
                max(0.0, (parser_items - parser_errors) / parser_items)
                if parser_items
                else 0.0
            ),
            scope_compatibility_rate=(
                sum(int(row["scope_compatible"]) for row in rows) / samples
            ),
            active_risk=sum(float(row["active_risk"]) for row in rows) / samples,
        )

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM provider_telemetry_events").fetchone()
        return int(row[0]) if row else 0

    def recent_events(
        self,
        provider_id: str,
        capability: str,
        target_kind: str,
        *,
        limit: int = 10,
    ) -> tuple[tuple[str, float], ...]:
        """Return bounded status/time pairs for health controls."""

        provider_id = self._label(provider_id)
        capability = self._label(capability)
        target_kind = self._label(target_kind, limit=64)
        safe_limit = max(1, min(int(limit), 100))
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT status, observed_at FROM provider_telemetry_events
                WHERE provider_id = ? AND capability = ? AND target_class = ?
                ORDER BY observed_at DESC, id DESC LIMIT ?
                """,
                (provider_id, capability, target_kind, safe_limit),
            ).fetchall()
        return tuple((str(row["status"]), float(row["observed_at"])) for row in rows)


__all__ = [
    "PROVIDER_TELEMETRY_SCHEMA_VERSION",
    "ProviderTelemetryEvent",
    "ProviderTelemetryStore",
    "ProviderTelemetrySummary",
    "target_class",
]
