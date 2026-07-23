"""Controller-owned, hash-chained request ledger for the blinded v3 lab."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import ActionEvent, BenchmarkV3SchemaError, canonical_json, stable_digest

LEDGER_SCHEMA_VERSION = "1.0"
_GENESIS_DIGEST = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    method: str
    route_id: str
    target_digest: str
    status: int
    evidence_ids: tuple[str, ...]
    violation: str
    observed_at: float
    previous_digest: str
    entry_digest: str

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> LedgerEntry:
        try:
            entry = cls(
                sequence=int(payload["sequence"]),
                method=str(payload["method"]),
                route_id=str(payload["route_id"]),
                target_digest=str(payload["target_digest"]),
                status=int(payload["status"]),
                evidence_ids=tuple(str(item) for item in payload.get("evidence_ids") or []),
                violation=str(payload.get("violation") or ""),
                observed_at=float(payload["observed_at"]),
                previous_digest=str(payload["previous_digest"]),
                entry_digest=str(payload["entry_digest"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BenchmarkV3SchemaError("invalid_ledger_entry") from exc
        if entry.sequence < 1 or not 100 <= entry.status <= 599:
            raise BenchmarkV3SchemaError("invalid_ledger_entry")
        if entry.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise BenchmarkV3SchemaError("invalid_ledger_method")
        if not _is_digest(entry.target_digest) or not _is_digest(entry.previous_digest):
            raise BenchmarkV3SchemaError("invalid_ledger_digest")
        if not _is_digest(entry.entry_digest):
            raise BenchmarkV3SchemaError("invalid_ledger_digest")
        return entry

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "evidence_ids": list(self.evidence_ids),
            "method": self.method,
            "observed_at": self.observed_at,
            "previous_digest": self.previous_digest,
            "route_id": self.route_id,
            "sequence": self.sequence,
            "status": self.status,
            "target_digest": self.target_digest,
            "violation": self.violation or None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "entry_digest": self.entry_digest}


@dataclass(frozen=True)
class LedgerSnapshot:
    variant_digest: str
    entry_count: int
    root_digest: str
    visited_route_ids: tuple[str, ...]
    observed_evidence_ids: tuple[str, ...]
    violations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_count": self.entry_count,
            "observed_evidence_ids": list(self.observed_evidence_ids),
            "root_digest": self.root_digest,
            "schema_version": LEDGER_SCHEMA_VERSION,
            "variant_digest": self.variant_digest,
            "violations": list(self.violations),
            "visited_route_ids": list(self.visited_route_ids),
        }


class ControlPlaneLedger:
    """Append-only controller ledger; it is never exposed as an HTTP route."""

    def __init__(
        self,
        *,
        variant_digest: str,
        path: str | Path | None = None,
        clock: Callable[[], float] = time.time,
        fsync: bool = True,
    ) -> None:
        if not _is_digest(variant_digest):
            raise BenchmarkV3SchemaError("invalid:variant_digest")
        self.variant_digest = variant_digest
        self.path = Path(path).resolve() if path is not None else None
        self.clock = clock
        self.fsync = bool(fsync)
        self._entries: list[LedgerEntry] = []
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size:
                self._entries.extend(read_ledger(self.path, variant_digest=variant_digest))
            else:
                self.path.touch(mode=0o600, exist_ok=True)
                os.chmod(self.path, 0o600)

    def record(
        self,
        *,
        method: str,
        target: str,
        route_id: str,
        status: int,
        evidence_ids: Sequence[str] = (),
        violation: str = "",
    ) -> LedgerEntry:
        method_name = str(method).upper()
        if method_name not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise BenchmarkV3SchemaError("invalid_ledger_method")
        if not 100 <= int(status) <= 599:
            raise BenchmarkV3SchemaError("invalid_ledger_status")
        with self._lock:
            previous = self._entries[-1].entry_digest if self._entries else _GENESIS_DIGEST
            unsigned = {
                "evidence_ids": sorted({str(item) for item in evidence_ids}),
                "method": method_name,
                "observed_at": round(float(self.clock()), 9),
                "previous_digest": previous,
                "route_id": str(route_id or "unmatched-route"),
                "sequence": len(self._entries) + 1,
                "status": int(status),
                "target_digest": stable_digest({"target": str(target)}),
                "violation": str(violation or "") or None,
            }
            entry_digest = stable_digest(
                {
                    "entry": unsigned,
                    "variant_digest": self.variant_digest,
                }
            )
            entry = LedgerEntry.from_dict({**unsigned, "entry_digest": entry_digest})
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(canonical_json(entry.to_dict()) + "\n")
                    handle.flush()
                    if self.fsync:
                        os.fsync(handle.fileno())
            self._entries.append(entry)
            return entry

    def entries(self) -> tuple[LedgerEntry, ...]:
        with self._lock:
            return tuple(self._entries)

    def snapshot(self) -> LedgerSnapshot:
        entries = self.entries()
        return LedgerSnapshot(
            variant_digest=self.variant_digest,
            entry_count=len(entries),
            root_digest=entries[-1].entry_digest if entries else _GENESIS_DIGEST,
            visited_route_ids=tuple(sorted({item.route_id for item in entries})),
            observed_evidence_ids=tuple(sorted({value for item in entries for value in item.evidence_ids})),
            violations=tuple(f"{item.method.lower()}_mutation_attempt" for item in entries if item.violation),
        )

    def action_events(self) -> tuple[ActionEvent, ...]:
        """Convert controller evidence to normalized action telemetry."""

        result: list[ActionEvent] = []
        for item in self.entries():
            if item.status in {408, 504}:
                status = "timeout"
            elif 200 <= item.status < 400:
                status = "succeeded"
            elif item.status in {401, 403, 405}:
                status = "blocked"
            else:
                status = "failed"
            result.append(
                ActionEvent(
                    event_id=f"ledger-event-{item.sequence}",
                    sequence=item.sequence - 1,
                    action_name="fixture-http-request",
                    action_type="http",
                    status=status,
                    method=item.method,
                    target_class="fixture-route",
                    evidence_refs=item.evidence_ids,
                )
            )
        return tuple(result)


def read_ledger(
    path: str | Path,
    *,
    variant_digest: str,
) -> tuple[LedgerEntry, ...]:
    """Read and verify every link in a persisted ledger chain."""

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise BenchmarkV3SchemaError("ledger_read_failed") from exc
    payloads: list[Mapping[str, Any]] = []
    for line in lines:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise BenchmarkV3SchemaError("invalid_ledger_json") from exc
        if not isinstance(payload, Mapping):
            raise BenchmarkV3SchemaError("invalid_ledger_entry")
        payloads.append(payload)
    return verify_ledger_entries(payloads, variant_digest=variant_digest)


def verify_ledger_entries(
    payloads: Sequence[Mapping[str, Any]],
    *,
    variant_digest: str,
) -> tuple[LedgerEntry, ...]:
    """Validate an in-memory public ledger payload and its complete hash chain."""

    if not _is_digest(variant_digest):
        raise BenchmarkV3SchemaError("invalid:variant_digest")
    previous = _GENESIS_DIGEST
    entries: list[LedgerEntry] = []
    for expected_sequence, payload in enumerate(payloads, start=1):
        if not isinstance(payload, Mapping):
            raise BenchmarkV3SchemaError("invalid_ledger_entry")
        entry = LedgerEntry.from_dict(payload)
        if entry.sequence != expected_sequence or entry.previous_digest != previous:
            raise BenchmarkV3SchemaError("broken_ledger_chain")
        expected_digest = stable_digest(
            {
                "entry": entry.unsigned_dict(),
                "variant_digest": variant_digest,
            }
        )
        if entry.entry_digest != expected_digest:
            raise BenchmarkV3SchemaError("ledger_digest_mismatch")
        entries.append(entry)
        previous = entry.entry_digest
    return tuple(entries)


def _is_digest(value: str) -> bool:
    return len(str(value)) == 64 and all(character in "0123456789abcdef" for character in str(value))
