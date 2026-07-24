"""Crash-safe state, locking, and content identity for benchmark campaigns."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

try:  # Linux and macOS; unsupported platforms fail closed when locking.
    import fcntl
except ImportError:  # pragma: no cover - exercised only on unsupported platforms
    fcntl = None  # type: ignore[assignment]

CAMPAIGN_STATE_SCHEMA_VERSION = "1.0"


class CampaignStateError(RuntimeError):
    """Base error for an invalid or unavailable campaign journal."""


class CampaignLockedError(CampaignStateError):
    """Raised when another process owns the campaign lock."""


class CampaignFingerprintMismatch(CampaignStateError):
    """Raised when resume inputs differ from the initialized campaign."""


def campaign_fingerprint(payload: Any) -> str:
    """Return the stable identity of all non-secret campaign inputs."""

    encoded = _canonical_json(payload).encode("utf-8")
    return f"benchmark-campaign://sha256/{hashlib.sha256(encoded).hexdigest()}"


def schedule_run_key(
    system_id: str,
    scenario_id: str,
    repetition: int,
    seed: int,
) -> str:
    """Return a path-safe content identity for one scheduled run."""

    digest = hashlib.sha256(
        _canonical_json(
            {
                "system_id": system_id,
                "scenario_id": scenario_id,
                "repetition": int(repetition),
                "seed": int(seed),
            }
        ).encode("utf-8")
    ).hexdigest()
    return digest


class CampaignJournal:
    """Atomic JSON journal whose completed run records are safe to resume."""

    def __init__(
        self,
        root: str | Path,
        *,
        campaign_id: str,
        fingerprint: str,
    ) -> None:
        self.root = Path(root)
        self.campaign_id = _safe_identifier(campaign_id)
        self.fingerprint = str(fingerprint)
        if not self.fingerprint.startswith("benchmark-campaign://sha256/"):
            raise CampaignStateError("invalid_campaign_fingerprint")
        self.campaign_root = self.root / self.campaign_id
        self._schedule_keys: frozenset[str] = frozenset()

    @property
    def diagnostics_directory(self) -> Path:
        """Return the private, unpublished diagnostics location for this campaign."""

        return self.campaign_root / "diagnostics"

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Acquire a non-blocking process lock for the whole campaign lifecycle."""

        if fcntl is None:
            raise CampaignStateError("campaign_lock_unsupported")
        self.campaign_root.mkdir(parents=True, exist_ok=True)
        lock_path = self.campaign_root / ".lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CampaignLockedError("campaign_locked") from None
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def initialize(self, schedule: Sequence[Mapping[str, Any]]) -> None:
        """Create or validate immutable campaign metadata for safe resume."""

        normalized_schedule = [_json_safe(dict(item)) for item in schedule]
        keys = [str(item.get("run_key") or "") for item in normalized_schedule]
        if not keys or any(not _is_digest(item) for item in keys):
            raise CampaignStateError("invalid_campaign_schedule")
        if len(keys) != len(set(keys)):
            raise CampaignStateError("duplicate_campaign_run_key")
        metadata = {
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "schedule": normalized_schedule,
        }
        path = self.campaign_root / "campaign.json"
        if path.exists():
            existing = _read_mapping(path)
            if existing.get("fingerprint") != self.fingerprint:
                raise CampaignFingerprintMismatch("campaign_fingerprint_mismatch")
            if _canonical_json(existing.get("schedule")) != _canonical_json(
                normalized_schedule
            ):
                raise CampaignFingerprintMismatch("campaign_schedule_mismatch")
        else:
            _atomic_json(path, metadata)
        self._schedule_keys = frozenset(keys)
        (self.campaign_root / "runs").mkdir(parents=True, exist_ok=True)
        (self.campaign_root / "attestations").mkdir(parents=True, exist_ok=True)

    def read_run(self, run_key: str) -> dict[str, Any] | None:
        self._require_run_key(run_key)
        path = self.campaign_root / "runs" / f"{run_key}.json"
        if not path.exists():
            return None
        record = _read_mapping(path)
        self._validate_record(record, run_key=run_key)
        return record

    def write_run(self, run_key: str, record: Mapping[str, Any]) -> Path:
        """Persist one completed outcome; existing records are immutable."""

        self._require_run_key(run_key)
        destination = self.campaign_root / "runs" / f"{run_key}.json"
        payload = {
            **_json_safe(dict(record)),
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "run_key": run_key,
        }
        self._validate_record(payload, run_key=run_key)
        if destination.exists():
            existing = _read_mapping(destination)
            if _canonical_json(existing) != _canonical_json(payload):
                raise CampaignStateError("immutable_run_record_conflict")
            return destination
        _atomic_json(destination, payload)
        return destination

    def write_attestation(
        self,
        run_key: str,
        attestation: Mapping[str, Any],
    ) -> Path:
        self._require_run_key(run_key)
        destination = self.campaign_root / "attestations" / f"{run_key}.json"
        payload = {
            **_json_safe(dict(attestation)),
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "run_key": run_key,
        }
        # A process can stop after reset succeeds but before its run record is
        # committed. Resume must reset again and replace that orphan
        # attestation; only the reset immediately preceding the completed run
        # is publishable evidence.
        _atomic_json(destination, payload)
        return destination

    def read_attestations(self) -> tuple[dict[str, Any], ...]:
        directory = self.campaign_root / "attestations"
        if not directory.exists():
            return ()
        records: list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            record = _read_mapping(path)
            if (
                record.get("schema_version") != CAMPAIGN_STATE_SCHEMA_VERSION
                or record.get("campaign_id") != self.campaign_id
                or record.get("fingerprint") != self.fingerprint
                or record.get("run_key") != path.stem
                or path.stem not in self._schedule_keys
            ):
                raise CampaignStateError("attestation_record_mismatch")
            records.append(record)
        return tuple(records)

    def write_cleanup_attestation(self, attestation: Mapping[str, Any]) -> Path:
        """Atomically record the latest campaign cleanup attempt."""

        destination = self.campaign_root / "cleanup.json"
        payload = {
            **_json_safe(dict(attestation)),
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
        }
        self._validate_cleanup_attestation(payload)
        _atomic_json(destination, payload)
        return destination

    def read_cleanup_attestation(self) -> dict[str, Any] | None:
        destination = self.campaign_root / "cleanup.json"
        if not destination.exists():
            return None
        record = _read_mapping(destination)
        self._validate_cleanup_attestation(record)
        return record

    def write_preflight(self, report: Mapping[str, Any]) -> Path:
        destination = self.campaign_root / "preflight.json"
        payload = {
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "report": _json_safe(dict(report)),
        }
        _atomic_json(destination, payload)
        return destination

    def set_status(self, status: str, **metadata: Any) -> Path:
        destination = self.campaign_root / "status.json"
        payload = {
            "schema_version": CAMPAIGN_STATE_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "fingerprint": self.fingerprint,
            "status": str(status)[:128],
            "metadata": _json_safe(metadata),
        }
        _atomic_json(destination, payload)
        return destination

    def completed_run_count(self) -> int:
        directory = self.campaign_root / "runs"
        return len(tuple(directory.glob("*.json"))) if directory.exists() else 0

    def _require_run_key(self, run_key: str) -> None:
        if not _is_digest(run_key):
            raise CampaignStateError("invalid_run_key")
        if not self._schedule_keys:
            raise CampaignStateError("campaign_journal_not_initialized")
        if run_key not in self._schedule_keys:
            raise CampaignStateError("run_not_in_campaign_schedule")

    def _validate_record(self, record: Mapping[str, Any], *, run_key: str) -> None:
        if record.get("schema_version") != CAMPAIGN_STATE_SCHEMA_VERSION:
            raise CampaignStateError("unsupported_run_record_schema")
        if record.get("campaign_id") != self.campaign_id:
            raise CampaignStateError("run_record_campaign_mismatch")
        if record.get("fingerprint") != self.fingerprint:
            raise CampaignFingerprintMismatch("run_record_fingerprint_mismatch")
        if record.get("run_key") != run_key:
            raise CampaignStateError("run_record_key_mismatch")
        if not isinstance(record.get("result"), Mapping):
            raise CampaignStateError("run_record_missing_result")

    def _validate_cleanup_attestation(self, record: Mapping[str, Any]) -> None:
        if record.get("schema_version") != CAMPAIGN_STATE_SCHEMA_VERSION:
            raise CampaignStateError("unsupported_cleanup_attestation_schema")
        if record.get("campaign_id") != self.campaign_id:
            raise CampaignStateError("cleanup_attestation_campaign_mismatch")
        if record.get("fingerprint") != self.fingerprint:
            raise CampaignFingerprintMismatch("cleanup_attestation_fingerprint_mismatch")
        if record.get("status") not in {"succeeded", "failed"}:
            raise CampaignStateError("invalid_cleanup_attestation_status")


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _read_mapping(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CampaignStateError("campaign_state_read_failed") from exc
    if not isinstance(value, Mapping):
        raise CampaignStateError("campaign_state_not_mapping")
    return {str(key): item for key, item in value.items()}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _safe_identifier(value: str) -> str:
    candidate = str(value).strip().lower()
    if (
        not candidate
        or len(candidate) > 128
        or not candidate[0].isalnum()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for character in candidate)
    ):
        raise CampaignStateError("invalid_campaign_id")
    return candidate


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth >= 8:
        raise CampaignStateError("campaign_state_depth_exceeded")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise CampaignStateError("campaign_state_nonfinite_number")
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [_json_safe(item, depth=depth + 1) for item in value]
    raise CampaignStateError("campaign_state_non_json_value")


__all__ = [
    "CAMPAIGN_STATE_SCHEMA_VERSION",
    "CampaignFingerprintMismatch",
    "CampaignJournal",
    "CampaignLockedError",
    "CampaignStateError",
    "campaign_fingerprint",
    "schedule_run_key",
]
