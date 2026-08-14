"""Daemon-side generic resource payload decoder registry (§14.6A)."""

from __future__ import annotations

import hashlib
import json
from threading import RLock
from typing import Any, Callable

from core.c2.resource_participant_models import C2DaemonResourceKindV1


class UnknownResourceSchemaError(ValueError):
    """Raised when a payload schema is not registered for a resource kind."""


class ResourcePayloadDigestMismatchError(ValueError):
    """Raised when the computed RFC-8785 canonical digest does not match expected_digest."""


class C2DaemonResourcePayloadRegistry:
    """Registry mapping (resource_kind, schema_id) pairs to decoding functions."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._decoders: dict[tuple[C2DaemonResourceKindV1, str], Callable[[bytes], Any]] = {}

    def register(
        self,
        kind: C2DaemonResourceKindV1,
        schema_id: str,
        decoder: Callable[[bytes], Any],
    ) -> None:
        if not schema_id:
            raise ValueError("schema_id must not be empty")
        with self._lock:
            self._decoders[(kind, schema_id)] = decoder

    def decode(
        self,
        kind: C2DaemonResourceKindV1,
        schema_id: str,
        payload_bytes: bytes,
        expected_digest: str | None = None,
    ) -> Any:
        if expected_digest is not None:
            computed = f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"
            if computed != expected_digest:
                raise ResourcePayloadDigestMismatchError(
                    f"Payload digest mismatch: computed {computed}, expected {expected_digest}"
                )

        with self._lock:
            decoder = self._decoders.get((kind, schema_id))
            if decoder is None:
                # Default canonical JSON parser if no special decoder registered
                try:
                    return json.loads(payload_bytes.decode("utf-8"))
                except Exception as exc:
                    raise UnknownResourceSchemaError(f"Unknown resource payload schema {schema_id} for {kind}") from exc

            return decoder(payload_bytes)
