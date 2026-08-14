"""Decode-only inventory for legacy V11 agent-task rows.

This module deliberately exposes no V11-to-V12 encoder. Legacy command and
payload values are reduced to bounded digests for migration inventory; they
cannot become a typed control-plane operation or a V12 wire payload.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

_MAX_LEGACY_ROW_BYTES = 1024 * 1024
_ALLOWED_FIELDS = frozenset({"task_id", "command", "action", "payload", "data"})


class LegacyAgentTaskDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class LegacyAgentTaskV11InventoryRecord:
    task_id: str
    source_schema_version: Literal["11.0"]
    disposition: Literal["migration_required"]
    legacy_field_names: tuple[str, ...]
    opaque_row_digest: str


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for name, value in pairs:
        if name in decoded:
            raise LegacyAgentTaskDecodeError(f"duplicate legacy field: {name}")
        decoded[name] = value
    return decoded


def decode_legacy_v11_task_row(
    serialized_row: bytes,
) -> LegacyAgentTaskV11InventoryRecord:
    if type(serialized_row) is not bytes:
        raise TypeError("legacy task row must be serialized bytes")
    if not serialized_row or len(serialized_row) > _MAX_LEGACY_ROW_BYTES:
        raise LegacyAgentTaskDecodeError("legacy task row is empty or oversized")
    try:
        decoded = json.loads(
            serialized_row.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=lambda value: (_ for _ in ()).throw(
                LegacyAgentTaskDecodeError(f"non-finite legacy value: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyAgentTaskDecodeError("legacy task row is not valid UTF-8 JSON") from exc
    if type(decoded) is not dict:
        raise LegacyAgentTaskDecodeError("legacy task row must be an object")
    unknown = set(decoded) - _ALLOWED_FIELDS
    if unknown:
        raise LegacyAgentTaskDecodeError(f"legacy task row contains unknown fields: {', '.join(sorted(unknown))}")
    task_id = decoded.get("task_id")
    if type(task_id) is not str or not task_id.strip() or len(task_id.encode("utf-8")) > 256:
        raise LegacyAgentTaskDecodeError("legacy task_id must be a bounded non-empty string")
    if "command" not in decoded and "action" not in decoded:
        raise LegacyAgentTaskDecodeError("legacy task row has no operation inventory field")
    canonical = json.dumps(
        decoded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return LegacyAgentTaskV11InventoryRecord(
        task_id=task_id.strip(),
        source_schema_version="11.0",
        disposition="migration_required",
        legacy_field_names=tuple(sorted(decoded)),
        opaque_row_digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


__all__ = [
    "LegacyAgentTaskDecodeError",
    "LegacyAgentTaskV11InventoryRecord",
    "decode_legacy_v11_task_row",
]
