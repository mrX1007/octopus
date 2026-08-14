"""Decode-only legacy task compatibility contract."""

from __future__ import annotations

import json

import pytest

import core.c2.agent_task_compat as compatibility
from core.c2.agent_task_compat import (
    LegacyAgentTaskDecodeError,
    decode_legacy_v11_task_row,
)

pytestmark = pytest.mark.unit


def test_v11_compat_is_decode_only() -> None:
    assert not hasattr(compatibility, "compat_v1_to_v12")
    assert not any(name.startswith("encode") for name in compatibility.__all__)
    row = json.dumps(
        {
            "task_id": "legacy-1",
            "command": "opaque legacy command",
            "payload": {"legacy": True},
        },
        separators=(",", ":"),
    ).encode()
    decoded = decode_legacy_v11_task_row(row)
    assert decoded.source_schema_version == "11.0"
    assert decoded.disposition == "migration_required"
    assert not hasattr(decoded, "command")
    assert not hasattr(decoded, "payload")


def test_legacy_compat_rejects_unknown_or_malformed_rows() -> None:
    with pytest.raises(LegacyAgentTaskDecodeError, match="unknown fields"):
        decode_legacy_v11_task_row(b'{"task_id":"legacy","command":"x","schema_version":"12.0"}')
    with pytest.raises(LegacyAgentTaskDecodeError):
        decode_legacy_v11_task_row(b"not-json")
