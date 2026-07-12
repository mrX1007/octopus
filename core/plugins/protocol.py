"""Strict JSON wire helpers shared by the plugin manager and worker.

The plugin boundary deliberately does not use pickle: a plugin process only
receives and returns JSON values.  Bytes are the sole extension and travel in
an explicit base64 envelope so payload-oriented plugins remain usable.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

_WIRE_TYPE = "__octopus_wire_type__"
_WIRE_BYTES = "bytes"


class WireError(ValueError):
    """Raised when a value cannot safely cross the plugin JSON boundary."""


def encode_value(value: Any) -> Any:
    """Convert *value* into a JSON-compatible structure.

    Mapping keys must be strings.  Arbitrary Python objects, callables, sets,
    and object references are rejected instead of being stringified because
    doing so would silently change the plugin API at the isolation boundary.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {
            _WIRE_TYPE: _WIRE_BYTES,
            "base64": base64.b64encode(value).decode("ascii"),
        }
    if isinstance(value, bytearray):
        return {
            _WIRE_TYPE: _WIRE_BYTES,
            "base64": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, Enum):
        return encode_value(value.value)
    if is_dataclass(value) and not isinstance(value, type):
        return encode_value(asdict(value))
    if isinstance(value, dict):
        encoded: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise WireError("JSON object keys must be strings")
            encoded[key] = encode_value(item)
        return encoded
    if isinstance(value, (list, tuple)):
        return [encode_value(item) for item in value]
    raise WireError(f"unsupported wire value: {type(value).__name__}")


def decode_value(value: Any) -> Any:
    """Decode a value previously returned by :func:`encode_value`."""
    if isinstance(value, list):
        return [decode_value(item) for item in value]
    if isinstance(value, dict):
        if value.get(_WIRE_TYPE) == _WIRE_BYTES and set(value) == {_WIRE_TYPE, "base64"}:
            encoded = value.get("base64")
            if not isinstance(encoded, str):
                raise WireError("invalid bytes envelope")
            try:
                return base64.b64decode(encoded.encode("ascii"), validate=True)
            except (ValueError, UnicodeEncodeError) as exc:
                raise WireError("invalid base64 bytes envelope") from exc
        return {str(key): decode_value(item) for key, item in value.items()}
    return value


def dumps_message(value: Any) -> bytes:
    """Serialize one protocol message as UTF-8 JSON bytes."""
    try:
        return json.dumps(
            encode_value(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, WireError):
            raise
        raise WireError(str(exc)) from exc


def loads_message(raw: bytes) -> Any:
    """Parse one UTF-8 JSON protocol message."""
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError("invalid worker JSON response") from exc
    return decode_value(parsed)
