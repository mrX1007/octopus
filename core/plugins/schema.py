"""Closed, inert input-schema helpers for class-based plugins.

The plugin SDK intentionally supports only a small JSON-Schema-like subset.
Schemas describe top-level keyword arguments; they are metadata, not code, and
reference formats remain opaque strings at this boundary.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

INPUT_SCHEMA_TYPES = frozenset(
    {
        "array",
        "boolean",
        "integer",
        "number",
        "object",
        "string",
    }
)
INPUT_SCHEMA_STRING_FORMATS = frozenset(
    {
        "artifact-ref",
        "credential-ref",
        "path-ref",
    }
)

_ROOT_KEYWORDS = frozenset({"additionalProperties", "properties", "required", "type"})
_PROPERTY_KEYWORDS = frozenset({"description", "format", "type"})
_PROPERTY_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


def _unsupported_keywords(value: dict[Any, Any], allowed: frozenset[str]) -> list[str]:
    return sorted(str(key) for key in value if not isinstance(key, str) or key not in allowed)


def empty_input_schema() -> dict[str, Any]:
    """Return a new closed schema that accepts no provider parameters."""

    return {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }


def normalize_input_schema(value: Any) -> dict[str, Any]:
    """Validate and copy the supported input-schema subset.

    The returned dictionary contains only JSON values. Unsupported keywords
    fail closed instead of being silently ignored and acquiring different
    semantics in a future validator.
    """

    if not isinstance(value, dict):
        raise ValueError("plugin metadata field 'input_schema' must be an object")

    unknown_root = _unsupported_keywords(value, _ROOT_KEYWORDS)
    if unknown_root:
        raise ValueError(f"plugin metadata field 'input_schema' contains unsupported keyword '{unknown_root[0]}'")
    missing_root = sorted(_ROOT_KEYWORDS - set(value))
    if missing_root:
        raise ValueError(f"plugin metadata field 'input_schema' is missing keyword '{missing_root[0]}'")
    if value.get("type") != "object":
        raise ValueError("plugin metadata field 'input_schema.type' must be 'object'")
    if value.get("additionalProperties") is not False:
        raise ValueError("plugin metadata field 'input_schema.additionalProperties' must be false")

    raw_properties = value.get("properties")
    if not isinstance(raw_properties, dict):
        raise ValueError("plugin metadata field 'input_schema.properties' must be an object")
    properties: dict[str, dict[str, Any]] = {}
    for name, raw_property in raw_properties.items():
        if not isinstance(name, str) or _PROPERTY_NAME.fullmatch(name) is None:
            raise ValueError("plugin input schema contains an invalid property name")
        if name in {"action", "target", "timeout"}:
            raise ValueError(f"plugin input schema property '{name}' is reserved")
        if not isinstance(raw_property, dict):
            raise ValueError(f"plugin input schema property '{name}' must be an object")
        unknown_property = _unsupported_keywords(raw_property, _PROPERTY_KEYWORDS)
        if unknown_property:
            raise ValueError(
                f"plugin input schema property '{name}' contains unsupported keyword '{unknown_property[0]}'"
            )
        declared_type = raw_property.get("type")
        if not isinstance(declared_type, str) or declared_type not in INPUT_SCHEMA_TYPES:
            raise ValueError(f"plugin input schema property '{name}' has unsupported type '{declared_type}'")
        normalized_property: dict[str, Any] = {"type": declared_type}
        if "description" in raw_property:
            description = raw_property["description"]
            if not isinstance(description, str):
                raise ValueError(f"plugin input schema property '{name}' description must be a string")
            normalized_property["description"] = description
        if "format" in raw_property:
            declared_format = raw_property["format"]
            if (
                declared_type != "string"
                or not isinstance(declared_format, str)
                or declared_format not in INPUT_SCHEMA_STRING_FORMATS
            ):
                raise ValueError(f"plugin input schema property '{name}' has unsupported format '{declared_format}'")
            normalized_property["format"] = declared_format
        properties[name] = normalized_property

    raw_required = value.get("required")
    if not isinstance(raw_required, list) or not all(isinstance(item, str) for item in raw_required):
        raise ValueError("plugin metadata field 'input_schema.required' must be a list of strings")
    if len(raw_required) != len(set(raw_required)):
        raise ValueError("plugin metadata field 'input_schema.required' must not contain duplicates")
    unknown_required = sorted(set(raw_required) - set(properties))
    if unknown_required:
        raise ValueError(
            f"plugin metadata field 'input_schema.required' contains undeclared property '{unknown_required[0]}'"
        )

    normalized = {
        "type": "object",
        "properties": properties,
        "required": list(raw_required),
        "additionalProperties": False,
    }
    try:
        json.dumps(normalized, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:  # pragma: no cover - defensive after shape checks
        raise ValueError("plugin metadata field 'input_schema' must be JSON-serializable") from exc
    return normalized


def _matches_type(value: Any, declared_type: str) -> bool:
    if declared_type == "string":
        return isinstance(value, str)
    if declared_type == "boolean":
        return isinstance(value, bool)
    if declared_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared_type == "number":
        if isinstance(value, int) and not isinstance(value, bool):
            return True
        return isinstance(value, float) and math.isfinite(value)
    if declared_type == "object":
        return isinstance(value, dict)
    if declared_type == "array":
        return isinstance(value, list)
    return False


def _is_strict_json_value(value: Any) -> bool:
    if value is None or isinstance(value, (bool, int, str)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_strict_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_strict_json_value(item) for key, item in value.items())
    return False


def validate_input_parameters(schema: dict[str, Any], parameters: dict[str, Any]) -> None:
    """Validate provider keyword arguments against one normalized schema.

    String reference formats are intentionally type-only here. Resolving or
    dereferencing them belongs to a separately authorized provider boundary.
    """

    properties = schema["properties"]
    undeclared = sorted(str(name) for name in parameters if not isinstance(name, str) or name not in properties)
    if undeclared:
        # Keep the established reason code while the closed schema replaces
        # the historical blanket denial behind it.
        raise ValueError(f"plugin_network_parameter_undeclared:{undeclared[0]}")
    missing = [name for name in schema["required"] if name not in parameters]
    if missing:
        raise ValueError(f"plugin_input_missing:{missing[0]}")
    for name, value in parameters.items():
        declared_type = properties[name]["type"]
        if not _matches_type(value, declared_type):
            raise ValueError(f"plugin_input_wrong_type:{name}:expected_{declared_type}")
        try:
            json.dumps(value, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError(f"plugin_input_not_json:{name}") from exc
        try:
            strict_json = _is_strict_json_value(value)
        except RecursionError:
            strict_json = False
        if not strict_json:
            raise ValueError(f"plugin_input_not_json:{name}")


__all__ = [
    "INPUT_SCHEMA_STRING_FORMATS",
    "INPUT_SCHEMA_TYPES",
    "empty_input_schema",
    "normalize_input_schema",
    "validate_input_parameters",
]
