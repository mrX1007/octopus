"""Unit tests for core/plugins/schema.py."""

from __future__ import annotations

import math
import pytest

from core.plugins.schema import (
    INPUT_SCHEMA_STRING_FORMATS,
    INPUT_SCHEMA_TYPES,
    empty_input_schema,
    normalize_input_schema,
    validate_input_parameters,
)

pytestmark = pytest.mark.unit


def test_empty_input_schema():
    s = empty_input_schema()
    assert s == {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    }


def test_normalize_input_schema_valid():
    valid = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "target name"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "is_admin": {"type": "boolean"},
            "meta": {"type": "object"},
            "items": {"type": "array"},
            "cred": {"type": "string", "format": "credential-ref"},
        },
        "required": ["name", "cred"],
        "additionalProperties": False,
    }
    norm = normalize_input_schema(valid)
    assert norm["type"] == "object"
    assert "name" in norm["properties"]
    assert norm["properties"]["name"]["description"] == "target name"
    assert norm["properties"]["cred"]["format"] == "credential-ref"


def test_normalize_input_schema_invalid():
    # Not a dict
    with pytest.raises(ValueError, match="must be an object"):
        normalize_input_schema(None)

    # Missing root keyword
    with pytest.raises(ValueError, match="missing keyword"):
        normalize_input_schema({"type": "object"})

    # Unknown keyword
    with pytest.raises(ValueError, match="unsupported keyword"):
        normalize_input_schema(
            {"type": "object", "properties": {}, "required": [], "additionalProperties": False, "unknown": True}
        )

    # Type not object
    with pytest.raises(ValueError, match="must be 'object'"):
        normalize_input_schema({"type": "string", "properties": {}, "required": [], "additionalProperties": False})

    # additionalProperties not False
    with pytest.raises(ValueError, match="additionalProperties"):
        normalize_input_schema({"type": "object", "properties": {}, "required": [], "additionalProperties": True})

    # properties not a dict
    with pytest.raises(ValueError, match="input_schema.properties"):
        normalize_input_schema(
            {"type": "object", "properties": "not a dict", "required": [], "additionalProperties": False}
        )

    # invalid property name
    with pytest.raises(ValueError, match="invalid property name"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"bad-name!": {"type": "string"}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # reserved property name
    with pytest.raises(ValueError, match="reserved"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"target": {"type": "string"}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # property not a dict
    with pytest.raises(ValueError, match="must be an object"):
        normalize_input_schema(
            {"type": "object", "properties": {"prop": "string"}, "required": [], "additionalProperties": False}
        )

    # property with unsupported keyword
    with pytest.raises(ValueError, match="unsupported keyword"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string", "extra": 1}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # property with unsupported type
    with pytest.raises(ValueError, match="unsupported type"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "unknown_type"}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # description not a string
    with pytest.raises(ValueError, match="description must be a string"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string", "description": 123}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # unsupported format
    with pytest.raises(ValueError, match="unsupported format"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string", "format": "invalid_format"}},
                "required": [],
                "additionalProperties": False,
            }
        )

    # required not list of strings
    with pytest.raises(ValueError, match="must be a list of strings"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string"}},
                "required": "prop",
                "additionalProperties": False,
            }
        )

    # required duplicates
    with pytest.raises(ValueError, match="duplicates"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string"}},
                "required": ["prop", "prop"],
                "additionalProperties": False,
            }
        )

    # required undeclared
    with pytest.raises(ValueError, match="undeclared property"):
        normalize_input_schema(
            {
                "type": "object",
                "properties": {"prop": {"type": "string"}},
                "required": ["undeclared"],
                "additionalProperties": False,
            }
        )


def test_validate_input_parameters():
    schema = normalize_input_schema(
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "score": {"type": "number"},
                "active": {"type": "boolean"},
                "data": {"type": "object"},
                "tags": {"type": "array"},
            },
            "required": ["name"],
            "additionalProperties": False,
        }
    )

    # Valid
    validate_input_parameters(
        schema,
        {
            "name": "octopus",
            "count": 5,
            "score": 4.5,
            "active": True,
            "data": {"key": "val"},
            "tags": ["a", "b"],
        },
    )

    # Int as number
    validate_input_parameters(schema, {"name": "test", "score": 10})

    # Undeclared parameter
    with pytest.raises(ValueError, match="plugin_network_parameter_undeclared"):
        validate_input_parameters(schema, {"name": "test", "extra": 1})

    # Missing required
    with pytest.raises(ValueError, match="plugin_input_missing"):
        validate_input_parameters(schema, {})

    # Wrong type (e.g. bool for integer)
    with pytest.raises(ValueError, match="plugin_input_wrong_type:count:expected_integer"):
        validate_input_parameters(schema, {"name": "test", "count": True})

    # Infinite float
    with pytest.raises(ValueError, match="plugin_input_wrong_type:score:expected_number"):
        validate_input_parameters(schema, {"name": "test", "score": float("inf")})
