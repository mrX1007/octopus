"""Immutable V2 action/target-schema binding projection.

Extraction itself is owned by :mod:`core.actions.target_extraction`; this
module exposes the schema inventory used by catalog and architecture gates.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.actions.target_extraction import get_action_target_extractor_registry


@dataclass(frozen=True)
class V2ActionTargetSchema:
    action_id: str
    input_schema_id: str
    input_type: type[object]


def get_all_v2_target_schemas() -> tuple[V2ActionTargetSchema, ...]:
    return tuple(
        V2ActionTargetSchema(action_id, input_schema_id, input_type)
        for action_id, input_schema_id, input_type in get_action_target_extractor_registry().bindings()
    )


def require_v2_target_schema(action_id: str, input_schema_id: str) -> V2ActionTargetSchema:
    matches = tuple(
        schema
        for schema in get_all_v2_target_schemas()
        if schema.action_id == action_id and schema.input_schema_id == input_schema_id
    )
    if len(matches) != 1:
        raise KeyError(f"no exact V2 target schema for {(action_id, input_schema_id)!r}")
    return matches[0]


__all__ = ["V2ActionTargetSchema", "get_all_v2_target_schemas", "require_v2_target_schema"]
