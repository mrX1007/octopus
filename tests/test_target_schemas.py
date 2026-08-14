"""V2 target-schema inventory tests."""

from __future__ import annotations

import pytest

from core.actions.schema_bindings import get_all_v2_schema_bindings
from core.actions.target_schemas import get_all_v2_target_schemas, require_v2_target_schema

pytestmark = pytest.mark.unit


def test_each_v2_input_has_target_schema() -> None:
    target_schemas = get_all_v2_target_schemas()
    assert len(target_schemas) == 20
    assert {(item.action_id, item.input_schema_id) for item in target_schemas} == {
        (item.action_id, item.input_schema_id) for item in get_all_v2_schema_bindings()
    }


def test_unknown_action_schema_pair_fails_closed() -> None:
    with pytest.raises(KeyError):
        require_v2_target_schema("plugin:payload_keying", "octopus:input:wrong:2.0")


def test_target_schema_inventory_has_exact_runtime_types() -> None:
    for schema in get_all_v2_target_schemas():
        assert isinstance(schema.input_type, type)
        assert schema.input_type.__module__ == "core.actions.input_contracts"
