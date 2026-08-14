"""Tests for V2ActionSchemaBinding matrix (§2.4)."""

from __future__ import annotations

import pytest

from core.actions.schema_bindings import get_all_v2_schema_bindings, get_v2_schema_binding

pytestmark = pytest.mark.unit


def test_v2_schema_binding_matrix_has_exact_20_rows() -> None:
    bindings = get_all_v2_schema_bindings()
    assert len(bindings) == 20
    action_ids = set()
    for binding in bindings:
        assert binding.action_id not in action_ids
        action_ids.add(binding.action_id)
        assert binding.input_schema_id.startswith("octopus:input:")
        assert binding.result_schema_id.startswith("octopus:result:")


def test_v2_schema_binding_ids_match_normative_table() -> None:
    binding = get_v2_schema_binding("c2:c2_deploy")
    assert binding.input_schema_id == "octopus:input:c2_deploy:3.0"
    assert binding.result_schema_id == "octopus:result:c2_deploy:2.0"

    with pytest.raises(KeyError):
        get_v2_schema_binding("non_existent_action")
