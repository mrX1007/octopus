"""Tests for V2ActionSemanticBinding matrix (§2.5)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from core.actions.models import CheckPolicyV2, VerifyPolicyV2
from core.actions.semantic_bindings import (
    get_all_v2_semantic_bindings,
    get_v2_semantic_binding,
    resolve_action_id_alias,
)


def test_v2_semantic_binding_matrix_has_exact_20_rows() -> None:
    bindings = get_all_v2_semantic_bindings()
    assert len(bindings) == 20
    for binding in bindings:
        assert binding.manual_gate is True
        assert binding.check_policy == CheckPolicyV2.REQUIRED
        assert binding.verify_policy == VerifyPolicyV2.REQUIRED


def test_alias_resolution() -> None:
    assert resolve_action_id_alias("pth") == "killchain:pass_the_hash"
    binding = get_v2_semantic_binding("pth")
    assert binding.action_id == "killchain:pass_the_hash"
