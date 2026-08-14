"""Tests for TypedInputDecoderRegistry skeleton."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

from core.actions.typed_input_decoders import (
    TypedInputDecoderNotRegistered,
    get_typed_input_decoder_registry,
)


def test_typed_input_decoder_registry_unknown_action_denied() -> None:
    registry = get_typed_input_decoder_registry()
    with pytest.raises(TypedInputDecoderNotRegistered):
        registry.require_decoder("plugin:non_existent_action", "octopus:input:non_existent:2.0")
