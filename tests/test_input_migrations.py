"""Additional validation for fail-closed legacy input inventory."""

from __future__ import annotations

import pytest

from core.actions.input_migrations import V1ToV2InputMigrator

pytestmark = pytest.mark.unit


def test_migration_batch_preserves_only_field_names() -> None:
    results = V1ToV2InputMigrator().migrate_batch(
        action_id="plugin:payload_keying",
        v1_payloads=(
            {"payload": object(), "parameters": {"secret": object()}},
            {"target_host": "192.0.2.1"},
        ),
    )
    assert tuple(result.legacy_field_names for result in results) == (
        ("parameters", "payload"),
        ("target_host",),
    )


@pytest.mark.parametrize("action_id", ("", 1, None))
def test_migration_rejects_invalid_action_id(action_id: object) -> None:
    with pytest.raises(ValueError, match="action_id"):
        V1ToV2InputMigrator().migrate(
            action_id=action_id,  # type: ignore[arg-type]
            v1_payload={},
        )


def test_migration_rejects_non_string_legacy_field_name() -> None:
    with pytest.raises(ValueError, match="field names"):
        V1ToV2InputMigrator().migrate(
            action_id="c2:c2_task",
            v1_payload={1: "value"},  # type: ignore[dict-item]
        )
