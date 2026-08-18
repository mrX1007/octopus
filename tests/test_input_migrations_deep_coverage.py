"""Unit tests for input_migrations.py."""

from __future__ import annotations

import pytest

from core.actions.input_migrations import (
    LegacyInputMigrationRequiredV2,
    V1ToV2InputMigrator,
    migrate_v1_to_v2,
)

pytestmark = pytest.mark.unit


def test_input_migrations_errors_and_helpers():
    # LegacyInputMigrationRequiredV2 errors
    with pytest.raises(ValueError, match="action_id must be a non-empty string"):
        LegacyInputMigrationRequiredV2(
            action_id="",
            disposition="migration_required",
            reason_code="explicit_action_migration_required",
            legacy_field_names=(),
        )

    with pytest.raises(ValueError, match="legacy migration disposition must fail closed"):
        LegacyInputMigrationRequiredV2(
            action_id="act-1",
            disposition="other",  # type: ignore
            reason_code="explicit_action_migration_required",
            legacy_field_names=(),
        )

    with pytest.raises(ValueError, match="legacy migration reason is not canonical"):
        LegacyInputMigrationRequiredV2(
            action_id="act-1",
            disposition="migration_required",
            reason_code="other",  # type: ignore
            legacy_field_names=(),
        )

    with pytest.raises(ValueError, match="legacy field names must be non-empty strings"):
        LegacyInputMigrationRequiredV2(
            action_id="act-1",
            disposition="migration_required",
            reason_code="explicit_action_migration_required",
            legacy_field_names=("",),
        )

    with pytest.raises(ValueError, match="legacy field names must be unique and sorted"):
        LegacyInputMigrationRequiredV2(
            action_id="act-1",
            disposition="migration_required",
            reason_code="explicit_action_migration_required",
            legacy_field_names=("b", "a"),
        )

    # V1ToV2InputMigrator errors
    migrator = V1ToV2InputMigrator()
    with pytest.raises(ValueError, match="action_id must be a non-empty string"):
        migrator.migrate(action_id="", v1_payload={})

    with pytest.raises(TypeError, match="v1_payload must be a mapping"):
        migrator.migrate(action_id="act-1", v1_payload="not_a_map")  # type: ignore

    with pytest.raises(ValueError, match="legacy input field names must be non-empty strings"):
        migrator.migrate(action_id="act-1", v1_payload={"": "val"})

    # migrate_batch and top level function
    res_batch = migrator.migrate_batch(action_id="act-1", v1_payloads=[{"a": 1}, {"b": 2}])
    assert len(res_batch) == 2

    res_single = migrate_v1_to_v2(action_id="act-1", v1_payload={"k": "v"})
    assert res_single.legacy_field_names == ("k",)
