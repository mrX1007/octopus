"""Fail-closed legacy-to-V2 input migration contracts."""

from __future__ import annotations

from dataclasses import fields

import pytest

from core.actions.input_migrations import (
    LegacyInputMigrationRequiredV2,
    V1ToV2InputMigrator,
    migrate_v1_to_v2,
)

pytestmark = pytest.mark.unit


def test_legacy_input_requires_explicit_migration() -> None:
    result = migrate_v1_to_v2(
        action_id="killchain:ad_smbexec",
        v1_payload={"target_host": "192.0.2.10"},
    )
    assert result == LegacyInputMigrationRequiredV2(
        action_id="killchain:ad_smbexec",
        disposition="migration_required",
        reason_code="explicit_action_migration_required",
        legacy_field_names=("target_host",),
    )
    assert tuple(field.name for field in fields(result)) == (
        "action_id",
        "disposition",
        "reason_code",
        "legacy_field_names",
    )


def test_legacy_raw_command_not_auto_migrated() -> None:
    result = V1ToV2InputMigrator().migrate(
        action_id="c2:c2_task",
        v1_payload={"command": "legacy opaque value", "agent_ref": "legacy-agent"},
    )
    assert result.disposition == "migration_required"
    assert result.legacy_field_names == ("agent_ref", "command")
    assert not hasattr(result, "typed_input")


def test_raw_command_cannot_populate_typed_fields() -> None:
    result = migrate_v1_to_v2(
        action_id="killchain:ad_winrm_exec",
        v1_payload={
            "command": "legacy opaque value",
            "host": "192.0.2.20",
            "params": {"operation_id": "operation://identity"},
        },
    )
    assert result.disposition == "migration_required"
    assert not hasattr(result, "target")
    assert not hasattr(result, "parameters")
    assert not hasattr(result, "operation_id")
