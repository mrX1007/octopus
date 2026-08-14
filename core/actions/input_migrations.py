"""Explicit, fail-closed inventory for legacy action-input migration.

The V2 input surface is a closed union. A generic key-renaming helper cannot
prove which union member a legacy mapping represents, so it must never create
a V2 payload. Reviewed, action-specific migrations can be added as separate
adapters in the PR that defines and tests the complete semantic mapping.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class LegacyInputMigrationRequiredV2:
    action_id: str
    disposition: Literal["migration_required"]
    reason_code: Literal["explicit_action_migration_required"]
    legacy_field_names: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.action_id) is not str or not self.action_id:
            raise ValueError("action_id must be a non-empty string")
        if self.disposition != "migration_required":
            raise ValueError("legacy migration disposition must fail closed")
        if self.reason_code != "explicit_action_migration_required":
            raise ValueError("legacy migration reason is not canonical")
        if type(self.legacy_field_names) is not tuple or any(
            type(name) is not str or not name for name in self.legacy_field_names
        ):
            raise ValueError("legacy field names must be non-empty strings")
        if self.legacy_field_names != tuple(sorted(set(self.legacy_field_names))):
            raise ValueError("legacy field names must be unique and sorted")


class V1ToV2InputMigrator:
    """Reports that an explicit per-action migration is required."""

    def migrate(
        self,
        *,
        action_id: str,
        v1_payload: Mapping[str, object],
    ) -> LegacyInputMigrationRequiredV2:
        if type(action_id) is not str or not action_id:
            raise ValueError("action_id must be a non-empty string")
        if not isinstance(v1_payload, Mapping):
            raise TypeError("v1_payload must be a mapping")
        if any(type(name) is not str or not name for name in v1_payload):
            raise ValueError("legacy input field names must be non-empty strings")
        return LegacyInputMigrationRequiredV2(
            action_id=action_id,
            disposition="migration_required",
            reason_code="explicit_action_migration_required",
            legacy_field_names=tuple(sorted(v1_payload)),
        )

    def migrate_batch(
        self,
        *,
        action_id: str,
        v1_payloads: Sequence[Mapping[str, object]],
    ) -> tuple[LegacyInputMigrationRequiredV2, ...]:
        return tuple(self.migrate(action_id=action_id, v1_payload=payload) for payload in v1_payloads)


def migrate_v1_to_v2(
    *,
    action_id: str,
    v1_payload: Mapping[str, object],
) -> LegacyInputMigrationRequiredV2:
    """Return a non-authoritative migration inventory result."""

    return V1ToV2InputMigrator().migrate(
        action_id=action_id,
        v1_payload=v1_payload,
    )


__all__ = [
    "LegacyInputMigrationRequiredV2",
    "V1ToV2InputMigrator",
    "migrate_v1_to_v2",
]
