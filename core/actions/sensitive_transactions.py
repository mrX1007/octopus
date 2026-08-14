"""PR-5 Module: Sensitive staging transactions (§8.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SensitiveStagingTransactionV2:
    transaction_id: str
    staging_active: bool = True
    drafts: list[Any] = field(default_factory=list)

    def add_draft(self, draft: Any) -> None:
        if not self.staging_active:
            raise RuntimeError("staging_transaction_inactive")
        self.drafts.append(draft)

    def close(self) -> None:
        self.staging_active = False


__all__ = [
    "SensitiveStagingTransactionV2",
]
