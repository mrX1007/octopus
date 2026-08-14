"""Dependency-free keyed-integrity metadata owned by PR-4."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class SensitiveIntegrityTagV2:
    """Keyed-integrity metadata; ``tag`` is never a plaintext hash."""

    key_id: str
    algorithm: Literal["hmac-sha256-v2"]
    domain: str
    tag: str

    def __post_init__(self) -> None:
        for field_name in ("key_id", "domain", "tag"):
            value = getattr(self, field_name)
            if type(value) is not str or not value:
                raise ValueError(f"sensitive_integrity_{field_name}_invalid")
        if self.algorithm != "hmac-sha256-v2":
            raise ValueError("sensitive_integrity_algorithm_invalid")


__all__ = ["SensitiveIntegrityTagV2"]
