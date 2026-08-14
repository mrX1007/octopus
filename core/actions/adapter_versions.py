"""Adapter API versioning definitions."""

from __future__ import annotations

from enum import IntEnum


class AdapterApiVersion(IntEnum):
    V1 = 1
    V2 = 2


__all__ = [
    "AdapterApiVersion",
]
