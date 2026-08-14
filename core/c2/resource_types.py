"""Closed resource vocabulary for typed C2 actions."""

from __future__ import annotations

from enum import Enum


class C2CleanupReason(str, Enum):
    OPERATOR_REQUEST = "operator-request"
    MISSION_TEARDOWN = "mission-teardown"
    EXPIRED = "expired"
    RECONCILIATION = "reconciliation"


__all__ = ["C2CleanupReason"]
