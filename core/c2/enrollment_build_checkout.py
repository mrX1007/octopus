"""Enrollment build checkout."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EnrollmentBuildReservationV1:
    reservation_id: str
    mission_id: str
    subject_id: str
    target_os: str
    target_arch: str
    expires_at: float
    status: str = "reserved"


class EnrollmentBuildCheckoutServiceV1:
    """Service managing build reservations and build material checkouts."""

    def __init__(self) -> None:
        self._reservations: dict[str, EnrollmentBuildReservationV1] = {}

    def reserve_build(
        self,
        mission_id: str,
        subject_id: str,
        target_os: str = "linux",
        target_arch: str = "amd64",
        ttl_seconds: float = 300.0,
    ) -> EnrollmentBuildReservationV1:
        """Create a new enrollment build reservation."""
        res_id = f"res_build_{uuid.uuid4().hex[:8]}"
        reservation = EnrollmentBuildReservationV1(
            reservation_id=res_id,
            mission_id=mission_id,
            subject_id=subject_id,
            target_os=target_os,
            target_arch=target_arch,
            expires_at=time.time() + ttl_seconds,
            status="reserved",
        )
        self._reservations[res_id] = reservation
        return reservation

    def checkout_build_material(self, reservation_id: str) -> dict[str, Any]:
        """Checkout build materials for a valid reservation."""
        res = self._reservations.get(reservation_id)
        if res is None:
            raise KeyError(f"Build reservation '{reservation_id}' not found")

        if time.time() >= res.expires_at:
            raise ValueError(f"Build reservation '{reservation_id}' has expired")

        if res.status != "reserved":
            raise ValueError(f"Build reservation '{reservation_id}' is in status '{res.status}'")

        # Transition status to checked_out
        updated = EnrollmentBuildReservationV1(
            reservation_id=res.reservation_id,
            mission_id=res.mission_id,
            subject_id=res.subject_id,
            target_os=res.target_os,
            target_arch=res.target_arch,
            expires_at=res.expires_at,
            status="checked_out",
        )
        self._reservations[reservation_id] = updated

        return {
            "reservation_id": reservation_id,
            "mission_id": res.mission_id,
            "target_os": res.target_os,
            "target_arch": res.target_arch,
            "build_token": f"token_{uuid.uuid4().hex[:12]}",
        }

    def release_reservation(self, reservation_id: str) -> bool:
        """Release/cancel a build reservation."""
        res = self._reservations.get(reservation_id)
        if res is None:
            return False
        del self._reservations[reservation_id]
        return True

    def query_reservation(self, reservation_id: str) -> EnrollmentBuildReservationV1 | None:
        """Query reservation details."""
        return self._reservations.get(reservation_id)
