"""Server-observed Unix peer identity."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PeerPrincipal:
    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        for name, value in (("pid", self.pid), ("uid", self.uid), ("gid", self.gid)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"peer {name} must be a non-negative integer")
