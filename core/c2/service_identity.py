"""Service identity."""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class C2ServiceIdentity:
    service_id: str
    domain: str
    socket_path: str
    fingerprint: str
    created_at: float

    def __post_init__(self) -> None:
        if not self.service_id:
            raise ValueError("service_id must not be empty")
        if not self.domain:
            raise ValueError("domain must not be empty")


def create_service_identity(domain: str = "c2.local", socket_path: str = "/run/octopus-c2.socket") -> C2ServiceIdentity:
    """Create a new C2ServiceIdentity instance."""
    s_id = f"srv_{uuid.uuid4().hex[:8]}"
    now = time.time()
    raw = f"{s_id}:{domain}:{socket_path}:{now}"
    fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return C2ServiceIdentity(
        service_id=s_id,
        domain=domain,
        socket_path=socket_path,
        fingerprint=fp,
        created_at=now,
    )


def verify_service_identity(identity: C2ServiceIdentity) -> bool:
    """Verify validity of C2ServiceIdentity."""
    if not identity.service_id or not identity.domain or not identity.socket_path:
        return False
    return len(identity.fingerprint) == 64

