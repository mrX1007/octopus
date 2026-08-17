"""Dedicated read-only health and readiness protocol for C2 Control Plane (§14.2, §14.6)."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_models import (
    calculate_health_signature_digest,
    canonical_json_bytes,
)
from core.c2.control_protocol import (
    strict_json_loads,
)
from core.c2.control_signing import _decode_sig_bytes
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION


@dataclass(frozen=True)
class HealthRequestV2:
    protocol_version: Literal["2.0"] = "2.0"
    probe_id: str = "health_probe"
    nonce: str = ""
    timestamp_ms: int = 0

    def __post_init__(self) -> None:
        if not self.nonce:
            object.__setattr__(self, "nonce", uuid.uuid4().hex)
        if not self.timestamp_ms:
            object.__setattr__(self, "timestamp_ms", int(time.time() * 1000))


@dataclass(frozen=True)
class VerifiedHealthStatusV2:
    reachable: bool
    protocol_version: str
    service_id: str
    boot_instance_id: str
    daemon_generation: str
    database_ready: bool
    key_store_ready: bool


@dataclass(frozen=True)
class SignedHealthResponseV2:
    protocol_version: Literal["2.0"]
    service_id: str
    boot_instance_id: str
    daemon_generation: str
    probe_nonce: str
    database_ready: bool
    key_store_ready: bool
    issued_at_ms: int
    key_id: str
    signature: str


def query_health_status(
    sock_path: str,
    trusted_public_key: bytes | None = None,
    expected_service_id: str | None = None,
    timeout_seconds: float = 5.0,
) -> VerifiedHealthStatusV2:
    """Execute dedicated health probe over Unix domain socket with kernel peer credentials."""
    if not os.path.exists(sock_path):
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
        )

    probe_req = HealthRequestV2()
    req_dict = {
        "nonce": probe_req.nonce,
        "probe_id": probe_req.probe_id,
        "protocol_version": probe_req.protocol_version,
        "timestamp_ms": probe_req.timestamp_ms,
        "type": "health_request_v2",
    }
    req_bytes = canonical_json_bytes(req_dict)
    # Send frame
    try:
        from core.c2.client import send_c2_socket_frame

        frame = len(req_bytes).to_bytes(4, byteorder="big") + req_bytes
        resp_frame = send_c2_socket_frame(sock_path, frame, timeout_seconds=timeout_seconds)
        resp_dict = strict_json_loads(resp_frame)
    except Exception:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
        )

    # Validate response
    try:
        service_id = str(resp_dict.get("service_id", ""))
        boot_instance_id = str(resp_dict.get("boot_instance_id", ""))
        daemon_gen = str(resp_dict.get("daemon_generation", ""))
        probe_nonce = str(resp_dict.get("probe_nonce", ""))
        db_ready = bool(resp_dict.get("database_ready", False))
        ks_ready = bool(resp_dict.get("key_store_ready", False))
        issued_ms = int(resp_dict.get("issued_at_ms", 0))
        key_id = str(resp_dict.get("key_id", ""))
        sig_str = str(resp_dict.get("signature", ""))

        if expected_service_id and service_id != expected_service_id:
            raise ValueError("service_id_mismatch")
        if probe_nonce != probe_req.nonce:
            raise ValueError("nonce_mismatch")
        now_ms = int(time.time() * 1000)
        if abs(now_ms - issued_ms) > 5000:
            raise ValueError("response_stale")

        if trusted_public_key is not None and len(trusted_public_key) == 32:
            body_dict = {
                "boot_instance_id": boot_instance_id,
                "daemon_generation": daemon_gen,
                "database_ready": db_ready,
                "issued_at_ms": issued_ms,
                "key_id": key_id,
                "key_store_ready": ks_ready,
                "probe_nonce": probe_nonce,
                "protocol_version": "2.0",
                "service_id": service_id,
            }
            transcript = calculate_health_signature_digest(body_dict)
            sig_bytes = _decode_sig_bytes(sig_str)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(trusted_public_key)
            pub_key.verify(sig_bytes, transcript)

        return VerifiedHealthStatusV2(
            reachable=True,
            protocol_version="2.0",
            service_id=service_id,
            boot_instance_id=boot_instance_id,
            daemon_generation=daemon_gen,
            database_ready=db_ready,
            key_store_ready=ks_ready,
        )
    except Exception:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
        )


__all__ = [
    "HealthRequestV2",
    "SignedHealthResponseV2",
    "VerifiedHealthStatusV2",
    "query_health_status",
]
