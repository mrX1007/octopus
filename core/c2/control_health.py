"""Dedicated read-only health and readiness protocol for C2 Control Plane (§14.2, §14.6)."""

from __future__ import annotations

import json
import os
import stat
import time
import uuid
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import ed25519

from core.c2.control_models import (
    calculate_health_signature_digest,
    canonical_json_bytes,
    strict_b64url_decode,
    strict_decode_signature_v2,
)
from core.c2.control_protocol import (
    strict_json_loads,
)
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
class HealthTrustDescriptor:
    version: str  # "2.0"
    service_id: str
    key_id: str
    public_key: bytes  # exactly 32 bytes
    valid_from_ms: int
    valid_until_ms: int
    revoked: bool = False
    predecessor_id: str | None = None

    def __post_init__(self) -> None:
        if self.version != "2.0":
            raise ValueError("version must be '2.0'")
        if type(self.service_id) is not str or not self.service_id:
            raise ValueError("service_id must be non-empty str")
        if type(self.key_id) is not str or not self.key_id:
            raise ValueError("key_id must be non-empty str")
        if type(self.public_key) is not bytes or len(self.public_key) != 32:
            raise ValueError("public_key must be exactly 32 bytes")
        if type(self.valid_from_ms) is not int or isinstance(self.valid_from_ms, bool):
            raise ValueError("valid_from_ms must be int")
        if type(self.valid_until_ms) is not int or isinstance(self.valid_until_ms, bool):
            raise ValueError("valid_until_ms must be int")
        if self.valid_until_ms <= self.valid_from_ms:
            raise ValueError("valid_until_ms must be greater than valid_from_ms")
        if type(self.revoked) is not bool:
            raise ValueError("revoked must be bool")


@dataclass(frozen=True)
class VerifiedHealthStatusV2:
    reachable: bool
    protocol_version: str
    service_id: str
    boot_instance_id: str
    daemon_generation: str
    database_ready: bool
    key_store_ready: bool
    reason_code: str = "ok"


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


def load_health_trust_descriptor(file_path: str | None = None) -> HealthTrustDescriptor:
    """Load and validate an independently provisioned health trust descriptor from disk."""
    path = file_path or os.environ.get("OCTOPUS_C2_HEALTH_TRUST_FILE")
    if not path:
        raise ValueError("health_trust_file_not_specified")
    if os.path.islink(path):
        raise RuntimeError(f"symlink forbidden for health trust descriptor: {path}")
    if not os.path.exists(path):
        raise FileNotFoundError(f"health trust descriptor not found: {path}")

    st = os.stat(path)
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"health trust descriptor must be a regular file: {path}")
    if st.st_mode & 0o022 != 0:
        raise RuntimeError(f"insecure health trust descriptor permissions: {oct(st.st_mode)}")
    if st.st_size > 16384:
        raise RuntimeError("health trust descriptor exceeds size limit")

    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise RuntimeError("health trust descriptor must be a JSON object")

    raw_pub = data.get("public_key") or data.get("public_key_b64u") or data.get("public_key_hex")
    if isinstance(raw_pub, str):
        if len(raw_pub) == 64:
            pub_bytes = bytes.fromhex(raw_pub)
        else:
            pub_bytes = strict_b64url_decode(raw_pub)
    elif isinstance(raw_pub, (bytes, bytearray)):
        pub_bytes = bytes(raw_pub)
    else:
        raise RuntimeError("invalid public_key in health trust descriptor")

    return HealthTrustDescriptor(
        version=str(data.get("version", "2.0")),
        service_id=str(data.get("service_id", "")),
        key_id=str(data.get("key_id", "")),
        public_key=pub_bytes,
        valid_from_ms=int(data.get("valid_from_ms", 0)),
        valid_until_ms=int(data.get("valid_until_ms", 253402300799000)),
        revoked=bool(data.get("revoked", False)),
        predecessor_id=data.get("predecessor_id"),
    )


def query_health_status(
    sock_path: str,
    trusted_public_key: bytes | None = None,
    expected_service_id: str | None = None,
    trust_descriptor: HealthTrustDescriptor | Any | None = None,
    timeout_seconds: float = 5.0,
) -> VerifiedHealthStatusV2:
    """Execute dedicated health probe over Unix domain socket with kernel peer credentials."""
    resolved_pub: bytes | None = trusted_public_key
    resolved_srv: str | None = expected_service_id

    if trust_descriptor is not None:
        if isinstance(trust_descriptor, HealthTrustDescriptor):
            resolved_pub = trust_descriptor.public_key
            resolved_srv = trust_descriptor.service_id
            now_ms = int(time.time() * 1000)
            if trust_descriptor.revoked:
                return VerifiedHealthStatusV2(
                    reachable=False,
                    protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                    service_id="",
                    boot_instance_id="",
                    daemon_generation="unverified",
                    database_ready=False,
                    key_store_ready=False,
                    reason_code="trust_descriptor_revoked",
                )
            if now_ms < trust_descriptor.valid_from_ms or now_ms > trust_descriptor.valid_until_ms:
                return VerifiedHealthStatusV2(
                    reachable=False,
                    protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                    service_id="",
                    boot_instance_id="",
                    daemon_generation="unverified",
                    database_ready=False,
                    key_store_ready=False,
                    reason_code="trust_descriptor_expired",
                )
        elif hasattr(trust_descriptor, "public_key") and hasattr(trust_descriptor, "service_id"):
            resolved_pub = getattr(trust_descriptor, "public_key")
            resolved_srv = getattr(trust_descriptor, "service_id")

    if resolved_pub is None or resolved_srv is None:
        try:
            desc = load_health_trust_descriptor()
            resolved_pub = desc.public_key
            resolved_srv = desc.service_id
        except Exception as exc:
            return VerifiedHealthStatusV2(
                reachable=False,
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                service_id="",
                boot_instance_id="",
                daemon_generation="unverified",
                database_ready=False,
                key_store_ready=False,
                reason_code=f"missing_trust_configuration:{exc}",
            )

    if resolved_pub is None or len(resolved_pub) != 32:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
            reason_code="invalid_trusted_public_key",
        )
    if not resolved_srv:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
            reason_code="empty_expected_service_id",
        )

    if not os.path.exists(sock_path):
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
            reason_code="socket_not_found",
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

    try:
        from core.c2.client import send_c2_socket_frame

        frame = len(req_bytes).to_bytes(4, byteorder="big") + req_bytes
        resp_frame = send_c2_socket_frame(sock_path, frame, timeout_seconds=timeout_seconds)
        resp_dict = strict_json_loads(resp_frame)
    except Exception as exc:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
            reason_code=f"transport_error:{exc}",
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

        if service_id != resolved_srv:
            return VerifiedHealthStatusV2(
                reachable=False,
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                service_id=service_id,
                boot_instance_id=boot_instance_id,
                daemon_generation=daemon_gen,
                database_ready=False,
                key_store_ready=False,
                reason_code="service_id_mismatch",
            )
        if probe_nonce != probe_req.nonce:
            return VerifiedHealthStatusV2(
                reachable=False,
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                service_id=service_id,
                boot_instance_id=boot_instance_id,
                daemon_generation=daemon_gen,
                database_ready=False,
                key_store_ready=False,
                reason_code="nonce_mismatch",
            )
        now_ms = int(time.time() * 1000)
        if abs(now_ms - issued_ms) > 5000:
            return VerifiedHealthStatusV2(
                reachable=False,
                protocol_version=C2_CONTROL_PROTOCOL_VERSION,
                service_id=service_id,
                boot_instance_id=boot_instance_id,
                daemon_generation=daemon_gen,
                database_ready=False,
                key_store_ready=False,
                reason_code="response_stale",
            )

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
        sig_bytes = strict_decode_signature_v2(sig_str)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(resolved_pub)
        pub_key.verify(sig_bytes, transcript)

        return VerifiedHealthStatusV2(
            reachable=True,
            protocol_version="2.0",
            service_id=service_id,
            boot_instance_id=boot_instance_id,
            daemon_generation=daemon_gen,
            database_ready=db_ready,
            key_store_ready=ks_ready,
            reason_code="ok",
        )
    except Exception as exc:
        return VerifiedHealthStatusV2(
            reachable=False,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
            service_id="",
            boot_instance_id="",
            daemon_generation="unverified",
            database_ready=False,
            key_store_ready=False,
            reason_code=f"verification_failed:{exc}",
        )


__all__ = [
    "HealthRequestV2",
    "HealthTrustDescriptor",
    "SignedHealthResponseV2",
    "VerifiedHealthStatusV2",
    "load_health_trust_descriptor",
    "query_health_status",
]
