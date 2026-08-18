"""Test client helpers for wrapping keys and constructing verifiers."""

from __future__ import annotations

from core.c2.control_signing import (
    DaemonResponseVerifier,
    TrustedDaemonResponseKey,
)


def make_trusted_daemon_key(
    service_id: str = "srv_test",
    key_id: str = "daemon_resp_key_1",
    public_key: bytes = b"\x00" * 32,
    valid_from_ms: int = 0,
    valid_until_ms: int = 253402300799000,
    revoked: bool = False,
    predecessor_id: str | None = None,
) -> TrustedDaemonResponseKey:
    return TrustedDaemonResponseKey(
        service_id=service_id,
        key_id=key_id,
        public_key=bytes(public_key),
        valid_from_ms=valid_from_ms,
        valid_until_ms=valid_until_ms,
        revoked=revoked,
        predecessor_id=predecessor_id,
    )


def make_daemon_response_verifier(
    service_id: str = "srv_test",
    key_id: str = "daemon_resp_key_1",
    public_key: bytes = b"\x00" * 32,
    valid_from_ms: int = 0,
    valid_until_ms: int = 253402300799000,
) -> DaemonResponseVerifier:
    tk = make_trusted_daemon_key(
        service_id=service_id,
        key_id=key_id,
        public_key=public_key,
        valid_from_ms=valid_from_ms,
        valid_until_ms=valid_until_ms,
    )
    return DaemonResponseVerifier(trusted_keys={key_id: tk})
