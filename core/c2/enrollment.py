"""Authenticated, single-use enrollment tokens for the C2 control plane."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


class EnrollmentAuthority:
    """Issue and consume authenticated enrollment tokens.

    Only a token fingerprint is persisted by the database on consumption. The
    signing key remains in a permission-restricted local file and is never sent
    to an enrolling client.
    """

    VERSION = 1
    MAX_TTL_SECONDS = 24 * 60 * 60

    def __init__(self, key_path: os.PathLike[str] | str):
        self.key_path = Path(key_path)
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.key_path.parent, 0o700)

        if self.key_path.exists():
            key = self.key_path.read_bytes()
            if len(key) != 32:
                raise ValueError("invalid enrollment signing key")
            with contextlib.suppress(OSError):
                os.chmod(self.key_path, 0o600)
            return key

        key = secrets.token_bytes(32)
        try:
            descriptor = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._load_or_create_key()
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        return key

    def issue(self, ttl_seconds: int = 900, now: float | None = None) -> str:
        if not 0 < int(ttl_seconds) <= self.MAX_TTL_SECONDS:
            raise ValueError("enrollment token TTL is outside the allowed range")
        issued_at = int(time.time() if now is None else now)
        payload = {
            "exp": issued_at + int(ttl_seconds),
            "iat": issued_at,
            "jti": secrets.token_urlsafe(24),
            "v": self.VERSION,
        }
        encoded = _b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        signature = _b64encode(
            hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{encoded}.{signature}"

    def consume(self, token: str, database, now: float | None = None) -> bool:
        """Validate ``token`` and atomically mark it used in ``database``."""
        try:
            encoded, supplied_signature = token.split(".", 1)
            expected_signature = _b64encode(
                hmac.new(self._key, encoded.encode("ascii"), hashlib.sha256).digest()
            )
            if not hmac.compare_digest(supplied_signature, expected_signature):
                return False
            payload = json.loads(_b64decode(encoded))
            current = int(time.time() if now is None else now)
            issued_at = int(payload["iat"])
            expires_at = int(payload["exp"])
            token_id = str(payload["jti"])
            if payload.get("v") != self.VERSION:
                return False
            if issued_at > current + 30 or expires_at < current or expires_at <= issued_at:
                return False
            if expires_at - issued_at > self.MAX_TTL_SECONDS:
                return False
        except (AttributeError, TypeError, ValueError, KeyError, json.JSONDecodeError):
            return False

        fingerprint = hashlib.sha256(token_id.encode("utf-8")).hexdigest()
        return bool(database.consume_enrollment_token(fingerprint, expires_at, current))

