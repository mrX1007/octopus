"""Control signing keyring and key rotation management (§14.5)."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SigningKeyMetadata:
    """Metadata describing a control signing key and its lifecycle."""

    key_id: str
    secret_key: bytes
    valid_from: float
    valid_until: float
    predecessor_id: str | None = None

    def is_valid(self, now: float | None = None) -> bool:
        ts = time.time() if now is None else now
        return self.valid_from <= ts < self.valid_until


class ControlSigningKeyring:
    """Keyring managing root-pinned and operational control signing keys."""

    def __init__(self) -> None:
        self._keys: dict[str, SigningKeyMetadata] = {}
        self._active_key_id: str | None = None

    def register_key(
        self,
        key_id: str,
        secret_key: bytes,
        valid_from: float = 0.0,
        valid_until: float = float("inf"),
        predecessor_id: str | None = None,
        make_active: bool = False,
    ) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        if valid_from >= valid_until:
            raise ValueError("valid_from must be strictly less than valid_until")

        meta = SigningKeyMetadata(
            key_id=key_id,
            secret_key=secret_key,
            valid_from=valid_from,
            valid_until=valid_until,
            predecessor_id=predecessor_id,
        )
        self._keys[key_id] = meta
        if make_active or self._active_key_id is None:
            self._active_key_id = key_id

    def get_key(self, key_id: str, now: float | None = None) -> bytes | None:
        meta = self._keys.get(key_id)
        if meta is None:
            return None
        if not meta.is_valid(now):
            return None
        return meta.secret_key

    def get_active_key(self, now: float | None = None) -> tuple[str, bytes]:
        if self._active_key_id is None:
            raise ValueError("No active signing key registered in keyring")
        meta = self._keys.get(self._active_key_id)
        if meta is None or not meta.is_valid(now):
            raise ValueError(f"Active key '{self._active_key_id}' is invalid or expired")
        return (meta.key_id, meta.secret_key)

    def rotate_key(
        self,
        new_key_id: str,
        new_secret_key: bytes,
        *,
        now: float | None = None,
        transition_seconds: float = 3600.0,
        new_valid_until: float = float("inf"),
    ) -> None:
        ts = time.time() if now is None else now
        old_active_id = self._active_key_id

        if old_active_id is not None and old_active_id in self._keys:
            old_meta = self._keys[old_active_id]
            # Keep old key valid through transition window
            updated_old = SigningKeyMetadata(
                key_id=old_meta.key_id,
                secret_key=old_meta.secret_key,
                valid_from=old_meta.valid_from,
                valid_until=ts + transition_seconds,
                predecessor_id=old_meta.predecessor_id,
            )
            self._keys[old_active_id] = updated_old

        self.register_key(
            key_id=new_key_id,
            secret_key=new_secret_key,
            valid_from=ts,
            valid_until=new_valid_until,
            predecessor_id=old_active_id,
            make_active=True,
        )

    def list_keys(self) -> list[SigningKeyMetadata]:
        return list(self._keys.values())

    def validate_keyring(self, now: float | None = None) -> list[str]:
        errors: list[str] = []
        if not self._keys:
            errors.append("Keyring is empty")
            return errors
        if self._active_key_id is None or self._active_key_id not in self._keys:
            errors.append(f"Invalid active_key_id: {self._active_key_id}")
        else:
            active_meta = self._keys[self._active_key_id]
            if not active_meta.is_valid(now):
                errors.append(f"Active key '{self._active_key_id}' is not currently valid")
        return errors
