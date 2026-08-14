"""Executor-owned keyed integrity services for sensitive V2 material.

The dependency-free tag DTO lives in :mod:`core.actions.sensitive_integrity`.
This module is the sole owner of the concrete keyed authenticator and keeps key
material behind one-shot, zeroizable leases.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from enum import Enum
from typing import Final, Literal, Protocol, final, runtime_checkable

from core.actions.sensitive_integrity import SensitiveIntegrityTagV2


class SensitiveIntegrityError(RuntimeError):
    """Raised when a keyed-integrity capability is invalid or exhausted."""


class SensitiveIntegrityStreamStateV2(str, Enum):
    OPEN = "open"
    FINALIZED = "finalized"
    ABORTED = "aborted"


class SensitiveIntegrityKeyLeaseStateV2(str, Enum):
    OPEN = "open"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


@runtime_checkable
class SensitiveIntegrityStreamV2(Protocol):
    @property
    def state(self) -> SensitiveIntegrityStreamStateV2: ...

    def update(self, view: memoryview) -> None: ...

    def finalize(self) -> SensitiveIntegrityTagV2: ...

    def abort_and_zeroize(self) -> None: ...

    def __enter__(self) -> SensitiveIntegrityStreamV2: ...

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None: ...


@runtime_checkable
class SensitiveIntegrityAuthenticatorV2(Protocol):
    def compute(self, *, domain: str, source: memoryview) -> SensitiveIntegrityTagV2: ...

    def verify(
        self,
        *,
        expected: SensitiveIntegrityTagV2,
        source: memoryview,
    ) -> Literal[True]: ...

    def new_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
    ) -> SensitiveIntegrityStreamV2: ...


@runtime_checkable
class SensitiveIntegrityKeyLeaseV2(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def state(self) -> SensitiveIntegrityKeyLeaseStateV2: ...

    def transfer_once_to_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
        authenticator_provenance_id: str,
    ) -> SensitiveIntegrityStreamV2: ...

    def close_and_zeroize(self) -> None: ...


@runtime_checkable
class SensitiveIntegrityKeyringV2(Protocol):
    def active_key_id(self) -> str: ...

    def acquire_for_authenticator(
        self,
        *,
        key_id: str,
        authenticator_provenance_id: str,
    ) -> SensitiveIntegrityKeyLeaseV2: ...


def _require_non_empty(value: str, *, field: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
        raise SensitiveIntegrityError(f"{field}_invalid")
    return value


def _require_length(value: int, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise SensitiveIntegrityError(f"{field}_invalid")
    return value


def _require_mutable_byte_view(view: memoryview) -> memoryview:
    if type(view) is not memoryview or view.readonly or not view.contiguous or view.ndim != 1 or view.itemsize != 1:
        raise SensitiveIntegrityError("integrity_source_view_invalid")
    return view


def _wipe_mutable(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
    if any(value):
        raise SensitiveIntegrityError("key_zeroize_verification_failed")


class _SensitiveKeyringConstructionTokenV2:
    pass


class _SensitiveKeyLeaseConstructionTokenV2:
    pass


class _SensitiveStreamConstructionTokenV2:
    pass


class _SensitiveAuthenticatorConstructionTokenV2:
    pass


_KEYRING_TOKEN: Final = _SensitiveKeyringConstructionTokenV2()
_KEY_LEASE_TOKEN: Final = _SensitiveKeyLeaseConstructionTokenV2()
_STREAM_TOKEN: Final = _SensitiveStreamConstructionTokenV2()
_AUTHENTICATOR_TOKEN: Final = _SensitiveAuthenticatorConstructionTokenV2()
_DOMAIN_PREFIX: Final = b"octopus-sensitive-integrity-v2\x00"


@final
class PersistentSensitiveIntegrityKeyringV2:
    """In-process key-id resolver backed by injected persistent key material."""

    def __init__(
        self,
        *,
        _token: _SensitiveKeyringConstructionTokenV2,
        active_key_id: str,
        owned_keys: dict[str, bytearray],
    ) -> None:
        if _token is not _KEYRING_TOKEN:
            raise SensitiveIntegrityError("keyring_construction_denied")
        self._active_key_id = _require_non_empty(active_key_id, field="active_key_id")
        if not owned_keys or self._active_key_id not in owned_keys:
            raise SensitiveIntegrityError("keyring_active_key_missing")
        self._keys = owned_keys
        self._closed = False
        self._lock = threading.RLock()

    @classmethod
    def from_owned_mutable_keys(
        cls,
        *,
        active_key_id: str,
        keys: dict[str, bytearray],
    ) -> PersistentSensitiveIntegrityKeyringV2:
        if type(keys) is not dict or not keys:
            raise SensitiveIntegrityError("keyring_keys_invalid")
        copied: dict[str, bytearray] = {}
        try:
            for key_id, source in keys.items():
                normalized_id = _require_non_empty(key_id, field="key_id")
                if type(source) is not bytearray or len(source) < 32:
                    raise SensitiveIntegrityError("key_material_invalid")
                copied[normalized_id] = bytearray(source)
            return cls(
                _token=_KEYRING_TOKEN,
                active_key_id=active_key_id,
                owned_keys=copied,
            )
        except BaseException:
            for value in copied.values():
                _wipe_mutable(value)
            raise
        finally:
            for source in keys.values():
                if type(source) is bytearray:
                    _wipe_mutable(source)

    def active_key_id(self) -> str:
        with self._lock:
            if self._closed:
                raise SensitiveIntegrityError("keyring_closed")
            return self._active_key_id

    def acquire_for_authenticator(
        self,
        *,
        key_id: str,
        authenticator_provenance_id: str,
    ) -> OwnedSensitiveIntegrityKeyLeaseV2:
        normalized_id = _require_non_empty(key_id, field="key_id")
        provenance = _require_non_empty(
            authenticator_provenance_id,
            field="authenticator_provenance_id",
        )
        with self._lock:
            if self._closed:
                raise SensitiveIntegrityError("keyring_closed")
            key = self._keys.get(normalized_id)
            if key is None:
                raise SensitiveIntegrityError("sensitive_integrity_key_unknown")
            return OwnedSensitiveIntegrityKeyLeaseV2(
                _token=_KEY_LEASE_TOKEN,
                key_id=normalized_id,
                key_material=bytearray(key),
                authenticator_provenance_id=provenance,
            )

    def close_and_zeroize(self) -> None:
        with self._lock:
            if self._closed:
                return
            for key in self._keys.values():
                _wipe_mutable(key)
            self._keys.clear()
            self._closed = True


@final
class OwnedSensitiveIntegrityKeyLeaseV2:
    """One-shot mutable key lease used only to seed one HMAC stream."""

    def __init__(
        self,
        *,
        _token: _SensitiveKeyLeaseConstructionTokenV2,
        key_id: str,
        key_material: bytearray,
        authenticator_provenance_id: str,
    ) -> None:
        if _token is not _KEY_LEASE_TOKEN:
            raise SensitiveIntegrityError("key_lease_construction_denied")
        self._key_id = key_id
        self._key_material: bytearray | None = key_material
        self._authenticator_provenance_id = authenticator_provenance_id
        self._state = SensitiveIntegrityKeyLeaseStateV2.OPEN
        self._lock = threading.RLock()

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def state(self) -> SensitiveIntegrityKeyLeaseStateV2:
        with self._lock:
            return self._state

    def transfer_once_to_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
        authenticator_provenance_id: str,
    ) -> OwnedHmacSensitiveIntegrityStreamV2:
        normalized_domain = _require_non_empty(domain, field="integrity_domain")
        expected = _require_length(expected_total_bytes, field="expected_total_bytes")
        with self._lock:
            if self._state is not SensitiveIntegrityKeyLeaseStateV2.OPEN:
                raise SensitiveIntegrityError("key_lease_not_open")
            if authenticator_provenance_id != self._authenticator_provenance_id:
                raise SensitiveIntegrityError("authenticator_provenance_mismatch")
            material = self._key_material
            if material is None:
                raise SensitiveIntegrityError("key_lease_material_missing")
            self._key_material = None
            self._state = SensitiveIntegrityKeyLeaseStateV2.TRANSFERRED
            try:
                return OwnedHmacSensitiveIntegrityStreamV2(
                    _token=_STREAM_TOKEN,
                    key_id=self._key_id,
                    key_material=material,
                    domain=normalized_domain,
                    expected_total_bytes=expected,
                )
            except BaseException:
                _wipe_mutable(material)
                self._state = SensitiveIntegrityKeyLeaseStateV2.CLOSED
                raise

    def close_and_zeroize(self) -> None:
        with self._lock:
            material = self._key_material
            if material is not None:
                _wipe_mutable(material)
                self._key_material = None
            if self._state is SensitiveIntegrityKeyLeaseStateV2.OPEN:
                self._state = SensitiveIntegrityKeyLeaseStateV2.CLOSED


@final
class OwnedHmacSensitiveIntegrityStreamV2:
    """Bounded domain-separated HMAC stream with terminal key destruction."""

    def __init__(
        self,
        *,
        _token: _SensitiveStreamConstructionTokenV2,
        key_id: str,
        key_material: bytearray,
        domain: str,
        expected_total_bytes: int,
    ) -> None:
        if _token is not _STREAM_TOKEN:
            raise SensitiveIntegrityError("integrity_stream_construction_denied")
        self._key_id = key_id
        self._key_material: bytearray | None = key_material
        self._domain = domain
        self._expected_total_bytes = expected_total_bytes
        self._seen_total_bytes = 0
        domain_bytes = domain.encode("utf-8")
        header = (
            _DOMAIN_PREFIX
            + len(domain_bytes).to_bytes(4, "big")
            + domain_bytes
            + expected_total_bytes.to_bytes(8, "big")
        )
        self._hmac: hmac.HMAC | None = hmac.new(key_material, header, hashlib.sha256)
        self._state = SensitiveIntegrityStreamStateV2.OPEN
        self._lock = threading.RLock()

    @property
    def state(self) -> SensitiveIntegrityStreamStateV2:
        with self._lock:
            return self._state

    def update(self, view: memoryview) -> None:
        _require_mutable_byte_view(view)
        with self._lock:
            if self._state is not SensitiveIntegrityStreamStateV2.OPEN or self._hmac is None:
                raise SensitiveIntegrityError("integrity_stream_not_open")
            next_total = self._seen_total_bytes + view.nbytes
            if next_total > self._expected_total_bytes:
                self.abort_and_zeroize()
                raise SensitiveIntegrityError("integrity_stream_overflow")
            self._hmac.update(view)
            self._seen_total_bytes = next_total

    def finalize(self) -> SensitiveIntegrityTagV2:
        with self._lock:
            if self._state is not SensitiveIntegrityStreamStateV2.OPEN or self._hmac is None:
                raise SensitiveIntegrityError("integrity_stream_not_open")
            if self._seen_total_bytes != self._expected_total_bytes:
                self.abort_and_zeroize()
                raise SensitiveIntegrityError("integrity_stream_length_mismatch")
            tag = self._hmac.hexdigest()
            self._destroy_key_state()
            self._state = SensitiveIntegrityStreamStateV2.FINALIZED
            return SensitiveIntegrityTagV2(
                key_id=self._key_id,
                algorithm="hmac-sha256-v2",
                domain=self._domain,
                tag=tag,
            )

    def abort_and_zeroize(self) -> None:
        with self._lock:
            if self._state is not SensitiveIntegrityStreamStateV2.OPEN:
                return
            self._destroy_key_state()
            self._state = SensitiveIntegrityStreamStateV2.ABORTED

    def _destroy_key_state(self) -> None:
        material = self._key_material
        if material is not None:
            _wipe_mutable(material)
            self._key_material = None
        # Native HMAC internals cannot be zeroized from Python; discard without
        # making a false claim about unavoidable native-library temporaries.
        self._hmac = None

    def __enter__(self) -> OwnedHmacSensitiveIntegrityStreamV2:
        with self._lock:
            if self._state is not SensitiveIntegrityStreamStateV2.OPEN:
                raise SensitiveIntegrityError("integrity_stream_not_open")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.abort_and_zeroize()


@final
class OwnedHmacSensitiveIntegrityAuthenticatorV2:
    """Sole concrete domain-separated sensitive-integrity authenticator."""

    def __init__(
        self,
        *,
        _token: _SensitiveAuthenticatorConstructionTokenV2,
        keyring: PersistentSensitiveIntegrityKeyringV2,
        provenance_id: str,
    ) -> None:
        if _token is not _AUTHENTICATOR_TOKEN or type(keyring) is not PersistentSensitiveIntegrityKeyringV2:
            raise SensitiveIntegrityError("authenticator_construction_denied")
        self._keyring = keyring
        self._provenance_id = _require_non_empty(provenance_id, field="provenance_id")

    @property
    def provenance_id(self) -> str:
        return self._provenance_id

    def _new_stream_for_key(
        self,
        *,
        key_id: str,
        domain: str,
        expected_total_bytes: int,
    ) -> OwnedHmacSensitiveIntegrityStreamV2:
        lease = self._keyring.acquire_for_authenticator(
            key_id=key_id,
            authenticator_provenance_id=self._provenance_id,
        )
        if type(lease) is not OwnedSensitiveIntegrityKeyLeaseV2:
            raise SensitiveIntegrityError("custom_key_lease_denied")
        try:
            stream = lease.transfer_once_to_stream(
                domain=domain,
                expected_total_bytes=expected_total_bytes,
                authenticator_provenance_id=self._provenance_id,
            )
            if type(stream) is not OwnedHmacSensitiveIntegrityStreamV2:
                raise SensitiveIntegrityError("custom_integrity_stream_denied")
            return stream
        finally:
            lease.close_and_zeroize()

    def compute(self, *, domain: str, source: memoryview) -> SensitiveIntegrityTagV2:
        _require_mutable_byte_view(source)
        stream = self.new_stream(domain=domain, expected_total_bytes=source.nbytes)
        try:
            stream.update(source)
            return stream.finalize()
        finally:
            stream.abort_and_zeroize()

    def verify(
        self,
        *,
        expected: SensitiveIntegrityTagV2,
        source: memoryview,
    ) -> Literal[True]:
        if type(expected) is not SensitiveIntegrityTagV2:
            raise SensitiveIntegrityError("custom_integrity_tag_denied")
        if expected.algorithm != "hmac-sha256-v2":
            raise SensitiveIntegrityError("integrity_algorithm_mismatch")
        _require_mutable_byte_view(source)
        stream = self._new_stream_for_key(
            key_id=expected.key_id,
            domain=expected.domain,
            expected_total_bytes=source.nbytes,
        )
        try:
            stream.update(source)
            actual = stream.finalize()
        finally:
            stream.abort_and_zeroize()
        if not hmac.compare_digest(actual.tag, expected.tag):
            raise SensitiveIntegrityError("sensitive_integrity_mismatch")
        return True

    def new_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
    ) -> OwnedHmacSensitiveIntegrityStreamV2:
        return self._new_stream_for_key(
            key_id=self._keyring.active_key_id(),
            domain=domain,
            expected_total_bytes=expected_total_bytes,
        )


@final
class OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2:
    """Only holder of the authenticator construction token."""

    def create(
        self,
        *,
        keyring: PersistentSensitiveIntegrityKeyringV2,
        provenance_id: str,
    ) -> OwnedHmacSensitiveIntegrityAuthenticatorV2:
        if type(keyring) is not PersistentSensitiveIntegrityKeyringV2:
            raise SensitiveIntegrityError("custom_keyring_denied")
        return OwnedHmacSensitiveIntegrityAuthenticatorV2(
            _token=_AUTHENTICATOR_TOKEN,
            keyring=keyring,
            provenance_id=provenance_id,
        )


__all__ = [
    "OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2",
    "OwnedHmacSensitiveIntegrityAuthenticatorV2",
    "OwnedHmacSensitiveIntegrityStreamV2",
    "OwnedSensitiveIntegrityKeyLeaseV2",
    "PersistentSensitiveIntegrityKeyringV2",
    "SensitiveIntegrityAuthenticatorV2",
    "SensitiveIntegrityError",
    "SensitiveIntegrityKeyLeaseStateV2",
    "SensitiveIntegrityKeyLeaseV2",
    "SensitiveIntegrityKeyringV2",
    "SensitiveIntegrityStreamStateV2",
    "SensitiveIntegrityStreamV2",
    "SensitiveIntegrityTagV2",
]
