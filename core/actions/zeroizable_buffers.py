"""Canonical one-shot owned zeroizable buffer capabilities for V2."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any, Final, Protocol, final, runtime_checkable

from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.sensitive_integrity_runtime import OwnedHmacSensitiveIntegrityAuthenticatorV2


class ZeroizableBufferError(RuntimeError):
    """Raised when an owned zeroizable capability is invalid or exhausted."""


@runtime_checkable
class ZeroizableSensitiveBufferV2(Protocol):
    @property
    def buffer_id(self) -> str: ...

    @property
    def byte_length(self) -> int: ...

    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...

    @property
    def zeroized(self) -> bool: ...

    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> ZeroizableSensitiveBufferLeaseV2: ...

    def zeroize(self) -> None: ...


@runtime_checkable
class ZeroizableSensitiveBufferLeaseV2(Protocol):
    @property
    def buffer_id(self) -> str: ...

    @property
    def lease_id(self) -> str: ...

    @property
    def byte_length(self) -> int: ...

    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...

    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int: ...

    def close_and_zeroize(self) -> None: ...


def _require_identifier(value: str, *, field: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
        raise ZeroizableBufferError(f"{field}_invalid")
    return value


def _overwrite_and_verify(storage: bytearray) -> None:
    for index in range(len(storage)):
        storage[index] = 0
    if any(storage):
        raise ZeroizableBufferError("zeroize_verification_failed")


def _require_no_exported_views(storage: bytearray, *, error: str) -> None:
    try:
        storage.append(0)
        storage.pop()
    except BufferError as exc:
        raise ZeroizableBufferError(error) from exc


class _DestinationConstructionTokenV2:
    pass


class _OwnedBufferConstructionTokenV2:
    pass


class _OwnedBufferLeaseConstructionTokenV2:
    pass


_DESTINATION_TOKEN: Final = _DestinationConstructionTokenV2()
_OWNED_BUFFER_TOKEN: Final = _OwnedBufferConstructionTokenV2()
_OWNED_BUFFER_LEASE_TOKEN: Final = _OwnedBufferLeaseConstructionTokenV2()


@final
class ZeroizableDestinationBufferV2:
    """Owned mutable destination whose context exit always overwrites it."""

    def __init__(
        self,
        *,
        _token: _DestinationConstructionTokenV2,
        capacity: int,
    ) -> None:
        if _token is not _DESTINATION_TOKEN:
            raise ZeroizableBufferError("destination_construction_denied")
        self._buffer_id = f"zdst_{secrets.token_urlsafe(18)}"
        self._storage: bytearray | None = bytearray(capacity)
        self._capacity = capacity
        self._closed = False
        self._zeroized = False
        self._borrow_count = 0
        self._lock = threading.RLock()

    @classmethod
    def allocate(cls, capacity: int) -> ZeroizableDestinationBufferV2:
        if type(capacity) is not int or capacity < 0:
            raise ZeroizableBufferError("destination_capacity_invalid")
        return cls(_token=_DESTINATION_TOKEN, capacity=capacity)

    @property
    def buffer_id(self) -> str:
        return self._buffer_id

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def zeroized(self) -> bool:
        with self._lock:
            return self._zeroized

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def __enter__(self) -> ZeroizableDestinationBufferV2:
        with self._lock:
            if self._closed or self._zeroized or self._storage is None:
                raise ZeroizableBufferError("destination_closed")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.zeroize_and_close()

    @contextmanager
    def borrow_writable_view(self) -> Iterator[memoryview]:
        with self._lock:
            if self._closed or self._zeroized or self._storage is None:
                raise ZeroizableBufferError("destination_closed")
            storage = self._storage
            self._borrow_count += 1
        view = memoryview(storage)
        try:
            if view.readonly:
                raise ZeroizableBufferError("destination_view_readonly")
            yield view
        finally:
            view.release()
            with self._lock:
                self._borrow_count -= 1

    def zeroize_and_close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._borrow_count:
                raise ZeroizableBufferError("destination_has_exported_view")
            storage = self._storage
            if storage is not None:
                _require_no_exported_views(
                    storage,
                    error="destination_has_exported_view",
                )
                _overwrite_and_verify(storage)
                self._storage = None
            self._zeroized = True
            self._closed = True

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("zeroizable_destination_is_not_serializable")

    def __del__(self) -> None:
        with suppress(BaseException):
            self.zeroize_and_close()


@final
class OwnedZeroizableSensitiveBufferV2:
    """Sole production sensitive-buffer implementation."""

    def __init__(
        self,
        *,
        _token: _OwnedBufferConstructionTokenV2,
        storage: bytearray,
        integrity_tag: SensitiveIntegrityTagV2,
    ) -> None:
        if _token is not _OWNED_BUFFER_TOKEN:
            raise ZeroizableBufferError("owned_buffer_construction_denied")
        if type(storage) is not bytearray or not storage:
            raise ZeroizableBufferError("owned_buffer_storage_invalid")
        if type(integrity_tag) is not SensitiveIntegrityTagV2:
            raise ZeroizableBufferError("owned_buffer_integrity_tag_invalid")
        self._buffer_id = f"zbuf_{secrets.token_urlsafe(18)}"
        self._storage: bytearray | None = storage
        self._byte_length = len(storage)
        self._integrity_tag = integrity_tag
        self._lease_id: str | None = None
        self._zeroized = False
        self._lock = threading.RLock()

    @classmethod
    def _from_owned_storage(
        cls,
        *,
        storage: bytearray,
        integrity_tag: SensitiveIntegrityTagV2,
        _token: _OwnedBufferConstructionTokenV2,
    ) -> OwnedZeroizableSensitiveBufferV2:
        return cls(_token=_token, storage=storage, integrity_tag=integrity_tag)

    @property
    def buffer_id(self) -> str:
        return self._buffer_id

    @property
    def byte_length(self) -> int:
        return self._byte_length

    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2:
        return self._integrity_tag

    @property
    def zeroized(self) -> bool:
        with self._lock:
            return self._zeroized

    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> OwnedZeroizableSensitiveBufferLeaseV2:
        _require_identifier(consumer_id, field="consumer_id")
        with self._lock:
            if self._zeroized or self._storage is None:
                raise ZeroizableBufferError("owned_buffer_zeroized")
            if self._lease_id is not None:
                raise ZeroizableBufferError("owned_buffer_already_leased")
            lease_id = f"zlease_{secrets.token_urlsafe(18)}"
            self._lease_id = lease_id
            return OwnedZeroizableSensitiveBufferLeaseV2(
                _token=_OWNED_BUFFER_LEASE_TOKEN,
                owner=self,
                lease_id=lease_id,
            )

    def _read_once_into(
        self,
        *,
        lease_id: str,
        destination: ZeroizableDestinationBufferV2,
    ) -> int:
        if type(destination) is not ZeroizableDestinationBufferV2:
            raise ZeroizableBufferError("raw_or_custom_destination_denied")
        with self._lock:
            if self._zeroized or self._storage is None:
                raise ZeroizableBufferError("owned_buffer_zeroized")
            if self._lease_id != lease_id:
                raise ZeroizableBufferError("owned_buffer_lease_mismatch")
            if destination.capacity < self._byte_length:
                raise ZeroizableBufferError("destination_capacity_too_small")
            with destination.borrow_writable_view() as writable:
                writable[: self._byte_length] = self._storage
            return self._byte_length

    def _close_lease_and_zeroize(self, *, lease_id: str) -> None:
        with self._lock:
            if self._zeroized:
                return
            if self._lease_id != lease_id:
                raise ZeroizableBufferError("owned_buffer_lease_mismatch")
            self._zeroize_locked()

    def zeroize(self) -> None:
        with self._lock:
            self._zeroize_locked()

    def _zeroize_locked(self) -> None:
        if self._zeroized:
            return
        storage = self._storage
        if storage is not None:
            _overwrite_and_verify(storage)
            self._storage = None
        self._zeroized = True

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("owned_zeroizable_buffer_is_not_serializable")

    def __del__(self) -> None:
        with suppress(BaseException):
            self.zeroize()


@final
class OwnedZeroizableSensitiveBufferLeaseV2:
    """Concrete single-read lease over an owned sensitive buffer."""

    def __init__(
        self,
        *,
        _token: _OwnedBufferLeaseConstructionTokenV2,
        owner: OwnedZeroizableSensitiveBufferV2,
        lease_id: str,
    ) -> None:
        if _token is not _OWNED_BUFFER_LEASE_TOKEN or type(owner) is not OwnedZeroizableSensitiveBufferV2:
            raise ZeroizableBufferError("owned_buffer_lease_construction_denied")
        self._owner = owner
        self._lease_id = lease_id
        self._closed = False
        self._read = False
        self._lock = threading.RLock()

    @property
    def buffer_id(self) -> str:
        return self._owner.buffer_id

    @property
    def lease_id(self) -> str:
        return self._lease_id

    @property
    def byte_length(self) -> int:
        return self._owner.byte_length

    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2:
        return self._owner.integrity_tag

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int:
        with self._lock:
            if self._closed:
                raise ZeroizableBufferError("owned_buffer_lease_closed")
            if self._read:
                raise ZeroizableBufferError("owned_buffer_lease_already_read")
            copied = self._owner._read_once_into(
                lease_id=self._lease_id,
                destination=destination,
            )
            self._read = True
            return copied

    def close_and_zeroize(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._owner._close_lease_and_zeroize(lease_id=self._lease_id)
            finally:
                self._closed = True

    def __enter__(self) -> OwnedZeroizableSensitiveBufferLeaseV2:
        with self._lock:
            if self._closed:
                raise ZeroizableBufferError("owned_buffer_lease_closed")
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close_and_zeroize()

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("owned_zeroizable_buffer_lease_is_not_serializable")

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close_and_zeroize()


@final
class OwnedZeroizableSensitiveBufferFactoryV2:
    """Executor/store factory retaining the sole concrete authenticator."""

    def __init__(self, *, authenticator: OwnedHmacSensitiveIntegrityAuthenticatorV2) -> None:
        if type(authenticator) is not OwnedHmacSensitiveIntegrityAuthenticatorV2:
            raise ZeroizableBufferError("custom_sensitive_authenticator_denied")
        self._authenticator = authenticator

    def from_owned_mutable(
        self,
        *,
        source: bytearray,
        domain: str,
    ) -> OwnedZeroizableSensitiveBufferV2:
        if type(source) is not bytearray or not source:
            raise ZeroizableBufferError("mutable_source_invalid")
        _require_identifier(domain, field="integrity_domain")
        owned_storage: bytearray | None = None
        owned_view: memoryview | None = None
        try:
            # A live exported view proves that another owner can mutate or retain
            # the caller's storage. A reversible resize is the CPython buffer-
            # protocol check and occurs before any owned copy is accepted.
            _require_no_exported_views(
                source,
                error="aliased_mutable_source_denied",
            )
            owned_storage = bytearray(source)
            owned_view = memoryview(owned_storage)
            integrity_tag = self._authenticator.compute(domain=domain, source=owned_view)
            result = OwnedZeroizableSensitiveBufferV2._from_owned_storage(
                storage=owned_storage,
                integrity_tag=integrity_tag,
                _token=_OWNED_BUFFER_TOKEN,
            )
            owned_storage = None
            return result
        finally:
            if owned_view is not None:
                owned_view.release()
            _overwrite_and_verify(source)
            if owned_storage is not None:
                _overwrite_and_verify(owned_storage)


__all__ = [
    "OwnedZeroizableSensitiveBufferFactoryV2",
    "OwnedZeroizableSensitiveBufferLeaseV2",
    "OwnedZeroizableSensitiveBufferV2",
    "ZeroizableBufferError",
    "ZeroizableDestinationBufferV2",
    "ZeroizableSensitiveBufferLeaseV2",
    "ZeroizableSensitiveBufferV2",
]
