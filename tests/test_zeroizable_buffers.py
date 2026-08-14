"""Exact PR-5 tests for the canonical owned zeroizable capabilities."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import cast

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    PersistentSensitiveIntegrityKeyringV2,
)
from core.actions.zeroizable_buffers import (
    OwnedZeroizableSensitiveBufferFactoryV2,
    OwnedZeroizableSensitiveBufferV2,
    ZeroizableBufferError,
    ZeroizableDestinationBufferV2,
)

pytestmark = pytest.mark.unit


def _factory() -> tuple[
    OwnedZeroizableSensitiveBufferFactoryV2,
    PersistentSensitiveIntegrityKeyringV2,
]:
    source_key = bytearray(b"k" * 32)
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="test-key-v2",
        keys={"test-key-v2": source_key},
    )
    assert not any(source_key)
    authenticator = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(
        keyring=keyring,
        provenance_id="zeroizable-tests-v2",
    )
    return OwnedZeroizableSensitiveBufferFactoryV2(authenticator=authenticator), keyring


@contextmanager
def _owned_buffer(
    plaintext: bytearray,
) -> Iterator[OwnedZeroizableSensitiveBufferV2]:
    factory, keyring = _factory()
    buffer = factory.from_owned_mutable(
        source=plaintext,
        domain="zeroizable-test/1",
    )
    try:
        yield buffer
    finally:
        buffer.zeroize()
        keyring.close_and_zeroize()


def test_owned_zeroizable_buffer_overwrites_and_releases_storage() -> None:
    source = bytearray(b"secret_data_123")
    with _owned_buffer(source) as buffer:
        storage = buffer._storage
        assert storage is not None
        lease = buffer.acquire_single_use(consumer_id="owned-buffer-test")
        lease.close_and_zeroize()

        assert buffer.zeroized is True
        assert buffer._storage is None
        assert not any(storage)
        with pytest.raises(ZeroizableBufferError, match="owned_buffer_zeroized"):
            buffer.acquire_single_use(consumer_id="second-consumer")


def test_zeroizable_destination_destroyed_after_read_into_success() -> None:
    source = bytearray(b"success-path-secret")
    with _owned_buffer(source) as buffer:
        lease = buffer.acquire_single_use(consumer_id="success-reader")
        destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
        destination_storage = destination._storage
        try:
            copied = lease.read_into(destination)
            assert copied == lease.byte_length
            with destination.borrow_writable_view() as view:
                assert view[:copied] == bytearray(b"success-path-secret")
        finally:
            destination.zeroize_and_close()
            lease.close_and_zeroize()

        assert destination.zeroized is True
        assert destination.closed is True
        assert destination._storage is None
        assert destination_storage is not None and not any(destination_storage)


def test_zeroizable_destination_destroyed_after_read_into_exception() -> None:
    source = bytearray(b"exception-path-secret")
    with _owned_buffer(source) as buffer:
        lease = buffer.acquire_single_use(consumer_id="exception-reader")
        destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
        destination_storage = destination._storage

        with pytest.raises(RuntimeError, match="injected encoder failure"):
            try:
                lease.read_into(destination)
                raise RuntimeError("injected encoder failure")
            finally:
                destination.zeroize_and_close()
                lease.close_and_zeroize()

        assert destination.zeroized is True
        assert destination_storage is not None and not any(destination_storage)
        assert lease.closed is True
        assert buffer.zeroized is True


def test_source_lease_destroyed_after_read_into() -> None:
    source = bytearray(b"one-shot-source")
    with _owned_buffer(source) as buffer:
        lease = buffer.acquire_single_use(consumer_id="single-use-reader")
        destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
        try:
            assert lease.read_into(destination) == lease.byte_length
            with pytest.raises(ZeroizableBufferError, match="already_read"):
                lease.read_into(destination)
        finally:
            destination.zeroize_and_close()
            lease.close_and_zeroize()

        assert lease.closed is True
        assert buffer.zeroized is True
        with pytest.raises(ZeroizableBufferError, match="lease_closed"):
            lease.read_into(ZeroizableDestinationBufferV2.allocate(lease.byte_length))


def test_exported_view_released_before_zeroize() -> None:
    destination = ZeroizableDestinationBufferV2.allocate(32)
    storage = destination._storage
    derived: memoryview | None = None

    with destination.borrow_writable_view() as view:
        view[:6] = bytearray(b"secret")
        derived = view[:6]
        with pytest.raises(ZeroizableBufferError, match="exported_view"):
            destination.zeroize_and_close()
        assert destination.zeroized is False

    with pytest.raises(ZeroizableBufferError, match="exported_view"):
        destination.zeroize_and_close()
    assert derived is not None
    derived.release()
    destination.zeroize_and_close()
    assert destination.zeroized is True
    assert storage is not None and not any(storage)


def test_mutable_source_zeroed_after_transfer() -> None:
    factory, keyring = _factory()
    source = bytearray(b"caller-owned-sensitive-source")
    try:
        buffer = factory.from_owned_mutable(
            source=source,
            domain="mutable-transfer/1",
        )
        try:
            assert not any(source)
            assert buffer.byte_length == len(source)
        finally:
            buffer.zeroize()
    finally:
        keyring.close_and_zeroize()


def test_factory_exception_still_zeroes_mutable_source() -> None:
    factory, keyring = _factory()
    source = bytearray(b"must-be-wiped-on-error")
    keyring.close_and_zeroize()

    with pytest.raises(Exception, match="keyring_closed"):
        factory.from_owned_mutable(source=source, domain="factory-error/1")
    assert not any(source)


def test_aliased_mutable_source_is_rejected_and_zeroed() -> None:
    factory, keyring = _factory()
    source = bytearray(b"aliased-sensitive-source")
    alias = memoryview(source)
    try:
        with pytest.raises(ZeroizableBufferError, match="aliased_mutable_source"):
            factory.from_owned_mutable(source=source, domain="aliased-source/1")
        assert not any(source)
    finally:
        alias.release()
        keyring.close_and_zeroize()


def test_raw_or_custom_read_destination_is_rejected() -> None:
    source = bytearray(b"raw-destination-denied")
    with _owned_buffer(source) as buffer:
        lease = buffer.acquire_single_use(consumer_id="raw-destination-test")
        try:
            with pytest.raises(ZeroizableBufferError, match="raw_or_custom_destination"):
                lease.read_into(bytearray(lease.byte_length))  # type: ignore[arg-type]
        finally:
            lease.close_and_zeroize()


def test_direct_keyless_owned_buffer_construction_is_denied() -> None:
    constructor = cast(Callable[..., object], OwnedZeroizableSensitiveBufferV2)
    with pytest.raises(TypeError):
        constructor(bytearray(b"forbidden"))
