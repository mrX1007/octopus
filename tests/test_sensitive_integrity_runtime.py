"""Tests for the sole PR-5 keyed sensitive-integrity runtime."""

from __future__ import annotations

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    PersistentSensitiveIntegrityKeyringV2,
    SensitiveIntegrityError,
    SensitiveIntegrityStreamStateV2,
)

pytestmark = pytest.mark.unit


def _authenticator() -> tuple[
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    PersistentSensitiveIntegrityKeyringV2,
]:
    source = bytearray(b"0123456789abcdef0123456789abcdef")
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="k1",
        keys={"k1": source},
    )
    assert not any(source)
    authenticator = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(
        keyring=keyring,
        provenance_id="sensitive-integrity-tests-v2",
    )
    return authenticator, keyring


def test_sensitive_integrity_tag() -> None:
    authenticator, keyring = _authenticator()
    data = bytearray(b"secret_observation_payload")
    view = memoryview(data)
    try:
        tag = authenticator.compute(domain="observation/1", source=view)
        assert authenticator.verify(expected=tag, source=view) is True
        data[0] ^= 1
        with pytest.raises(SensitiveIntegrityError, match="integrity_mismatch"):
            authenticator.verify(expected=tag, source=view)
    finally:
        view.release()
        for index in range(len(data)):
            data[index] = 0
        keyring.close_and_zeroize()


def test_sensitive_integrity_stream_under_or_over_expected_total_bytes_fails_and_zeroizes() -> None:
    authenticator, keyring = _authenticator()
    short = bytearray(b"short")
    short_view = memoryview(short)
    try:
        stream = authenticator.new_stream(
            domain="bounded-stream/1",
            expected_total_bytes=len(short) + 1,
        )
        stream.update(short_view)
        with pytest.raises(SensitiveIntegrityError, match="length_mismatch"):
            stream.finalize()
        assert stream.state is SensitiveIntegrityStreamStateV2.ABORTED

        overflow = authenticator.new_stream(
            domain="bounded-stream/1",
            expected_total_bytes=len(short) - 1,
        )
        with pytest.raises(SensitiveIntegrityError, match="overflow"):
            overflow.update(short_view)
        assert overflow.state is SensitiveIntegrityStreamStateV2.ABORTED
    finally:
        short_view.release()
        for index in range(len(short)):
            short[index] = 0
        keyring.close_and_zeroize()


def test_immutable_sensitive_integrity_source_is_rejected() -> None:
    authenticator, keyring = _authenticator()
    immutable_view = memoryview(b"immutable-secret")
    try:
        with pytest.raises(SensitiveIntegrityError, match="source_view_invalid"):
            authenticator.compute(domain="immutable-source/1", source=immutable_view)
    finally:
        immutable_view.release()
        keyring.close_and_zeroize()
