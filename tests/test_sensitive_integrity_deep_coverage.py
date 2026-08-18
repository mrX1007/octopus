"""Comprehensive unit test coverage for sensitive_integrity_runtime.py."""

from __future__ import annotations

import pytest

from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    OwnedHmacSensitiveIntegrityAuthenticatorV2,
    OwnedHmacSensitiveIntegrityStreamV2,
    OwnedSensitiveIntegrityKeyLeaseV2,
    PersistentSensitiveIntegrityKeyringV2,
    SensitiveIntegrityError,
    SensitiveIntegrityKeyLeaseStateV2,
    SensitiveIntegrityStreamStateV2,
    SensitiveIntegrityTagV2,
    _require_length,
    _require_mutable_byte_view,
    _require_non_empty,
)

pytestmark = pytest.mark.unit


def test_helper_validations():
    with pytest.raises(SensitiveIntegrityError, match="field_invalid"):
        _require_non_empty("", field="field")

    with pytest.raises(SensitiveIntegrityError, match="field_invalid"):
        _require_non_empty("a" * 300, field="field")

    with pytest.raises(SensitiveIntegrityError, match="field_invalid"):
        _require_length(-1, field="field")

    with pytest.raises(SensitiveIntegrityError, match="integrity_source_view_invalid"):
        _require_mutable_byte_view("not_view")  # type: ignore

    with pytest.raises(SensitiveIntegrityError, match="integrity_source_view_invalid"):
        _require_mutable_byte_view(memoryview(b"readonly"))


def test_keyring_and_lease_denials():
    # Direct constructor denied
    with pytest.raises(SensitiveIntegrityError, match="keyring_construction_denied"):
        PersistentSensitiveIntegrityKeyringV2(
            _token="bad_token",  # type: ignore
            active_key_id="k1",
            owned_keys={},
        )

    # Empty keys in factory
    with pytest.raises(SensitiveIntegrityError, match="keyring_keys_invalid"):
        PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
            active_key_id="k1",
            keys={},
        )

    # Short key material < 32 bytes
    with pytest.raises(SensitiveIntegrityError, match="key_material_invalid"):
        PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
            active_key_id="k1",
            keys={"k1": bytearray(b"short")},
        )

    # Lease direct constructor denied
    with pytest.raises(SensitiveIntegrityError, match="key_lease_construction_denied"):
        OwnedSensitiveIntegrityKeyLeaseV2(
            _token="bad_token",  # type: ignore
            key_id="k1",
            key_material=bytearray(32),
            authenticator_provenance_id="p1",
        )

    # Stream direct constructor denied
    with pytest.raises(SensitiveIntegrityError, match="integrity_stream_construction_denied"):
        OwnedHmacSensitiveIntegrityStreamV2(
            _token="bad_token",  # type: ignore
            key_id="k1",
            key_material=bytearray(32),
            domain="dom",
            expected_total_bytes=10,
        )

    # Authenticator direct constructor denied
    with pytest.raises(SensitiveIntegrityError, match="authenticator_construction_denied"):
        OwnedHmacSensitiveIntegrityAuthenticatorV2(
            _token="bad_token",  # type: ignore
            keyring="not_keyring",  # type: ignore
            provenance_id="p1",
        )


def test_authenticator_and_stream_lifecycle():
    key_bytes = bytearray(b"a" * 32)
    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="k1",
        keys={"k1": key_bytes},
    )
    factory = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2()

    with pytest.raises(SensitiveIntegrityError, match="custom_keyring_denied"):
        factory.create(keyring="fake", provenance_id="p1")  # type: ignore

    auth = factory.create(keyring=keyring, provenance_id="prov-1")
    assert auth.provenance_id == "prov-1"

    data = bytearray(b"sensitive payload")
    view = memoryview(data)
    tag = auth.compute(domain="domain.v1", source=view)
    assert isinstance(tag, SensitiveIntegrityTagV2)

    # Verify
    assert auth.verify(expected=tag, source=view) is True

    # Verify with invalid algorithm
    bad_algo_tag = SensitiveIntegrityTagV2(
        key_id="k1",
        algorithm="hmac-sha256-v2",
        domain="domain.v1",
        tag="wrong_tag",
    )
    with pytest.raises(SensitiveIntegrityError, match="sensitive_integrity_mismatch"):
        auth.verify(expected=bad_algo_tag, source=view)
    # Stream overflow error
    stream_overflow = auth.new_stream(domain="domain.v1", expected_total_bytes=5)
    overflow_view = memoryview(bytearray(b"1234567890"))
    with pytest.raises(SensitiveIntegrityError, match="integrity_stream_overflow"):
        stream_overflow.update(overflow_view)

    # Stream length underflow / mismatch on finalize
    stream_short = auth.new_stream(domain="domain.v1", expected_total_bytes=10)
    short_view = memoryview(bytearray(b"123"))
    stream_short.update(short_view)
    with pytest.raises(SensitiveIntegrityError, match="integrity_stream_length_mismatch"):
        stream_short.finalize()

    # Algorithm mismatch on verify
    bad_algo = object.__new__(SensitiveIntegrityTagV2)
    object.__setattr__(bad_algo, "key_id", "k1")
    object.__setattr__(bad_algo, "algorithm", "sha256-v1")
    object.__setattr__(bad_algo, "domain", "domain.v1")
    object.__setattr__(bad_algo, "tag", "tag")
    with pytest.raises(SensitiveIntegrityError, match="integrity_algorithm_mismatch"):
        auth.verify(expected=bad_algo, source=view)

    # Unknown key in keyring
    with pytest.raises(SensitiveIntegrityError, match="sensitive_integrity_key_unknown"):
        keyring.acquire_for_authenticator(key_id="k_unknown", authenticator_provenance_id="p1")

    # Key lease transfer provenance mismatch
    lease = keyring.acquire_for_authenticator(key_id="k1", authenticator_provenance_id="prov-1")
    with pytest.raises(SensitiveIntegrityError, match="authenticator_provenance_mismatch"):
        lease.transfer_once_to_stream(domain="dom", expected_total_bytes=10, authenticator_provenance_id="prov-DIFF")

    # Lease double transfer
    s1 = lease.transfer_once_to_stream(domain="dom", expected_total_bytes=10, authenticator_provenance_id="prov-1")
    assert s1.state == SensitiveIntegrityStreamStateV2.OPEN
    s1.abort_and_zeroize()
    assert s1.state == SensitiveIntegrityStreamStateV2.ABORTED

    assert lease.key_id == "k1"
    assert lease.state == SensitiveIntegrityKeyLeaseStateV2.TRANSFERRED
    lease.close_and_zeroize()

    with pytest.raises(SensitiveIntegrityError, match="key_lease_not_open"):
        lease.transfer_once_to_stream(domain="dom", expected_total_bytes=10, authenticator_provenance_id="prov-1")

    # Keyring close and zeroize
    keyring.close_and_zeroize()
    keyring.close_and_zeroize()  # idempotent
    with pytest.raises(SensitiveIntegrityError, match="keyring_closed"):
        keyring.active_key_id()

    with pytest.raises(SensitiveIntegrityError, match="keyring_closed"):
        keyring.acquire_for_authenticator(key_id="k1", authenticator_provenance_id="p1")

    # Direct keyring active_key_id missing
    from core.actions.sensitive_integrity_runtime import _KEYRING_TOKEN

    with pytest.raises(SensitiveIntegrityError, match="keyring_active_key_missing"):
        PersistentSensitiveIntegrityKeyringV2(
            _token=_KEYRING_TOKEN,
            active_key_id="k_missing",
            owned_keys={"k1": bytearray(b"a" * 32)},
        )
