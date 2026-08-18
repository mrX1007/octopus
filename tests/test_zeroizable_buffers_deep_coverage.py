"""Comprehensive unit tests for zeroizable_buffers.py error branches."""

from __future__ import annotations

import pytest

from core.actions.sensitive_integrity import SensitiveIntegrityTagV2
from core.actions.sensitive_integrity_runtime import (
    OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2,
    PersistentSensitiveIntegrityKeyringV2,
)
from core.actions.zeroizable_buffers import (
    OwnedZeroizableSensitiveBufferFactoryV2,
    OwnedZeroizableSensitiveBufferLeaseV2,
    OwnedZeroizableSensitiveBufferV2,
    ZeroizableBufferError,
    ZeroizableDestinationBufferV2,
    _require_identifier,
)

pytestmark = pytest.mark.unit


def test_zeroizable_buffer_helpers_and_destination_errors():
    with pytest.raises(ZeroizableBufferError, match="field_invalid"):
        _require_identifier("", field="field")

    with pytest.raises(ZeroizableBufferError, match="destination_construction_denied"):
        ZeroizableDestinationBufferV2(_token="bad", capacity=10)  # type: ignore

    dest = ZeroizableDestinationBufferV2.allocate(10)
    dest.zeroize_and_close()

    with pytest.raises(ZeroizableBufferError, match="destination_closed"):
        with dest:
            pass

    with pytest.raises(ZeroizableBufferError, match="destination_closed"):
        with dest.borrow_writable_view():
            pass

    with pytest.raises(TypeError, match="zeroizable_destination_is_not_serializable"):
        dest.__reduce__()


def test_owned_sensitive_buffer_direct_and_error_paths():
    tag = SensitiveIntegrityTagV2(key_id="k1", algorithm="hmac-sha256-v2", domain="dom", tag="sha256:d")

    # Direct constructor denials
    with pytest.raises(ZeroizableBufferError, match="owned_buffer_construction_denied"):
        OwnedZeroizableSensitiveBufferV2(
            _token="bad",  # type: ignore
            storage=bytearray(10),
            integrity_tag=tag,
        )

    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_construction_denied"):
        OwnedZeroizableSensitiveBufferLeaseV2(
            _token="bad",  # type: ignore
            owner="not_owner",  # type: ignore
            lease_id="l1",
        )

    with pytest.raises(ZeroizableBufferError, match="custom_sensitive_authenticator_denied"):
        OwnedZeroizableSensitiveBufferFactoryV2(authenticator="fake")  # type: ignore

    keyring = PersistentSensitiveIntegrityKeyringV2.from_owned_mutable_keys(
        active_key_id="k1",
        keys={"k1": bytearray(b"a" * 32)},
    )
    auth = OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2().create(keyring=keyring, provenance_id="prov-1")
    factory = OwnedZeroizableSensitiveBufferFactoryV2(authenticator=auth)

    with pytest.raises(ZeroizableBufferError, match="mutable_source_invalid"):
        factory.from_owned_mutable(source="not_bytes", domain="dom")  # type: ignore

    with pytest.raises(ZeroizableBufferError, match="mutable_source_invalid"):
        factory.from_owned_mutable(source=bytearray(), domain="dom")

    # Valid buffer operations
    buf = factory.from_owned_mutable(source=bytearray(b"secret"), domain="dom")
    assert buf.byte_length == 6
    assert buf.zeroized is False

    with pytest.raises(TypeError, match="owned_zeroizable_buffer_is_not_serializable"):
        buf.__reduce__()

    # Read into custom destination denied
    lease = buf.acquire_single_use(consumer_id="consumer-1")

    with pytest.raises(TypeError, match="owned_zeroizable_buffer_lease_is_not_serializable"):
        lease.__reduce__()

    with pytest.raises(ZeroizableBufferError, match="raw_or_custom_destination_denied"):
        buf._read_once_into(lease_id=lease.lease_id, destination="not_a_dest")  # type: ignore

    # Capacity too small
    small_dest = ZeroizableDestinationBufferV2.allocate(2)
    with pytest.raises(ZeroizableBufferError, match="destination_capacity_too_small"):
        lease.read_into(small_dest)

    # Read into valid destination
    good_dest = ZeroizableDestinationBufferV2.allocate(10)
    lease.read_into(good_dest)

    # Read twice error
    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_already_read"):
        lease.read_into(good_dest)

    lease.close_and_zeroize()
    assert lease.closed is True

    # Operations after close/zeroize
    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_closed"):
        with lease:
            pass

    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_closed"):
        lease.read_into(good_dest)

    # Aliased mutable source with exported view
    aliased_src = bytearray(b"aliased")
    aliased_view = memoryview(aliased_src)
    with pytest.raises(ZeroizableBufferError, match="aliased_mutable_source_denied"):
        factory.from_owned_mutable(source=aliased_src, domain="dom")
    del aliased_view

    # In use and zeroized buffer errors
    buf2 = factory.from_owned_mutable(source=bytearray(b"secret2"), domain="dom")
    lease1 = buf2.acquire_single_use(consumer_id="c1")
    assert lease1.closed is False
    with pytest.raises(ZeroizableBufferError, match="owned_buffer_already_leased"):
        buf2.acquire_single_use(consumer_id="c2")

    buf2.zeroize()
    assert buf2.zeroized is True

    with pytest.raises(ZeroizableBufferError, match="owned_buffer_zeroized"):
        buf2.acquire_single_use(consumer_id="c3")

    # Negative capacity
    with pytest.raises(ZeroizableBufferError, match="destination_capacity_invalid"):
        ZeroizableDestinationBufferV2.allocate(-1)

    # Destination buffer_id property
    dest3 = ZeroizableDestinationBufferV2.allocate(5)
    assert dest3.buffer_id.startswith("zdst_")
    assert dest3.capacity == 5
    dest3.zeroize_and_close()

    # Buffer buffer_id property and lease_mismatch
    buf3 = factory.from_owned_mutable(source=bytearray(b"secret3"), domain="dom")
    assert buf3.buffer_id.startswith("zbuf_")
    l3 = buf3.acquire_single_use(consumer_id="c3")
    assert l3.buffer_id == buf3.buffer_id
    assert l3.lease_id.startswith("zlease_")
    assert l3.byte_length == 7
    assert l3.integrity_tag is not None

    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_mismatch"):
        buf3._read_once_into(lease_id="zlease_WRONG", destination=ZeroizableDestinationBufferV2.allocate(10))

    with pytest.raises(ZeroizableBufferError, match="owned_buffer_lease_mismatch"):
        buf3._close_lease_and_zeroize(lease_id="zlease_WRONG")

    l3.close_and_zeroize()
