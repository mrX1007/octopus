"""Exact PR-5 tests for the sole opaque ``SecretValue`` owner and bridge."""

from __future__ import annotations

import ast
import pickle
import threading
from collections.abc import Generator
from pathlib import Path

import pytest

from core.actions.zeroizable_buffers import ZeroizableDestinationBufferV2
from core.secrets import (
    LegacySecretValueAdapterV2,
    OpaqueSecretValueFactoryV2,
    OpaqueSecretValueV2,
    SecretStore,
    SecretStoreError,
    SecretValue,
    SecretValueState,
)

pytestmark = pytest.mark.unit


@pytest.fixture  # type: ignore[untyped-decorator]
def secret_store() -> Generator[SecretStore, None, None]:
    store = SecretStore(":memory:", key=b"s" * 32)
    try:
        yield store
    finally:
        store.close()


def _checkout(store: SecretStore, plaintext: str = "supersecret") -> OpaqueSecretValueV2:
    reference = store.store(plaintext, kind="test-secret")
    return store.checkout_zeroizable(reference, consumer_id="secret-value-test")


def _assert_state(value: OpaqueSecretValueV2, expected: SecretValueState) -> None:
    assert value.state is expected


def _read_once(value: OpaqueSecretValueV2, *, consumer_id: str) -> bytearray:
    lease = value.acquire_single_use(consumer_id=consumer_id)
    destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
    copied = 0
    result = bytearray()
    try:
        copied = lease.read_into(destination)
        with destination.borrow_writable_view() as view:
            result.extend(view[:copied])
        return result
    finally:
        destination.zeroize_and_close()
        lease.close_and_zeroize()


def test_secret_value_created_in_pr5_before_pr6_dto_import() -> None:
    assert SecretValue.__module__ == "core.secrets"
    assert OpaqueSecretValueV2.__module__ == "core.secrets"
    assert not hasattr(SecretValue, "reveal_secret")
    assert not hasattr(SecretValue, "serialize")


def test_secret_value_has_one_canonical_owner() -> None:
    root = Path(__file__).resolve().parents[1] / "core"
    owners: list[Path] = []
    for path in root.rglob("*.py"):
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef, ast.FunctionDef))
            and isinstance(node, ast.ClassDef)
            and node.name == "SecretValue"
            for node in ast.walk(module)
        ):
            owners.append(path)
    assert owners == [root / "secrets.py"]


def test_secret_value_single_use_lease_and_clear_contract(
    secret_store: SecretStore,
) -> None:
    value = _checkout(secret_store)
    assert isinstance(value, SecretValue)
    _assert_state(value, SecretValueState.AVAILABLE)

    lease = value.acquire_single_use(consumer_id="first-consumer")
    _assert_state(value, SecretValueState.LEASED)
    with pytest.raises(SecretStoreError, match="not_available"):
        value.acquire_single_use(consumer_id="second-consumer")

    destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
    try:
        assert lease.read_into(destination) == lease.byte_length
    finally:
        destination.zeroize_and_close()
        lease.close_and_zeroize()

    _assert_state(value, SecretValueState.CONSUMED)
    assert lease.closed is True
    with pytest.raises(SecretStoreError, match="not_available"):
        value.acquire_single_use(consumer_id="third-consumer")


def test_opaque_secret_value_single_use_and_clear(secret_store: SecretStore) -> None:
    value = _checkout(secret_store, "single-use-value")
    plaintext = _read_once(value, consumer_id="opaque-reader")
    try:
        assert plaintext == bytearray(b"single-use-value")
        _assert_state(value, SecretValueState.CONSUMED)
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
    value.clear()
    _assert_state(value, SecretValueState.CONSUMED)

    cleared = _checkout(secret_store, "clear-before-lease")
    cleared.clear()
    _assert_state(cleared, SecretValueState.CLEARED)
    with pytest.raises(SecretStoreError, match="not_available"):
        cleared.acquire_single_use(consumer_id="denied-after-clear")


def test_concurrent_clear_is_completed_by_live_lease(secret_store: SecretStore) -> None:
    value = _checkout(secret_store, "concurrent-clear-value")
    lease = value.acquire_single_use(consumer_id="concurrent-reader")
    barrier = threading.Barrier(2)

    def request_clear() -> None:
        barrier.wait()
        value.clear()

    thread = threading.Thread(target=request_clear)
    thread.start()
    barrier.wait()
    thread.join(timeout=2)
    assert not thread.is_alive()
    _assert_state(value, SecretValueState.LEASED)

    destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
    try:
        assert lease.read_into(destination) == lease.byte_length
    finally:
        destination.zeroize_and_close()
        lease.close_and_zeroize()
    _assert_state(value, SecretValueState.CLEARED)


def test_legacy_secret_adapter_is_only_v2_secret_bridge(
    secret_store: SecretStore,
) -> None:
    reference = secret_store.store("adapter-secret")
    adapter = LegacySecretValueAdapterV2(
        secret_store=secret_store,
        factory=OpaqueSecretValueFactoryV2(),
    )
    value = adapter.checkout(reference, consumer_id="legacy-adapter-test")
    assert type(value) is OpaqueSecretValueV2
    value.clear()


def test_v2_secret_checkout_never_calls_reveal(
    secret_store: SecretStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = secret_store.store("never-reveal-me")

    def forbidden_reveal(*args: object, **kwargs: object) -> str:
        raise AssertionError(f"legacy reveal called: {args!r} {kwargs!r}")

    monkeypatch.setattr(secret_store, "reveal", forbidden_reveal)
    value = secret_store.checkout_zeroizable(
        reference,
        consumer_id="no-reveal-checkout",
    )
    plaintext = _read_once(value, consumer_id="no-reveal-reader")
    try:
        assert plaintext == bytearray(b"never-reveal-me")
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0


def test_secret_destination_and_lease_destroyed_after_consumer_exception(
    secret_store: SecretStore,
) -> None:
    value = _checkout(secret_store, "consumer-exception")
    lease = value.acquire_single_use(consumer_id="exception-consumer")
    destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
    destination_storage = destination._storage

    with pytest.raises(RuntimeError, match="encoder failed"):
        try:
            lease.read_into(destination)
            raise RuntimeError("encoder failed")
        finally:
            destination.zeroize_and_close()
            lease.close_and_zeroize()

    assert destination.zeroized is True
    assert destination_storage is not None and not any(destination_storage)
    assert lease.closed is True
    _assert_state(value, SecretValueState.CONSUMED)


def test_secret_value_has_no_plaintext_repr_or_serialization(
    secret_store: SecretStore,
) -> None:
    value = _checkout(secret_store, "repr-must-not-leak")
    assert "repr-must-not-leak" not in repr(value)
    with pytest.raises(TypeError, match="not_serializable"):
        pickle.dumps(value)
    value.clear()


def test_direct_secret_value_construction_is_denied() -> None:
    with pytest.raises(TypeError):
        OpaqueSecretValueV2("plaintext")  # type: ignore[call-arg,misc]
