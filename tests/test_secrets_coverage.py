"""Hermetic branch coverage for encrypted secret storage and redaction."""

from __future__ import annotations

import base64
import logging
import os
import sqlite3
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import core.secrets as secrets_module
from core.secrets import (
    REDACTED,
    RedactionFilter,
    Redactor,
    SecretReference,
    SecretStore,
    SecretStoreError,
)

pytestmark = pytest.mark.unit

SYNTHETIC_VALUE = "fixture-credential-value"


@pytest.fixture(autouse=True)
def isolated_defaults():
    secrets_module.reset_default_secret_store_for_tests()
    yield
    secrets_module.reset_default_secret_store_for_tests()


def test_secret_reference_and_key_loading_paths(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("OCTOPUS_SECRET_KEY", raising=False)
    assert str(SecretReference("fixture")) == "secret://fixture"

    memory = SecretStore(":memory:")
    assert len(memory._key) == 32
    memory.close()

    key_path = tmp_path / "store.key"
    db_path = tmp_path / "store.db"
    created = SecretStore(str(db_path), key_path=str(key_path))
    reference = created.store(SYNTHETIC_VALUE)
    created.close()

    reopened = SecretStore(str(db_path), key_path=str(key_path))
    assert reopened.reveal(reference) == SYNTHETIC_VALUE
    reopened.close()

    invalid_path = tmp_path / "invalid.key"
    invalid_path.write_bytes(b"invalid")
    invalid_path.chmod(0o600)
    loader = object.__new__(SecretStore)
    loader.key_path = str(invalid_path)
    with monkeypatch.context() as key_context:
        key_context.setattr(
            secrets_module.base64,
            "urlsafe_b64decode",
            MagicMock(side_effect=ValueError("invalid encoding")),
        )
        with pytest.raises(SecretStoreError, match="invalid secret-store key file"):
            loader._load_key(None)

    encoded = base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=")
    assert SecretStore._normalize_key(encoded) == b"n" * 32


def test_private_file_permissions_are_repaired_or_rejected(tmp_path, monkeypatch) -> None:
    repairable = tmp_path / "repairable.key"
    repairable.write_bytes(b"fixture")
    repairable.chmod(0o644)
    SecretStore._assert_private_file(str(repairable))
    assert os.stat(repairable).st_mode & 0o077 == 0

    rejected = tmp_path / "rejected.key"
    rejected.write_bytes(b"fixture")
    rejected.chmod(0o644)
    with monkeypatch.context() as chmod_context:
        chmod_context.setattr(
            secrets_module.os,
            "chmod",
            MagicMock(side_effect=OSError("denied")),
        )
        with pytest.raises(SecretStoreError, match="must be mode 0600"):
            SecretStore._assert_private_file(str(rejected))


class StubConnection:
    def __init__(self, error: sqlite3.OperationalError | None = None):
        self.error = error
        self.closed = False
        self.executions = 0

    def execute(self, _statement):
        self.executions += 1
        if self.error is not None:
            raise self.error
        return self

    def close(self):
        self.closed = True


def connection_store() -> SecretStore:
    store = object.__new__(SecretStore)
    store.db_path = "fixture.db"
    store._memory_conn = None
    return store


def test_connect_retries_busy_sqlite_without_sleeping(monkeypatch) -> None:
    busy = StubConnection(sqlite3.OperationalError("database is busy"))
    ready = StubConnection()
    connect = MagicMock(side_effect=[busy, ready])
    sleep = MagicMock()
    monkeypatch.setattr(secrets_module.sqlite3, "connect", connect)
    monkeypatch.setattr(secrets_module.time, "sleep", sleep)

    assert connection_store()._connect() is ready
    assert busy.closed is True
    sleep.assert_called_once()


def test_connect_propagates_non_retryable_and_exhausted_errors(monkeypatch) -> None:
    broken = StubConnection(sqlite3.OperationalError("malformed database"))
    monkeypatch.setattr(secrets_module.sqlite3, "connect", MagicMock(return_value=broken))
    with pytest.raises(sqlite3.OperationalError, match="malformed"):
        connection_store()._connect()
    assert broken.closed is True

    busy = StubConnection(sqlite3.OperationalError("database is locked"))
    connect = MagicMock(return_value=busy)
    sleep = MagicMock()
    monkeypatch.setattr(secrets_module.sqlite3, "connect", connect)
    monkeypatch.setattr(secrets_module.time, "sleep", sleep)
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        connection_store()._connect()
    assert connect.call_count == 12
    assert sleep.call_count == 12


def test_database_permission_failure_is_typed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        secrets_module.os,
        "chmod",
        MagicMock(side_effect=OSError("denied")),
    )
    with pytest.raises(SecretStoreError, match="cannot protect secret store"):
        SecretStore(str(tmp_path / "protected.db"), key=b"p" * 32)


def test_store_reveal_and_close_edge_contracts() -> None:
    store = SecretStore(":memory:", key=b"e" * 32)
    with pytest.raises(ValueError, match="empty secret"):
        store.store("")

    byte_reference = store.store(
        b"fixture-bytes",
        metadata={"opaque": SimpleNamespace(label="fixture")},
    )
    assert store.store(byte_reference) == byte_reference
    with pytest.raises(KeyError):
        store.reveal("secret://missing")

    text_reference = store.store(SYNTHETIC_VALUE)
    identifier = text_reference.removeprefix("secret://")
    assert store.reveal(SecretReference(identifier)) == SYNTHETIC_VALUE
    assert store.keyed_digest(b"fixture", kind="bytes") != store.keyed_digest(
        "fixture",
        kind="text",
    )

    store.close()
    assert store._memory_conn is None
    assert store.known_values() == ()


def test_redactor_scalar_and_fact_specific_edges() -> None:
    store = SecretStore(":memory:", key=b"f" * 32)
    redactor = Redactor(store)
    assert redactor.protect("secret://already") == "secret://already"
    assert redactor._text_replacement("", "fixture") == ""
    assert redactor._text_replacement(REDACTED, "fixture") == REDACTED
    assert redactor._text_replacement("secret://already", "fixture") == "secret://already"

    session, session_refs = redactor.redact_fact(
        "credential",
        f"session_token:{SYNTHETIC_VALUE}",
    )
    pair, pair_refs = redactor.redact_fact(
        "credential",
        f"alice:{SYNTHETIC_VALUE} (observed)",
    )
    scalar, scalar_refs = redactor.redact_fact("credential", SYNTHETIC_VALUE)
    empty, empty_refs = redactor.redact_fact("credential", "")
    exempt, exempt_refs = redactor.redact_fact("credential", "login_success")

    assert session_refs and pair_refs and scalar_refs
    assert SYNTHETIC_VALUE not in session
    assert SYNTHETIC_VALUE not in pair
    assert SYNTHETIC_VALUE not in scalar
    assert (empty, empty_refs) == ("", ())
    assert (exempt, exempt_refs) == ("login_success", ())

    protected_password, password_refs = redactor.redact_fact("password", SYNTHETIC_VALUE)
    file_marker, file_refs = redactor.redact_fact("password", "password_file")
    assert password_refs and SYNTHETIC_VALUE not in protected_password
    assert (file_marker, file_refs) == ("password_file", ())

    known_value = "fixture-known-value"
    redactor.protect(known_value)
    structured, structured_refs = redactor.redact_fact(
        "secret_finding",
        f"generic:{known_value}:validated:rotation_required",
    )
    unstructured, unstructured_refs = redactor.redact_fact(
        "secret_finding",
        f"password={SYNTHETIC_VALUE}",
    )
    assert known_value not in structured and structured_refs
    assert SYNTHETIC_VALUE not in unstructured and unstructured_refs


@dataclass
class SecretPayload:
    token: str


def test_redact_data_handles_dataclasses_sets_and_bytes() -> None:
    redactor = Redactor(SecretStore(":memory:", key=b"d" * 32))
    dataclass_result = redactor.redact_data(SecretPayload(SYNTHETIC_VALUE))
    set_result = redactor.redact_data({"safe", "values"})
    bytes_result = redactor.redact_data(b"fixture-bytes", field="blob")

    assert str(dataclass_result["token"]).startswith("secret://")
    assert set_result == {"safe", "values"}
    assert str(bytes_result).startswith("secret://")


def test_logging_filter_redacts_messages_exceptions_and_failures(monkeypatch) -> None:
    redactor = Redactor(SecretStore(":memory:", key=b"l" * 32))
    monkeypatch.setattr(secrets_module, "get_redactor", lambda: redactor)
    filter_instance = RedactionFilter()

    record = logging.LogRecord(
        "fixture",
        logging.ERROR,
        __file__,
        1,
        "password=%s",
        (SYNTHETIC_VALUE,),
        None,
    )
    record.exc_text = f"token={SYNTHETIC_VALUE}"
    assert filter_instance.filter(record) is True
    assert SYNTHETIC_VALUE not in str(record.msg)
    assert SYNTHETIC_VALUE not in str(record.exc_text)
    assert record.args == ()

    clean = logging.LogRecord("fixture", logging.INFO, __file__, 1, "clean", (), None)
    assert filter_instance.filter(clean) is True
    assert clean.msg == "clean"

    broken_redactor = SimpleNamespace(
        redact_text=MagicMock(side_effect=RuntimeError("redaction failed"))
    )
    broken_filter = RedactionFilter(broken_redactor)
    broken = logging.LogRecord("fixture", logging.INFO, __file__, 1, "value", (), None)
    assert broken_filter.filter(broken) is True
    assert broken.msg == "[REDACTED: logging filter failure]"
    assert broken.args == ()


def test_logging_installation_is_idempotent_for_logger_and_handlers() -> None:
    secrets_module._DEFAULT_REDACTOR = Redactor(
        SecretStore(":memory:", key=b"i" * 32)
    )
    logger = logging.Logger("secret-coverage")
    handler = logging.NullHandler()
    logger.addHandler(handler)

    first = secrets_module.install_logging_redaction(logger)
    second = secrets_module.install_logging_redaction(logger)

    assert first is second
    assert sum(isinstance(item, RedactionFilter) for item in logger.filters) == 1
    assert sum(isinstance(item, RedactionFilter) for item in handler.filters) == 1


def test_reference_validation_and_default_path_sources(tmp_path, monkeypatch) -> None:
    with pytest.raises(ValueError, match="invalid secret reference"):
        secrets_module._reference_identifier("not-a-reference")

    configured = tmp_path / "configured.db"
    monkeypatch.setenv("OCTOPUS_SECRET_STORE", str(configured))
    assert secrets_module.default_secret_store_path() == str(configured)

    monkeypatch.delenv("OCTOPUS_SECRET_STORE")
    import config

    monkeypatch.setattr(config, "CFG", {"paths": {"secrets": "~/fixture-secrets.db"}})
    assert secrets_module.default_secret_store_path().endswith("fixture-secrets.db")

    monkeypatch.setattr(config, "CFG", {"paths": []})
    assert secrets_module.default_secret_store_path() == "data/secrets.db"

    class BrokenConfig:
        def get(self, _key, _default):
            raise KeyError("paths")

    monkeypatch.setattr(config, "CFG", BrokenConfig())
    assert secrets_module.default_secret_store_path() == "data/secrets.db"


class FakeDefaultStore:
    def __init__(self):
        self.close = MagicMock()
        self.reveal = MagicMock(return_value="revealed-fixture")


class InjectingLock:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        secrets_module._DEFAULT_STORE = self.store
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return False


def test_default_store_initialization_cache_and_lock_race(monkeypatch) -> None:
    store = FakeDefaultStore()
    factory = MagicMock(return_value=store)
    monkeypatch.setattr(secrets_module, "SecretStore", factory)
    monkeypatch.setattr(secrets_module, "default_secret_store_path", lambda: "fixture.db")

    assert secrets_module.get_secret_store() is store
    assert secrets_module.get_secret_store() is store
    factory.assert_called_once_with("fixture.db")

    raced_store = FakeDefaultStore()
    secrets_module._DEFAULT_STORE = None
    secrets_module._DEFAULT_REDACTOR = None
    monkeypatch.setattr(secrets_module, "_DEFAULT_LOCK", InjectingLock(raced_store))
    assert secrets_module.get_secret_store() is raced_store
    factory.assert_called_once()


def test_default_redactor_wrappers_failure_and_reset(monkeypatch) -> None:
    secrets_module._DEFAULT_REDACTOR = None
    monkeypatch.setattr(secrets_module, "get_secret_store", lambda: None)
    with pytest.raises(SecretStoreError, match="default redactor initialization failed"):
        secrets_module.get_redactor()

    redactor = SimpleNamespace(
        redact_text=MagicMock(return_value="safe-text"),
        redact_data=MagicMock(return_value={"safe": True}),
    )
    store = FakeDefaultStore()
    secrets_module._DEFAULT_REDACTOR = redactor
    secrets_module._DEFAULT_STORE = store
    monkeypatch.setattr(secrets_module, "get_secret_store", lambda: store)

    assert secrets_module.get_redactor() is redactor
    assert secrets_module.redact_text("fixture", kind="field") == "safe-text"
    assert secrets_module.redact_data({"fixture": True}) == {"safe": True}
    assert secrets_module.reveal_secret("secret://fixture") == "revealed-fixture"

    secrets_module.reset_default_secret_store_for_tests()
    store.close.assert_called_once_with()
    secrets_module.reset_default_secret_store_for_tests()
