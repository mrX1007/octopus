"""Hermetic failure-boundary coverage for C2 cryptography and storage."""

from __future__ import annotations

import base64
import copy
import errno
import importlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import core.c2.db_backend as database_module
import core.c2.key_store as key_store_module
from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.key_store import KeyStore

pytestmark = [pytest.mark.contract, pytest.mark.security]


def _unlock_in_memory(store: KeyStore) -> ed25519.Ed25519PrivateKey:
    private_key = ed25519.Ed25519PrivateKey.generate()
    store._ed25519_private = private_key
    store._ed25519_public = private_key.public_key()
    store._unlocked = True
    return private_key


def test_crypto_engine_rejects_invalid_keys_unknown_agents_malformed_data_and_replay(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="X25519 private key"):
        C2CryptoEngine(str(tmp_path / "invalid-explicit"), private_key=object())

    legacy_dir = tmp_path / "invalid-legacy"
    legacy_dir.mkdir()
    legacy_private = ed25519.Ed25519PrivateKey.generate()
    (legacy_dir / "server_x25519_private.pem").write_bytes(
        legacy_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="legacy C2 private key is not X25519"):
        C2CryptoEngine(str(legacy_dir))

    engine = C2CryptoEngine(
        str(tmp_path / "valid"),
        private_key=x25519.X25519PrivateKey.generate(),
    )
    with pytest.raises(ValueError, match="Agent crypto state not found"):
        engine.encrypt_aes_gcm("missing", "payload")
    with pytest.raises(ValueError, match="Agent crypto state not found"):
        engine.decrypt_aes_gcm("missing", "payload")

    engine.agent_state["agent-1"] = {
        "key": os.urandom(32),
        "rx_seq": 0,
        "tx_seq": 0,
        "epoch": 1,
    }
    malformed = base64.b64encode(b"x" * 35).decode("ascii")
    with pytest.raises(ValueError, match="Malformed ciphertext"):
        engine.decrypt_aes_gcm("agent-1", malformed)

    encrypted = engine.encrypt_aes_gcm("agent-1", "round trip")
    assert engine.decrypt_aes_gcm("agent-1", encrypted) == "round trip"
    with pytest.raises(ValueError, match="Replay detected"):
        engine.decrypt_aes_gcm("agent-1", encrypted)


def test_database_migrates_legacy_task_delivery_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY,
                agent_id TEXT,
                command TEXT,
                status TEXT,
                output TEXT,
                created_at TEXT,
                operator_id TEXT
            )
            """
        )
        connection.commit()

    C2Database(str(db_path))

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1]: row[2:] for row in connection.execute("PRAGMA table_info(tasks)")
        }
    assert {"sent_at", "acknowledged_at", "delivery_attempts"} <= set(columns)


def test_database_agent_state_tasks_rollback_and_empty_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(database_module, "time", SimpleNamespace(time=lambda: 1_000.0))
    database = C2Database(str(tmp_path / "state.db"))

    with pytest.raises(RuntimeError, match="rollback"), database._get_conn() as connection:
        connection.execute(
            """
            INSERT INTO agents (agent_id, hostname, os, user, ip, last_seen, crypto_state)
            VALUES ('rolled-back', '', '', '', '', '', '{}')
            """
        )
        raise RuntimeError("rollback")
    assert database.get_agent_crypto("rolled-back") is None

    assert database.register_agent(
        "agent-1",
        "host-a",
        "linux",
        "alice",
        "127.0.0.1",
        {"epoch": 1},
    ) is True
    assert database.get_agent_crypto("agent-1") == {"epoch": 1}

    database.update_agent(
        "agent-2",
        "host-b",
        "linux",
        "bob",
        "127.0.0.2",
        {"epoch": 2},
    )
    assert database.get_agent_crypto("agent-2") == {"epoch": 2}
    database.update_agent(
        "agent-2",
        "host-c",
        "linux",
        "bob",
        "127.0.0.3",
        "sealed-state",
    )
    assert database.get_agent_crypto("agent-2") == "sealed-state"

    assert database.update_agent_seen(
        "agent-1",
        "host-new",
        "linux",
        "alice",
        "127.0.0.4",
        {"epoch": 3},
    ) is True
    assert database.update_agent_seen(
        "missing",
        "host",
        "linux",
        "nobody",
        "127.0.0.5",
        "sealed",
    ) is False
    assert database.update_agent_crypto("agent-1", {"epoch": 4}) is True
    assert database.update_agent_crypto("missing", None) is False
    assert database.get_agent_crypto("agent-1") == {"epoch": 4}

    assert {item["agent_id"] for item in database.get_all_agents()} == {"agent-1", "agent-2"}
    assert database.acknowledge_tasks("agent-1", [None, "", None]) == 0

    database.queue_task("task-error", "agent-1", "status")
    assert database.get_pending_tasks("agent-1")[0]["task_id"] == "task-error"
    assert database.update_task_result(
        "task-error",
        "agent-1",
        "partial output",
        error="command failed",
    ) is True
    assert database.get_results("agent-1") == [
        {
            "task_id": "task-error",
            "output": "Error: command failed\npartial output",
            "status": "error",
        }
    ]
    assert database.get_results("agent-1") == []

    assert database.update_agent_crypto("agent-2", "") is True
    assert database.get_agent_crypto("agent-2") is None


def test_database_key_epoch_lifecycle_covers_missing_and_active_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timestamps = iter((10.0, 11.0, 20.0, 21.0, 30.0))
    monkeypatch.setattr(
        database_module,
        "time",
        SimpleNamespace(time=lambda: next(timestamps)),
    )
    database = C2Database(str(tmp_path / "epochs.db"))

    assert database.increment_beacon_count("agent-1") == 0
    assert database.get_active_epoch("agent-1") is None

    first_id = database.create_key_epoch("agent-1", "hash-1")
    assert first_id == 1
    assert database.increment_beacon_count("agent-1") == 1
    assert database.get_active_epoch("agent-1")["key_hash"] == "hash-1"

    second_id = database.create_key_epoch("agent-1", "hash-2")
    assert second_id == 2
    active = database.get_active_epoch("agent-1")
    assert active["epoch_id"] == second_id
    assert active["key_hash"] == "hash-2"

    database.expire_key_epoch("agent-1")
    assert database.get_active_epoch("agent-1") is None
    assert database.increment_beacon_count("agent-1") == 0


def _valid_identity_envelope() -> dict[str, Any]:
    salt = b"s" * 32
    nonce = b"n" * 12
    header = KeyStore._envelope_header(salt, nonce)
    return {
        **header,
        "cipher": {
            **header["cipher"],
            "ciphertext": base64.b64encode(b"c" * 48).decode("ascii"),
        },
    }


def _identity_envelope_blob(envelope: Any) -> bytes:
    return key_store_module._KEY_ENVELOPE_MAGIC + json.dumps(
        envelope,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


@pytest.mark.parametrize(
    ("value", "length"),
    (
        (None, 12),
        ("\udcff", 12),
        ("not-base64!", 12),
        (base64.b64encode(b"short").decode("ascii"), 12),
    ),
)
def test_key_store_rejects_invalid_encoded_envelope_fields(value: Any, length: int) -> None:
    with pytest.raises(ValueError, match="invalid key envelope nonce"):
        KeyStore._decode_envelope_bytes(value, "nonce", length)


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("magic", "magic"),
        ("encoding", "encoding"),
        ("schema", "schema"),
        ("version-type", "version"),
        ("version-value", "version"),
        ("kdf-schema", "KDF"),
        ("kdf-id", "KDF"),
        ("cipher-schema", "cipher"),
        ("cipher-id", "cipher"),
    ),
)
def test_key_store_rejects_untrusted_envelope_structure(case: str, message: str) -> None:
    envelope: Any = copy.deepcopy(_valid_identity_envelope())
    if case == "magic":
        blob = b"wrong magic"
    elif case == "encoding":
        blob = key_store_module._KEY_ENVELOPE_MAGIC + b"\xff"
    else:
        if case == "schema":
            envelope = []
        elif case == "version-type":
            envelope["version"] = True
        elif case == "version-value":
            envelope["version"] = 99
        elif case == "kdf-schema":
            envelope["kdf"] = []
        elif case == "kdf-id":
            envelope["kdf"]["id"] = "unknown"
        elif case == "cipher-schema":
            envelope["cipher"] = []
        elif case == "cipher-id":
            envelope["cipher"]["id"] = "unknown"
        blob = _identity_envelope_blob(envelope)

    with pytest.raises(ValueError, match=message):
        KeyStore._parse_identity_envelope(blob)


def test_key_store_invalid_tag_legacy_sizes_and_wrong_decrypted_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    salt = b"s" * 32
    nonce = b"n" * 12
    header = KeyStore._envelope_header(salt, nonce)
    aad = key_store_module._KEY_ENVELOPE_AAD_PREFIX + key_store_module._canonical_json(header)
    ciphertext = AESGCM(b"a" * 32).encrypt(nonce, b"p" * 32, aad)
    envelope = {
        **header,
        "cipher": {
            **header["cipher"],
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        },
    }
    monkeypatch.setattr(
        key_store_module,
        "_derive_scrypt_kek",
        lambda *_args: b"b" * 32,
    )
    assert KeyStore._decrypt_identity_envelope("wrong", _identity_envelope_blob(envelope)) is None

    assert KeyStore._decrypt_legacy_identity("pass", b"short", b"x" * 60) is None
    assert KeyStore._decrypt_legacy_identity("pass", b"s" * 32, b"x" * 59) is None

    class WrongLengthAESGCM:
        def __init__(self, _key: bytes) -> None:
            pass

        @staticmethod
        def decrypt(*_args: Any) -> bytes:
            return b"x" * 31

    monkeypatch.setattr(key_store_module, "AESGCM", WrongLengthAESGCM)
    monkeypatch.setattr(
        key_store_module,
        "_legacy_kek_candidates",
        lambda *_args: iter((b"k" * 32,)),
    )
    assert KeyStore._decrypt_legacy_identity("pass", b"s" * 32, b"x" * 60) is None


def test_key_store_optional_argon_backend_and_public_key_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class ArgonType:
        ID = "argon-id"

    def derive_argon(**kwargs: Any) -> bytes:
        calls.append(kwargs)
        return b"a" * 32

    monkeypatch.setattr(key_store_module, "_Argon2Type", ArgonType)
    monkeypatch.setattr(key_store_module, "_argon2_hash_secret_raw", derive_argon)
    assert key_store_module._derive_legacy_argon2id_kek("pass", b"s" * 32) == b"a" * 32
    assert calls[0]["type"] == "argon-id"

    empty = KeyStore(str(tmp_path / "empty"))
    assert empty.public_key_bytes == b""

    projected_dir = tmp_path / "projected"
    projected = KeyStore(str(projected_dir))
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    Path(projected._pub_path).write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    reopened = KeyStore(str(projected_dir))
    assert reopened.public_key_bytes == public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_key_store_locked_short_state_and_signature_failure_boundaries(tmp_path: Path) -> None:
    store = KeyStore(str(tmp_path / "keys"))
    assert store.unlock("missing") is False

    Path(store._identity_path).write_bytes(b"x" * 60)
    assert store.unlock("missing-salt") is False

    with pytest.raises(RuntimeError, match="locked"):
        store.sign(b"message")
    with pytest.raises(RuntimeError, match="locked"):
        store._state_encryption_key()
    with pytest.raises(RuntimeError, match="locked"):
        store.get_or_create_x25519_private_key()
    with pytest.raises(RuntimeError, match="locked"):
        store.create_session(x25519.X25519PrivateKey.generate().public_key().public_bytes_raw())

    private_key = _unlock_in_memory(store)
    assert store.verify(b"message", b"invalid-signature") is False
    signature = private_key.sign(b"message")
    assert store.verify(b"message", signature) is True

    short_state = base64.urlsafe_b64encode(b"short").decode("ascii")
    with pytest.raises(ValueError, match="invalid sealed state"):
        store.unseal_bytes(short_state)


def test_key_store_rejects_corrupt_or_inconsistent_x25519_storage(tmp_path: Path) -> None:
    encrypted_dir = tmp_path / "encrypted"
    encrypted_store = KeyStore(str(encrypted_dir))
    _unlock_in_memory(encrypted_store)
    Path(encrypted_store._x25519_path).write_text(
        encrypted_store.seal_bytes(b"short", aad=b"x25519-static-v1"),
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="invalid encrypted X25519 private key"):
        encrypted_store.get_or_create_x25519_private_key()

    invalid_legacy_dir = tmp_path / "invalid-legacy"
    invalid_legacy = KeyStore(str(invalid_legacy_dir))
    _unlock_in_memory(invalid_legacy)
    Path(invalid_legacy._legacy_x25519_path).write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="legacy C2 private key is not X25519"):
        invalid_legacy.get_or_create_x25519_private_key()

    mismatch_dir = tmp_path / "mismatch"
    mismatch = KeyStore(str(mismatch_dir))
    legacy_key = x25519.X25519PrivateKey.generate()
    Path(mismatch._legacy_x25519_path).write_bytes(
        legacy_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="does not match encrypted key"):
        mismatch._remove_matching_legacy_x25519_key(x25519.X25519PrivateKey.generate())

    wrong_type_dir = tmp_path / "wrong-type"
    wrong_type = KeyStore(str(wrong_type_dir))
    Path(wrong_type._legacy_x25519_path).write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="legacy C2 private key is not X25519"):
        wrong_type._remove_matching_legacy_x25519_key(x25519.X25519PrivateKey.generate())


def _fake_os_for_fsync(
    *,
    name: str = "posix",
    open_result: int | BaseException = 7,
    fsync_error: OSError | None = None,
    closed: list[int] | None = None,
) -> SimpleNamespace:
    def open_directory(_path: str, _flags: int) -> int:
        if isinstance(open_result, BaseException):
            raise open_result
        return open_result

    def fsync_directory(_descriptor: int) -> None:
        if fsync_error is not None:
            raise fsync_error

    def close_directory(descriptor: int) -> None:
        if closed is not None:
            closed.append(descriptor)

    return SimpleNamespace(
        name=name,
        path=os.path,
        O_RDONLY=os.O_RDONLY,
        O_DIRECTORY=getattr(os, "O_DIRECTORY", 0),
        open=open_directory,
        fsync=fsync_directory,
        close=close_directory,
    )


def test_key_store_parent_fsync_handles_platform_and_filesystem_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(key_store_module, "os", _fake_os_for_fsync(name="nt"))
        KeyStore._fsync_parent_directory("ignored")

    with monkeypatch.context() as context:
        context.setattr(
            key_store_module,
            "os",
            _fake_os_for_fsync(open_result=OSError(errno.EINVAL, "unsupported")),
        )
        KeyStore._fsync_parent_directory("ignored")

    with monkeypatch.context() as context:
        context.setattr(
            key_store_module,
            "os",
            _fake_os_for_fsync(open_result=OSError(errno.EACCES, "denied")),
        )
        with pytest.raises(OSError, match="denied"):
            KeyStore._fsync_parent_directory("ignored")

    closed: list[int] = []
    with monkeypatch.context() as context:
        context.setattr(
            key_store_module,
            "os",
            _fake_os_for_fsync(
                fsync_error=OSError(errno.EINVAL, "unsupported"),
                closed=closed,
            ),
        )
        KeyStore._fsync_parent_directory("ignored")
    assert closed == [7]

    closed.clear()
    with monkeypatch.context() as context:
        context.setattr(
            key_store_module,
            "os",
            _fake_os_for_fsync(
                fsync_error=OSError(errno.EIO, "I/O failure"),
                closed=closed,
            ),
        )
        with pytest.raises(OSError, match="I/O failure"):
            KeyStore._fsync_parent_directory("ignored")
    assert closed == [7]


def test_key_store_creates_forward_secret_session_and_derives_matching_key(
    tmp_path: Path,
) -> None:
    store = KeyStore(str(tmp_path / "keys"))
    store._unlocked = True
    client_private = x25519.X25519PrivateKey.generate()
    session = store.create_session(client_private.public_key().public_bytes_raw())

    server_ephemeral = x25519.X25519PublicKey.from_public_bytes(session["ephemeral_pub"])
    raw_shared = client_private.exchange(server_ephemeral)
    assert session["session_key"] == KeyStore.derive_session_key(raw_shared)
    assert len(session["ephemeral_pub"]) == 32
    assert len(session["session_key"]) == 32


def test_key_store_optional_argon_import_success_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_package = ModuleType("argon2")
    fake_package.__path__ = []
    fake_low_level = ModuleType("argon2.low_level")

    class FakeType:
        ID = "fake-id"

    fake_low_level.Type = FakeType
    fake_low_level.hash_secret_raw = lambda **_kwargs: b"f" * 32

    with monkeypatch.context() as context:
        context.setitem(sys.modules, "argon2", fake_package)
        context.setitem(sys.modules, "argon2.low_level", fake_low_level)
        reloaded = importlib.reload(key_store_module)
        assert reloaded._Argon2Type is FakeType
        assert reloaded._argon2_hash_secret_raw is fake_low_level.hash_secret_raw

    importlib.reload(key_store_module)
