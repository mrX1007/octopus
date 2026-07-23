"""Regression coverage for C2 key-at-rest compatibility boundaries."""

import base64
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core.c2 import key_store as key_store_module
from core.c2.crypto_engine import C2CryptoEngine
from core.c2.key_store import KeyStore

pytestmark = [pytest.mark.contract, pytest.mark.security, pytest.mark.slow]


_ENVELOPE_MAGIC = b"OCTOPUS-C2-KEY-ENVELOPE\n"
_PASSPHRASE = "legacy fixture passphrase"
_LEGACY_PRIVATE_BYTES = bytes(range(32))
_LEGACY_SALT = bytes(range(32, 64))
_LEGACY_NONCE = bytes(range(12))


def _legacy_kek(kdf_id: str) -> bytes:
    password = _PASSPHRASE.encode("utf-8")
    if kdf_id == "scrypt":
        return Scrypt(
            salt=_LEGACY_SALT,
            length=32,
            n=2**17,
            r=8,
            p=1,
        ).derive(password)
    if kdf_id == "pbkdf2-sha256":
        return hashlib.pbkdf2_hmac(
            "sha256", password, _LEGACY_SALT, 600000, dklen=32
        )
    if kdf_id == "argon2id":
        return Argon2id(
            salt=_LEGACY_SALT,
            length=32,
            iterations=3,
            lanes=1,
            memory_cost=65536,
        ).derive(password)
    raise AssertionError(f"unknown test KDF: {kdf_id}")


def _write_legacy_identity(key_dir: Path, kdf_id: str) -> bytes:
    key_dir.mkdir(parents=True, exist_ok=True)
    ciphertext = AESGCM(_legacy_kek(kdf_id)).encrypt(
        _LEGACY_NONCE, _LEGACY_PRIVATE_BYTES, None
    )
    blob = _LEGACY_NONCE + ciphertext
    (key_dir / "identity.enc").write_bytes(blob)
    (key_dir / "identity.salt").write_bytes(_LEGACY_SALT)
    return blob


def _read_envelope(path: Path) -> dict:
    payload = path.read_bytes()
    assert payload.startswith(_ENVELOPE_MAGIC)
    return json.loads(payload[len(_ENVELOPE_MAGIC):])


def test_generated_identity_uses_self_contained_versioned_scrypt_envelope(
    tmp_path, monkeypatch
):
    key_dir = tmp_path / "keys"
    store = KeyStore(str(key_dir))
    store.generate(_PASSPHRASE)
    public_key = store.public_key_bytes

    envelope = _read_envelope(key_dir / "identity.enc")

    assert envelope["version"] == 1
    assert envelope["kdf"] == {
        "id": "scrypt",
        "params": {"length": 32, "n": 2**17, "p": 1, "r": 8},
        "salt": envelope["kdf"]["salt"],
    }
    assert len(base64.b64decode(envelope["kdf"]["salt"], validate=True)) == 32
    assert envelope["cipher"]["id"] == "aes-256-gcm"
    assert b"PRIVATE KEY" not in (key_dir / "identity.enc").read_bytes()

    # The historical salt sidecar is retained for old filesystem layouts, but
    # the new envelope must remain readable without it.
    (key_dir / "identity.salt").unlink()
    reopened = KeyStore(str(key_dir))
    assert reopened.unlock(_PASSPHRASE) is True
    assert reopened.public_key_bytes == public_key
    signature = reopened.sign(b"versioned-envelope-control")
    assert reopened.verify(b"versioned-envelope-control", signature) is True

    envelope["kdf"]["params"]["n"] = 2**30
    (key_dir / "identity.enc").write_bytes(
        _ENVELOPE_MAGIC
        + json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
    )

    def unexpected_derivation(*args, **kwargs):
        raise AssertionError("untrusted KDF parameters must be rejected first")

    monkeypatch.setattr(
        key_store_module, "_derive_scrypt_kek", unexpected_derivation
    )
    assert KeyStore(str(key_dir)).unlock(_PASSPHRASE) is False


@pytest.mark.parametrize(
    "legacy_kdf",
    ["scrypt", "pbkdf2-sha256", "argon2id"],
)
def test_legacy_kdf_is_autodetected_and_atomically_rewritten(
    tmp_path, monkeypatch, legacy_kdf
):
    key_dir = tmp_path / "keys"
    legacy_blob = _write_legacy_identity(key_dir, legacy_kdf)
    expected_public = ed25519.Ed25519PrivateKey.from_private_bytes(
        _LEGACY_PRIVATE_BYTES
    ).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    store = KeyStore(str(key_dir))
    assert store.unlock(_PASSPHRASE) is True
    assert store.public_key_bytes == expected_public
    assert (key_dir / "identity.enc").read_bytes() != legacy_blob
    assert _read_envelope(key_dir / "identity.enc")["kdf"]["id"] == "scrypt"
    assert list(key_dir.glob(".identity.enc.*.tmp")) == []

    def unexpected_legacy_detection(*args, **kwargs):
        raise AssertionError("rewritten envelopes must not re-run legacy detection")

    monkeypatch.setattr(
        key_store_module,
        "_legacy_kek_candidates",
        unexpected_legacy_detection,
    )
    reopened = KeyStore(str(key_dir))
    assert reopened.unlock(_PASSPHRASE) is True
    assert reopened.public_key_bytes == expected_public


def test_failed_legacy_rewrite_preserves_original_blob(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    legacy_blob = _write_legacy_identity(key_dir, "scrypt")
    real_replace = key_store_module.os.replace

    def fail_identity_replace(source, destination):
        if destination == str(key_dir / "identity.enc"):
            raise OSError("simulated atomic replace failure")
        return real_replace(source, destination)

    monkeypatch.setattr(key_store_module.os, "replace", fail_identity_replace)
    store = KeyStore(str(key_dir))
    with pytest.raises(OSError, match="simulated atomic replace failure"):
        store.unlock(_PASSPHRASE)

    assert store.is_unlocked is False
    assert (key_dir / "identity.enc").read_bytes() == legacy_blob
    assert list(key_dir.glob(".identity.enc.*.tmp")) == []


@pytest.mark.parametrize(
    "blob",
    [
        _ENVELOPE_MAGIC + (b"[" * 1100) + (b"]" * 1100),
        _ENVELOPE_MAGIC + b"{}" + (b" " * 4096),
    ],
    ids=["deeply-nested-json", "oversized-envelope"],
)
def test_malformed_envelope_is_rejected_before_kdf(
    tmp_path, monkeypatch, blob
):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "identity.enc").write_bytes(blob)

    def unexpected_derivation(*args, **kwargs):
        raise AssertionError("malformed envelopes must not reach the KDF")

    monkeypatch.setattr(
        key_store_module, "_derive_scrypt_kek", unexpected_derivation
    )

    assert KeyStore(str(key_dir)).unlock(_PASSPHRASE) is False


def test_unsupported_legacy_argon_backend_is_skipped(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "identity.enc").write_bytes(b"x" * 60)
    (key_dir / "identity.salt").write_bytes(b"s" * 32)

    monkeypatch.setattr(key_store_module, "_derive_kek", lambda *args: b"a" * 32)
    monkeypatch.setattr(
        key_store_module.hashlib,
        "pbkdf2_hmac",
        lambda *args, **kwargs: b"b" * 32,
    )
    monkeypatch.setattr(key_store_module, "_argon2_hash_secret_raw", None)
    monkeypatch.setattr(key_store_module, "_Argon2Type", None)

    def unsupported_argon2(**kwargs):
        raise UnsupportedAlgorithm("Argon2 is unavailable")

    monkeypatch.setattr(key_store_module, "Argon2id", unsupported_argon2)

    assert KeyStore(str(key_dir)).unlock(_PASSPHRASE) is False


def test_partial_x25519_migration_is_repaired_on_retry(tmp_path, monkeypatch):
    key_dir = tmp_path / "keys"
    identity_key = ed25519.Ed25519PrivateKey.generate()
    legacy_key = x25519.X25519PrivateKey.generate()
    legacy_path = key_dir / "server_x25519_private.pem"
    key_dir.mkdir()
    legacy_path.write_bytes(
        legacy_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    store = KeyStore(str(key_dir))
    store._ed25519_private = identity_key
    store._ed25519_public = identity_key.public_key()
    store._unlocked = True
    real_atomic_write = store._atomic_write

    def fail_public_write(path, payload, mode):
        if path == str(key_dir / "server_x25519_public.pem"):
            raise OSError("simulated public-key projection failure")
        return real_atomic_write(path, payload, mode)

    monkeypatch.setattr(store, "_atomic_write", fail_public_write)
    with pytest.raises(OSError, match="projection failure"):
        store.get_or_create_x25519_private_key()

    assert (key_dir / "server_x25519_private.enc").exists()
    assert legacy_path.exists()
    assert not (key_dir / "server_x25519_public.pem").exists()

    reopened = KeyStore(str(key_dir))
    reopened._ed25519_private = identity_key
    reopened._ed25519_public = identity_key.public_key()
    reopened._unlocked = True
    recovered = reopened.get_or_create_x25519_private_key()

    assert recovered.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ) == legacy_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert (key_dir / "server_x25519_public.pem").exists()
    assert not legacy_path.exists()


def test_atomic_replace_and_remove_fsync_parent_directory(tmp_path, monkeypatch):
    real_fsync = key_store_module.os.fsync
    fsynced_kinds = []

    def tracking_fsync(descriptor):
        mode = os.fstat(descriptor).st_mode
        fsynced_kinds.append("directory" if stat.S_ISDIR(mode) else "file")
        return real_fsync(descriptor)

    monkeypatch.setattr(key_store_module.os, "fsync", tracking_fsync)
    target = tmp_path / "durable-key"

    KeyStore._atomic_write(str(target), b"encrypted", 0o600)
    assert fsynced_kinds == ["file", "directory"]

    fsynced_kinds.clear()
    KeyStore._durable_remove(str(target))
    assert fsynced_kinds == ["directory"]


def test_crypto_engine_never_implicitly_creates_plaintext_private_pem(tmp_path):
    key_dir = tmp_path / "keys"

    with pytest.raises(RuntimeError, match="explicit X25519 private key"):
        C2CryptoEngine(str(key_dir))

    assert not (key_dir / "server_x25519_private.pem").exists()
    assert not (key_dir / "server_x25519_public.pem").exists()


def test_crypto_engine_accepts_explicit_keystore_owned_private_key(tmp_path):
    key_dir = tmp_path / "keys"
    private_key = x25519.X25519PrivateKey.generate()

    engine = C2CryptoEngine(str(key_dir), private_key=private_key)

    assert engine.private_key is private_key
    assert engine.public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert list(key_dir.iterdir()) == []


def test_crypto_engine_can_read_but_does_not_rewrite_existing_legacy_pem(tmp_path):
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    private_key = x25519.X25519PrivateKey.generate()
    legacy_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    legacy_path = key_dir / "server_x25519_private.pem"
    legacy_path.write_bytes(legacy_pem)

    engine = C2CryptoEngine(str(key_dir))

    assert engine.private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ) == private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert legacy_path.read_bytes() == legacy_pem
    assert not (key_dir / "server_x25519_public.pem").exists()
