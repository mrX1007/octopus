"""

Encrypted key storage with a versioned Scrypt key envelope.

Architecture:
  - Static Ed25519 identity key (signing/authentication only)
  - Ephemeral X25519 session keys (ECDH, in-memory only)
  - Server identity key encrypted on disk via a Scrypt-derived KEK
  - Decrypted key lives only in memory, zeroed on shutdown

NEVER stores decrypted keys in SQLite.
NEVER uses raw shared key as session key (always HKDF).
"""

import base64
import binascii
import errno
import hashlib
import json
import os
import secrets
from collections.abc import Iterator
from contextlib import suppress
from typing import Optional

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core.c2.protocol import C2_SESSION_KDF_CONTEXT

# Old, unversioned identity blobs selected a KDF from the import environment.
# These optional implementations exist only to recognize and migrate those
# blobs; all new envelopes use the mandatory Scrypt implementation above.
try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw
except ImportError:
    _Argon2Type = None
    _argon2_hash_secret_raw = None

_KEY_ENVELOPE_MAGIC = b"OCTOPUS-C2-KEY-ENVELOPE\n"
_KEY_ENVELOPE_VERSION = 1
_KEY_ENVELOPE_KDF_ID = "scrypt"
_KEY_ENVELOPE_KDF_PARAMS = {
    "length": 32,
    "n": 2**17,
    "p": 1,
    "r": 8,
}
_KEY_ENVELOPE_CIPHER_ID = "aes-256-gcm"
_KEY_ENVELOPE_AAD_PREFIX = b"octopus-c2-identity-key-envelope-v1\x00"
_MAX_KEY_ENVELOPE_BYTES = 4096


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _derive_scrypt_kek(passphrase: str, salt: bytes, params: dict) -> bytes:
    """Derive a KEK with the parameters recorded in a validated envelope."""
    return Scrypt(
        salt=salt,
        length=params["length"],
        n=params["n"],
        r=params["r"],
        p=params["p"],
    ).derive(passphrase.encode("utf-8"))


def _derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Derive the mandatory 32-byte Scrypt KEK for new key envelopes."""
    return _derive_scrypt_kek(passphrase, salt, _KEY_ENVELOPE_KDF_PARAMS)


def _derive_legacy_argon2id_kek(passphrase: str, salt: bytes) -> bytes:
    """Reproduce the historical Argon2id settings when an implementation exists."""
    passphrase_bytes = passphrase.encode("utf-8")
    if _argon2_hash_secret_raw is not None and _Argon2Type is not None:
        return _argon2_hash_secret_raw(
            secret=passphrase_bytes,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=_Argon2Type.ID,
        )
    return Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=1,
        memory_cost=65536,
    ).derive(passphrase_bytes)


def _legacy_kek_candidates(passphrase: str, salt: bytes) -> Iterator[bytes]:
    """Yield each KEK that the historical environment-dependent code could use."""
    with suppress(UnsupportedAlgorithm):
        yield _derive_kek(passphrase, salt)
    yield hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, 600000, dklen=32
    )
    with suppress(UnsupportedAlgorithm):
        yield _derive_legacy_argon2id_kek(passphrase, salt)


def _wipe_bytes(data: bytearray):
    """Zero out a mutable byte buffer."""
    for i in range(len(data)):
        data[i] = 0


class KeyStore:
    """
    Manages the server's cryptographic identity.

    - Ed25519 static key: identity/signing (encrypted on disk)
    - X25519 ephemeral keys: per-session ECDH (in-memory only)
    - HKDF for all key derivation

    Usage:
        ks = KeyStore("data/keys")
        ks.unlock("my-passphrase")  # Decrypt identity key into memory
        session_key = ks.create_session(client_x25519_pub_bytes)
        ks.lock()  # Zero identity key from memory
    """

    def __init__(self, key_dir: str = "data/keys"):
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)

        self._identity_path = os.path.join(key_dir, "identity.enc")
        self._salt_path = os.path.join(key_dir, "identity.salt")
        self._pub_path = os.path.join(key_dir, "identity_pub.pem")
        self._x25519_path = os.path.join(key_dir, "server_x25519_private.enc")
        self._x25519_pub_path = os.path.join(key_dir, "server_x25519_public.pem")
        self._legacy_x25519_path = os.path.join(key_dir, "server_x25519_private.pem")

        # In-memory only — never persisted
        self._ed25519_private: ed25519.Ed25519PrivateKey = None
        self._ed25519_public: ed25519.Ed25519PublicKey = None
        self._unlocked = False

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    @property
    def public_key_bytes(self) -> bytes:
        """Return the raw Ed25519 public key bytes (always available)."""
        if self._ed25519_public is None:
            if os.path.exists(self._pub_path):
                with open(self._pub_path, "rb") as f:
                    self._ed25519_public = serialization.load_pem_public_key(f.read())
            else:
                return b""
        return self._ed25519_public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def exists(self) -> bool:
        """Check if an identity key has been generated."""
        return os.path.exists(self._identity_path)

    @staticmethod
    def _envelope_header(salt: bytes, nonce: bytes) -> dict:
        return {
            "cipher": {
                "id": _KEY_ENVELOPE_CIPHER_ID,
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "kdf": {
                "id": _KEY_ENVELOPE_KDF_ID,
                "params": dict(_KEY_ENVELOPE_KDF_PARAMS),
                "salt": base64.b64encode(salt).decode("ascii"),
            },
            "version": _KEY_ENVELOPE_VERSION,
        }

    @staticmethod
    def _decode_envelope_bytes(value: object, field: str, length: int) -> bytes:
        if not isinstance(value, str):
            raise ValueError(f"invalid key envelope {field}")
        try:
            decoded = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
            raise ValueError(f"invalid key envelope {field}") from exc
        if len(decoded) != length:
            raise ValueError(f"invalid key envelope {field}")
        return decoded

    @classmethod
    def _parse_identity_envelope(
        cls, blob: bytes
    ) -> tuple[bytes, bytes, bytes, bytes]:
        if not blob.startswith(_KEY_ENVELOPE_MAGIC):
            raise ValueError("invalid key envelope magic")
        try:
            envelope = json.loads(blob[len(_KEY_ENVELOPE_MAGIC):].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("invalid key envelope encoding") from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "cipher",
            "kdf",
            "version",
        }:
            raise ValueError("invalid key envelope schema")
        if (
            type(envelope["version"]) is not int
            or envelope["version"] != _KEY_ENVELOPE_VERSION
        ):
            raise ValueError("unsupported key envelope version")

        kdf = envelope["kdf"]
        cipher = envelope["cipher"]
        if not isinstance(kdf, dict) or set(kdf) != {"id", "params", "salt"}:
            raise ValueError("invalid key envelope KDF")
        if kdf["id"] != _KEY_ENVELOPE_KDF_ID:
            raise ValueError("unsupported key envelope KDF")
        params = kdf["params"]
        if (
            not isinstance(params, dict)
            or set(params) != set(_KEY_ENVELOPE_KDF_PARAMS)
            or any(type(value) is not int for value in params.values())
            or params != _KEY_ENVELOPE_KDF_PARAMS
        ):
            raise ValueError("unsupported key envelope KDF parameters")
        if not isinstance(cipher, dict) or set(cipher) != {
            "ciphertext",
            "id",
            "nonce",
        }:
            raise ValueError("invalid key envelope cipher")
        if cipher["id"] != _KEY_ENVELOPE_CIPHER_ID:
            raise ValueError("unsupported key envelope cipher")

        salt = cls._decode_envelope_bytes(kdf["salt"], "salt", 32)
        nonce = cls._decode_envelope_bytes(cipher["nonce"], "nonce", 12)
        ciphertext = cls._decode_envelope_bytes(
            cipher["ciphertext"], "ciphertext", 48
        )
        header = cls._envelope_header(salt, nonce)
        aad = _KEY_ENVELOPE_AAD_PREFIX + _canonical_json(header)
        return salt, nonce, ciphertext, aad

    @classmethod
    def _encrypt_identity_envelope(
        cls, passphrase: str, salt: bytes, private_bytes: bytes
    ) -> bytes:
        nonce = secrets.token_bytes(12)
        header = cls._envelope_header(salt, nonce)
        aad = _KEY_ENVELOPE_AAD_PREFIX + _canonical_json(header)
        kek = _derive_kek(passphrase, salt)
        try:
            ciphertext = AESGCM(kek).encrypt(nonce, private_bytes, aad)
        finally:
            kek_mut = bytearray(kek)
            _wipe_bytes(kek_mut)
        envelope = {
            **header,
            "cipher": {
                **header["cipher"],
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        }
        return _KEY_ENVELOPE_MAGIC + _canonical_json(envelope)

    @classmethod
    def _decrypt_identity_envelope(
        cls, passphrase: str, blob: bytes
    ) -> Optional[bytes]:
        salt, nonce, ciphertext, aad = cls._parse_identity_envelope(blob)
        kek = _derive_scrypt_kek(passphrase, salt, _KEY_ENVELOPE_KDF_PARAMS)
        try:
            return AESGCM(kek).decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            return None
        finally:
            kek_mut = bytearray(kek)
            _wipe_bytes(kek_mut)

    @staticmethod
    def _decrypt_legacy_identity(
        passphrase: str, salt: bytes, blob: bytes
    ) -> Optional[bytes]:
        if len(salt) != 32 or len(blob) != 60:
            return None
        nonce = blob[:12]
        ciphertext = blob[12:]
        for kek in _legacy_kek_candidates(passphrase, salt):
            try:
                private_bytes = AESGCM(kek).decrypt(nonce, ciphertext, None)
            except InvalidTag:
                continue
            finally:
                kek_mut = bytearray(kek)
                _wipe_bytes(kek_mut)
            if len(private_bytes) == 32:
                return private_bytes
        return None

    def generate(self, passphrase: str):
        """Generate an Ed25519 identity and persist a versioned key envelope."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        try:
            salt = secrets.token_bytes(32)
            envelope = self._encrypt_identity_envelope(
                passphrase, salt, priv_bytes
            )
            self._atomic_write(self._identity_path, envelope, 0o600)
            # Retain the historical sidecar for filesystem compatibility. The
            # v1 envelope is self-contained and never reads this copy.
            self._atomic_write(self._salt_path, salt, 0o600)
            self._atomic_write(
                self._pub_path,
                public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                0o644,
            )
        finally:
            priv_mut = bytearray(priv_bytes)
            _wipe_bytes(priv_mut)

        self._ed25519_private = private_key
        self._ed25519_public = public_key
        self._unlocked = True

    def unlock(self, passphrase: str) -> bool:
        """Decrypt the identity key and migrate a recognized legacy blob."""
        if not self.exists():
            return False
        with open(self._identity_path, "rb") as handle:
            blob = handle.read(_MAX_KEY_ENVELOPE_BYTES + 1)
        if len(blob) > _MAX_KEY_ENVELOPE_BYTES:
            return False

        legacy = not blob.startswith(_KEY_ENVELOPE_MAGIC)
        try:
            if legacy:
                if not os.path.exists(self._salt_path):
                    return False
                with open(self._salt_path, "rb") as handle:
                    salt = handle.read()
                priv_bytes = self._decrypt_legacy_identity(passphrase, salt, blob)
            else:
                priv_bytes = self._decrypt_identity_envelope(passphrase, blob)
        except ValueError:
            return False
        if priv_bytes is None:
            return False

        try:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
            if legacy:
                migrated = self._encrypt_identity_envelope(
                    passphrase, salt, priv_bytes
                )
                self._atomic_write(self._identity_path, migrated, 0o600)
            self._ed25519_private = private_key
            self._ed25519_public = private_key.public_key()
            self._unlocked = True
            return True
        finally:
            priv_mut = bytearray(priv_bytes)
            _wipe_bytes(priv_mut)

    def lock(self):
        """Zero the identity key from memory."""
        self._ed25519_private = None
        self._unlocked = False

    def sign(self, data: bytes) -> bytes:
        """Sign data with the Ed25519 identity key."""
        if not self._unlocked:
            raise RuntimeError("KeyStore is locked")
        return self._ed25519_private.sign(data)

    def _state_encryption_key(self) -> bytes:
        if not self._unlocked or self._ed25519_private is None:
            raise RuntimeError("KeyStore is locked")
        private_bytes = self._ed25519_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        try:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"octopus-c2-state-v1",
            ).derive(private_bytes)
        finally:
            private_mut = bytearray(private_bytes)
            _wipe_bytes(private_mut)

    def seal_bytes(self, value: bytes, aad: bytes = b"") -> str:
        """Encrypt sensitive runtime state for persistence."""
        key = self._state_encryption_key()
        try:
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(key).encrypt(nonce, value, aad)
            return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        finally:
            key_mut = bytearray(key)
            _wipe_bytes(key_mut)

    def unseal_bytes(self, value: str, aad: bytes = b"") -> bytes:
        """Decrypt state produced by :meth:`seal_bytes`."""
        key = self._state_encryption_key()
        try:
            blob = base64.urlsafe_b64decode(value.encode("ascii"))
            if len(blob) < 29:
                raise ValueError("invalid sealed state")
            return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
        finally:
            key_mut = bytearray(key)
            _wipe_bytes(key_mut)

    def seal_json(self, value: dict, aad: bytes = b"") -> str:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return self.seal_bytes(payload, aad=aad)

    def unseal_json(self, value: str, aad: bytes = b"") -> dict:
        return json.loads(self.unseal_bytes(value, aad=aad).decode("utf-8"))

    @staticmethod
    def _x25519_public_pem(
        private_key: x25519.X25519PrivateKey,
    ) -> bytes:
        return private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _repair_x25519_public_key(
        self, private_key: x25519.X25519PrivateKey
    ) -> None:
        expected = self._x25519_public_pem(private_key)
        try:
            with open(self._x25519_pub_path, "rb") as handle:
                current = handle.read()
        except FileNotFoundError:
            current = None
        if current != expected:
            self._atomic_write(self._x25519_pub_path, expected, 0o644)

    def _remove_matching_legacy_x25519_key(
        self, private_key: x25519.X25519PrivateKey
    ) -> None:
        if not os.path.exists(self._legacy_x25519_path):
            return
        with open(self._legacy_x25519_path, "rb") as handle:
            legacy = serialization.load_pem_private_key(
                handle.read(), password=None
            )
        if not isinstance(legacy, x25519.X25519PrivateKey):
            raise ValueError("legacy C2 private key is not X25519")
        expected_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        legacy_public = legacy.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if not secrets.compare_digest(expected_public, legacy_public):
            raise ValueError(
                "legacy C2 private key does not match encrypted key"
            )
        self._durable_remove(self._legacy_x25519_path)

    def get_or_create_x25519_private_key(self) -> x25519.X25519PrivateKey:
        """Load the C2 handshake key from encrypted storage or create it.

        Existing plaintext PEM keys are migrated once and removed only after
        the encrypted replacement and matching public key have been written.
        """
        if not self._unlocked:
            raise RuntimeError("KeyStore is locked")

        if os.path.exists(self._x25519_path):
            with open(self._x25519_path, encoding="ascii") as handle:
                raw = self.unseal_bytes(handle.read(), aad=b"x25519-static-v1")
            try:
                if len(raw) != 32:
                    raise ValueError("invalid encrypted X25519 private key")
                private_key = x25519.X25519PrivateKey.from_private_bytes(raw)
            finally:
                raw_mut = bytearray(raw)
                _wipe_bytes(raw_mut)
            # A previous migration may have stopped after committing the
            # encrypted key. Repair its public projection and finish removing
            # a matching plaintext predecessor on every subsequent load.
            self._repair_x25519_public_key(private_key)
            self._remove_matching_legacy_x25519_key(private_key)
            return private_key

        if os.path.exists(self._legacy_x25519_path):
            with open(self._legacy_x25519_path, "rb") as handle:
                loaded = serialization.load_pem_private_key(
                    handle.read(), password=None
                )
            if not isinstance(loaded, x25519.X25519PrivateKey):
                raise ValueError("legacy C2 private key is not X25519")
            private_key = loaded
        else:
            private_key = x25519.X25519PrivateKey.generate()

        raw_private = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        try:
            sealed = self.seal_bytes(raw_private, aad=b"x25519-static-v1")
            self._atomic_write(
                self._x25519_path, sealed.encode("ascii"), 0o600
            )
            self._repair_x25519_public_key(private_key)
            self._remove_matching_legacy_x25519_key(private_key)
            return private_key
        finally:
            raw_mut = bytearray(raw_private)
            _wipe_bytes(raw_mut)

    @staticmethod
    def _fsync_parent_directory(path: str) -> None:
        """Persist a rename/unlink directory entry where the platform allows it."""
        if os.name == "nt":
            return
        directory = os.path.dirname(os.path.abspath(path))
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        unsupported = {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        try:
            descriptor = os.open(directory, flags)
        except OSError as exc:
            if exc.errno in unsupported:
                return
            raise
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                if exc.errno not in unsupported:
                    raise
        finally:
            os.close(descriptor)

    @staticmethod
    def _durable_remove(path: str) -> None:
        os.remove(path)
        KeyStore._fsync_parent_directory(path)

    @staticmethod
    def _atomic_write(path: str, payload: bytes, mode: int) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        temporary = os.path.join(
            directory,
            f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp",
        )
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            KeyStore._fsync_parent_directory(path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against the Ed25519 public key."""
        try:
            self._ed25519_public.verify(signature, data)
            return True
        except Exception:
            return False

    def create_session(self, client_x25519_pub_bytes: bytes) -> dict:
        """
        Create an ephemeral X25519 session.

        Returns:
            {
                "ephemeral_pub": bytes,  # Our ephemeral X25519 public key (send to client)
                "session_key": bytes,    # HKDF-derived 32-byte session key
            }

        The ephemeral private key is generated, used for ECDH, then discarded.
        This provides forward secrecy: compromising the identity key
        does NOT compromise past sessions.
        """
        if not self._unlocked:
            raise RuntimeError("KeyStore is locked")

        # Generate ephemeral X25519 keypair (lives only for this call)
        eph_private = x25519.X25519PrivateKey.generate()
        eph_public = eph_private.public_key()

        # Perform ECDH
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_x25519_pub_bytes)
        raw_shared = eph_private.exchange(client_pub)

        # HKDF derivation — NEVER use raw shared key directly
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=C2_SESSION_KDF_CONTEXT,
        ).derive(raw_shared)

        eph_pub_bytes = eph_public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

        # Wipe the raw shared key
        raw_mut = bytearray(raw_shared)
        _wipe_bytes(raw_mut)

        return {
            "ephemeral_pub": eph_pub_bytes,
            "session_key": session_key,
        }

    @staticmethod
    def derive_session_key(raw_shared: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Standalone HKDF derivation for use outside create_session().
        For example, when the implant sends its X25519 pub and we need
        to derive from the static server key (backward compat).
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=C2_SESSION_KDF_CONTEXT,
        ).derive(raw_shared)
