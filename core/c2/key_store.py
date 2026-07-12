"""

Encrypted Key Storage with Argon2id KDF.

Architecture:
  - Static Ed25519 identity key (signing/authentication only)
  - Ephemeral X25519 session keys (ECDH, in-memory only)
  - Server identity key encrypted on disk via Argon2id-derived KEK
  - Decrypted key lives only in memory, zeroed on shutdown

NEVER stores decrypted keys in SQLite.
NEVER uses raw shared key as session key (always HKDF).
"""

import base64
import json
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Argon2id — try argon2-cffi first, fallback to cryptography's Scrypt
try:
    from argon2.low_level import Type, hash_secret_raw
    _ARGON2_OK = True
except ImportError:
    _ARGON2_OK = False

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as _Scrypt
    _SCRYPT_OK = True
except ImportError:
    _SCRYPT_OK = False


def _derive_kek(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte Key Encryption Key from passphrase using Argon2id."""
    passphrase_bytes = passphrase.encode('utf-8')

    if _ARGON2_OK:
        # Argon2id: 64MB memory, 3 iterations, 1 parallelism
        return hash_secret_raw(
            secret=passphrase_bytes,
            salt=salt,
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=1,
            hash_len=32,
            type=Type.ID
        )
    elif _SCRYPT_OK:
        # Fallback: Scrypt via cryptography lib (still better than PBKDF2)
        kdf = _Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
        return kdf.derive(passphrase_bytes)
    else:
        # Last resort: PBKDF2 with high iterations
        import hashlib
        return hashlib.pbkdf2_hmac('sha256', passphrase_bytes, salt, 600000, dklen=32)


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

    def generate(self, passphrase: str):
        """Generate a new Ed25519 identity and encrypt it to disk."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize private key to raw bytes
        priv_bytes = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )

        # Derive KEK from passphrase
        salt = secrets.token_bytes(32)
        kek = _derive_kek(passphrase, salt)

        # Encrypt private key with AES-256-GCM
        aesgcm = AESGCM(kek)
        nonce = secrets.token_bytes(12)
        encrypted = aesgcm.encrypt(nonce, priv_bytes, None)

        # Write encrypted blob: nonce || ciphertext
        with open(self._identity_path, "wb") as f:
            f.write(nonce + encrypted)
        os.chmod(self._identity_path, 0o600)

        # Write salt separately
        with open(self._salt_path, "wb") as f:
            f.write(salt)
        os.chmod(self._salt_path, 0o600)

        # Write public key as PEM (not secret)
        with open(self._pub_path, "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        os.chmod(self._pub_path, 0o644)

        # Load into memory
        self._ed25519_private = private_key
        self._ed25519_public = public_key
        self._unlocked = True

        # Wipe intermediate buffers
        priv_mut = bytearray(priv_bytes)
        _wipe_bytes(priv_mut)
        kek_mut = bytearray(kek)
        _wipe_bytes(kek_mut)

    def unlock(self, passphrase: str) -> bool:
        """Decrypt the identity key into memory. Returns True on success."""
        if not self.exists():
            return False

        with open(self._salt_path, "rb") as f:
            salt = f.read()
        with open(self._identity_path, "rb") as f:
            blob = f.read()

        nonce = blob[:12]
        ciphertext = blob[12:]

        kek = _derive_kek(passphrase, salt)

        try:
            aesgcm = AESGCM(kek)
            priv_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return False
        finally:
            kek_mut = bytearray(kek)
            _wipe_bytes(kek_mut)

        self._ed25519_private = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        self._ed25519_public = self._ed25519_private.public_key()
        self._unlocked = True

        priv_mut = bytearray(priv_bytes)
        _wipe_bytes(priv_mut)
        return True

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
            if len(raw) != 32:
                raise ValueError("invalid encrypted X25519 private key")
            return x25519.X25519PrivateKey.from_private_bytes(raw)

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
        sealed = self.seal_bytes(raw_private, aad=b"x25519-static-v1")
        self._atomic_write(self._x25519_path, sealed.encode("ascii"), 0o600)
        self._atomic_write(
            self._x25519_pub_path,
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            0o644,
        )

        if os.path.exists(self._legacy_x25519_path):
            os.remove(self._legacy_x25519_path)
        raw_mut = bytearray(raw_private)
        _wipe_bytes(raw_mut)
        return private_key

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
            info=b"octopus-session-v10",
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
            info=b"octopus-session-v10",
        ).derive(raw_shared)
