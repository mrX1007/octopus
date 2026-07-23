
import base64
import os
import struct
import threading
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.c2.protocol import C2_SESSION_KDF_CONTEXT


class C2CryptoEngine:
    """
    Manages per-agent session cryptography.

    Key derivation uses HKDF-SHA256. Raw ECDH output is NEVER used directly.
    Sequence numbers in AAD provide replay protection.
    """

    def __init__(self, key_dir: str = "data/keys", private_key=None):
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)

        # Legacy X25519 key pair retained for existing implants.
        self._legacy_priv_path = os.path.join(key_dir, "server_x25519_private.pem")
        self._legacy_pub_path = os.path.join(key_dir, "server_x25519_public.pem")
        self.private_key = private_key
        if private_key is not None:
            if not isinstance(private_key, x25519.X25519PrivateKey):
                raise TypeError("private_key must be an X25519 private key")
            self.public_key = private_key.public_key()
        else:
            self.public_key = None
            self._load_legacy_private_key()

        # agent_id -> {"key": bytes, "rx_seq": int, "tx_seq": int, "epoch": int}
        self.agent_state: dict[str, dict[str, Any]] = {}
        self._state_lock = threading.RLock()

    def _load_legacy_private_key(self):
        """Load an existing legacy key, but never create plaintext key material."""
        if not os.path.exists(self._legacy_priv_path):
            raise RuntimeError(
                "C2CryptoEngine requires an explicit X25519 private key; "
                "load or create it with an unlocked KeyStore"
            )
        with open(self._legacy_priv_path, "rb") as handle:
            loaded = serialization.load_pem_private_key(
                handle.read(), password=None
            )
        if not isinstance(loaded, x25519.X25519PrivateKey):
            raise ValueError("legacy C2 private key is not X25519")
        self.private_key = loaded
        self.public_key = loaded.public_key()

    def derive_shared_key(self, client_pub_bytes: bytes) -> bytes:
        """
        Derive session key from client's X25519 public key.
        Uses HKDF — raw ECDH output is never used directly.
        """
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
        raw_shared = self.private_key.exchange(client_pub)

        # HKDF derivation
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=C2_SESSION_KDF_CONTEXT,
        ).derive(raw_shared)

        return session_key

    def decrypt_aes_gcm(self, agent_id: str, b64_ciphertext: str) -> str:
        """Decrypt with Replay Protection via AAD Sequence Numbers."""
        with self._state_lock:
            if agent_id not in self.agent_state:
                raise ValueError("Agent crypto state not found")

            state = self.agent_state[agent_id]
            ciphertext = base64.b64decode(b64_ciphertext, validate=True)
            if len(ciphertext) < 8 + 12 + 16:
                raise ValueError("Malformed ciphertext")

            # Format: [8 bytes seq][12 bytes nonce][ciphertext][16 bytes tag]
            seq_bytes = ciphertext[:8]
            nonce = ciphertext[8:20]
            data = ciphertext[20:-16]
            tag = ciphertext[-16:]

            rx_seq = struct.unpack("<Q", seq_bytes)[0]
            if rx_seq <= state["rx_seq"]:
                raise ValueError("Replay detected")

            aesgcm = AESGCM(state["key"])
            plaintext = aesgcm.decrypt(nonce, data + tag, seq_bytes)

            state["rx_seq"] = rx_seq
            return plaintext.decode('utf-8')

    def encrypt_aes_gcm(self, agent_id: str, plaintext: str) -> str:
        """Encrypt and inject monotonic sequence into AAD."""
        with self._state_lock:
            if agent_id not in self.agent_state:
                raise ValueError("Agent crypto state not found")

            state = self.agent_state[agent_id]
            state["tx_seq"] += 1
            seq_bytes = struct.pack("<Q", state["tx_seq"])

            nonce = os.urandom(12)
            aesgcm = AESGCM(state["key"])
            ct_with_tag = aesgcm.encrypt(
                nonce,
                plaintext.encode("utf-8"),
                seq_bytes,
            )
            full_payload = seq_bytes + nonce + ct_with_tag

            return base64.b64encode(full_payload).decode("utf-8")
