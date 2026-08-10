"""
Command & Control subsystem.

Components:
  - daemon: FastAPI listener + IPC control plane
  - crypto_engine: X25519 ECDH + HKDF + AES-GCM
  - db_backend: SQLite WAL projections
  - event_store: Append-only event sourcing
  - operators: RBAC with API key auth
  - builder: Garble-obfuscated Go implant builder
  - key_store: Encrypted key storage
"""

from core.c2 import evasion
from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.evasion import (
    aes_decrypt_payload,
    aes_encrypt_payload,
    base64_multilayer,
    base64_multilayer_decode,
    entropy_reduce,
    entropy_restore,
    generate_stager,
    polymorphic_wrapper,
    string_obfuscate,
    xor_encode,
)
from core.c2.event_store import Event, EventStore
from core.c2.key_store import KeyStore
from core.c2.operators import OperatorManager

__all__ = [
    "C2CryptoEngine",
    "C2Database",
    "Event",
    "EventStore",
    "KeyStore",
    "OperatorManager",
    "aes_decrypt_payload",
    "aes_encrypt_payload",
    "base64_multilayer",
    "base64_multilayer_decode",
    "entropy_reduce",
    "entropy_restore",
    "evasion",
    "generate_stager",
    "polymorphic_wrapper",
    "string_obfuscate",
    "xor_encode",
]
