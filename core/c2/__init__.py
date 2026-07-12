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

from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
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
]
