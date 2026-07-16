#!/usr/bin/env python3
"""
Unified Credential Store.

Single source of truth that synchronizes:
  1. In-memory cache (_KNOWN_CREDS in exploit_tools.py)  — fast session lookups
  2. MariaDB `credentials` table (db.py)                 — persistent storage
  3. Knowledge Graph (core/knowledge/graph.py)            — relationship mapping

Usage:
    from core.credentials import CredentialStore

    creds = CredentialStore.instance()   # singleton
    creds.add("ssh", "10.0.0.1", "root", "fixture-password", source="bruteforce")
    creds.get("ssh", "10.0.0.1")         # → [("root", "fixture-password")]
    creds.get_best("10.0.0.1")           # → ("root", "fixture-password")
    creds.get_all("10.0.0.1")            # → {"ssh": [("root", "fixture-password")]}
"""

import logging
import threading
from typing import Optional

from core.credential_ranking import best_credential
from core.secrets import SecretStore, get_secret_store, is_secret_ref

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RESET  = "\033[0m"


class CredentialStore:
    """
    Thread-safe credential store with 3-layer sync.

    Layer 1: In-memory dict (instant lookups)
    Layer 2: MariaDB credentials table (persistence across sessions)
    Layer 3: Knowledge Graph nodes/edges (relationship mapping)
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(self, secret_store: Optional[SecretStore] = None):
        # {(service, target): [(user, secret_ref), ...]}
        self._cache: dict[tuple, list] = {}
        self.secret_store = secret_store or get_secret_store()
        self._db_available = False
        self._kg_available = False
        self._boot()

    @classmethod
    def instance(cls) -> "CredentialStore":
        """Get or create the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _boot(self):
        """Try to hydrate cache from MariaDB on startup."""
        try:
            from db import get_connection
            conn = get_connection()
            c = conn.cursor()
            c.execute("SELECT target_ip, service, username, password FROM credentials")
            for row in c.fetchall():
                target, service, user, pwd = row
                secret_ref = pwd if is_secret_ref(pwd) else self.secret_store.store(
                    str(pwd), kind=f"credential:{service}"
                )
                key = (service.lower(), target)
                if key not in self._cache:
                    self._cache[key] = []
                entry = (user, secret_ref)
                if entry not in self._cache[key]:
                    self._cache[key].append(entry)
                if secret_ref != pwd:
                    c.execute(
                        "UPDATE credentials SET password = %s WHERE target_ip = %s AND service = %s AND username = %s AND password = %s",
                        (secret_ref, target, service, user, pwd),
                    )
            conn.commit()
            conn.close()
            self._db_available = True
        except Exception:
            pass  # MariaDB not available — cache-only mode

        try:
            self._kg_available = True
        except Exception as _exc:
            logging.debug(f"Suppressed in credentials.py: {_exc}")

    # ─── Write API ───────────────────────────────────────────

    def add(self, service: str, target: str, user: str, password: str,
            source: str = "", verified: bool = False, port: int = 0,
            quiet: bool = False) -> bool:
        """
        Register a credential. Syncs to all available stores.

        Args:
            service: Protocol name (ssh, http, mysql, ftp, etc.)
            target: IP or hostname
            user: Username
            password: Password, hash, or key
            source: Tool that discovered it (nmap, bruteforce, etc.)
            verified: Whether the credential has been verified working
            port: Optional port number
            quiet: If True, suppress console output

        Returns:
            True if new credential, False if duplicate
        """
        service = service.lower()
        key = (service, target)
        secret_ref = password if is_secret_ref(password) else self.secret_store.store(
            password, kind=f"credential:{service}"
        )
        entry = (user, secret_ref)

        with self._lock:
            if key not in self._cache:
                self._cache[key] = []
            if entry in self._cache[key]:
                return False  # duplicate
            self._cache[key].append(entry)

        if not quiet:
            print(f"  {C_GREEN}[+] Credential registered: {service}://{user}@{target}{C_RESET}")

        # Layer 2: MariaDB
        self._sync_to_db(service, target, user, secret_ref)

        # Layer 3: Knowledge Graph
        self._sync_to_kg(service, target, user, secret_ref, source, verified, port)

        # Layer 1b: Sync to legacy in-memory cache in exploit_tools.py
        runtime_secret = self.secret_store.reveal(secret_ref) if is_secret_ref(secret_ref) else secret_ref
        self._sync_to_legacy(service, target, user, runtime_secret)

        return True

    def _sync_to_db(self, service, target, user, password):
        """Persist to MariaDB credentials table."""
        if not self._db_available:
            return
        try:
            from db import get_connection
            conn = get_connection()
            c = conn.cursor()
            c.execute("""
                INSERT IGNORE INTO credentials (target_ip, service, username, password)
                VALUES (%s, %s, %s, %s)
            """, (target, service, user, password))
            conn.commit()
            conn.close()
        except Exception as _exc:
            logging.debug(f"Suppressed in credentials.py: {_exc}")

    def _sync_to_kg(self, service, target, user, password, source, verified, port):
        """Add to Knowledge Graph as Credential → Asset edge."""
        if not self._kg_available:
            return
        try:
            from core.knowledge import KnowledgeGraph
            kg = KnowledgeGraph()
            # Ensure asset exists
            asset = kg.add_asset(target)
            # Add credential
            cred = kg.add_credential(user, password, source=source,
                                     service=service, verified=verified,
                                     host=target)
            # Link credential → asset
            from core.knowledge.models import EdgeType
            kg.link(cred.node_id, asset.node_id, EdgeType.CAN_ACCESS,
                    method=service, port=port)
        except Exception as _exc:
            logging.debug(f"Suppressed in credentials.py: {_exc}")

    def _sync_to_legacy(self, service, target, user, password):
        """Sync to the old _KNOWN_CREDS dict in exploit_tools.py."""
        try:
            from core.tools.exploit_tools import _KNOWN_CREDS
            key = (service.lower(), target)
            if key not in _KNOWN_CREDS:
                _KNOWN_CREDS[key] = []
            if (user, password) not in _KNOWN_CREDS[key]:
                _KNOWN_CREDS[key].append((user, password))
        except Exception as _exc:
            logging.debug(f"Suppressed in credentials.py: {_exc}")

    # ─── Read API ────────────────────────────────────────────

    def get(self, service: str, target: str) -> list[tuple[str, str]]:
        """Get credentials for service@target. Returns [(user, password), ...]."""
        return [
            (user, self.secret_store.reveal(secret) if is_secret_ref(secret) else secret)
            for user, secret in self._cache.get((service.lower(), target), [])
        ]

    def get_best(self, target: str) -> tuple[Optional[str], Optional[str]]:
        """Get best credential for any service on target.
        Prefers real SSH secrets over auth-state markers."""
        # SSH first
        ssh_creds = self.get("ssh", target)
        if ssh_creds:
            return best_credential(ssh_creds)
        # Any service
        for (_svc, tgt), cred_list in self._cache.items():
            if tgt == target and cred_list:
                user, secret = cred_list[0]
                return user, self.secret_store.reveal(secret) if is_secret_ref(secret) else secret
        return (None, None)

    def get_all(self, target: str) -> dict[str, list[tuple[str, str]]]:
        """Get ALL credentials for target, grouped by service."""
        result = {}
        for (svc, tgt), cred_list in self._cache.items():
            if tgt == target and cred_list:
                result[svc] = [
                    (user, self.secret_store.reveal(secret) if is_secret_ref(secret) else secret)
                    for user, secret in cred_list
                ]
        return result

    def has_creds(self, service: str, target: str) -> bool:
        """Check if we have any credentials for service@target."""
        return bool(self._cache.get((service.lower(), target)))

    def count(self) -> int:
        """Total number of unique credentials."""
        return sum(len(v) for v in self._cache.values())

    def all_targets(self) -> list[str]:
        """Get all targets that have credentials."""
        return list({tgt for (_, tgt) in self._cache})

    # ─── Bulk API ────────────────────────────────────────────

    def import_from_legacy(self):
        """One-time import from the old _KNOWN_CREDS dict."""
        try:
            from core.tools.exploit_tools import _KNOWN_CREDS
            for (svc, tgt), cred_list in _KNOWN_CREDS.items():
                for user, pwd in cred_list:
                    self.add(svc, tgt, user, pwd, quiet=True)
        except Exception as _exc:
            logging.debug(f"Suppressed in credentials.py: {_exc}")

    def export_summary(self) -> str:
        """Formatted summary for AI context or display."""
        if not self._cache:
            return "No credentials known."
        lines = ["KNOWN CREDENTIALS:"]
        for (svc, tgt), cred_list in sorted(self._cache.items()):
            for user, secret in cred_list:
                pwd = self.secret_store.reveal(secret) if is_secret_ref(secret) else secret
                masked = pwd[:2] + "***" if len(pwd) > 3 else "***"
                lines.append(f"  {svc}://{user}:{masked}@{tgt}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize for JSON export."""
        result = {}
        for (svc, tgt), cred_list in self._cache.items():
            key = f"{svc}@{tgt}"
            result[key] = [
                {
                    "user": user,
                    "secret_ref": secret if is_secret_ref(secret) else self.secret_store.store(
                        secret, kind=f"credential:{svc}"
                    ),
                }
                for user, secret in cred_list
            ]
        return result
