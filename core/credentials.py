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
    creds.add("ssh", "10.0.0.1", "root", "toor", source="bruteforce")
    creds.get("ssh", "10.0.0.1")         # → [("root", "toor")]
    creds.get_best("10.0.0.1")           # → ("root", "toor")
    creds.get_all("10.0.0.1")            # → {"ssh": [("root", "toor")]}
"""

import logging
import threading
from typing import List, Tuple, Dict, Optional

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

    def __init__(self):
        # {(service, target): [(user, password, metadata), ...]}
        self._cache: Dict[tuple, list] = {}
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
                key = (service.lower(), target)
                if key not in self._cache:
                    self._cache[key] = []
                entry = (user, pwd)
                if entry not in self._cache[key]:
                    self._cache[key].append(entry)
            conn.close()
            self._db_available = True
        except Exception as e:
            pass  # MariaDB not available — cache-only mode

        try:
            from core.knowledge import KnowledgeGraph
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
        entry = (user, password)

        with self._lock:
            if key not in self._cache:
                self._cache[key] = []
            if entry in self._cache[key]:
                return False  # duplicate
            self._cache[key].append(entry)

        if not quiet:
            print(f"  {C_GREEN}[+] Credential registered: {service}://{user}@{target}{C_RESET}")

        # Layer 2: MariaDB
        self._sync_to_db(service, target, user, password)

        # Layer 3: Knowledge Graph
        self._sync_to_kg(service, target, user, password, source, verified, port)

        # Layer 1b: Sync to legacy in-memory cache in exploit_tools.py
        self._sync_to_legacy(service, target, user, password)

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
            kg.add_asset(target)
            # Add credential
            cred = kg.add_credential(user, password, source=source,
                                     service=service, verified=verified)
            # Link credential → asset
            from core.knowledge.models import EdgeType
            kg.link(cred.node_id, f"asset:{target}", EdgeType.CAN_ACCESS,
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

    def get(self, service: str, target: str) -> List[Tuple[str, str]]:
        """Get credentials for service@target. Returns [(user, password), ...]."""
        return list(self._cache.get((service.lower(), target), []))

    def get_best(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        """Get best credential for any service on target.
        Prefers root > other SSH > any service."""
        # SSH first
        ssh_creds = self.get("ssh", target)
        if ssh_creds:
            for user, pwd in ssh_creds:
                if user == "root":
                    return (user, pwd)
            return ssh_creds[0]
        # Any service
        for (svc, tgt), cred_list in self._cache.items():
            if tgt == target and cred_list:
                return cred_list[0]
        return (None, None)

    def get_all(self, target: str) -> Dict[str, List[Tuple[str, str]]]:
        """Get ALL credentials for target, grouped by service."""
        result = {}
        for (svc, tgt), cred_list in self._cache.items():
            if tgt == target and cred_list:
                result[svc] = list(cred_list)
        return result

    def has_creds(self, service: str, target: str) -> bool:
        """Check if we have any credentials for service@target."""
        return bool(self._cache.get((service.lower(), target)))

    def count(self) -> int:
        """Total number of unique credentials."""
        return sum(len(v) for v in self._cache.values())

    def all_targets(self) -> List[str]:
        """Get all targets that have credentials."""
        return list(set(tgt for (_, tgt) in self._cache.keys()))

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
            for user, pwd in cred_list:
                masked = pwd[:2] + "***" if len(pwd) > 3 else "***"
                lines.append(f"  {svc}://{user}:{masked}@{tgt}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize for JSON export."""
        result = {}
        for (svc, tgt), cred_list in self._cache.items():
            key = f"{svc}@{tgt}"
            result[key] = [{"user": u, "password": p} for u, p in cred_list]
        return result
