#!/usr/bin/env python3
"""Runtime credential synchronization for the AI pipeline.

Secret persistence and reveal semantics intentionally remain owned by
``core.credentials``/``core.secrets``.  This adapter only translates the
pipeline's legacy credential facts to and from the existing runtime cache.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from core.tools.targeting import target_host

RegisterCredential = Callable[[str, str, str, str], Any]
CredentialLookup = Callable[[str], Mapping[str, Sequence[tuple[str, str]]]]


@dataclass(frozen=True)
class CredentialSeedResult:
    """Compatibility result for projecting cached credentials into facts."""

    seeded: int
    announcements: tuple[str, ...] = ()


class RuntimeCredentialSynchronizer:
    """Synchronize runtime credential lookup without owning secret storage."""

    def __init__(
        self,
        register: RegisterCredential | None = None,
        lookup: CredentialLookup | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._register = register
        self._lookup = lookup
        self._logger = logger or logging.getLogger("octopus.pipeline.credentials")

    def _register_credential(self) -> RegisterCredential:
        if self._register is not None:
            return self._register
        from core.tools.exploit_tools import register_credential

        return register_credential

    def _lookup_credentials(self) -> CredentialLookup:
        if self._lookup is not None:
            return self._lookup
        from core.tools.exploit_tools import get_all_known_creds_for_target

        return get_all_known_creds_for_target

    def sync_from_facts(self, target: str, facts: Sequence[Mapping[str, Any]]) -> None:
        """Mirror concrete SSH credentials from parsed facts into runtime lookup."""

        try:
            register = self._register_credential()
        except Exception as exc:  # Existing optional compatibility boundary.
            self._logger.debug("Could not sync runtime credentials: %s", exc)
            return

        host = target_host(target)
        for fact in facts:
            if fact.get("type") != "credential":
                continue
            value = str(fact.get("value", "")).strip()
            key_match = re.match(r"ssh_key_available:([^@\s]+)@([^\s]+)", value)
            if key_match:
                user, credential_host = key_match.groups()
                if credential_host == host:
                    register("ssh", host, user, "__KEY_AUTH__")
                continue

            cached_match = re.match(r"([^:\s]+):([^\s]+)\s+\(cached\)", value)
            if cached_match and not value.startswith(("whm_session:", "cpanel_session:")):
                user, password = cached_match.groups()
                register("ssh", host, user, password)

    def known_for_target(self, target: str) -> dict[str, list[tuple[str, str]]]:
        """Read grouped credentials through the existing unified/legacy facade."""

        try:
            lookup = self._lookup_credentials()
            grouped = lookup(target_host(target)) or {}
        except Exception as exc:  # Existing optional compatibility boundary.
            self._logger.debug("Could not read known credentials: %s", exc)
            return {}
        return {
            str(service): [(str(user), str(secret)) for user, secret in credentials]
            for service, credentials in grouped.items()
        }

    def seed_known_credentials(
        self,
        scan_id: str,
        target: str,
        fact_store: Any,
        credentials: Mapping[str, Sequence[tuple[str, str]]] | None = None,
    ) -> CredentialSeedResult:
        """Project known credentials into the existing FactStore boundary."""

        host = target_host(target)
        grouped = credentials if credentials is not None else self.known_for_target(host)
        seeded = 0
        announcements: list[str] = []
        for service, credential_list in grouped.items():
            for user, password in credential_list:
                if not user or not password:
                    continue
                if service == "ssh" and password == "__KEY_AUTH__":
                    fact_type = "credential"
                    fact_value = f"ssh_key_available:{user}@{host}"
                elif service == "ssh":
                    fact_type = "credential"
                    fact_value = f"{user}:{password} (cached)"
                else:
                    fact_type = "credential"
                    fact_value = f"{service}_credential:{user}@{host}"
                _fact_id, created = fact_store.add_fact_with_status(
                    scan_id,
                    host,
                    fact_type,
                    fact_value,
                    "credential_store",
                    confidence=90,
                    session_id="credential_store",
                )
                if created:
                    seeded += 1
                    announcements.append(f"{service}://{user}@{host}")
        return CredentialSeedResult(seeded=seeded, announcements=tuple(announcements))


__all__ = ["CredentialSeedResult", "RuntimeCredentialSynchronizer"]
