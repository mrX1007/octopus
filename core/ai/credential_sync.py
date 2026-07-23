#!/usr/bin/env python3
"""Runtime credential synchronization for the AI pipeline.

Secret persistence and reveal semantics intentionally remain owned by
``core.credentials``/``core.secrets``.  This adapter projects only non-secret
credential availability facts into the AI control plane.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from core.credential_ranking import KEY_AUTH_MARKER
from core.credentials import CredentialRef
from core.secrets import is_secret_ref
from core.tools.targeting import target_host

RegisterCredential = Callable[[str, str, str, str], Any]
CredentialLookup = Callable[[str], Mapping[str, Sequence[CredentialRef]]]


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
        from core.credentials import register_credential

        return register_credential

    def _lookup_credentials(self) -> CredentialLookup:
        if self._lookup is not None:
            return self._lookup
        from core.credentials import get_all_credential_refs_for_target

        return get_all_credential_refs_for_target

    def sync_from_facts(self, target: str, facts: Sequence[Mapping[str, Any]]) -> None:
        """Migrate legacy reference facts without accepting fact-plane plaintext.

        Key-auth availability contains no secret and remains importable.  A
        legacy ``user:secret://... (cached)`` fact may be consumed during
        migration, but plaintext values are deliberately ignored.
        """

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
                    register("ssh", host, user, KEY_AUTH_MARKER)
                continue

            cached_match = re.match(r"([^:\s]+):([^\s]+)\s+\(cached\)", value)
            if cached_match and not value.startswith(("whm_session:", "cpanel_session:")):
                user, legacy_secret_ref = cached_match.groups()
                if is_secret_ref(legacy_secret_ref):
                    register("ssh", host, user, legacy_secret_ref)

    def known_for_target(self, target: str) -> dict[str, list[CredentialRef]]:
        """Return grouped opaque references for a normalized target."""

        try:
            lookup = self._lookup_credentials()
            grouped = lookup(target_host(target)) or {}
        except Exception as exc:  # Existing optional compatibility boundary.
            self._logger.debug("Could not read known credentials: %s", exc)
            return {}
        return {
            str(service): list(credentials)
            for service, credentials in grouped.items()
        }

    def seed_known_credentials(
        self,
        scan_id: str,
        target: str,
        fact_store: Any,
        credentials: Mapping[str, Sequence[CredentialRef]] | None = None,
    ) -> CredentialSeedResult:
        """Project known credentials into the existing FactStore boundary."""

        host = target_host(target)
        grouped = credentials if credentials is not None else self.known_for_target(host)
        seeded = 0
        announcements: list[str] = []
        for service, credential_list in grouped.items():
            for credential in credential_list:
                if not isinstance(credential, CredentialRef):
                    self._logger.warning(
                        "Ignoring non-reference credential projection for %s", service
                    )
                    continue
                user = credential.username
                if not user:
                    continue
                if service == "ssh" and credential.auth_kind == "ssh_key":
                    fact_type = "credential"
                    fact_value = f"ssh_key_available:{user}@{host}"
                elif service == "ssh":
                    fact_type = "credential"
                    fact_value = f"ssh_credential_available:{user}@{host}"
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
