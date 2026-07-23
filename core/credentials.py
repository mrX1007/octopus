#!/usr/bin/env python3
"""Reference-only credential ownership and execution-boundary reveal helpers.

``CredentialStore`` is the sole in-process credential index.  Control-plane
callers receive immutable :class:`CredentialRef` handles; secret plaintext is
available only through an explicit, lexically bounded execution context.
"""

from __future__ import annotations

import threading
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from core.credential_ranking import KEY_AUTH_MARKER
from core.secrets import SecretStore, get_secret_store, is_secret_ref

CREDENTIAL_HANDLE_PREFIX = "credential://"
SSH_KEY_AUTH_REF = "credential-auth://ssh-key"

C_GREEN = "\033[92m"
C_RESET = "\033[0m"


def is_credential_handle(value: object) -> bool:
    return isinstance(value, str) and value.startswith(CREDENTIAL_HANDLE_PREFIX)


@dataclass(frozen=True)
class CredentialRef:
    """Opaque control-plane identity for one scoped credential."""

    handle: str
    service: str
    target: str
    username: str
    secret_ref: str = field(default="", repr=False)
    auth_kind: str = "password"
    source: str = ""
    verified: bool = False
    port: int = 0

    def audit_dict(self) -> dict[str, object]:
        return {
            "handle": self.handle,
            "service": self.service,
            "target": self.target,
            "username": self.username,
            "auth_kind": self.auth_kind,
            "source": self.source,
            "verified": self.verified,
            "port": self.port,
        }


@dataclass
class CredentialMaterial:
    """Short-lived provider input whose secret is excluded from repr/audit."""

    credential: CredentialRef
    _password: str = field(repr=False)

    @property
    def username(self) -> str:
        return self.credential.username

    @property
    def password(self) -> str:
        return self._password

    @property
    def service(self) -> str:
        return self.credential.service

    @property
    def target(self) -> str:
        return self.credential.target

    @property
    def port(self) -> int:
        return self.credential.port

    def clear(self) -> None:
        # Python strings and cryptography backend temporaries cannot be
        # guaranteed to be zeroized.  Clearing the last application-owned
        # reference still bounds accidental reuse and subsequent serialization.
        self._password = ""


class CredentialStore:
    """Thread-safe reference index backed by SecretStore and optional MariaDB."""

    _instance: CredentialStore | None = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        secret_store: SecretStore | None = None,
        *,
        hydrate: bool = True,
    ) -> None:
        self.secret_store = secret_store or get_secret_store()
        self._cache: dict[tuple[str, str], list[CredentialRef]] = {}
        self._by_handle: dict[str, CredentialRef] = {}
        self._cache_lock = threading.RLock()
        self._db_available = False
        if hydrate:
            self._boot()

    @classmethod
    def instance(cls) -> CredentialStore:
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _boot(self) -> None:
        """Hydrate refs and atomically replace legacy plaintext DB values."""

        try:
            from db import get_connection

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT target_ip, service, username, password FROM credentials"
            )
            for target, service, username, persisted in cursor.fetchall():
                persisted_value = str(persisted or "")
                if persisted_value in {KEY_AUTH_MARKER, SSH_KEY_AUTH_REF}:
                    secret_ref = SSH_KEY_AUTH_REF
                    auth_kind = "ssh_key"
                elif is_secret_ref(persisted_value):
                    secret_ref = persisted_value
                    auth_kind = "password"
                elif is_credential_handle(persisted_value):
                    # A credential handle cannot recover secret material and must
                    # never be treated as a password.
                    continue
                elif persisted_value:
                    secret_ref = self.secret_store.store(
                        persisted_value,
                        kind=f"credential:{str(service).lower()}",
                    )
                    auth_kind = "password"
                else:
                    continue

                credential = self._make_ref(
                    str(service),
                    str(target),
                    str(username),
                    secret_ref,
                    auth_kind=auth_kind,
                )
                self._remember(credential)
                if secret_ref != persisted_value:
                    cursor.execute(
                        """
                        UPDATE credentials SET password = %s
                        WHERE target_ip = %s AND service = %s
                          AND username = %s AND password = %s
                        """,
                        (secret_ref, target, service, username, persisted),
                    )
            conn.commit()
            conn.close()
            self._db_available = True
        except Exception:
            # Optional MariaDB remains a cache-only compatibility backend.
            self._db_available = False

    def _make_ref(
        self,
        service: str,
        target: str,
        username: str,
        secret_ref: str,
        *,
        auth_kind: str = "password",
        source: str = "",
        verified: bool = False,
        port: int = 0,
    ) -> CredentialRef:
        service = str(service or "").strip().lower()
        target = str(target or "").strip()
        username = str(username or "").strip()
        payload = "\x1f".join((service, target, username, secret_ref, auth_kind))
        digest = self.secret_store.keyed_digest(payload, kind="credential_handle")
        return CredentialRef(
            handle=f"{CREDENTIAL_HANDLE_PREFIX}{digest[:40]}",
            service=service,
            target=target,
            username=username,
            secret_ref=secret_ref,
            auth_kind=auth_kind,
            source=str(source or ""),
            verified=bool(verified),
            port=max(0, int(port or 0)),
        )

    def _remember(self, credential: CredentialRef) -> bool:
        key = (credential.service, credential.target)
        with self._cache_lock:
            current = self._by_handle.get(credential.handle)
            if current is not None:
                return False
            self._cache.setdefault(key, []).append(credential)
            self._by_handle[credential.handle] = credential
            return True

    def register(
        self,
        service: str,
        target: str,
        username: str,
        secret: str,
        *,
        source: str = "",
        verified: bool = False,
        port: int = 0,
        quiet: bool = False,
    ) -> tuple[CredentialRef, bool]:
        service = str(service or "").strip().lower()
        target = str(target or "").strip()
        username = str(username or "").strip()
        secret_value = str(secret or "")

        if is_credential_handle(secret_value):
            resolved = self.resolve(secret_value)
            if resolved is None:
                raise KeyError("unknown credential handle")
            if service and resolved.service != service:
                raise ValueError("credential handle service mismatch")
            if target and resolved.target != target:
                raise ValueError("credential handle target mismatch")
            if username and resolved.username != username:
                raise ValueError("credential handle username mismatch")
            return resolved, False
        if secret_value == KEY_AUTH_MARKER:
            secret_ref = SSH_KEY_AUTH_REF
            auth_kind = "ssh_key"
        elif is_secret_ref(secret_value):
            secret_ref = secret_value
            auth_kind = "password"
        elif secret_value:
            secret_ref = self.secret_store.store(
                secret_value,
                kind=f"credential:{service}",
            )
            auth_kind = "password"
        else:
            raise ValueError("credential secret must not be empty")

        credential = self._make_ref(
            service,
            target,
            username,
            secret_ref,
            auth_kind=auth_kind,
            source=source,
            verified=verified,
            port=port,
        )
        created = self._remember(credential)
        if not created:
            existing = self.resolve(credential.handle)
            assert existing is not None
            return existing, False

        self._sync_to_db(credential)
        if not quiet:
            print(
                f"  {C_GREEN}[+] Credential registered: "
                f"{credential.service}://{credential.username}@{credential.target}{C_RESET}"
            )
        return credential, True

    def add(
        self,
        service: str,
        target: str,
        user: str,
        password: str,
        source: str = "",
        verified: bool = False,
        port: int = 0,
        quiet: bool = False,
    ) -> bool:
        """Compatibility write API; plaintext is sealed before this returns."""

        _credential, created = self.register(
            service,
            target,
            user,
            password,
            source=source,
            verified=verified,
            port=port,
            quiet=quiet,
        )
        return created

    def _sync_to_db(self, credential: CredentialRef) -> None:
        if not self._db_available:
            return
        try:
            from db import get_connection

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT IGNORE INTO credentials
                    (target_ip, service, username, password)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    credential.target,
                    credential.service,
                    credential.username,
                    credential.secret_ref,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            return

    def refs(self, service: str, target: str) -> tuple[CredentialRef, ...]:
        key = (str(service or "").strip().lower(), str(target or "").strip())
        with self._cache_lock:
            return tuple(self._cache.get(key, ()))

    def get_refs(self, service: str, target: str) -> tuple[CredentialRef, ...]:
        return self.refs(service, target)

    def all_refs(self, target: str) -> dict[str, tuple[CredentialRef, ...]]:
        target = str(target or "").strip()
        with self._cache_lock:
            services = sorted(
                service
                for service, candidate_target in self._cache
                if candidate_target == target
            )
            return {
                service: tuple(self._cache[(service, target)])
                for service in services
                if self._cache[(service, target)]
            }

    def get_all_refs(self, target: str) -> dict[str, tuple[CredentialRef, ...]]:
        return self.all_refs(target)

    def resolve(self, credential: CredentialRef | str) -> CredentialRef | None:
        if isinstance(credential, CredentialRef):
            candidate = self._by_handle.get(credential.handle)
            return candidate if candidate == credential else None
        if not is_credential_handle(credential):
            return None
        with self._cache_lock:
            return self._by_handle.get(str(credential))

    def best_ref(
        self,
        target: str,
        service: str | None = None,
        *,
        username: str = "",
        prefer_privileged: bool = False,
    ) -> CredentialRef | None:
        if service:
            candidates = list(self.refs(service, target))
        else:
            grouped = self.all_refs(target)
            candidates = [
                credential
                for preferred_service in ("ssh", *sorted(grouped))
                for credential in grouped.get(preferred_service, ())
            ]
            candidates = list(dict.fromkeys(candidates))
        if username:
            candidates = [item for item in candidates if item.username == username]

        def rank(item: CredentialRef) -> tuple[int, str, str]:
            is_root = item.username.casefold() == "root"
            if item.auth_kind == "password" and is_root:
                bucket = 0
            elif item.auth_kind == "password":
                bucket = 1
            elif item.auth_kind == "ssh_key" and is_root:
                bucket = 2
            else:
                bucket = 3
            if prefer_privileged and is_root:
                bucket -= 2
            return bucket, item.username.casefold(), item.handle

        return min(candidates, key=rank) if candidates else None

    def has_creds(self, service: str, target: str) -> bool:
        return bool(self.refs(service, target))

    def count(self) -> int:
        with self._cache_lock:
            return len(self._by_handle)

    def all_targets(self) -> list[str]:
        with self._cache_lock:
            return sorted({target for _service, target in self._cache})

    def to_dict(self) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {}
        with self._cache_lock:
            for (service, target), credentials in sorted(self._cache.items()):
                result[f"{service}@{target}"] = [
                    credential.audit_dict() for credential in credentials
                ]
        return result

    @contextmanager
    def material_for_execution(
        self,
        credential: CredentialRef | str,
    ) -> Iterator[CredentialMaterial]:
        resolved = self.resolve(credential)
        if resolved is None:
            raise KeyError("unknown credential handle")
        if resolved.auth_kind == "ssh_key":
            password = KEY_AUTH_MARKER
        elif is_secret_ref(resolved.secret_ref):
            password = self.secret_store.reveal(resolved.secret_ref)
        else:
            raise ValueError("credential has no revealable secret reference")
        material = CredentialMaterial(resolved, password)
        try:
            yield material
        finally:
            material.clear()
            password = ""

    # Old ambiguous getters intentionally no longer reveal plaintext.
    def get(self, service: str, target: str) -> tuple[CredentialRef, ...]:
        warnings.warn(
            "CredentialStore.get() now returns CredentialRef objects; use "
            "material_for_execution() only at a provider boundary",
            FutureWarning,
            stacklevel=2,
        )
        return self.refs(service, target)

    def get_best(
        self,
        target: str,
        service: str | None = None,
    ) -> CredentialRef | None:
        warnings.warn(
            "CredentialStore.get_best() now returns CredentialRef; use best_ref()",
            FutureWarning,
            stacklevel=2,
        )
        return self.best_ref(target, service)

    def get_all(self, target: str) -> dict[str, tuple[CredentialRef, ...]]:
        warnings.warn(
            "CredentialStore.get_all() now returns CredentialRef objects; use all_refs()",
            FutureWarning,
            stacklevel=2,
        )
        return self.all_refs(target)


def register_credential(
    service: str,
    target: str,
    user: str,
    secret: str,
    *,
    source: str = "octopus",
    verified: bool = False,
    port: int = 0,
    quiet: bool = False,
) -> bool:
    return CredentialStore.instance().add(
        service,
        target,
        user,
        secret,
        source=source,
        verified=verified,
        port=port,
        quiet=quiet,
    )


def get_credential_refs(service: str, target: str) -> tuple[CredentialRef, ...]:
    return CredentialStore.instance().refs(service, target)


def get_best_credential_ref(
    target: str,
    service: str | None = None,
    *,
    username: str = "",
    prefer_privileged: bool = False,
) -> CredentialRef | None:
    return CredentialStore.instance().best_ref(
        target,
        service,
        username=username,
        prefer_privileged=prefer_privileged,
    )


def get_all_credential_refs_for_target(
    target: str,
) -> dict[str, tuple[CredentialRef, ...]]:
    return CredentialStore.instance().all_refs(target)


def resolve_credential_handle(
    credential: CredentialRef | str,
) -> CredentialRef | None:
    return CredentialStore.instance().resolve(credential)


@contextmanager
def credential_material_for_execution(
    credential: CredentialRef | str,
) -> Iterator[CredentialMaterial]:
    with CredentialStore.instance().material_for_execution(credential) as material:
        yield material


@contextmanager
def deprecated_plaintext_credential_for_execution(
    credential: CredentialRef | str,
) -> Iterator[CredentialMaterial]:
    """Deprecated public compatibility wrapper with an explicit unsafe shape."""

    warnings.warn(
        "deprecated plaintext credential compatibility wrapper; migrate to "
        "credential_material_for_execution() inside the provider adapter",
        FutureWarning,
        stacklevel=2,
    )
    with credential_material_for_execution(credential) as material:
        yield material


__all__ = [
    "CREDENTIAL_HANDLE_PREFIX",
    "SSH_KEY_AUTH_REF",
    "CredentialMaterial",
    "CredentialRef",
    "CredentialStore",
    "credential_material_for_execution",
    "deprecated_plaintext_credential_for_execution",
    "get_all_credential_refs_for_target",
    "get_best_credential_ref",
    "get_credential_refs",
    "is_credential_handle",
    "register_credential",
    "resolve_credential_handle",
]
