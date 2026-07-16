#!/usr/bin/env python3
"""Versioned canonical identities shared by graph and read-model projections."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from core.secrets import is_secret_ref

ENTITY_NORMALIZATION_VERSION = "1.0"
_ID_VERSION_TOKEN = "v1"
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")


class EntityKind(str, Enum):
    ASSET = "asset"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    SERVICE = "service"
    SESSION = "session"
    VULNERABILITY = "vulnerability"


@dataclass(frozen=True)
class CanonicalEntityIdentity:
    entity_id: str
    kind: EntityKind
    components: tuple[tuple[str, str], ...]
    aliases: tuple[str, ...] = ()
    normalization_version: str = ENTITY_NORMALIZATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "kind": self.kind.value,
            "normalization_version": self.normalization_version,
            "components": dict(self.components),
            "aliases": list(self.aliases),
        }

    def component(self, name: str, default: str = "") -> str:
        return dict(self.components).get(name, default)


def normalize_host(value: str) -> tuple[str, str]:
    """Return ``(kind, canonical address)`` for an IP or DNS host."""

    raw = unicodedata.normalize("NFKC", str(value or "")).strip()
    if "://" in raw:
        parsed = urlsplit(raw)
        raw = parsed.hostname or ""
    raw = raw.strip().strip("[]").rstrip(".")
    if not raw:
        raise ValueError("Asset host must not be empty")
    try:
        return "ip", ipaddress.ip_address(raw).compressed.lower()
    except ValueError:
        pass
    try:
        canonical = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid DNS host: {value!r}") from exc
    if not canonical or any(not label for label in canonical.split(".")):
        raise ValueError(f"Invalid DNS host: {value!r}")
    if len(canonical) > 253 or any(len(label) > 63 for label in canonical.split(".")):
        raise ValueError(f"Invalid DNS host: {value!r}")
    return "dns", canonical


def canonical_asset(value: str) -> CanonicalEntityIdentity:
    address_kind, address = normalize_host(value)
    aliases = tuple(dict.fromkeys((f"asset:{address}", address)))
    return _identity(
        EntityKind.ASSET,
        (("address_kind", address_kind), ("address", address)),
        aliases,
    )


def normalize_protocol(value: str) -> str:
    protocol = str(value or "tcp").strip().lower()
    aliases = {"tcp6": "tcp", "udp6": "udp"}
    protocol = aliases.get(protocol, protocol)
    if protocol not in {"tcp", "udp", "sctp"}:
        raise ValueError(f"Unsupported service protocol: {value!r}")
    return protocol


def canonical_service(
    host: str,
    port: int | str,
    protocol: str = "tcp",
) -> CanonicalEntityIdentity:
    asset = canonical_asset(host)
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid service port: {port!r}") from exc
    if not 1 <= normalized_port <= 65535:
        raise ValueError(f"Invalid service port: {port!r}")
    normalized_protocol = normalize_protocol(protocol)
    address = asset.component("address")
    # The legacy ``svc:<host>:<port>`` form encoded no protocol and therefore
    # cannot safely alias both TCP and UDP.  It historically meant TCP in this
    # codebase, so retain it only for that protocol; protocol-aware aliases are
    # unambiguous for every service.
    aliases = tuple(
        dict.fromkeys(
            (
                *((f"svc:{address}:{normalized_port}",) if normalized_protocol == "tcp" else ()),
                f"{address}:{normalized_port}/{normalized_protocol}",
                f"service:{address}:{normalized_port}/{normalized_protocol}",
            )
        )
    )
    return _identity(
        EntityKind.SERVICE,
        (
            ("asset_id", asset.entity_id),
            ("host", address),
            ("port", str(normalized_port)),
            ("protocol", normalized_protocol),
        ),
        aliases,
    )


def normalize_endpoint_url(value: str) -> tuple[str, str, int, str, str]:
    raw = unicodedata.normalize("NFKC", str(value or "")).strip()
    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Endpoint must be an absolute HTTP(S) URL: {value!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Endpoint userinfo is not part of canonical identity")
    _host_kind, host = normalize_host(parsed.hostname)
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"Invalid endpoint port: {value!r}") from exc
    if not 1 <= int(port) <= 65535:
        raise ValueError(f"Invalid endpoint port: {value!r}")
    path = _normalize_path(parsed.path or "/")
    query = _normalize_percent_encoding(parsed.query)
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = display_host if int(port) == default_port else f"{display_host}:{int(port)}"
    canonical_url = urlunsplit((scheme, netloc, path, query, ""))
    return canonical_url, host, int(port), path, query


def canonical_endpoint(value: str) -> CanonicalEntityIdentity:
    canonical_url, host, port, path, query = normalize_endpoint_url(value)
    scheme = urlsplit(canonical_url).scheme
    aliases = tuple(
        dict.fromkeys(
            (
                canonical_url,
                canonical_url.rstrip("/"),
                f"endpoint:{canonical_url}",
            )
        )
    )
    return _identity(
        EntityKind.ENDPOINT,
        (
            ("scheme", scheme),
            ("host", host),
            ("effective_port", str(port)),
            ("path", path),
            ("query", query),
            ("url", canonical_url),
        ),
        aliases,
    )


def canonical_identity(
    username: str,
    *,
    domain: str = "",
    identity_type: str = "local",
    host: str = "",
) -> CanonicalEntityIdentity:
    normalized_type = re.sub(r"[^a-z0-9_.-]+", "_", str(identity_type or "local").lower()).strip("_")
    normalized_type = normalized_type or "local"
    normalized_domain = _normalize_realm(domain)
    raw_username = unicodedata.normalize("NFKC", str(username or "")).strip()
    if not raw_username:
        raise ValueError("Identity username must not be empty")
    normalized_username = (
        raw_username.casefold()
        if normalized_domain or normalized_type in {"domain", "service", "application"}
        else raw_username
    )
    asset_id = canonical_asset(host).entity_id if host else ""
    scope = normalized_domain or asset_id or "global"
    legacy_name = f"{normalized_domain}\\{normalized_username}" if normalized_domain else normalized_username
    aliases = tuple(dict.fromkeys((f"identity:{legacy_name}", f"identity:{normalized_username}")))
    return _identity(
        EntityKind.IDENTITY,
        (
            ("username", normalized_username),
            ("domain", normalized_domain),
            ("identity_type", normalized_type),
            ("scope", scope),
        ),
        aliases,
    )


def canonical_credential(
    username: str,
    secret_ref: str,
    *,
    service: str = "",
    host: str = "",
    domain: str = "",
    identity_type: str = "local",
    secret_type: str = "password",
) -> CanonicalEntityIdentity:
    if not is_secret_ref(secret_ref):
        raise ValueError("Canonical credential identity requires an opaque secret reference")
    identity = canonical_identity(
        username,
        domain=domain,
        identity_type=identity_type,
        host=host,
    )
    normalized_service = str(service or "").strip().lower()
    asset_id = canonical_asset(host).entity_id if host else ""
    normalized_secret_type = str(secret_type or "password").strip().lower()
    legacy_hash = hashlib.sha256(secret_ref.encode("utf-8")).hexdigest()[:8]
    aliases = (f"cred:{identity.component('username')}:{legacy_hash}",)
    return _identity(
        EntityKind.CREDENTIAL,
        (
            ("identity_id", identity.entity_id),
            ("secret_ref", secret_ref),
            ("secret_type", normalized_secret_type),
            ("service", normalized_service),
            ("asset_id", asset_id),
        ),
        aliases,
    )


def canonical_session(
    session_id: str,
    *,
    session_type: str = "ssh",
    host: str = "",
    username: str = "",
    domain: str = "",
) -> CanonicalEntityIdentity:
    normalized_session_id = unicodedata.normalize("NFKC", str(session_id or "")).strip()
    if not normalized_session_id:
        raise ValueError("Session identifier must not be empty")
    normalized_type = str(session_type or "session").strip().lower()
    asset_id = canonical_asset(host).entity_id if host else ""
    identity_id = (
        canonical_identity(
            username,
            domain=domain,
            identity_type="domain" if domain else "local",
            host=host,
        ).entity_id
        if username
        else ""
    )
    return _identity(
        EntityKind.SESSION,
        (
            ("session_id", normalized_session_id),
            ("session_type", normalized_type),
            ("asset_id", asset_id),
            ("identity_id", identity_id),
        ),
        (f"sess:{normalized_session_id}",),
    )


def canonical_vulnerability(value: str) -> CanonicalEntityIdentity:
    raw = unicodedata.normalize("NFKC", str(value or "")).strip()
    if not raw:
        raise ValueError("Vulnerability identifier must not be empty")
    cve = re.search(r"\bCVE-\d{4}-\d{4,7}\b", raw, re.IGNORECASE)
    cwe = re.search(r"\bCWE-\d{1,5}\b", raw, re.IGNORECASE)
    if cve:
        namespace, key = "cve", cve.group(0).upper()
    elif cwe:
        namespace, key = "cwe", cwe.group(0).upper()
    elif re.match(r"^(?:exploit|auxiliary|post)/", raw, re.IGNORECASE):
        namespace, key = "module", raw.lower()
    else:
        namespace = "custom"
        key = re.sub(r"\s+", " ", raw).casefold()
    return _identity(
        EntityKind.VULNERABILITY,
        (("namespace", namespace), ("key", key)),
        tuple(dict.fromkeys((f"vuln:{raw}", f"vuln:{key}"))),
    )


def canonical_from_legacy(
    node_type: str,
    properties: dict[str, Any],
) -> CanonicalEntityIdentity | None:
    """Best-effort migration adapter for the legacy graph node contract."""

    kind = str(node_type or "").lower()
    try:
        if kind == EntityKind.ASSET.value:
            return canonical_asset(str(properties.get("ip") or properties.get("host") or ""))
        if kind == EntityKind.SERVICE.value:
            return canonical_service(
                str(properties.get("host") or ""),
                str(properties.get("port") or ""),
                str(properties.get("protocol") or properties.get("proto") or "tcp"),
            )
        if kind == EntityKind.ENDPOINT.value:
            return canonical_endpoint(str(properties.get("url") or ""))
        if kind == EntityKind.IDENTITY.value:
            return canonical_identity(
                str(properties.get("username") or ""),
                domain=str(properties.get("domain") or ""),
                identity_type=str(properties.get("identity_type") or "local"),
                host=str(properties.get("host") or ""),
            )
        if kind == EntityKind.CREDENTIAL.value:
            return canonical_credential(
                str(properties.get("username") or ""),
                str(properties.get("secret") or ""),
                service=str(properties.get("service") or ""),
                host=str(properties.get("host") or ""),
                domain=str(properties.get("domain") or ""),
                secret_type=str(properties.get("secret_type") or "password"),
            )
        if kind == EntityKind.SESSION.value:
            return canonical_session(
                str(properties.get("session_id") or ""),
                session_type=str(properties.get("session_type") or "session"),
                host=str(properties.get("host") or ""),
                username=str(properties.get("username") or ""),
            )
        if kind == EntityKind.VULNERABILITY.value:
            return canonical_vulnerability(
                str(properties.get("vuln_id") or properties.get("name") or "")
            )
    except (TypeError, ValueError):
        return None
    return None


def _identity(
    kind: EntityKind,
    components: tuple[tuple[str, str], ...],
    aliases: tuple[str, ...],
) -> CanonicalEntityIdentity:
    payload = json.dumps(
        {
            "kind": kind.value,
            "normalization_version": ENTITY_NORMALIZATION_VERSION,
            "components": components,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return CanonicalEntityIdentity(
        entity_id=f"{kind.value}:{_ID_VERSION_TOKEN}:{digest}",
        kind=kind,
        components=components,
        aliases=tuple(alias for alias in dict.fromkeys(aliases) if alias),
    )


def _normalize_realm(value: str) -> str:
    raw = unicodedata.normalize("NFKC", str(value or "")).strip().rstrip(".")
    if not raw:
        return ""
    try:
        return raw.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return raw.casefold()


def _normalize_percent_encoding(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        byte = int(match.group(1), 16)
        char = chr(byte)
        return char if char in _UNRESERVED else f"%{byte:02X}"

    return _PERCENT_ESCAPE.sub(replace, str(value or ""))


def _normalize_path(value: str) -> str:
    path = _normalize_percent_encoding(value or "/")
    leading = path.startswith("/")
    trailing = path.endswith("/") and path != "/"
    output: list[str] = []
    for segment in path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if output:
                output.pop()
            continue
        output.append(segment)
    normalized = "/".join(output)
    if leading:
        normalized = "/" + normalized
    if not normalized:
        normalized = "/"
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


__all__ = [
    "ENTITY_NORMALIZATION_VERSION",
    "CanonicalEntityIdentity",
    "EntityKind",
    "canonical_asset",
    "canonical_credential",
    "canonical_endpoint",
    "canonical_from_legacy",
    "canonical_identity",
    "canonical_service",
    "canonical_session",
    "canonical_vulnerability",
    "normalize_endpoint_url",
    "normalize_host",
    "normalize_protocol",
]
