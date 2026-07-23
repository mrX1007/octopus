"""Encrypted secret storage and lossless-safe redaction helpers.

The rest of OCTOPUS persists only opaque ``secret://`` references. Plaintext is
available solely through an explicit :meth:`SecretStore.reveal` call at an
execution boundary that actually needs it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECRET_REF_PREFIX = "secret://"
REDACTED = "[REDACTED]"

_SECRET_REF_RE = re.compile(r"secret://[A-Za-z0-9_-]+")
_SENSITIVE_FIELD_RE = re.compile(
    r"(?ix)(?:^|[_-])(?:"
    r"api[_-]?key|authorization|auth[_-]?token|bearer|cookie|credential|"
    r"hash[_-]?value|key[_-]?material|nonce|nthash|pass(?:word|wd)?|"
    r"private[_-]?key|refresh[_-]?token|secret|session[_-]?token|token"
    r")(?:$|[_-])"
)


class SecretStoreError(RuntimeError):
    """Raised when encrypted secret material cannot be accessed safely."""


@dataclass(frozen=True)
class SecretReference:
    """Opaque identifier for one encrypted secret."""

    identifier: str

    def __str__(self) -> str:
        return f"{SECRET_REF_PREFIX}{self.identifier}"


class SecretStore:
    """Small AES-256-GCM encrypted store backed by SQLite.

    A keyed digest provides deterministic deduplication without writing a plain
    SHA-256 oracle to disk. The encryption key is supplied by
    ``OCTOPUS_SECRET_KEY`` or generated into a mode-0600 sidecar file.
    """

    def __init__(
        self,
        db_path: str = "data/secrets.db",
        *,
        key: bytes | None = None,
        key_path: str | None = None,
    ) -> None:
        self.db_path = os.path.abspath(os.path.expanduser(db_path)) if db_path != ":memory:" else db_path
        self.key_path = key_path or (f"{self.db_path}.key" if self.db_path != ":memory:" else "")
        self._key = self._load_key(key)
        self._lock = threading.RLock()
        self._known_values: dict[str, str] = {}
        self._memory_conn: sqlite3.Connection | None = None
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(self.db_path), mode=0o700, exist_ok=True)
        else:
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._init_db()

    def _load_key(self, explicit_key: bytes | None) -> bytes:
        if explicit_key is not None:
            return self._normalize_key(explicit_key)

        configured = os.environ.get("OCTOPUS_SECRET_KEY", "")
        if configured:
            return self._normalize_key(configured.encode("utf-8"))

        if not self.key_path:
            return secrets.token_bytes(32)

        expanded = os.path.abspath(os.path.expanduser(self.key_path))
        os.makedirs(os.path.dirname(expanded), mode=0o700, exist_ok=True)
        try:
            fd = os.open(expanded, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            self._assert_private_file(expanded)
            with open(expanded, "rb") as handle:
                encoded = handle.read().strip()
            try:
                return self._normalize_key(base64.urlsafe_b64decode(encoded))
            except (ValueError, TypeError) as exc:
                raise SecretStoreError(f"invalid secret-store key file: {expanded}") from exc

        generated = secrets.token_bytes(32)
        try:
            os.write(fd, base64.urlsafe_b64encode(generated))
        finally:
            os.close(fd)
        self._assert_private_file(expanded)
        return generated

    @staticmethod
    def _normalize_key(value: bytes) -> bytes:
        if len(value) == 32:
            return bytes(value)
        try:
            decoded = base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))
        except (ValueError, TypeError):
            decoded = b""
        if len(decoded) == 32:
            return decoded
        return hashlib.sha256(value).digest()

    @staticmethod
    def _assert_private_file(path: str) -> None:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            try:
                os.chmod(path, 0o600)
            except OSError as exc:
                raise SecretStoreError(f"secret-store key must be mode 0600: {path}") from exc

    def _connect(self) -> sqlite3.Connection:
        if self._memory_conn is not None:
            return self._memory_conn
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _close(self, conn: sqlite3.Connection) -> None:
        if conn is not self._memory_conn:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS secrets (
                        id TEXT PRIMARY KEY,
                        digest TEXT NOT NULL UNIQUE,
                        kind TEXT NOT NULL,
                        nonce BLOB NOT NULL,
                        ciphertext BLOB NOT NULL,
                        metadata TEXT NOT NULL DEFAULT '{}',
                        created_at REAL NOT NULL,
                        accessed_at REAL
                    )
                    """
                )
                conn.commit()
            finally:
                self._close(conn)
        if self.db_path != ":memory:":
            try:
                os.chmod(self.db_path, 0o600)
            except OSError as exc:
                raise SecretStoreError(f"cannot protect secret store: {self.db_path}") from exc

    def store(
        self,
        value: str | bytes,
        *,
        kind: str = "secret",
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Encrypt *value* and return a stable opaque reference."""
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if not raw:
            raise ValueError("refusing to store an empty secret")
        if isinstance(value, str) and is_secret_ref(value):
            return value

        digest = hmac.new(self._key, raw, hashlib.sha256).hexdigest()
        with self._lock:
            conn = self._connect()
            try:
                existing = conn.execute("SELECT id FROM secrets WHERE digest = ?", (digest,)).fetchone()
                if existing:
                    reference = f"{SECRET_REF_PREFIX}{existing[0]}"
                else:
                    identifier = f"sec_{secrets.token_urlsafe(18)}"
                    nonce = secrets.token_bytes(12)
                    aad = f"{identifier}\x1f{kind}".encode()
                    ciphertext = AESGCM(self._key).encrypt(nonce, raw, aad)
                    safe_metadata = json.dumps(dict(metadata or {}), sort_keys=True, default=str)
                    conn.execute(
                        """
                        INSERT INTO secrets (id, digest, kind, nonce, ciphertext, metadata, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (identifier, digest, str(kind), nonce, ciphertext, safe_metadata, time.time()),
                    )
                    conn.commit()
                    reference = f"{SECRET_REF_PREFIX}{identifier}"
            finally:
                self._close(conn)

        if isinstance(value, str):
            self._known_values[value] = reference
        return reference

    def reveal(self, reference: str | SecretReference) -> str:
        """Explicitly decrypt a reference for a runtime consumer."""
        ref = str(reference)
        identifier = _reference_identifier(ref)
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT kind, nonce, ciphertext FROM secrets WHERE id = ?", (identifier,)
                ).fetchone()
                if not row:
                    raise KeyError(ref)
                kind, nonce, ciphertext = row
                aad = f"{identifier}\x1f{kind}".encode()
                plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, aad)
                conn.execute("UPDATE secrets SET accessed_at = ? WHERE id = ?", (time.time(), identifier))
                conn.commit()
            finally:
                self._close(conn)
        value = plaintext.decode("utf-8")
        self._known_values[value] = ref
        return value

    def known_values(self) -> tuple[tuple[str, str], ...]:
        """Return plaintexts already seen in this process, longest first."""
        return tuple(sorted(self._known_values.items(), key=lambda item: len(item[0]), reverse=True))

    def keyed_digest(self, value: str | bytes, *, kind: str) -> str:
        """Return a namespaced stable digest without creating a plaintext oracle."""
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        namespace = str(kind).encode("utf-8", "replace")
        return hmac.new(
            self._key,
            namespace + b"\x00" + raw,
            hashlib.sha256,
        ).hexdigest()

    def close(self) -> None:
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None
        self._known_values.clear()


class Redactor:
    """Detect secrets in text/structures and replace them with store references."""

    _NAMED_VALUE_RE = re.compile(
        r"(?ix)(?P<prefix>\b(?:api[_-]?key|auth[_-]?token|cookie|"
        r"hash[_-]?value|nthash|pass(?:word|wd)?|private[_-]?key|refresh[_-]?token|"
        r"secret|session[_-]?token|token)\b[\"']?\s*(?:=|:)\s*[\"']?)"
        r"(?!(?:\[REDACTED\b|secret://|//))"
        r"(?P<value>[^\s,;\"'}\]]{3,})(?P<suffix>[\"']?)"
    )
    _CLI_VALUE_RE = re.compile(
        r"(?ix)(?P<prefix>--(?:api-key|authorization|cookie|password|passwd|"
        r"private-key|secret|token)\s+)(?!(?:\[REDACTED\b|secret://))(?P<value>[^\s]+)"
    )
    _AUTH_RE = re.compile(
        r"(?ix)(?P<prefix>\bAuthorization\s*:\s*(?:Basic|Bearer)\s+)"
        r"(?P<value>[A-Za-z0-9._~+/=-]{6,})"
    )
    _URL_USERINFO_RE = re.compile(
        r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<user>[^\s/@:]+):"
        r"(?!(?:\[REDACTED\b|secret://))(?P<value>[^\s/@]+)@"
    )
    _PRIVATE_KEY_RE = re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
        r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
        re.DOTALL,
    )
    _JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

    def __init__(self, store: SecretStore) -> None:
        self.store = store

    def protect(self, value: str | bytes, *, kind: str = "secret") -> str:
        """Store a scalar secret and return only its opaque reference."""
        if isinstance(value, str) and is_secret_ref(value):
            return value
        return self.store.store(value, kind=kind)

    def _text_replacement(self, value: str, kind: str) -> str:
        if not value or value == REDACTED or is_secret_ref(value):
            return value
        reference = self.protect(value, kind=kind)
        return f"[REDACTED {reference}]"

    def _replace_known_values(self, text: str) -> str:
        protected: dict[str, str] = {}
        safe_token_re = re.compile(r"\[REDACTED secret://[A-Za-z0-9_-]+\]|secret://[A-Za-z0-9_-]+")

        def shield(match: re.Match[str]) -> str:
            token = f"\x00OCTOPUS_REF_{len(protected)}\x00"
            protected[token] = match.group(0)
            return token

        text = safe_token_re.sub(shield, text)
        for plaintext, reference in self.store.known_values():
            if len(plaintext) >= 4 and plaintext in text and not plaintext.startswith("[REDACTED"):
                text = text.replace(plaintext, f"[REDACTED {reference}]")
        for token, original in protected.items():
            text = text.replace(token, original)
        return text

    def redact_text(self, value: Any, *, kind: str = "text") -> str:
        """Return text with common credential/token forms replaced."""
        text = str(value if value is not None else "")
        if not text:
            return text

        def private_key(match: re.Match[str]) -> str:
            return self._text_replacement(match.group(0), "private_key")

        def named(match: re.Match[str]) -> str:
            return f"{match.group('prefix')}{self._text_replacement(match.group('value'), 'named_secret')}{match.groupdict().get('suffix') or ''}"

        def auth(match: re.Match[str]) -> str:
            return f"{match.group('prefix')}{self._text_replacement(match.group('value'), 'authorization')}"

        def userinfo(match: re.Match[str]) -> str:
            protected = self._text_replacement(match.group("value"), "url_password")
            return f"{match.group('scheme')}{match.group('user')}:{protected}@"

        text = self._PRIVATE_KEY_RE.sub(private_key, text)
        text = self._AUTH_RE.sub(auth, text)
        text = self._URL_USERINFO_RE.sub(userinfo, text)
        text = self._CLI_VALUE_RE.sub(named, text)
        text = self._NAMED_VALUE_RE.sub(named, text)
        text = self._JWT_RE.sub(lambda match: self._text_replacement(match.group(0), "jwt"), text)

        return self._replace_known_values(text)

    def redact_fact(self, fact_type: str, value: Any) -> tuple[str, tuple[str, ...]]:
        """Apply fact-aware protection and return ``(safe_value, refs)``."""
        fact_kind = str(fact_type or "").lower()
        text = str(value if value is not None else "")

        if fact_kind == "credential":
            cached = re.match(r"^([^:\s]+):(.+?)\s+\(cached\)$", text)
            if cached:
                ref = self.protect(cached.group(2), kind="credential")
                text = f"{cached.group(1)}:{ref} (cached)"
            else:
                session = re.match(
                    r"^((?:access|auth|cpanel|refresh|session|whm)[_-]?(?:session|token)):(.{4,})$",
                    text,
                    re.IGNORECASE,
                )
                if session:
                    ref = self.protect(session.group(2), kind=session.group(1).lower())
                    text = f"{session.group(1)}:{ref}"
                elif not re.match(
                    r"^(?:cpanel_auth_bypass_session|login_success|"
                    r"(?:pth_auth_success|ssh_key_available|ssh_login_success):[^\s]+|"
                    r"cracked_password_for:[^\s]+)$",
                    text,
                    re.IGNORECASE,
                ):
                    pair = re.match(r"^([^:\s]+):(.+?)(\s+\(.+\))?$", text)
                    if pair:
                        ref = self.protect(pair.group(2), kind="credential")
                        text = f"{pair.group(1)}:{ref}{pair.group(3) or ''}"
                    elif text and text.lower() not in {"credential_available", "login_success"}:
                        text = self.protect(text, kind="credential")
        elif fact_kind in {"hash", "hash_material", "password", "private_key", "token"}:
            if text and not text.endswith(("_file", "_file_extracted", "_observed")):
                text = self.protect(text, kind=fact_kind)

        if fact_kind == "secret_finding":
            parts = text.split(":")
            structured = (
                len(parts) == 4
                and parts[2].lower() in {"validated", "unvalidated"}
                and parts[3].lower() == "rotation_required"
            )
            safe = self._replace_known_values(text) if structured else self.redact_text(text, kind=f"fact:{fact_kind}")
        else:
            safe = self.redact_text(text, kind=f"fact:{fact_kind}")
        refs = tuple(dict.fromkeys(_SECRET_REF_RE.findall(safe)))
        return safe, refs

    def redact_data(self, value: Any, *, field: str = "") -> Any:
        """Recursively redact mappings, sequences, dataclasses, bytes and text."""
        if is_dataclass(value) and not isinstance(value, type):
            return self.redact_data(asdict(value), field=field)
        if isinstance(value, Mapping):
            result: dict[Any, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if _is_sensitive_field(key_text) and isinstance(item, (str, bytes)) and item:
                    result[key] = self.protect(item, kind=key_text)
                else:
                    result[key] = self.redact_data(item, field=key_text)
            return result
        if isinstance(value, tuple):
            return tuple(self.redact_data(item, field=field) for item in value)
        if isinstance(value, list):
            return [self.redact_data(item, field=field) for item in value]
        if isinstance(value, set):
            return {self.redact_data(item, field=field) for item in value}
        if isinstance(value, bytes):
            return self.protect(value, kind=field or "bytes")
        if isinstance(value, str):
            return self.redact_text(value, kind=field or "text")
        return value


class RedactionFilter(logging.Filter):
    """Last-resort logging boundary for messages and structured arguments."""

    def __init__(self, redactor: Redactor | None = None) -> None:
        super().__init__()
        self.redactor = redactor or get_redactor()

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
            record.msg = self.redactor.redact_text(rendered, kind="log")
            record.args = ()
            if record.exc_text:
                record.exc_text = self.redactor.redact_text(record.exc_text, kind="exception")
        except Exception:
            record.msg = "[REDACTED: logging filter failure]"
            record.args = ()
        return True


def install_logging_redaction(logger: logging.Logger | None = None) -> RedactionFilter:
    """Attach one redaction filter to every current handler."""
    target = logger or logging.getLogger()
    existing = next(
        (item for item in target.filters if isinstance(item, RedactionFilter)),
        None,
    )
    filter_instance = existing or RedactionFilter()
    if existing is None:
        target.addFilter(filter_instance)
    for handler in target.handlers:
        if not any(isinstance(item, RedactionFilter) for item in handler.filters):
            handler.addFilter(filter_instance)
    return filter_instance


def is_secret_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"secret://[A-Za-z0-9_-]+", value.strip()))


def _reference_identifier(reference: str) -> str:
    if not is_secret_ref(reference):
        raise ValueError("invalid secret reference")
    return reference[len(SECRET_REF_PREFIX):]


def _is_sensitive_field(field: str) -> bool:
    normalized = re.sub(r"[^a-z0-9_-]+", "_", field.lower()).strip("_")
    # Authorization is sensitive when it contains credential material (for
    # example an ``Authorization`` header), but decision metadata is part of
    # the auditable policy contract and must remain readable.  Treat opaque
    # references and the small set of structural authorization fields as
    # metadata; their nested values are still recursively redacted.
    if normalized.endswith(("_ref", "_refs")) or normalized in {
        "authorization_decision",
        "authorization_phase",
        "authorization_reason",
    }:
        return False
    return bool(normalized and _SENSITIVE_FIELD_RE.search(normalized))


_DEFAULT_LOCK = threading.Lock()
_DEFAULT_STORE: SecretStore | None = None
_DEFAULT_REDACTOR: Redactor | None = None


def default_secret_store_path() -> str:
    configured = os.environ.get("OCTOPUS_SECRET_STORE", "")
    if configured:
        return os.path.expanduser(configured)
    try:
        from config import CFG

        paths = CFG.get("paths", {})
        if isinstance(paths, Mapping) and paths.get("secrets"):
            return os.path.expanduser(str(paths["secrets"]))
    except (ImportError, KeyError, TypeError):
        pass
    return "data/secrets.db"


def get_secret_store() -> SecretStore:
    global _DEFAULT_STORE, _DEFAULT_REDACTOR
    if _DEFAULT_STORE is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_STORE is None:
                _DEFAULT_STORE = SecretStore(default_secret_store_path())
                _DEFAULT_REDACTOR = Redactor(_DEFAULT_STORE)
    return _DEFAULT_STORE


def get_redactor() -> Redactor:
    global _DEFAULT_REDACTOR
    if _DEFAULT_REDACTOR is None:
        get_secret_store()
    if _DEFAULT_REDACTOR is None:
        raise SecretStoreError("default redactor initialization failed")
    return _DEFAULT_REDACTOR


def redact_text(value: Any, *, kind: str = "text") -> str:
    return get_redactor().redact_text(value, kind=kind)


def redact_data(value: Any) -> Any:
    return get_redactor().redact_data(value)


def reveal_secret(reference: str | SecretReference) -> str:
    return get_secret_store().reveal(reference)


def reset_default_secret_store_for_tests() -> None:
    """Drop process-wide state; intended for isolated tests only."""
    global _DEFAULT_STORE, _DEFAULT_REDACTOR
    with _DEFAULT_LOCK:
        if _DEFAULT_STORE is not None:
            _DEFAULT_STORE.close()
        _DEFAULT_STORE = None
        _DEFAULT_REDACTOR = None
