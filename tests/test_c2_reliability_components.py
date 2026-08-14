"""Hermetic reliability, state, and serialization contracts for C2 helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import core.c2.enrollment as enrollment_module
import core.c2.implants.python_implant as implant_module
from core.c2.enrollment import EnrollmentAuthority
from core.c2.event_store import Event, EventStore
from core.c2.implants.python_implant import _encrypt_config, _split_key, generate_python_implant
from core.c2.operators import (
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READONLY,
    OperatorManager,
    _hash_api_key,
)

pytestmark = pytest.mark.contract


class EnrollmentDatabaseStub:
    def __init__(self, result: Any = True) -> None:
        self.result = result
        self.calls: list[tuple[str, int, int]] = []

    def consume_enrollment_token(
        self,
        fingerprint: str,
        expires_at: int,
        current: int,
    ) -> Any:
        self.calls.append((fingerprint, expires_at, current))
        return self.result


def _signed_enrollment_token(authority: EnrollmentAuthority, payload: Any) -> str:
    encoded = enrollment_module._b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = enrollment_module._b64encode(hmac.new(authority._key, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def _signed_raw_enrollment_token(authority: EnrollmentAuthority, payload: bytes) -> str:
    encoded = enrollment_module._b64encode(payload)
    signature = enrollment_module._b64encode(hmac.new(authority._key, encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def test_enrollment_key_creation_reopen_validation_and_creation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        enrollment_module,
        "secrets",
        SimpleNamespace(
            token_bytes=lambda size: b"k" * size,
            token_urlsafe=lambda _size: "issued-token-id",
        ),
    )
    key_path = tmp_path / "keys" / "enrollment.key"

    created = EnrollmentAuthority(key_path)
    assert created._key == b"k" * 32
    assert key_path.read_bytes() == b"k" * 32
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    reopened = EnrollmentAuthority(key_path)
    assert reopened._key == created._key

    invalid_path = tmp_path / "invalid.key"
    invalid_path.write_bytes(b"short")
    with pytest.raises(ValueError, match="invalid enrollment signing key"):
        EnrollmentAuthority(invalid_path)

    race_path = tmp_path / "race" / "enrollment.key"

    def racing_open(path: os.PathLike[str] | str, *_args: Any) -> int:
        Path(path).write_bytes(b"r" * 32)
        raise FileExistsError(path)

    def denied_chmod(*_args: Any) -> None:
        raise OSError("simulated permission race")

    with monkeypatch.context() as context:
        context.setattr(enrollment_module.os, "open", racing_open)
        context.setattr(enrollment_module.os, "chmod", denied_chmod)
        raced = EnrollmentAuthority(race_path)
    assert raced._key == b"r" * 32


def test_enrollment_issue_and_consume_enforce_authenticated_time_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        enrollment_module,
        "secrets",
        SimpleNamespace(
            token_bytes=lambda size: b"s" * size,
            token_urlsafe=lambda _size: "stable-token-id",
        ),
    )
    monkeypatch.setattr(
        enrollment_module,
        "time",
        SimpleNamespace(time=lambda: 1_000.0),
    )
    authority = EnrollmentAuthority(tmp_path / "enrollment.key")

    token = authority.issue(ttl_seconds=60)
    encoded, _signature = token.split(".", 1)
    payload = json.loads(enrollment_module._b64decode(encoded))
    assert payload == {
        "exp": 1_060,
        "iat": 1_000,
        "jti": "stable-token-id",
        "v": authority.VERSION,
    }

    database = EnrollmentDatabaseStub(result="consumed")
    assert authority.consume(token, database) is True
    expected_fingerprint = hashlib.sha256(b"stable-token-id").hexdigest()
    assert database.calls == [(expected_fingerprint, 1_060, 1_000)]

    refusing_database = EnrollmentDatabaseStub(result=0)
    assert authority.consume(authority.issue(ttl_seconds=10, now=2_000), refusing_database, now=2_001) is False
    assert refusing_database.calls[0][1:] == (2_010, 2_001)

    for invalid_ttl in (0, authority.MAX_TTL_SECONDS + 1):
        with pytest.raises(ValueError, match="TTL is outside"):
            authority.issue(invalid_ttl)

    assert authority.consume(token + "tampered", database, now=1_001) is False


@pytest.mark.parametrize(
    "payload",
    (
        {"iat": 100, "exp": 200, "jti": "id", "v": 0},
        {"iat": 131, "exp": 200, "jti": "id", "v": 1},
        {"iat": 0, "exp": 99, "jti": "id", "v": 1},
        {"iat": 100, "exp": 100, "jti": "id", "v": 1},
        {"iat": 0, "exp": EnrollmentAuthority.MAX_TTL_SECONDS + 1, "jti": "id", "v": 1},
    ),
)
def test_enrollment_consume_rejects_invalid_signed_claims(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    authority = EnrollmentAuthority(tmp_path / "enrollment.key")
    database = EnrollmentDatabaseStub()

    assert authority.consume(_signed_enrollment_token(authority, payload), database, now=100) is False
    assert database.calls == []


def test_enrollment_consume_rejects_malformed_payloads(tmp_path: Path) -> None:
    authority = EnrollmentAuthority(tmp_path / "enrollment.key")
    database = EnrollmentDatabaseStub()
    missing_claim = _signed_enrollment_token(
        authority,
        {"iat": 100, "exp": 200, "v": authority.VERSION},
    )
    wrong_type = _signed_enrollment_token(authority, [100, 200, "id", authority.VERSION])
    invalid_json = _signed_raw_enrollment_token(authority, b"not-json")

    for token in (None, "not-a-token", missing_claim, wrong_type, invalid_json):
        assert authority.consume(token, database, now=100) is False
    assert database.calls == []


def test_event_store_appends_filters_serializes_and_isolates_subscriber_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    timestamps = iter((10.0, 20.0, 30.0))
    import core.c2.event_store as event_store_module

    monkeypatch.setattr(
        event_store_module,
        "time",
        SimpleNamespace(time=lambda: next(timestamps)),
    )
    store = EventStore(str(tmp_path / "events.db"))
    first = store.append("agent", "agent-1", "agent.seen", {"online": True})

    delivered: list[int] = []

    def successful_handler(event: Event) -> None:
        delivered.append(event.event_id)

    def broken_handler(_event: Event) -> None:
        raise RuntimeError("subscriber failed")

    store.subscribe("agent.updated", successful_handler)
    store.subscribe("agent.updated", broken_handler)
    second = store.append(
        "agent",
        "agent-1",
        "agent.updated",
        {"hostname": "host-a"},
        causation_id=first.event_id,
        correlation_id="mission-1",
    )
    third = store.append("task", "task-1", "task.queued", {"command": "status"})

    assert delivered == [second.event_id]
    assert "Handler error for agent.updated: subscriber failed" in capsys.readouterr().out
    assert second.to_dict() == {
        "event_id": 2,
        "timestamp": 20.0,
        "aggregate_type": "agent",
        "aggregate_id": "agent-1",
        "event_type": "agent.updated",
        "payload": {"hostname": "host-a"},
        "causation_id": 1,
        "correlation_id": "mission-1",
    }

    assert [event.event_id for event in store.read_stream(limit=2)] == [1, 2]
    assert (
        store.read_stream(
            aggregate_type="agent",
            aggregate_id="agent-1",
            event_type="agent.updated",
            after_id=first.event_id,
        )[0].to_dict()
        == second.to_dict()
    )
    assert store.read_stream(after_id=third.event_id) == []


def test_event_store_replay_offsets_upsert_and_transaction_rollback(tmp_path: Path) -> None:
    store = EventStore(str(tmp_path / "events.db"))
    alpha = store.append("agent", "a", "alpha", {"value": 1})
    store.append("agent", "a", "beta", {"value": 2})
    assert store.get_subscriber_offset("projection") == 0

    replayed: list[int] = []
    store.replay("projection", lambda event: replayed.append(event.event_id), event_type="alpha")
    assert replayed == [alpha.event_id]
    assert store.get_subscriber_offset("projection") == alpha.event_id

    store.replay("projection", lambda event: replayed.append(event.event_id), event_type="alpha")
    assert replayed == [alpha.event_id]
    store.update_subscriber_offset("projection", 2)
    assert store.get_subscriber_offset("projection") == 2

    with pytest.raises(RuntimeError, match="rollback"), store._get_conn() as connection:
        connection.execute(
            "INSERT INTO subscriber_offsets (subscriber_name, last_event_id) VALUES (?, ?)",
            ("rolled-back", 99),
        )
        raise RuntimeError("rollback")
    assert store.get_subscriber_offset("rolled-back") == 0


def test_operator_manager_does_not_auto_create_admin(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "operators.db"
    manager = OperatorManager(str(db_path))
    assert manager.list_operators() == []
    assert not (tmp_path / "default_admin.key").exists()

    admin_key = manager.create_operator("admin", ROLE_ADMIN, subject_id="subject:admin")
    admin = manager.authenticate(admin_key)
    assert admin is not None
    assert admin["name"] == "admin"
    assert admin["role"] == ROLE_ADMIN
    assert admin["subject_id"] == "subject:admin"
    assert "api_key_hash" not in admin
    assert manager.authenticate("wrong-key") is None
    assert _hash_api_key(admin_key) == hashlib.sha256(admin_key.encode("utf-8")).hexdigest()

    operator_key = manager.create_operator("alice", ROLE_OPERATOR)
    readonly_key = manager.create_operator("viewer", ROLE_READONLY)
    with pytest.raises(ValueError, match="Invalid role"):
        manager.create_operator("invalid", "owner")
    with pytest.raises(sqlite3.IntegrityError):
        manager.create_operator("alice", ROLE_OPERATOR)
    assert [item["name"] for item in manager.list_operators()].count("alice") == 1

    alice = manager.authenticate(operator_key)
    viewer = manager.authenticate(readonly_key)
    assert alice is not None and viewer is not None
    assert manager.authorize(alice, "queue_task") is True
    assert manager.authorize(viewer, "queue_task") is False
    assert manager.authorize({"role": "unknown"}, "ping") is False

    rotated = manager.rotate_api_key("alice")
    assert rotated is not None
    assert manager.authenticate(operator_key) is None
    assert manager.authenticate(rotated) is not None

    assert manager.deactivate_operator("viewer") is True
    assert manager.authenticate(readonly_key) is None
    assert manager.rotate_api_key("viewer") is None
    assert manager.rotate_api_key("missing") is None
    assert manager.deactivate_operator("missing") is False

    reopened = OperatorManager(str(db_path))
    assert len(reopened.list_operators()) == 3
    assert not (tmp_path / "default_admin.key").exists()


def test_implant_config_encryption_and_key_split_are_lossless(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = b"n" * 12
    key = bytes(range(32))
    monkeypatch.setattr(
        implant_module,
        "secrets",
        SimpleNamespace(token_bytes=lambda size: nonce if size == 12 else b"k" * size),
    )
    config = {"urls": "https://one.invalid", "enrollment_token": "token"}

    encrypted = _encrypt_config(config, key)
    blob = base64.b64decode(encrypted)
    assert blob[:12] == nonce
    assert json.loads(AESGCM(key).decrypt(blob[:12], blob[12:], None)) == config

    first, second = _split_key(key)
    assert len(first) == len(second) == 32
    assert bytes.fromhex(first + second) == key


def _generated_string_constant(source: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)} = "([^"]*)"$', source, re.MULTILINE)
    assert match is not None
    return match.group(1)


def test_generate_python_implant_serializes_supplied_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_key = b"c" * 32
    nonce = b"n" * 12

    def token_bytes(size: int) -> bytes:
        return config_key if size == 32 else nonce

    monkeypatch.setattr(
        implant_module,
        "secrets",
        SimpleNamespace(token_bytes=token_bytes),
    )
    server_public = base64.b64encode(b"p" * 32).decode("ascii")
    source = generate_python_implant(
        ["https://one.invalid", "https://two.invalid"],
        beacon_interval=15,
        jitter_percent=25,
        server_pub_b64=server_public,
        enrollment_token="single-use-token",
    )

    split_key = bytes.fromhex(_generated_string_constant(source, "_KP1") + _generated_string_constant(source, "_KP2"))
    encrypted = base64.b64decode(_generated_string_constant(source, "_ENC_BLOB"))
    config = json.loads(AESGCM(split_key).decrypt(encrypted[:12], encrypted[12:], None))
    assert config == {
        "urls": "https://one.invalid,https://two.invalid",
        "pub": server_public,
        "enrollment_token": "single-use-token",
    }
    assert "_BEACON_INT = 15" in source
    assert "_JITTER_PCT = 25" in source


def test_generate_python_implant_loads_default_key_and_enrollment_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.c2 import builder

    server_public = base64.b64encode(b"d" * 32).decode("ascii")
    loaded_paths: list[str] = []
    authority_paths: list[str] = []

    def load_server_pub_key(path: str) -> str:
        loaded_paths.append(path)
        return server_public

    class AuthorityStub:
        def __init__(self, path: str) -> None:
            authority_paths.append(path)

        @staticmethod
        def issue() -> str:
            return "issued-enrollment-token"

    fake_source_path = tmp_path / "project" / "core" / "c2" / "implants" / "python_implant.py"
    monkeypatch.setattr(builder, "load_server_pub_key", load_server_pub_key)
    monkeypatch.setattr(enrollment_module, "EnrollmentAuthority", AuthorityStub)
    monkeypatch.setattr(implant_module, "__file__", str(fake_source_path))
    monkeypatch.setattr(
        implant_module,
        "secrets",
        SimpleNamespace(token_bytes=lambda size: b"z" * size),
    )

    source = generate_python_implant(["https://default.invalid"])

    expected_root = tmp_path / "project"
    assert loaded_paths == [str(expected_root / "data" / "keys" / "server_x25519_public.pem")]
    assert authority_paths == [str(expected_root / "data" / "keys" / "enrollment.key")]
    split_key = bytes.fromhex(_generated_string_constant(source, "_KP1") + _generated_string_constant(source, "_KP2"))
    encrypted = base64.b64decode(_generated_string_constant(source, "_ENC_BLOB"))
    config = json.loads(AESGCM(split_key).decrypt(encrypted[:12], encrypted[12:], None))
    assert config["enrollment_token"] == "issued-enrollment-token"


@pytest.mark.parametrize(
    ("urls", "interval", "jitter", "server_public", "message"),
    (
        ([], 60, 20, base64.b64encode(b"p" * 32).decode("ascii"), "At least one"),
        (["https://c2.invalid"], 0, 20, base64.b64encode(b"p" * 32).decode("ascii"), "must be ≥ 1"),
        (["https://c2.invalid"], 60, -1, base64.b64encode(b"p" * 32).decode("ascii"), "must be 0-50"),
        (["https://c2.invalid"], 60, 51, base64.b64encode(b"p" * 32).decode("ascii"), "must be 0-50"),
        (["https://c2.invalid"], 60, 20, base64.b64encode(b"p" * 31).decode("ascii"), "raw 32-byte"),
    ),
)
def test_generate_python_implant_rejects_invalid_configuration(
    urls: list[str],
    interval: int,
    jitter: int,
    server_public: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        generate_python_implant(
            urls,
            beacon_interval=interval,
            jitter_percent=jitter,
            server_pub_b64=server_public,
            enrollment_token="token",
        )
