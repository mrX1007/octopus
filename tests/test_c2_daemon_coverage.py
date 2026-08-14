"""Hermetic lifecycle, validation, and IPC coverage for the C2 daemon."""

from __future__ import annotations

import asyncio
import base64
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

import core.c2.daemon as daemon

pytestmark = [pytest.mark.contract, pytest.mark.security]


class RequestStub:
    def __init__(
        self,
        value: Any,
        *,
        headers: dict[str, str] | None = None,
        raw: bytes | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.headers = headers or {}
        self.client = SimpleNamespace(host=host)
        self._body = json.dumps(value).encode("utf-8") if raw is None else raw

    async def body(self) -> bytes:
        return self._body


def _run(awaitable: Any) -> Any:
    return asyncio.run(awaitable)


def _assert_http_error(awaitable: Any, status_code: int, detail: str) -> None:
    with pytest.raises(HTTPException) as raised:
        _run(awaitable)
    assert raised.value.status_code == status_code
    assert raised.value.detail == detail


def test_keystore_passphrase_sources_validate_and_persist_securely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    passphrase_path = key_dir / "keystore.passphrase"
    monkeypatch.setattr(daemon, "KEYSTORE_PASSPHRASE_FILE", str(passphrase_path))

    monkeypatch.setenv("OCTOPUS_C2_KEY_PASSPHRASE", "short")
    with pytest.raises(RuntimeError, match="at least 16"):
        daemon._load_or_create_keystore_passphrase()
    monkeypatch.setenv("OCTOPUS_C2_KEY_PASSPHRASE", "configured-passphrase-value")
    assert daemon._load_or_create_keystore_passphrase() == "configured-passphrase-value"

    monkeypatch.delenv("OCTOPUS_C2_KEY_PASSPHRASE")
    passphrase_path.write_text("too-short", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid local KeyStore passphrase"):
        daemon._load_or_create_keystore_passphrase()

    persisted = "p" * 32
    passphrase_path.write_text(f" {persisted} \n", encoding="utf-8")
    assert daemon._load_or_create_keystore_passphrase() == persisted
    assert stat.S_IMODE(passphrase_path.stat().st_mode) == 0o600

    passphrase_path.unlink()
    monkeypatch.setattr(
        daemon,
        "secrets",
        SimpleNamespace(token_urlsafe=lambda _size: "generated-passphrase" * 4),
    )
    generated = daemon._load_or_create_keystore_passphrase()
    assert generated == "generated-passphrase" * 4
    assert passphrase_path.read_text(encoding="utf-8") == generated
    assert stat.S_IMODE(passphrase_path.stat().st_mode) == 0o600


def test_component_initialization_is_double_checked_and_unlocks_existing_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(daemon, "KEY_DIR", str(tmp_path / "data" / "keys"))
    monkeypatch.setattr(daemon, "DB_PATH", str(tmp_path / "data" / "c2.db"))
    monkeypatch.setattr(daemon, "ENROLLMENT_KEY_FILE", str(tmp_path / "data" / "keys" / "enroll.key"))
    monkeypatch.setattr(daemon, "_load_or_create_keystore_passphrase", lambda: "p" * 32)
    monkeypatch.setattr(daemon, "_components_initialized", False)
    for name in ("key_store", "crypto", "db", "events", "operators", "enrollment"):
        monkeypatch.setattr(daemon, name, None, raising=False)

    class FlipLock:
        @staticmethod
        def __enter__() -> None:
            daemon._components_initialized = True

        @staticmethod
        def __exit__(*args: Any) -> None:
            return None

    monkeypatch.setattr(daemon, "_components_lock", FlipLock())
    daemon._initialize_components()
    assert daemon.key_store is None

    daemon._components_initialized = False
    monkeypatch.setattr(daemon, "_components_lock", __import__("threading").Lock())
    unlock_results = iter((False, True))

    class KeyStoreStub:
        def __init__(self, key_dir: str) -> None:
            self.key_dir = key_dir

        @staticmethod
        def exists() -> bool:
            return True

        @staticmethod
        def unlock(_passphrase: str) -> bool:
            return next(unlock_results)

        @staticmethod
        def generate(_passphrase: str) -> None:
            raise AssertionError("existing stores must not regenerate")

        @staticmethod
        def get_or_create_x25519_private_key() -> str:
            return "private-key"

    class EventsStub:
        def __init__(self, db_path: str) -> None:
            self.db_path = db_path
            self.subscriptions: list[tuple[str, Any]] = []

        def subscribe(self, event_type: str, handler: Any) -> None:
            self.subscriptions.append((event_type, handler))

    monkeypatch.setattr(daemon, "KeyStore", KeyStoreStub)
    monkeypatch.setattr(
        daemon,
        "C2CryptoEngine",
        lambda **kwargs: SimpleNamespace(arguments=kwargs),
    )
    monkeypatch.setattr(daemon, "C2Database", lambda **kwargs: SimpleNamespace(arguments=kwargs))
    monkeypatch.setattr(daemon, "EventStore", EventsStub)
    monkeypatch.setattr(daemon, "OperatorManager", lambda **kwargs: SimpleNamespace(arguments=kwargs))
    monkeypatch.setattr(daemon, "EnrollmentAuthority", lambda path: SimpleNamespace(path=path))

    with pytest.raises(RuntimeError, match="unable to unlock"):
        daemon._initialize_components()
    assert daemon._components_initialized is False

    daemon._initialize_components()
    assert daemon._components_initialized is True
    assert daemon.crypto.arguments["private_key"] == "private-key"
    assert [item[0] for item in daemon.events.subscriptions] == [
        "agent.registered",
        "task.queued",
    ]

    initialized_store = daemon.key_store
    daemon._initialize_components()
    assert daemon.key_store is initialized_store


def test_lifespan_initializes_and_task_projection_queues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initialized: list[bool] = []
    monkeypatch.setattr(daemon, "_initialize_components", lambda: initialized.append(True))

    async def enter_lifespan() -> None:
        async with daemon._lifespan(daemon.app):
            initialized.append(False)

    _run(enter_lifespan())
    assert initialized == [True, False]

    queued: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        daemon,
        "db",
        SimpleNamespace(queue_task=lambda *args: queued.append(args)),
        raising=False,
    )
    daemon._on_task_queued(SimpleNamespace(payload={"task_id": "task-1", "agent_id": "agent-1", "command": "status"}))
    assert queued == [("task-1", "agent-1", "status")]


def test_agent_crypto_reload_handles_sealed_legacy_invalid_and_cached_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DatabaseStub:
        def __init__(self, values: list[Any]) -> None:
            self.values = values
            self.updated: list[tuple[str, str]] = []

        def get_agent_crypto(self, _agent_id: str) -> Any:
            return self.values.pop(0) if len(self.values) > 1 else self.values[0]

        def update_agent_crypto(self, agent_id: str, value: str) -> None:
            self.updated.append((agent_id, value))

    crypto = SimpleNamespace(agent_state={})
    monkeypatch.setattr(daemon, "crypto", crypto, raising=False)

    monkeypatch.setattr(daemon, "db", DatabaseStub(["sealed"]), raising=False)
    monkeypatch.setattr(
        daemon,
        "key_store",
        SimpleNamespace(unseal_json=lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad"))),
        raising=False,
    )
    assert daemon._load_agent_crypto("agent-bad") is False

    sealed_db = DatabaseStub(["sealed"])
    monkeypatch.setattr(daemon, "db", sealed_db)
    monkeypatch.setattr(
        daemon,
        "key_store",
        SimpleNamespace(
            unseal_json=lambda *_args, **_kwargs: {"key": "11" * 32, "rx_seq": 2, "tx_seq": 3},
            seal_json=lambda *_args, **_kwargs: "unused",
        ),
    )
    assert daemon._load_agent_crypto("agent-sealed") is True
    assert crypto.agent_state["agent-sealed"]["key"] == b"\x11" * 32
    assert sealed_db.updated == []

    legacy_db = DatabaseStub(
        [
            {"key": "22" * 32},
            {"key": "22" * 32},
        ]
    )
    monkeypatch.setattr(daemon, "db", legacy_db)
    monkeypatch.setattr(
        daemon,
        "key_store",
        SimpleNamespace(
            unseal_json=lambda *_args, **_kwargs: {},
            seal_json=lambda *_args, **_kwargs: "migrated-sealed-state",
        ),
    )
    assert daemon._load_agent_crypto("agent-legacy") is True
    assert legacy_db.updated == [("agent-legacy", "migrated-sealed-state")]

    monkeypatch.setattr(daemon, "db", DatabaseStub([{"rx_seq": 1}]))
    assert daemon._load_agent_crypto("agent-invalid") is False
    assert daemon._load_agent_crypto("agent-sealed") is True


def test_limited_json_reader_rejects_length_encoding_and_shape() -> None:
    assert _run(daemon._read_json_limited(RequestStub({"ok": True}), 100)) == {"ok": True}
    _assert_http_error(
        daemon._read_json_limited(RequestStub({}, headers={"content-length": "101"}), 100),
        413,
        "Request too large",
    )
    _assert_http_error(
        daemon._read_json_limited(RequestStub({}, headers={"content-length": "NaN"}), 100),
        400,
        "Invalid Content-Length",
    )
    _assert_http_error(
        daemon._read_json_limited(RequestStub({}, raw=b"{" + b"x" * 100), 100),
        413,
        "Request too large",
    )
    _assert_http_error(
        daemon._read_json_limited(RequestStub({}, raw=b"not-json"), 100),
        400,
        "Invalid JSON",
    )
    _assert_http_error(
        daemon._read_json_limited(RequestStub([], raw=b"[]"), 100),
        400,
        "JSON object required",
    )


class RegistrationCryptoStub:
    def __init__(self, decrypted: Any) -> None:
        self.decrypted = decrypted
        self.agent_state: dict[str, dict[str, Any]] = {}

    @staticmethod
    def derive_shared_key(_client_public: bytes) -> bytes:
        return b"k" * 32

    def decrypt_aes_gcm(self, _agent_id: str, _value: str) -> str:
        return json.dumps(self.decrypted)

    @staticmethod
    def encrypt_aes_gcm(_agent_id: str, _value: str) -> str:
        return "encrypted-response"


def _registration_request(public_key: bytes) -> RequestStub:
    return RequestStub(
        {
            "client_pub": base64.b64encode(public_key).decode("ascii"),
            "data": "encrypted-registration",
            "enrollment_token": "token",
        }
    )


def test_registration_rejects_key_shape_payload_shape_and_projection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon,
        "enrollment",
        SimpleNamespace(consume=lambda *_args: True),
        raising=False,
    )
    monkeypatch.setattr(daemon, "_sealed_agent_crypto", lambda _agent_id: "sealed")
    monkeypatch.setattr(daemon, "events", SimpleNamespace(append=lambda *_args, **_kwargs: None), raising=False)
    monkeypatch.setattr(daemon, "db", SimpleNamespace(get_agent_crypto=lambda _agent_id: "other"), raising=False)

    crypto = RegistrationCryptoStub({"hostname": "host"})
    monkeypatch.setattr(daemon, "crypto", crypto, raising=False)
    _assert_http_error(
        daemon.register_agent(_registration_request(b"short")),
        400,
        "Registration failed",
    )
    assert crypto.agent_state == {}

    crypto = RegistrationCryptoStub([])
    monkeypatch.setattr(daemon, "crypto", crypto)
    _assert_http_error(
        daemon.register_agent(_registration_request(b"p" * 32)),
        400,
        "Registration failed",
    )
    assert crypto.agent_state == {}

    crypto = RegistrationCryptoStub({"hostname": "host"})
    monkeypatch.setattr(daemon, "crypto", crypto)
    _assert_http_error(
        daemon.register_agent(_registration_request(b"p" * 32)),
        400,
        "Registration failed",
    )
    assert crypto.agent_state == {}


class BeaconDatabaseStub:
    def __init__(
        self,
        *,
        seen: bool = True,
        acknowledgements: int | None = None,
        task_result: bool = True,
        crypto_update: bool = True,
    ) -> None:
        self.seen = seen
        self.acknowledgements = acknowledgements
        self.task_result = task_result
        self.crypto_update = crypto_update

    def update_agent_seen(self, **_kwargs: Any) -> bool:
        return self.seen

    def acknowledge_tasks(self, _agent_id: str, task_ids: list[str]) -> int:
        return len(set(task_ids)) if self.acknowledgements is None else self.acknowledgements

    def update_task_result(self, *_args: Any) -> bool:
        return self.task_result

    @staticmethod
    def get_pending_tasks(_agent_id: str) -> list[dict[str, Any]]:
        return []

    def update_agent_crypto(self, *_args: Any) -> bool:
        return self.crypto_update


class BeaconCryptoStub:
    def __init__(self, payload: Any = None, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.agent_state = {"agent-1": {"key": b"k" * 32, "rx_seq": 1, "tx_seq": 1}}

    def decrypt_aes_gcm(self, _agent_id: str, _value: str) -> str:
        if self.error is not None:
            raise self.error
        return json.dumps(self.payload)

    @staticmethod
    def encrypt_aes_gcm(_agent_id: str, _value: str) -> str:
        return "encrypted-beacon"


def _call_beacon(
    monkeypatch: pytest.MonkeyPatch,
    payload: Any,
    *,
    database: BeaconDatabaseStub | None = None,
    crypto_error: Exception | None = None,
) -> Any:
    monkeypatch.setattr(daemon, "db", database or BeaconDatabaseStub(), raising=False)
    monkeypatch.setattr(daemon, "crypto", BeaconCryptoStub(payload, crypto_error), raising=False)
    monkeypatch.setattr(daemon, "events", SimpleNamespace(append=lambda *_args, **_kwargs: None), raising=False)
    monkeypatch.setattr(daemon, "_load_agent_crypto", lambda _agent_id: True)
    monkeypatch.setattr(daemon, "_sealed_agent_crypto", lambda _agent_id: "sealed")
    return daemon.beacon(RequestStub({"data": "cipher"}, headers={"Agent-ID": "agent-1"}))


def test_beacon_rejects_identity_state_acknowledgement_and_result_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _assert_http_error(
        daemon.beacon(RequestStub({"data": 123}, headers={"Agent-ID": "agent-1"})),
        400,
        "Missing encrypted payload",
    )
    _assert_http_error(
        daemon.beacon(RequestStub({"data": "cipher"})),
        401,
        "Agent not found",
    )
    monkeypatch.setattr(daemon, "_load_agent_crypto", lambda _agent_id: False)
    _assert_http_error(
        daemon.beacon(RequestStub({"data": "cipher"}, headers={"Agent-ID": "agent-1"})),
        401,
        "Agent not found",
    )

    _assert_http_error(
        _call_beacon(monkeypatch, {}, database=BeaconDatabaseStub(seen=False)),
        401,
        "Agent not found",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {"acks": "invalid"}),
        400,
        "Invalid task acknowledgements",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {"acks": [None]}),
        400,
        "Invalid task acknowledgements",
    )
    _assert_http_error(
        _call_beacon(
            monkeypatch,
            {"acks": ["task-1"]},
            database=BeaconDatabaseStub(acknowledgements=0),
        ),
        409,
        "One or more acknowledgements were rejected",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {"results": {"not": "a list"}}),
        413,
        "Too many results",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {"results": ["invalid"]}),
        409,
        "One or more task results were rejected",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {"results": [{"task_id": "", "output": ""}]}),
        409,
        "One or more task results were rejected",
    )
    _assert_http_error(
        _call_beacon(
            monkeypatch,
            {"results": [{"task_id": "task-1", "output": "ok"}]},
            database=BeaconDatabaseStub(task_result=False),
        ),
        409,
        "One or more task results were rejected",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {}, database=BeaconDatabaseStub(crypto_update=False)),
        401,
        "Agent not found",
    )
    _assert_http_error(
        _call_beacon(monkeypatch, {}, crypto_error=ValueError("bad ciphertext")),
        400,
        "Invalid beacon",
    )

    response = _run(
        _call_beacon(
            monkeypatch,
            {"results": [{"task_id": "task-1", "output": "", "error": "failed"}]},
        )
    )
    assert response == {"data": "encrypted-beacon"}


class IPCConnection:
    def __init__(self, requests: list[Any]) -> None:
        import socket

        from core.c2.control_protocol import ControlProtocolCodec

        self.codec = ControlProtocolCodec()
        self.requests = list(requests)
        self.responses: list[Any] = []
        self.closed = False
        self._buffer = bytearray()
        self.family = socket.AF_UNIX

    def recv(self, size: int) -> bytes:
        if not self._buffer and self.requests:
            req = self.requests.pop(0)
            if isinstance(req, BaseException):
                raise req
            if isinstance(req, bytes):
                self._buffer.extend(req)
            elif hasattr(req, "authorization"):
                self._buffer.extend(self.codec.encode_request(req))
            else:
                self._buffer.extend(json.dumps(req).encode("utf-8"))

        if not self._buffer:
            return b""
        chunk = bytes(self._buffer[:size])
        del self._buffer[:size]
        return chunk

    def sendall(self, payload: bytes) -> None:
        try:
            self.responses.append(self.codec.decode_response(payload))
        except Exception:
            self.responses.append(json.loads(payload))

    def close(self) -> None:
        self.closed = True


def test_ipc_dispatches_auth_rbac_actions_management_and_audit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    import os
    import time

    from core.c2.control_auth import PeerPrincipal
    from core.c2.control_boundary import ControlVerificationKeyStore
    from core.c2.control_commands import (
        C2ControlActionV1,
        ParticipantControlAuthorizationV1,
        ParticipantControlRequestV1,
        SignedControlResponseV1,
    )
    from core.c2.control_models import calculate_payload_digest
    from core.c2.control_signing import ControlSignerV1
    from core.c2.grant_service import GrantService
    from core.c2.operators import OperatorManager

    db_path = str(tmp_path / "daemon_cov.db")
    monkeypatch.setenv("OCTOPUS_C2_DB_PATH", db_path)
    monkeypatch.setenv("OCTOPUS_C2_ALLOW_EPHEMERAL_CONTROL_STATE", "1")
    monkeypatch.setattr(daemon, "_daemon_resource_participant_instance", None)
    monkeypatch.setattr(daemon, "_replay_store_instance", None)
    monkeypatch.setattr(daemon, "_key_store_instance", None)
    monkeypatch.setattr(daemon, "_control_boundary_instance", None)

    op_mgr = OperatorManager(db_path=db_path)
    grant_svc = GrantService(db_path=db_path)
    key_store = ControlVerificationKeyStore(db_path=db_path)

    op_mgr.create_operator(
        operator_id="op_admin",
        subject_id="op-admin",
        name="Admin Operator",
        role="admin",
        api_key="api_key_test_admin_12345",
    )
    key_store.register_key(
        key_id="key_test",
        operator_id="op_admin",
        verification_key=b"secret_key_12345678901234567890",
        algorithm="hmac-sha256",
    )
    current_uid = os.getuid()
    current_gid = os.getgid()
    grant_svc.set_peer_binding("op_admin", uid=current_uid, gid=current_gid, active=True)
    grant_svc.set_mission_grant("op_admin", subject_id="op-admin", mission_id="m_test", active=True)

    signer = ControlSignerV1("key_test", b"secret_key_12345678901234567890")

    def _make_signed(action: C2ControlActionV1, tx_id: str, sub_id: str = "op-admin"):
        auth = ParticipantControlAuthorizationV1(
            key_id="key_test",
            transaction_id=tx_id,
            participant_id="part_test",
            mission_id="m_test",
            subject_id=sub_id,
            action_id=action.value,
            coordinator_revision=1,
            request_digest="init_digest",
            expires_at=time.time() + 100.0,
            nonce=f"nonce_{tx_id}_1234567890",
            signature="",
        )
        req = ParticipantControlRequestV1(
            action=action,
            authorization=auth,
            payload_schema_id="schema:test",
            payload_digest=calculate_payload_digest(b""),
            canonical_payload_b64u="",
        )
        return signer.sign_participant_request(req)

    requests = [
        _make_signed(C2ControlActionV1.PING, "tx_1"),
        _make_signed(C2ControlActionV1.READINESS, "tx_2"),
        _make_signed(C2ControlActionV1.PREPARE_C2_RESOURCE, "tx_3"),
        _make_signed(C2ControlActionV1.RESERVE_ENROLLMENT_FOR_BUILD, "tx_4"),
    ]
    connection = IPCConnection(requests)

    def peer_mock(_conn: Any) -> PeerPrincipal:
        return PeerPrincipal(pid=os.getpid(), uid=current_uid, gid=current_gid)

    daemon.handle_client(connection, peer_resolver=peer_mock)

    assert connection.closed is True
    assert len(connection.responses) == 4
    # All responses are wrapped in SignedControlResponseV1
    assert all(isinstance(r, SignedControlResponseV1) for r in connection.responses)

    broken = IPCConnection([b"not-json-or-ctrl1"])
    daemon.handle_client(broken, peer_resolver=peer_mock)
    assert broken.closed is True


class SocketStub:
    def __init__(self, *, connect_error: Exception | None = None, accepts: list[Any] | None = None) -> None:
        self.connect_error = connect_error
        self.accepts = list(accepts or [])
        self.closed = False
        self.bound: str | None = None
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, _path: str) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    def close(self) -> None:
        self.closed = True

    def bind(self, path: str) -> None:
        self.bound = path

    def listen(self, _backlog: int) -> None:
        return None

    def accept(self) -> Any:
        if not self.accepts:
            raise RuntimeError("stop accept loop")
        return self.accepts.pop(0)


def test_socket_server_refuses_existing_socket_and_accepts_locally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = False

    def create_socket(*_args: Any) -> SocketStub:
        nonlocal created
        created = True
        return SocketStub()

    monkeypatch.setattr(
        daemon,
        "socket",
        SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=create_socket),
    )
    monkeypatch.setattr(
        daemon,
        "os",
        SimpleNamespace(
            path=SimpleNamespace(exists=lambda _path: True),
            remove=lambda _path: None,
            chmod=lambda *_args: None,
        ),
    )
    with pytest.raises(RuntimeError, match="control socket already exists"):
        daemon.run_socket_server()
    assert created is False

    connection = object()
    server = SocketStub(accepts=[(connection, None)])
    started: list[tuple[Any, ...]] = []

    class ThreadStub:
        def __init__(self, **kwargs: Any) -> None:
            started.append((kwargs["target"], kwargs["args"], kwargs["daemon"]))

        @staticmethod
        def start() -> None:
            return None

    monkeypatch.setattr(
        daemon,
        "socket",
        SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, socket=lambda *_args: server),
    )
    monkeypatch.setattr(
        daemon,
        "os",
        SimpleNamespace(
            path=SimpleNamespace(exists=lambda _path: False),
            remove=lambda _path: None,
            chmod=lambda *_args: None,
        ),
    )
    monkeypatch.setattr(daemon, "threading", SimpleNamespace(Thread=ThreadStub))
    with pytest.raises(RuntimeError, match="stop accept loop"):
        daemon.run_socket_server()
    assert server.bound == daemon.SOCK_FILE
    assert started == [(daemon.handle_client, (connection,), True)]


class MainOperatorsStub:
    def __init__(self, *, empty: bool, fail_create: bool = False) -> None:
        self.empty = empty
        self.fail_create = fail_create

    def list_operators(self) -> list[str]:
        return [] if self.empty else ["operator"]

    def create_operator(self, _name: str, _role: str) -> str:
        if self.fail_create:
            raise RuntimeError("bootstrap failed")
        self.empty = False
        return "admin-key"


def _install_main_stubs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    operators: MainOperatorsStub,
    uvicorn_outcome: Exception | None = None,
) -> list[dict[str, Any]]:
    monkeypatch.setattr(daemon, "create_app", lambda: "application")
    monkeypatch.setattr(daemon, "operators", operators, raising=False)
    monkeypatch.setattr(daemon, "DATA_DIR", str(tmp_path))
    started: list[dict[str, Any]] = []

    class ThreadStub:
        def __init__(self, **kwargs: Any) -> None:
            started.append(kwargs)

        @staticmethod
        def start() -> None:
            return None

    monkeypatch.setattr(daemon, "threading", SimpleNamespace(Thread=ThreadStub))

    def run(*_args: Any, **_kwargs: Any) -> None:
        if uvicorn_outcome is not None:
            raise uvicorn_outcome

    monkeypatch.setattr(daemon, "uvicorn", SimpleNamespace(run=run))
    return started


def test_main_bootstrap_port_validation_and_uvicorn_error_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    started = _install_main_stubs(
        monkeypatch,
        tmp_path,
        MainOperatorsStub(empty=True),
        OSError("Address already in use"),
    )
    monkeypatch.setenv("OCTOPUS_C2_PORT", "8443")
    daemon.main()
    assert not (tmp_path / "default_admin.key").exists()
    assert started[0]["target"] is daemon.run_socket_server
    output = capsys.readouterr().out
    assert "Port 8443 already in use" in output
    assert "admin-key" not in output

    _install_main_stubs(
        monkeypatch,
        tmp_path,
        MainOperatorsStub(empty=True, fail_create=True),
    )
    daemon.main()
    assert not (tmp_path / "default_admin.key").exists()
    assert "bootstrap" not in capsys.readouterr().out.lower()

    _install_main_stubs(monkeypatch, tmp_path, MainOperatorsStub(empty=False))
    monkeypatch.setenv("OCTOPUS_C2_PORT", "not-an-integer")
    with pytest.raises(RuntimeError, match="must be an integer"):
        daemon.main()

    monkeypatch.setenv("OCTOPUS_C2_PORT", "0")
    with pytest.raises(RuntimeError, match="outside the valid range"):
        daemon.main()

    _install_main_stubs(
        monkeypatch,
        tmp_path,
        MainOperatorsStub(empty=False),
        OSError("different failure"),
    )
    monkeypatch.setenv("OCTOPUS_C2_PORT", "8443")
    with pytest.raises(OSError, match="different failure"):
        daemon.main()
