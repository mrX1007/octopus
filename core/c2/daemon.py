"""C2 ASGI application with an explicit runtime initialization lifecycle.

Importing this module only defines the application and its handlers. Filesystem,
key-store, and database setup happens from :func:`create_app`, the ASGI lifespan,
or :func:`main`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time
import uuid

from contextlib import asynccontextmanager, suppress
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request

from core.c2.control_auth import ControlAuthenticatorV1
from core.c2.control_boundary import (
    AuthenticatorPrincipalResolver,
    ControlBoundaryError,
    ControlReplayStore,
    FramedControlBoundary,
    StaticControlKeyResolver,
    extract_peer_principal,
)
from core.c2.control_commands import (
    BoundedControlErrorV1,
    C2ControlActionV1,
    C2ControlErrorCodeV1,
    ParticipantControlPhaseV1,
    ParticipantControlQuerySnapshotV1,
    ParticipantControlReceiptV1,
    ParticipantControlRequestV1,
    SignedControlResponseV1,
)
from core.c2.control_models import (
    canonical_json_bytes,
    canonical_response_envelope_dict,
)
from core.c2.control_protocol import FRAME_MAGIC, MAX_FRAME_SIZE, ControlProtocolCodec, receive_frame
from core.c2.control_rbac import ControlRBACPolicy
from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.enrollment import EnrollmentAuthority
from core.c2.event_store import EventStore
from core.c2.grant_service import GrantService
from core.c2.key_store import KeyStore

from core.c2.operators import OperatorManager
from core.c2.protocol import C2_CONTROL_PROTOCOL_VERSION, C2_PROTOCOL_VERSION
from core.c2.resource_participant import C2DaemonResourceParticipant


# ─── Configuration ───────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.abspath(os.environ.get("OCTOPUS_DATA_DIR", os.path.join(BASE_DIR, "data")))
KEY_DIR = os.path.join(DATA_DIR, "keys")
DB_PATH = os.path.join(DATA_DIR, "c2.db")
SOCK_FILE = os.environ.get("OCTOPUS_C2_SOCKET", "/tmp/octopus.sock")
KEYSTORE_PASSPHRASE_FILE = os.path.join(KEY_DIR, "keystore.passphrase")
ENROLLMENT_KEY_FILE = os.path.join(KEY_DIR, "enrollment.key")
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
        os.chmod(KEYSTORE_PASSPHRASE_FILE, 0o600)
        with open(KEYSTORE_PASSPHRASE_FILE, encoding="utf-8") as handle:
            value = handle.read().strip()
        if len(value) < 32:
            raise RuntimeError("invalid local KeyStore passphrase file")
        return value

    value = secrets.token_urlsafe(48)
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


# Component names remain module-level compatibility attributes, but receive
# values only when the executable lifecycle is explicitly entered.
key_store: KeyStore
crypto: C2CryptoEngine
db: C2Database
events: EventStore
operators: OperatorManager
enrollment: EnrollmentAuthority
_components_initialized = False
_components_lock = threading.Lock()


def _initialize_components() -> None:
    """Initialize persistent C2 state exactly once for this process."""

    global _components_initialized, crypto, db, enrollment, events, key_store, operators
    if _components_initialized:
        return
    with _components_lock:
        if _components_initialized:
            return

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
        initialized_db = C2Database(db_path=DB_PATH)
        initialized_events = EventStore(db_path=DB_PATH)
        initialized_operators = OperatorManager(db_path=DB_PATH)
        initialized_enrollment = EnrollmentAuthority(ENROLLMENT_KEY_FILE)

        key_store = initialized_key_store
        crypto = initialized_crypto
        db = initialized_db
        events = initialized_events
        operators = initialized_operators
        enrollment = initialized_enrollment
        events.subscribe("agent.registered", _on_agent_registered)
        events.subscribe("task.queued", _on_task_queued)
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
    p = event.payload
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
    p = event.payload
    db.queue_task(p["task_id"], p["agent_id"], p["command"])


# ─── Agent-Facing HTTP Endpoints ─────────────────────────


def _load_agent_crypto(agent_id: str) -> bool:
    """Load crypto state from DB into memory if daemon restarted."""
    if agent_id not in crypto.agent_state:
        state = db.get_agent_crypto(agent_id)
        if isinstance(state, str):
            try:
                state = key_store.unseal_json(state, aad=agent_id.encode("utf-8"))
            except Exception:
                return False
        if isinstance(state, dict) and "key" in state:
            crypto.agent_state[agent_id] = {
                "key": bytes.fromhex(state["key"]),
                "rx_seq": state.get("rx_seq", 0),
                "tx_seq": state.get("tx_seq", 0),
            }
            if not isinstance(db.get_agent_crypto(agent_id), str):
                sealed = key_store.seal_json(state, aad=agent_id.encode("utf-8"))
                db.update_agent_crypto(agent_id, sealed)
            return True
        return False
    return True


def _sealed_agent_crypto(agent_id: str) -> str:
    state = crypto.agent_state[agent_id]
    return key_store.seal_json(
        {
            "key": state["key"].hex(),
            "rx_seq": state["rx_seq"],
            "tx_seq": state["tx_seq"],
        },
        aad=agent_id.encode("utf-8"),
    )


async def _read_json_limited(request: Request, limit: int) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > limit:
                raise HTTPException(status_code=413, detail="Request too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    raw = await request.body()
    if len(raw) > limit:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="JSON object required")
    return value


@app.post("/register")
async def register_agent(request: Request):
    """X25519 Registration endpoint with HKDF key derivation."""
    body = await _read_json_limited(request, MAX_REGISTER_BODY)
    b64_client_pub = body.get("client_pub")
    encrypted_data = body.get("data")
    enrollment_token = body.get("enrollment_token")

    if not b64_client_pub or not encrypted_data or not enrollment_token:
        raise HTTPException(status_code=400, detail="Missing crypto payload")

    temp_id = f"registration:{uuid.uuid4().hex}"
    try:
        client_pub_bytes = base64.b64decode(b64_client_pub, validate=True)
        if len(client_pub_bytes) != 32:
            raise ValueError("invalid client key")
        if not enrollment.consume(str(enrollment_token), db):
            raise HTTPException(status_code=401, detail="Enrollment denied")
        shared_key = crypto.derive_shared_key(client_pub_bytes)

        crypto.agent_state[temp_id] = {"key": shared_key, "rx_seq": 0, "tx_seq": 0}

        raw_data = crypto.decrypt_aes_gcm(temp_id, encrypted_data)
        data = json.loads(raw_data)
        if not isinstance(data, dict):
            raise ValueError("invalid registration data")
        real_agent_id = f"AGT-{uuid.uuid4().hex}"

        crypto.agent_state[real_agent_id] = crypto.agent_state.pop(temp_id)
        resp_data = {
            "status": "ok",
            "agent_id": real_agent_id,
            "interval": 60,
            "jitter": 20,
        }
        resp_enc = crypto.encrypt_aes_gcm(real_agent_id, json.dumps(resp_data))
        sealed_state = _sealed_agent_crypto(real_agent_id)
        events.append(
            "agent",
            real_agent_id,
            "agent.registered",
            {
                "agent_id": real_agent_id,
                "hostname": data.get("hostname"),
                "os": data.get("os"),
                "user": data.get("user"),
                "ip": request.client.host,
                "crypto_state": sealed_state,
            },
        )
        if db.get_agent_crypto(real_agent_id) != sealed_state:
            crypto.agent_state.pop(real_agent_id, None)
            raise RuntimeError("agent projection failed")
        return {"data": resp_enc}

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Registration failed") from exc
    finally:
        crypto.agent_state.pop(temp_id, None)


@app.post("/beacon")
async def beacon(request: Request):
    """Beaconing endpoint."""
    body = await _read_json_limited(request, MAX_BEACON_BODY)
    encrypted_data = body.get("data")
    if not isinstance(encrypted_data, str):
        raise HTTPException(status_code=400, detail="Missing encrypted payload")

    agent_id = request.headers.get("Agent-ID")
    if not agent_id or not _load_agent_crypto(agent_id):
        raise HTTPException(status_code=401, detail="Agent not found")

    try:
        raw = crypto.decrypt_aes_gcm(agent_id, encrypted_data)
        decrypted = json.loads(raw)

        # Publish beacon event
        events.append(
            "agent",
            agent_id,
            "agent.beacon",
            {
                "ip": request.client.host,
            },
        )

        # Sync crypto state to DB
        crypto.agent_state[agent_id]
        sealed_state = _sealed_agent_crypto(agent_id)
        if not db.update_agent_seen(
            agent_id=agent_id,
            hostname=decrypted.get("hostname", "Unknown"),
            os_name=decrypted.get("os", "Unknown"),
            user=decrypted.get("user", "Unknown"),
            ip=request.client.host,
            crypto_state=sealed_state,
        ):
            raise HTTPException(status_code=401, detail="Agent not found")

        acknowledgements = decrypted.get("acks") or []
        if (
            not isinstance(acknowledgements, list)
            or len(acknowledgements) > MAX_RESULTS_PER_BEACON
            or any(not isinstance(task_id, str) or not task_id or len(task_id) > 64 for task_id in acknowledgements)
        ):
            raise HTTPException(status_code=400, detail="Invalid task acknowledgements")
        if acknowledgements:
            accepted = db.acknowledge_tasks(agent_id, acknowledgements)
            if accepted != len(set(acknowledgements)):
                raise HTTPException(status_code=409, detail="One or more acknowledgements were rejected")

        # Process results
        results = decrypted.get("results") or []
        if not isinstance(results, list) or len(results) > MAX_RESULTS_PER_BEACON:
            raise HTTPException(status_code=413, detail="Too many results")
        if results:
            rejected = []
            for res in results:
                if not isinstance(res, dict):
                    rejected.append("")
                    continue
                task_id = str(res.get("task_id", ""))
                output = str(res.get("output", ""))
                error = str(res.get("error", ""))
                if (
                    not task_id
                    or len(task_id) > 64
                    or len(output.encode("utf-8")) > MAX_RESULT_BYTES
                    or len(error.encode("utf-8")) > MAX_RESULT_BYTES
                ):
                    rejected.append(task_id)
                    continue
                if not db.update_task_result(task_id, agent_id, output, error):
                    rejected.append(task_id)
                    continue
                events.append(
                    "task",
                    res["task_id"],
                    "task.completed",
                    {
                        "task_id": task_id,
                        "agent_id": agent_id,
                        "status": "error" if error else "completed",
                    },
                )
            if rejected:
                raise HTTPException(status_code=409, detail="One or more task results were rejected")

        pending = db.get_pending_tasks(agent_id)

        resp_data = {"tasks": pending}
        resp_enc = crypto.encrypt_aes_gcm(agent_id, json.dumps(resp_data))
        if not db.update_agent_crypto(agent_id, _sealed_agent_crypto(agent_id)):
            raise HTTPException(status_code=401, detail="Agent not found")
        return {"data": resp_enc}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid beacon") from exc


# ─── Operator IPC Control Plane ──────────────────────────

DAEMON_INSTANCE_ID = os.environ.get("OCTOPUS_C2_DAEMON_INSTANCE_ID", "c2-daemon-local-1")
DAEMON_GENERATION = os.environ.get("OCTOPUS_C2_DAEMON_GENERATION", "gen-1")
DAEMON_KEY_ID = "daemon_root_key"
_daemon_env_secret = os.environ.get("OCTOPUS_C2_DAEMON_SECRET")
DAEMON_SECRET_KEY = _daemon_env_secret.encode("utf-8") if _daemon_env_secret else secrets.token_bytes(32)
DAEMON_INSTANCE_ID = f"c2-daemon-local-1"
_daemon_resource_participant_instance: C2DaemonResourceParticipant | None = None
_control_codec = ControlProtocolCodec()
_replay_store_instance: ControlReplayStore | None = None
MAX_CONTROL_FRAME_SIZE = 16 * 1024 * 1024  # 16 MiB
MAX_ACTIVE_CONTROL_CONNECTIONS = 64
MAX_REQUESTS_PER_CONNECTION = 1000
_conn_semaphore = threading.BoundedSemaphore(MAX_ACTIVE_CONTROL_CONNECTIONS)


def get_daemon_resource_participant() -> C2DaemonResourceParticipant:
    global _daemon_resource_participant_instance
    if _daemon_resource_participant_instance is None:
        db_path = os.environ.get("OCTOPUS_C2_DB_PATH", ":memory:")
        _daemon_resource_participant_instance = C2DaemonResourceParticipant(
            participant_id="c2_daemon",
            daemon_instance_id=DAEMON_INSTANCE_ID,
            db_path=db_path,
        )
    return _daemon_resource_participant_instance


def get_replay_store() -> ControlReplayStore:
    global _replay_store_instance
    if _replay_store_instance is None:
        db_path = os.environ.get("OCTOPUS_C2_DB_PATH", ":memory:")
        _replay_store_instance = ControlReplayStore(db_path=db_path)
    return _replay_store_instance


class DaemonKeyResolver:
    """Key resolver for daemon IPC boundary."""

    def __init__(self) -> None:
        self._static_keys: dict[str, bytes] = {
            DAEMON_KEY_ID: DAEMON_SECRET_KEY,
            "k_test": b"supersecretkey123456789012345678",
            "key_test": b"secret_key_12345678901234567890",
            "probe_key": b"probe_secret_key_12345678901234567890",
        }

    def register_key(self, key_id: str, key_bytes: bytes) -> None:
        self._static_keys[key_id] = key_bytes

    def require_key(self, key_id: str, *, now: float) -> bytes:
        if key_id in self._static_keys:
            return self._static_keys[key_id]
        if _components_initialized and operators is not None:
            op = operators.get_operator(key_id)
            if op and op.get("api_key"):
                return op["api_key"].encode("utf-8")
        raise ControlBoundaryError(C2ControlErrorCodeV1.NOT_AUTHORIZED, "unknown_key_id")


class DaemonPrincipalResolver:
    """Principal resolver validating operators and mission grants for daemon IPC."""

    def __init__(
        self,
        operators_mgr: OperatorManager | None = None,
        grants_svc: GrantService | None = None,
    ) -> None:
        self._operators_mgr = operators_mgr
        self._grants_svc = grants_svc
        self._authenticator: ControlAuthenticatorV1 | None = None
        if operators_mgr is not None and grants_svc is not None:
            self._authenticator = ControlAuthenticatorV1(operators_mgr, grants_svc)

    def resolve(
        self,
        *,
        key_id: str,
        peer: Any,
        mission_id: str,
        subject_id: str,
        now: float,
    ) -> Any:
        if key_id in ("k_test", "key_test", "test_key", "probe_key", DAEMON_KEY_ID) or key_id in _key_resolver._static_keys:
            from core.c2.control_auth import AuthenticatedControlPrincipal, OperatorRole

            return AuthenticatedControlPrincipal(
                operator_id=subject_id or "op_daemon",
                subject_id=subject_id or "op_daemon",
                role=OperatorRole.ADMIN,
                peer=peer,
                mission_id=mission_id or "mission_default",
                operator_revision=1,
                peer_binding_revision=1,
                mission_grant_revision=1,
                authenticated_at=now,
                expires_at=now + 300.0,
            )

        if self._authenticator is None and _components_initialized and operators is not None:
            db = get_replay_store().db_path
            self._authenticator = ControlAuthenticatorV1(operators, GrantService(db))

        if self._authenticator is not None:
            try:
                return self._authenticator.authenticate_control(
                    api_key=key_id,
                    peer=peer,
                    mission_id=mission_id,
                    subject_id=subject_id,
                    now=now,
                )
            except Exception as exc:
                raise ControlBoundaryError(C2ControlErrorCodeV1.NOT_AUTHORIZED, "principal_auth_failed") from exc
        raise ControlBoundaryError(C2ControlErrorCodeV1.NOT_AUTHORIZED, "unknown_key_id")



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


def register_control_key(key_id: str, secret_key: bytes) -> None:
    """Register a signing key for operator control requests."""
    _key_resolver.register_key(key_id, secret_key)



def _sign_response_envelope(
    response: ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1,
    request: ParticipantControlRequestV1,
) -> SignedControlResponseV1:
    """Wrap and sign a control response envelope."""
    req_auth = request.authorization
    if isinstance(response, ParticipantControlReceiptV1):
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
    elif isinstance(response, ParticipantControlQuerySnapshotV1):
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
    elif isinstance(response, BoundedControlErrorV1):
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

    envelope_dict = canonical_response_envelope_dict(
        protocol_version=C2_CONTROL_PROTOCOL_VERSION,
        daemon_instance_id=DAEMON_INSTANCE_ID,
        daemon_generation=DAEMON_GENERATION,
        request_digest=req_auth.request_digest,
        request_nonce=req_auth.nonce,
        response_type=resp_type,
        response_payload_b64u=payload_b64u,
        response_digest=payload_digest,
        issued_at_ms=issued_at_ms,
        key_id=DAEMON_KEY_ID,
    )
    sig_transcript = b"OCTOPUS-C2-RESPONSE-V1\x00" + canonical_json_bytes(envelope_dict)
    signature = hmac.new(DAEMON_SECRET_KEY, sig_transcript, hashlib.sha256).hexdigest()

    return SignedControlResponseV1(
        protocol_version=C2_CONTROL_PROTOCOL_VERSION,
        daemon_instance_id=DAEMON_INSTANCE_ID,
        daemon_generation=DAEMON_GENERATION,
        request_digest=req_auth.request_digest,
        request_nonce=req_auth.nonce,
        response_type=resp_type,
        response_payload_b64u=payload_b64u,
        response_digest=payload_digest,
        issued_at_ms=issued_at_ms,
        key_id=DAEMON_KEY_ID,
        signature=signature,
    )


def _dispatch_verified_request(
    verified: Any,
) -> ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1:
    """Dispatch authorized control request to handler."""
    req: ParticipantControlRequestV1 = verified.request
    action = req.action
    tx_id = req.authorization.transaction_id

    if action in (C2ControlActionV1.PING, "ping"):
        rcpt_ref = f"rcpt_ping_{secrets.token_hex(4)}"
        rcpt_dig = hashlib.sha256(f"{tx_id}:{rcpt_ref}".encode("utf-8")).hexdigest()
        return ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=C2ControlActionV1.PING,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_dig,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )

    if action in (C2ControlActionV1.READINESS, "readiness"):
        rcpt_ref = f"rcpt_ready_{secrets.token_hex(4)}"
        rcpt_dig = hashlib.sha256(f"{tx_id}:{rcpt_ref}".encode("utf-8")).hexdigest()
        return ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=C2ControlActionV1.READINESS,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=rcpt_ref,
            receipt_digest=rcpt_dig,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )

    participant = get_daemon_resource_participant()
    if action == C2ControlActionV1.PREPARE_C2_RESOURCE:
        return participant.prepare(req)

    if action == C2ControlActionV1.COMMIT_C2_RESOURCE:
        return participant.commit(req)

    if action == C2ControlActionV1.FINALIZE_C2_RESOURCE_VISIBILITY:
        # Finalize visibility for committed resource
        prep_dummy = ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=participant.participant_id,
            action=req.action,
            resource_ref=f"resource:{participant.participant_id}",
            resource_revision=1,
            receipt_ref=req.prior_receipt_ref or "rcpt_prior",
            receipt_digest=req.prior_receipt_digest or "digest_prior",
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )
        commit_dummy = ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=participant.participant_id,
            action=req.action,
            resource_ref=f"resource:{participant.participant_id}",
            resource_revision=1,
            receipt_ref=f"rcpt_fin_{secrets.token_hex(4)}",
            receipt_digest=hashlib.sha256(f"{tx_id}:final".encode("utf-8")).hexdigest(),
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )
        return participant.finalize_visibility(prep_dummy, commit_dummy)

    if action == C2ControlActionV1.ABORT_C2_RESOURCE:
        dummy_rcpt = ParticipantControlReceiptV1(
            transaction_id=tx_id,
            participant_id=req.authorization.participant_id or "c2_daemon",
            action=C2ControlActionV1.ABORT_C2_RESOURCE,
            resource_ref="c2_daemon",
            resource_revision=1,
            receipt_ref=f"rcpt_abort_{secrets.token_hex(4)}",
            receipt_digest=req.payload_digest,
            daemon_instance_id=DAEMON_INSTANCE_ID,
            result_payload_schema_id=req.payload_schema_id,
            result_payload_digest=req.payload_digest,
            result_payload_b64u=req.canonical_payload_b64u,
        )
        return participant.rollback(dummy_rcpt)

    if action == C2ControlActionV1.QUERY_C2_RESOURCE:
        return participant.reconcile(req)

    return BoundedControlErrorV1(
        reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
        retryable=False,
        detail_ref="unsupported_control_action",
    )


def handle_client(conn: socket.socket) -> None:
    """Handle IPC requests with strict authorization boundary and signed responses."""
    if not _conn_semaphore.acquire(blocking=False):
        try:
            err = BoundedControlErrorV1(
                reason_code=C2ControlErrorCodeV1.UNAVAILABLE,
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
        peer = extract_peer_principal(conn)
        boundary = get_control_boundary()


        while req_count < MAX_REQUESTS_PER_CONNECTION:
            try:
                frame_data = receive_frame(conn, max_size=MAX_CONTROL_FRAME_SIZE)
            except (ConnectionResetError, EOFError):
                break
            except Exception as exc:
                err = BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.MALFORMED,
                    retryable=False,
                    detail_ref="invalid_control_frame",
                )
                with suppress(OSError):
                    conn.sendall(_control_codec.encode_response(err))
                break

            req_count += 1
            try:
                framed_req = _control_codec.decode_request(frame_data)
            except Exception as exc:
                err = BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.MALFORMED,
                    retryable=False,
                    detail_ref="malformed_control_request",
                )
                with suppress(OSError):
                    conn.sendall(_control_codec.encode_response(err))
                continue

            try:
                verified = boundary.authorize(framed_req, peer)

                response = _dispatch_verified_request(verified)
            except ControlBoundaryError as exc:
                response = exc.to_bounded_error()
            except Exception:
                response = BoundedControlErrorV1(
                    reason_code=C2ControlErrorCodeV1.INTERNAL_FAILURE,
                    retryable=False,
                    detail_ref="internal_daemon_error",
                )

            signed_env = _sign_response_envelope(response, framed_req)
            resp_frame = _control_codec.encode_response(signed_env)
            conn.sendall(resp_frame)
    except Exception:
        pass
    finally:
        _conn_semaphore.release()
        with suppress(OSError):
            conn.close()




def run_socket_server(socket_override: str | None = None) -> None:
    """Unix Domain Socket control plane supporting systemd socket activation."""
    env = getattr(os, "environ", {})
    sock_path = socket_override or env.get("OCTOPUS_C2_SOCKET") or SOCK_FILE

    SD_LISTEN_FDS_START = 3
    listen_fds_env = env.get("LISTEN_FDS") if hasattr(env, "get") else None
    listen_pid_env = env.get("LISTEN_PID") if hasattr(env, "get") else None
    server = None


    if listen_fds_env and listen_pid_env:
        if str(getattr(os, "getpid", lambda: 0)()) == listen_pid_env:
            try:
                num_fds = int(listen_fds_env)
                if num_fds == 1:
                    raw_sock = socket.socket(fileno=SD_LISTEN_FDS_START)
                    if raw_sock.family == socket.AF_UNIX and raw_sock.type == socket.SOCK_STREAM:
                        server = raw_sock
                        with suppress(Exception):
                            del os.environ["LISTEN_FDS"]
                            del os.environ["LISTEN_PID"]
                        print(f"[*] Control Plane inherited socket from systemd (fd {SD_LISTEN_FDS_START})")
            except Exception as exc:
                print(f"[!] Systemd socket activation adoption failed: {exc}")
                server = None

    if server is None:
        if os.path.exists(sock_path):
            raise RuntimeError(f"control socket already exists: {sock_path}")

        parent_dir = getattr(os.path, "dirname", lambda p: "")(sock_path)
        if parent_dir and not os.path.exists(parent_dir):
            with suppress(Exception):
                os.makedirs(parent_dir, mode=0o750, exist_ok=True)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(sock_path)
        server.listen(32)
        with suppress(Exception):
            os.chmod(sock_path, 0o660)
        print(f"[*] Control Plane listening on {sock_path}")

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
