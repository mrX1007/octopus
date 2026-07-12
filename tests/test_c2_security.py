import base64
import importlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.c2.builder import encrypt_config, load_server_pub_key
from core.c2.db_backend import C2Database
from core.c2.enrollment import EnrollmentAuthority
from core.c2.implants.python_implant import generate_python_implant
from core.c2.key_store import KeyStore


def test_enrollment_token_is_authenticated_expiring_and_single_use(tmp_path):
    authority = EnrollmentAuthority(tmp_path / "enrollment.key")
    database = C2Database(str(tmp_path / "c2.db"))

    token = authority.issue(ttl_seconds=60, now=1_000)

    assert authority.consume(token, database, now=1_001) is True
    assert authority.consume(token, database, now=1_002) is False
    assert authority.consume(token + "tampered", database, now=1_002) is False

    expired = authority.issue(ttl_seconds=10, now=2_000)
    assert authority.consume(expired, database, now=2_011) is False


def test_agent_registration_is_insert_only(tmp_path):
    database = C2Database(str(tmp_path / "c2.db"))

    assert database.register_agent(
        "AGT-server-assigned",
        hostname="host-a",
        os_name="linux",
        user="operator",
        ip="127.0.0.1",
        crypto_state="sealed-state-a",
    ) is True
    assert database.register_agent(
        "AGT-server-assigned",
        hostname="host-b",
        os_name="linux",
        user="other",
        ip="127.0.0.2",
        crypto_state="sealed-state-b",
    ) is False
    assert database.get_agent_crypto("AGT-server-assigned") == "sealed-state-a"


def test_task_result_requires_owner_and_sent_state(tmp_path):
    database = C2Database(str(tmp_path / "c2.db"))
    database.queue_task("task-1", "agent-a", "whoami")

    assert database.update_task_result("task-1", "agent-a", "too early") is False
    assert database.get_pending_tasks("agent-a") == [
        {"task_id": "task-1", "command": "whoami", "delivery_attempt": 1}
    ]
    assert database.update_task_result("task-1", "agent-b", "forged") is False
    assert database.update_task_result("task-1", "agent-a", "ok") is True
    assert database.update_task_result("task-1", "agent-a", "duplicate") is False


def test_task_delivery_ack_and_retry_are_owned_and_idempotent(tmp_path):
    database = C2Database(str(tmp_path / "c2.db"))
    database.queue_task("task-retry", "agent-a", "status")

    first = database.get_pending_tasks(
        "agent-a", now=100, retry_after_seconds=10, ack_retry_after_seconds=30
    )
    assert first[0]["delivery_attempt"] == 1
    assert database.get_pending_tasks(
        "agent-a", now=105, retry_after_seconds=10, ack_retry_after_seconds=30
    ) == []
    retried = database.get_pending_tasks(
        "agent-a", now=111, retry_after_seconds=10, ack_retry_after_seconds=30
    )
    assert retried[0]["delivery_attempt"] == 2

    assert database.acknowledge_tasks("agent-b", ["task-retry"], now=112) == 0
    assert database.acknowledge_tasks("agent-a", ["task-retry"], now=112) == 1
    assert database.acknowledge_tasks("agent-a", ["task-retry"], now=113) == 1
    assert database.get_pending_tasks(
        "agent-a", now=130, retry_after_seconds=10, ack_retry_after_seconds=30
    ) == []
    acknowledged_retry = database.get_pending_tasks(
        "agent-a", now=143, retry_after_seconds=10, ack_retry_after_seconds=30
    )
    assert acknowledged_retry[0]["delivery_attempt"] == 3


def test_keystore_seals_session_state_and_protects_files(tmp_path):
    store = KeyStore(str(tmp_path / "keys"))
    store.generate("correct horse battery staple")
    sealed = store.seal_json(
        {"key": "super-secret-session-key", "rx_seq": 3, "tx_seq": 8},
        aad=b"agent-1",
    )

    assert "super-secret-session-key" not in sealed
    assert store.unseal_json(sealed, aad=b"agent-1") == {
        "key": "super-secret-session-key",
        "rx_seq": 3,
        "tx_seq": 8,
    }
    for filename in ("identity.enc", "identity.salt"):
        assert os.stat(tmp_path / "keys" / filename).st_mode & 0o077 == 0

    first_key = store.get_or_create_x25519_private_key()
    first_raw = first_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert not (tmp_path / "keys" / "server_x25519_private.pem").exists()
    assert os.stat(
        tmp_path / "keys" / "server_x25519_private.enc"
    ).st_mode & 0o077 == 0

    reopened = KeyStore(str(tmp_path / "keys"))
    assert reopened.unlock("correct horse battery staple") is True
    reopened_raw = reopened.get_or_create_x25519_private_key().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    assert reopened_raw == first_raw


def test_builder_exports_raw_x25519_public_key(tmp_path):
    private_key = x25519.X25519PrivateKey.generate()
    public_path = tmp_path / "server_x25519_public.pem"
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    encoded = load_server_pub_key(str(public_path))

    assert len(base64.b64decode(encoded)) == 32


def test_go_builder_contract_contains_enrollment_token():
    blob, hex_key = encrypt_config(
        "https://c2.example.test:8443",
        "pin-value",
        base64.b64encode(b"x" * 32).decode("ascii"),
        "single-use-token",
    )
    raw = base64.b64decode(blob)
    config = json.loads(
        AESGCM(bytes.fromhex(hex_key)).decrypt(raw[:12], raw[12:], None)
    )

    assert config["enrollment_token"] == "single-use-token"
    assert len(base64.b64decode(config["pub"])) == 32


def test_go_client_uses_unified_bounded_acknowledged_protocol():
    source_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "core", "c2", "implant.go"
    )
    with open(source_path, encoding="utf-8") as source_file:
        source = source_file.read()

    assert '"enrollment_token": string(enrollmentTokenBytes)' in source
    assert 'registration["agent_id"]' in source
    assert "func exchangeBeacon(" in source
    assert '"acks": acknowledgements' in source
    assert "exec.CommandContext(" in source
    assert "chunk_index" not in source
    assert "sessionKey = make([]byte, 32)" not in source
    assert "InsecureSkipVerify: len(allowedPins) > 0" in source


def test_python_client_requires_enrollment_and_verified_tls():
    private_key = x25519.X25519PrivateKey.generate()
    server_public = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    source = generate_python_implant(
        ["https://c2.example.test:8443"],
        server_pub_b64=server_public,
        enrollment_token="single-use-token",
    )
    namespace = {"__name__": "generated_client_test"}

    exec(compile(source, "<generated-client>", "exec"), namespace)

    assert namespace["_init_config"]() is True
    assert namespace["_enrollment_token"] == "single-use-token"
    assert namespace["_server_pub"] == base64.b64decode(server_public)
    assert "enrollment_token" in source
    assert "ssl.CERT_NONE" not in source


def _encrypt_message(key, payload, sequence_number=1):
    sequence = struct.pack("<Q", sequence_number)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), sequence)
    return base64.b64encode(sequence + nonce + ciphertext).decode("ascii")


def _decrypt_message(key, payload):
    raw = base64.b64decode(payload)
    sequence = raw[:8]
    return json.loads(AESGCM(key).decrypt(raw[8:20], raw[20:], sequence))


def test_register_endpoint_requires_token_and_assigns_identity(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("OCTOPUS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OCTOPUS_C2_KEY_PASSPHRASE", "a" * 32)
    sys.modules.pop("core.c2.daemon", None)
    daemon = importlib.import_module("core.c2.daemon")
    client = TestClient(daemon.app)

    private_key = x25519.X25519PrivateKey.generate()
    client_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    raw_shared = private_key.exchange(daemon.crypto.public_key)
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"octopus-session-v10",
    ).derive(raw_shared)
    registration = _encrypt_message(
        session_key,
        {
            "agent_id": "AGT-client-controlled",
            "hostname": "test-host",
            "os": "linux",
            "user": "tester",
        },
    )
    request_body = {
        "client_pub": base64.b64encode(client_public).decode("ascii"),
        "data": registration,
    }

    assert client.post("/register", json=request_body).status_code == 400
    token = daemon.enrollment.issue()
    request_body["enrollment_token"] = token
    response = client.post("/register", json=request_body)

    assert response.status_code == 200
    response_data = _decrypt_message(
        session_key, response.json()["data"]
    )
    assigned_id = response_data["agent_id"]
    assert assigned_id.startswith("AGT-")
    assert assigned_id != "AGT-client-controlled"
    persisted = daemon.db.get_agent_crypto(assigned_id)
    assert isinstance(persisted, str)
    assert session_key.hex() not in persisted
    assert client.post("/register", json=request_body).status_code == 401

    daemon.db.queue_task("task-contract", assigned_id, "status")
    beacon_headers = {"Agent-ID": assigned_id}
    beacon_response = client.post(
        "/beacon",
        headers=beacon_headers,
        json={
            "data": _encrypt_message(
                session_key,
                {"hostname": "test-host", "results": [], "acks": []},
                2,
            )
        },
    )
    assert beacon_response.status_code == 200
    tasks = _decrypt_message(session_key, beacon_response.json()["data"])["tasks"]
    assert tasks == [{
        "task_id": "task-contract",
        "command": "status",
        "delivery_attempt": 1,
    }]

    ack_response = client.post(
        "/beacon",
        headers=beacon_headers,
        json={
            "data": _encrypt_message(
                session_key,
                {"hostname": "test-host", "results": [], "acks": ["task-contract"]},
                3,
            )
        },
    )
    assert ack_response.status_code == 200
    assert _decrypt_message(session_key, ack_response.json()["data"])["tasks"] == []

    result_response = client.post(
        "/beacon",
        headers=beacon_headers,
        json={
            "data": _encrypt_message(
                session_key,
                {
                    "hostname": "test-host",
                    "acks": [],
                    "results": [{
                        "task_id": "task-contract",
                        "output": "ok",
                        "error": "",
                    }],
                },
                4,
            )
        },
    )
    assert result_response.status_code == 200
    assert daemon.db.get_results(assigned_id) == [{
        "task_id": "task-contract",
        "output": "ok",
        "status": "completed",
    }]

    stored_state = daemon.key_store.unseal_json(
        daemon.db.get_agent_crypto(assigned_id), aad=assigned_id.encode("utf-8")
    )
    assert stored_state["rx_seq"] == 4
    assert stored_state["tx_seq"] == 4

    daemon.key_store.lock()
    sys.modules.pop("core.c2.daemon", None)
