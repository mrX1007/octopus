"""Canaries for the C2 cryptographic and protocol identity boundaries."""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.c2 import crypto_engine, protocol

pytestmark = [pytest.mark.contract, pytest.mark.security]


def test_session_cipher_uses_the_single_cryptography_backend(tmp_path, monkeypatch):
    calls: list[str] = []

    class AESGCMSpy:
        def __init__(self, key: bytes):
            self._backend = AESGCM(key)

        def encrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
            calls.append("encrypt")
            return self._backend.encrypt(nonce, data, aad)

        def decrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
            calls.append("decrypt")
            return self._backend.decrypt(nonce, data, aad)

    monkeypatch.setattr(crypto_engine, "AESGCM", AESGCMSpy, raising=False)
    engine = crypto_engine.C2CryptoEngine(
        str(tmp_path / "keys"),
        private_key=x25519.X25519PrivateKey.generate(),
    )
    engine.agent_state["agent-1"] = {
        "key": os.urandom(32),
        "rx_seq": 0,
        "tx_seq": 0,
        "epoch": 0,
    }

    payload = engine.encrypt_aes_gcm("agent-1", "protocol payload")

    assert engine.decrypt_aes_gcm("agent-1", payload) == "protocol payload"
    assert calls == ["encrypt", "decrypt"]
    assert not hasattr(crypto_engine, "_PYCRYPTO_OK")
    assert not hasattr(crypto_engine, "AES")


def test_session_kdf_context_is_owned_by_protocol_constants(tmp_path, monkeypatch):
    context = b"octopus-test-session-context"
    monkeypatch.setattr(
        crypto_engine,
        "C2_SESSION_KDF_CONTEXT",
        context,
        raising=False,
    )
    server_private = x25519.X25519PrivateKey.generate()
    client_private = x25519.X25519PrivateKey.generate()
    client_public_bytes = client_private.public_key().public_bytes_raw()
    engine = crypto_engine.C2CryptoEngine(
        str(tmp_path / "keys"),
        private_key=server_private,
    )

    derived = engine.derive_shared_key(client_public_bytes)
    expected = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(server_private.exchange(client_private.public_key()))

    assert derived == expected


def test_keystore_session_kdf_context_is_owned_by_protocol_constants(monkeypatch):
    from core.c2 import key_store

    context = b"octopus-test-keystore-context"
    monkeypatch.setattr(
        key_store,
        "C2_SESSION_KDF_CONTEXT",
        context,
        raising=False,
    )
    raw_shared = os.urandom(32)

    derived = key_store.KeyStore.derive_session_key(raw_shared)
    expected = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(raw_shared)

    assert derived == expected


def test_generated_python_implant_uses_protocol_kdf_context(monkeypatch):
    from core.c2.implants import python_implant

    context = b"octopus-test-implant-context"
    monkeypatch.setattr(
        python_implant,
        "C2_SESSION_KDF_CONTEXT",
        context,
        raising=False,
    )
    server_private = x25519.X25519PrivateKey.generate()
    server_public_bytes = server_private.public_key().public_bytes_raw()
    source = python_implant.generate_python_implant(
        ["https://c2.example.test:8443"],
        server_pub_b64=__import__("base64").b64encode(
            server_public_bytes
        ).decode("ascii"),
        enrollment_token="single-use-token",
    )
    namespace = {"__name__": "generated_protocol_test"}
    exec(compile(source, "<generated-protocol-test>", "exec"), namespace)
    implant_private = x25519.X25519PrivateKey.generate()

    derived = namespace["_derive_shared_key"](
        implant_private.private_bytes_raw(),
        server_public_bytes,
    )
    expected = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(implant_private.exchange(server_private.public_key()))

    assert derived == expected


def test_go_implant_represents_protocol_kdf_context_via_linker(monkeypatch):
    from core.c2 import builder

    context = b"octopus-test-go-context"
    monkeypatch.setattr(
        builder,
        "C2_SESSION_KDF_CONTEXT",
        context,
        raising=False,
    )

    flags = builder._go_linker_flags("blob", "part-one", "part-two")
    go_source = Path(builder.__file__).with_name("implant.go").read_text(
        encoding="utf-8"
    )

    assert f"main.SessionKDFContext={context.decode('ascii')}" in flags
    assert "[]byte(SessionKDFContext)" in go_source
    assert protocol.C2_SESSION_KDF_CONTEXT.decode("ascii") not in go_source


def test_daemon_version_is_owned_by_protocol_constants(monkeypatch, capsys):
    module_name = "core.c2.daemon"
    original_daemon = sys.modules.pop(module_name, None)
    sentinel = "test-protocol-version"

    try:
        with monkeypatch.context() as patch:
            patch.setattr(protocol, "C2_PROTOCOL_VERSION", sentinel)
            daemon = importlib.import_module(module_name)
            assert daemon.app.version == sentinel

            class OperatorsStub:
                @staticmethod
                def list_operators():
                    return ("operator",)

                @staticmethod
                def authenticate(_api_key):
                    return None

            class ConnectionStub:
                def __init__(self):
                    self._requests = [json.dumps({"action": "ping"}).encode()]
                    self.responses: list[dict] = []

                def recv(self, _size):
                    return self._requests.pop(0) if self._requests else b""

                def sendall(self, payload):
                    self.responses.append(json.loads(payload))

                def close(self):
                    return None

            class ThreadStub:
                @staticmethod
                def start():
                    return None

            patch.setattr(daemon, "create_app", lambda: daemon.app)
            patch.setattr(daemon, "operators", OperatorsStub(), raising=False)
            patch.setattr(
                daemon.threading,
                "Thread",
                lambda **_kwargs: ThreadStub(),
            )
            patch.setattr(daemon.uvicorn, "run", lambda *_args, **_kwargs: None)
            patch.setenv("OCTOPUS_C2_HOST", "127.0.0.1")
            patch.setenv("OCTOPUS_C2_PORT", "8443")

            connection = ConnectionStub()
            daemon.handle_client(connection)
            assert connection.responses == [
                {"status": "ok", "msg": "pong", "version": sentinel}
            ]

            daemon.main()
            assert f"C2 Daemon v{sentinel}" in capsys.readouterr().out
    finally:
        sys.modules.pop(module_name, None)
        if original_daemon is not None:
            sys.modules[module_name] = original_daemon
