"""End-to-end guarantees for encrypted secrets and persistence redaction."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from core.ai.fact_store import FactStore
from core.ai.trace_report import TraceReporter
from core.secrets import Redactor, SecretStore, reset_default_secret_store_for_tests

pytestmark = pytest.mark.security

CANARY = "octopus-canary-password-7f39"


@pytest.fixture(autouse=True)
def isolated_default_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    reset_default_secret_store_for_tests()
    monkeypatch.setenv("OCTOPUS_SECRET_STORE", str(tmp_path / "default-secrets.db"))
    monkeypatch.setenv("OCTOPUS_SECRET_KEY", "test-only-master-key")
    yield
    reset_default_secret_store_for_tests()


def test_secret_store_encrypts_deduplicates_and_uses_private_files(tmp_path: Path):
    db_path = tmp_path / "secrets.db"
    store = SecretStore(str(db_path), key=b"k" * 32)

    first = store.store(CANARY, kind="password")
    second = store.store(CANARY, kind="password")

    assert first == second
    assert first.startswith("secret://sec_")
    assert store.reveal(first) == CANARY
    assert CANARY.encode() not in db_path.read_bytes()
    assert os.stat(db_path).st_mode & 0o077 == 0


def test_secret_store_detects_wrong_key_and_ciphertext_tampering(tmp_path: Path):
    db_path = tmp_path / "secrets.db"
    store = SecretStore(str(db_path), key=b"a" * 32)
    reference = store.store(CANARY, kind="token")

    wrong_key_store = SecretStore(str(db_path), key=b"b" * 32)
    with pytest.raises(InvalidTag):
        wrong_key_store.reveal(reference)

    identifier = reference.removeprefix("secret://")
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT ciphertext FROM secrets WHERE id = ?", (identifier,)).fetchone()
        ciphertext = bytearray(row[0])
        ciphertext[-1] ^= 1
        conn.execute("UPDATE secrets SET ciphertext = ? WHERE id = ?", (bytes(ciphertext), identifier))
        conn.commit()
    with pytest.raises(InvalidTag):
        store.reveal(reference)


@pytest.mark.parametrize(
    "raw",
    [
        f"password={CANARY}",
        f"--password {CANARY}",
        f'{{"api_key":"{CANARY}"}}',
        f"Authorization: Bearer {CANARY}",
        f"Cookie: session_token={CANARY}",
        f"postgres://alice:{CANARY}@db.internal/app",
        f"token: {CANARY}\nnext=line",
        "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXk=\n-----END PRIVATE KEY-----",
    ],
)
def test_text_redaction_is_idempotent(raw: str):
    redactor = Redactor(SecretStore(":memory:", key=b"r" * 32))

    safe = redactor.redact_text(raw)

    assert CANARY not in safe
    assert "secret://sec_" in safe
    assert redactor.redact_text(safe) == safe


def test_recursive_redaction_preserves_shape_and_protects_sensitive_fields():
    store = SecretStore(":memory:", key=b"r" * 32)
    redactor = Redactor(store)
    raw = {
        "name": "finding",
        "credentials": [
            {"username": "alice", "password": CANARY},
            {"token": CANARY},
        ],
        "nested": (f"password={CANARY}", {"safe": "value"}),
    }

    safe = redactor.redact_data(raw)

    assert safe["name"] == "finding"
    assert safe["credentials"][0]["username"] == "alice"
    assert safe["credentials"][0]["password"].startswith("secret://")
    assert isinstance(safe["nested"], tuple)
    assert CANARY not in repr(safe)
    assert redactor.redact_data(safe) == safe


def test_policy_authorization_metadata_remains_auditable():
    store = SecretStore(":memory:", key=b"policy-metadata-redaction-key")
    redactor = Redactor(store)

    safe = redactor.redact_data(
        {
            "authorization_phase": "pre_execute",
            "authorization_decision": "denied",
            "authorization_reason": "target_out_of_scope",
            "authorization": "Bearer policy-secret-value",
        }
    )

    assert safe["authorization_phase"] == "pre_execute"
    assert safe["authorization_decision"] == "denied"
    assert safe["authorization_reason"] == "target_out_of_scope"
    assert str(safe["authorization"]).startswith("secret://")


def test_fact_store_never_persists_plaintext_in_facts_observations_or_commands(tmp_path: Path):
    db_path = tmp_path / "facts.db"
    store = FactStore(str(db_path))
    fact_id, created = store.add_fact_with_status(
        "scan-1",
        "host.example",
        "credential",
        f"alice:{CANARY} (cached)",
        f"ssh_session host alice {CANARY}",
    )
    store.add_command_result(
        "scan-1",
        "host.example",
        "ssh",
        f"ssh_session host alice {CANARY}",
        "hash",
    )

    facts = store.get_facts("scan-1", "host.example")
    commands = store.get_command_results("scan-1", "host.example")
    assert fact_id > 0 and created
    assert facts[0]["secret_refs"]
    assert store.secret_store.reveal(facts[0]["secret_refs"][0]) == CANARY
    assert CANARY not in json.dumps(facts)
    assert CANARY not in json.dumps(commands)
    assert CANARY.encode() not in db_path.read_bytes()


def test_fact_store_migrates_legacy_plaintext_and_clear_scan_cascades_scope(tmp_path: Path):
    db_path = tmp_path / "facts.db"
    FactStore(str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO facts (
                scan_id, host, type, value, confidence, source, session_id,
                derived_from, evidence_hash, timestamp, secret_refs
            ) VALUES (?, ?, ?, ?, 100, ?, 'none', '[]', '', 1, '[]')
            """,
            ("legacy", "host", "credential", f"alice:{CANARY} (cached)", CANARY),
        )
        fact_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            """
            INSERT INTO fact_observations (
                fact_id, scan_id, host, type, value, confidence, source,
                session_id, evidence_hash, timestamp, secret_refs
            ) VALUES (?, 'legacy', 'host', 'credential', ?, 100, ?, 'none', '', 1, '[]')
            """,
            (fact_id, f"alice:{CANARY} (cached)", CANARY),
        )
        conn.execute(
            "INSERT INTO hypotheses (scan_id, host, claim, required_evidence, source, timestamp) VALUES ('legacy', 'host', ?, '[]', ?, 1)",
            (f"password={CANARY}", CANARY),
        )
        conn.execute(
            """
            INSERT INTO command_results (
                scan_id, host, command_key, command, output_hash, timestamp
            ) VALUES ('legacy', 'host', 'key', ?, 'hash', 1)
            """,
            (f"--password {CANARY}",),
        )
        conn.commit()

    migrated = FactStore(str(db_path))
    assert CANARY not in repr(migrated.get_facts("legacy"))
    assert CANARY.encode() not in db_path.read_bytes()

    migrated.clear_scan("legacy")
    with sqlite3.connect(db_path) as conn:
        for table in ("facts", "fact_observations", "hypotheses", "command_results"):
            assert conn.execute(f"SELECT COUNT(*) FROM {table} WHERE scan_id = 'legacy'").fetchone()[0] == 0


def test_trace_report_redacts_external_trace_payloads(tmp_path: Path):
    store = FactStore(str(tmp_path / "facts.db"))
    store.add_fact("scan", "host", "port_open", "22/tcp (ssh)", "nmap")
    reporter = TraceReporter(store)

    report = reporter.build(
        "scan",
        "host",
        goal_trace=[{"thought": f"password={CANARY}"}],
        command_trace=[{"command": f"--token {CANARY}"}],
        task_outcomes=[{"output": f"Authorization: Bearer {CANARY}"}],
    )
    text = reporter.to_text(report)
    serialized = reporter.to_json(report)

    assert CANARY not in repr(report)
    assert CANARY not in text
    assert CANARY not in serialized
    assert "secret://sec_" in serialized


def test_vector_memory_redacts_document_and_metadata(monkeypatch: pytest.MonkeyPatch):
    import memory as memory_module

    class FakeCollection:
        def __init__(self):
            self.documents = []
            self.metadatas = []

        def count(self):
            return 0

        def add(self, *, documents, metadatas, ids):
            self.documents.extend(documents)
            self.metadatas.extend(metadatas)

    memory = object.__new__(memory_module.VectorMemory)
    memory.session_id = "test"
    memory.enabled = True
    memory.secret_store = SecretStore(":memory:", key=b"m" * 32)
    memory.redactor = Redactor(memory.secret_store)
    memory.collection = FakeCollection()

    assert memory.store_credential("ssh", "host", "alice", CANARY)
    assert CANARY not in repr(memory.collection.documents)
    assert CANARY not in repr(memory.collection.metadatas)
    assert "secret://sec_" in repr(memory.collection.metadatas)
