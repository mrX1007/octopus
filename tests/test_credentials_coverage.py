"""Focused branch coverage for the reference-only credential store."""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace

import pytest

import core.credentials as credentials_module
from core.credential_ranking import KEY_AUTH_MARKER
from core.credentials import (
    SSH_KEY_AUTH_REF,
    CredentialMaterial,
    CredentialRef,
    CredentialStore,
    get_all_credential_refs_for_target,
)
from core.secrets import SecretStore

pytestmark = pytest.mark.unit

TARGET = "198.51.100.44"


@pytest.fixture
def credential_store() -> CredentialStore:
    secret_store = SecretStore(":memory:", key=b"u" * 32)
    store = CredentialStore(secret_store=secret_store, hydrate=False)
    yield store
    secret_store.close()


class CursorStub:
    def __init__(self, rows: list[tuple[object, object, object, object]]) -> None:
        self.rows = rows
        self.executions: list[tuple[str, object]] = []

    def execute(self, statement: str, params: object = None) -> None:
        self.executions.append((statement, params))

    def fetchall(self) -> list[tuple[object, object, object, object]]:
        return list(self.rows)


class ConnectionStub:
    def __init__(self, rows: list[tuple[object, object, object, object]]) -> None:
        self.cursor_stub = CursorStub(rows)
        self.commits = 0
        self.closed = False

    def cursor(self) -> CursorStub:
        return self.cursor_stub

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


def test_material_properties_and_clear() -> None:
    credential = CredentialRef(
        handle="credential://material",
        service="ssh",
        target=TARGET,
        username="alice",
        port=2222,
    )
    material = CredentialMaterial(credential, "secret")

    assert material.username == "alice"
    assert material.service == "ssh"
    assert material.target == TARGET
    assert material.port == 2222
    assert material.password == "secret"
    material.clear()
    assert material.password == ""


def test_hydrating_constructor_and_singleton_double_checked_paths(
    credential_store: CredentialStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    booted: list[CredentialStore] = []
    monkeypatch.setattr(CredentialStore, "_boot", lambda self: booted.append(self))
    hydrated = CredentialStore(secret_store=credential_store.secret_store, hydrate=True)
    assert booted == [hydrated]

    monkeypatch.setattr(credentials_module, "get_secret_store", lambda: credential_store.secret_store)
    monkeypatch.setattr(CredentialStore, "_instance", None)
    monkeypatch.setattr(CredentialStore, "_instance_lock", threading.Lock())
    first = CredentialStore.instance()
    assert CredentialStore.instance() is first

    sentinel = object()

    class InjectingLock:
        def __enter__(self) -> None:
            CredentialStore._instance = sentinel

        def __exit__(self, *_args: object) -> None:
            return None

    CredentialStore._instance = None
    CredentialStore._instance_lock = InjectingLock()
    assert CredentialStore.instance() is sentinel


def test_boot_hydrates_every_legacy_shape_and_updates_only_migrations(
    credential_store: CredentialStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing_ref = credential_store.secret_store.store("already-sealed", kind="credential:ssh")
    rows = [
        (TARGET, "ssh", "key-user", KEY_AUTH_MARKER),
        (TARGET, "ssh", "sealed-user", existing_ref),
        (TARGET, "ssh", "handle-user", "credential://unrecoverable"),
        (TARGET, "postgres", "plain-user", "legacy-plaintext"),
        (TARGET, "ssh", "empty-user", ""),
    ]
    connection = ConnectionStub(rows)
    monkeypatch.setitem(sys.modules, "db", SimpleNamespace(get_connection=lambda: connection))

    credential_store._boot()

    assert credential_store._db_available is True
    assert credential_store.count() == 3
    assert credential_store.best_ref(TARGET, "ssh", username="key-user").auth_kind == "ssh_key"
    assert connection.commits == 1
    assert connection.closed is True
    updates = [entry for entry in connection.cursor_stub.executions if "UPDATE credentials" in entry[0]]
    assert len(updates) == 2


def test_boot_failure_falls_back_to_cache_only(
    credential_store: CredentialStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_connection() -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setitem(sys.modules, "db", SimpleNamespace(get_connection=fail_connection))

    credential_store._boot()

    assert credential_store._db_available is False


def test_register_handle_guards_duplicate_key_auth_empty_and_visible_notice(
    credential_store: CredentialStore,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_ref = credential_store.secret_store.store("password", kind="credential:ssh")
    credential, created = credential_store.register(
        "ssh",
        TARGET,
        "alice",
        secret_ref,
        port=22,
        quiet=False,
    )
    assert created is True
    assert "Credential registered" in capsys.readouterr().out

    duplicate, created = credential_store.register("ssh", TARGET, "alice", secret_ref, port=22, quiet=True)
    assert duplicate == credential
    assert created is False

    with pytest.raises(KeyError, match="unknown credential handle"):
        credential_store.register("ssh", TARGET, "alice", "credential://missing", quiet=True)
    with pytest.raises(ValueError, match="service mismatch"):
        credential_store.register("ldap", TARGET, "alice", credential.handle, quiet=True)
    with pytest.raises(ValueError, match="target mismatch"):
        credential_store.register("ssh", "other.example", "alice", credential.handle, quiet=True)
    with pytest.raises(ValueError, match="username mismatch"):
        credential_store.register("ssh", TARGET, "bob", credential.handle, quiet=True)
    with pytest.raises(ValueError, match="port mismatch"):
        credential_store.register("ssh", TARGET, "alice", credential.handle, port=2222, quiet=True)
    assert credential_store.register("ssh", TARGET, "alice", credential.handle, port=22, quiet=True) == (
        credential,
        False,
    )

    key_ref, key_created = credential_store.register(
        "ssh",
        TARGET,
        "root",
        KEY_AUTH_MARKER,
        quiet=True,
    )
    assert key_created is True
    assert key_ref.auth_kind == "ssh_key"
    assert credential_store._secret_refs_by_handle[key_ref.handle] == SSH_KEY_AUTH_REF

    with pytest.raises(ValueError, match="must not be empty"):
        credential_store.register("ssh", TARGET, "nobody", "", quiet=True)


def test_sync_to_db_success_and_failure_use_privately_owned_secret_ref(
    credential_store: CredentialStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _created = credential_store.register("ssh", TARGET, "alice", "password", quiet=True)
    connection = ConnectionStub([])
    database = SimpleNamespace(get_connection=lambda: connection)
    monkeypatch.setitem(sys.modules, "db", database)
    credential_store._db_available = True

    credential_store._sync_to_db(credential)

    assert connection.commits == 1
    assert connection.closed is True
    params = connection.cursor_stub.executions[0][1]
    assert isinstance(params, tuple)
    assert params[:3] == (TARGET, "ssh", "alice")
    assert str(params[3]).startswith("secret://")

    def fail_connection() -> None:
        raise RuntimeError("offline")

    database.get_connection = fail_connection
    assert credential_store._sync_to_db(credential) is None


def test_reference_views_resolution_counts_and_targets(credential_store: CredentialStore) -> None:
    ssh_ref, _created = credential_store.register("ssh", TARGET, "alice", "ssh-password", quiet=True)
    db_ref, _created = credential_store.register("postgres", TARGET, "db", "db-password", quiet=True)
    credential_store._cache[("empty", TARGET)] = []

    assert credential_store.get_refs("SSH", f" {TARGET} ") == (ssh_ref,)
    grouped = credential_store.all_refs(f" {TARGET} ")
    assert grouped == {"postgres": (db_ref,), "ssh": (ssh_ref,)}
    assert credential_store.get_all_refs(TARGET) == grouped
    assert credential_store.resolve("plaintext") is None
    assert (
        credential_store.resolve(
            CredentialRef(
                handle=ssh_ref.handle,
                service="ssh",
                target=TARGET,
                username="mallory",
            )
        )
        is None
    )
    assert credential_store.has_creds("ssh", TARGET) is True
    assert credential_store.has_creds("ldap", TARGET) is False
    assert credential_store.count() == 2
    assert credential_store.all_targets() == [TARGET]


def test_best_ref_runs_every_ranking_bucket_and_filter(credential_store: CredentialStore) -> None:
    root_password, _ = credential_store.register("ssh", TARGET, "root", "root-password", port=22, quiet=True)
    user_password, _ = credential_store.register("ssh", TARGET, "alice", "user-password", quiet=True)
    root_key, _ = credential_store.register("ssh", TARGET, "ROOT", KEY_AUTH_MARKER, port=2222, quiet=True)
    user_key, _ = credential_store.register("ssh", TARGET, "bob", KEY_AUTH_MARKER, port=2222, quiet=True)
    credential_store.register("postgres", TARGET, "db", "database-password", quiet=True)

    assert credential_store.best_ref(TARGET) == root_password
    assert credential_store.best_ref(TARGET, prefer_privileged=True) == root_password
    assert credential_store.best_ref(TARGET, "ssh", username="alice") == user_password
    assert credential_store.best_ref(TARGET, "ssh", username="ROOT", port=2222) == root_key
    assert credential_store.best_ref(TARGET, "ssh", username="bob", port=2222) == user_key
    assert credential_store.best_ref(TARGET, "ssh", username="missing") is None


def test_material_and_sanitizer_error_paths_for_unknown_key_and_opaque_refs(
    credential_store: CredentialStore,
) -> None:
    with (
        pytest.raises(KeyError, match="unknown credential handle"),
        credential_store.material_for_execution("credential://missing"),
    ):
        pass

    key_ref, _created = credential_store.register("ssh", TARGET, "root", KEY_AUTH_MARKER, quiet=True)
    with credential_store.material_for_execution(key_ref) as material:
        assert material.password == KEY_AUTH_MARKER
    assert material.password == ""

    opaque = credential_store._make_ref("ssh", TARGET, "opaque", "not-a-secret-ref")
    assert credential_store._remember(opaque, "not-a-secret-ref") is True
    with pytest.raises(ValueError, match="no revealable secret"), credential_store.material_for_execution(opaque):
        pass

    with pytest.raises(KeyError, match="unknown credential handle"):
        credential_store.call_provider("credential://missing", lambda _material: "unused")
    assert credential_store.call_provider(key_ref, lambda material: material.password) == KEY_AUTH_MARKER
    assert credential_store.call_provider(key_ref, lambda _material: (_ for _ in ()).throw(RuntimeError())) == (
        "[!] Credential provider failed (RuntimeError)"
    )

    with pytest.raises(KeyError, match="unknown credential handle"):
        credential_store.sanitize_result("credential://missing", "value")
    assert credential_store.sanitize_result(key_ref, KEY_AUTH_MARKER) == KEY_AUTH_MARKER
    with pytest.raises(ValueError, match="no revealable secret"):
        credential_store.sanitize_result(opaque, "value")


def test_deprecated_getters_and_public_grouped_wrapper(
    credential_store: CredentialStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _created = credential_store.register("ssh", TARGET, "alice", "password", quiet=True)
    monkeypatch.setattr(CredentialStore, "_instance", credential_store)

    with pytest.warns(FutureWarning):
        assert credential_store.get("ssh", TARGET) == (credential,)
    with pytest.warns(FutureWarning):
        assert credential_store.get_best(TARGET, "ssh") == credential
    with pytest.warns(FutureWarning):
        assert credential_store.get_all(TARGET) == {"ssh": (credential,)}
    assert get_all_credential_refs_for_target(TARGET) == {"ssh": (credential,)}
