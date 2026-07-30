"""Complete hermetic coverage for the optional vector-memory facade."""

from __future__ import annotations

import builtins
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import memory as memory_module
from core.secrets import SecretStore

pytestmark = pytest.mark.unit


class Redactor:
    def __init__(self) -> None:
        self.calls = []

    def redact_text(self, value, *, kind: str):
        self.calls.append(("text", str(value), kind))
        return f"safe:{value}"

    def redact_data(self, value):
        self.calls.append(("data", value))
        return {
            key: item if key == "category" else f"safe:{item}"
            for key, item in value.items()
        }

    def protect(self, value, *, kind: str):
        self.calls.append(("protect", value, kind))
        return "secret://credential-ref"


class Collection:
    def __init__(self, *, count=0, query_results=None) -> None:
        self.count_value = count
        self.query_results = query_results
        self.additions = []
        self.raise_count = None
        self.raise_query = None
        self.raise_add = None

    def count(self):
        if self.raise_count:
            raise self.raise_count
        return self.count_value

    def query(self, **kwargs):
        if self.raise_query:
            raise self.raise_query
        self.last_query = kwargs
        return self.query_results

    def add(self, **kwargs):
        if self.raise_add:
            raise self.raise_add
        self.additions.append(kwargs)


def _memory(*, enabled=True, collection=None):
    instance = object.__new__(memory_module.VectorMemory)
    instance.session_id = "fixture"
    instance.secret_store = SimpleNamespace()
    instance.redactor = Redactor()
    instance.enabled = enabled
    instance.collection_name = "session_fixture"
    instance.collection = collection or Collection()
    instance.client = SimpleNamespace()
    return instance


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_module_imports_with_and_without_optional_dependencies(monkeypatch) -> None:
    path = Path(memory_module.__file__)
    fake_chroma = ModuleType("chromadb")
    fake_chroma.PersistentClient = object
    monkeypatch.setitem(sys.modules, "chromadb", fake_chroma)
    loaded = _load(path, "memory_with_chroma")
    assert loaded.HAS_CHROMA is True

    real_import = builtins.__import__

    def missing_optional(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"chromadb", "config"}:
            raise ImportError(f"{name} unavailable")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.delitem(sys.modules, "chromadb", raising=False)
    monkeypatch.setattr(builtins, "__import__", missing_optional)
    loaded = _load(path, "memory_without_optional_dependencies")
    assert loaded.HAS_CHROMA is False
    assert loaded.CFG == {"paths": {"memory": "~/OCTOPUS/memory"}}


def test_initialization_disabled_success_and_backend_failure(monkeypatch, tmp_path, caplog) -> None:
    store = SecretStore(":memory:", key=b"m" * 32)
    monkeypatch.setattr(memory_module, "HAS_CHROMA", False)
    with caplog.at_level("WARNING"):
        disabled = memory_module.VectorMemory("disabled", store)
    assert disabled.enabled is False
    assert "ChromaDB not installed" in caplog.text

    collection = Collection()
    client = SimpleNamespace(
        get_or_create_collection=lambda **kwargs: collection,
    )
    paths = []
    monkeypatch.setattr(memory_module, "HAS_CHROMA", True)
    monkeypatch.setattr(memory_module, "CFG", {"paths": {"memory": str(tmp_path / "memory")}})
    monkeypatch.setattr(memory_module.os, "makedirs", lambda path, exist_ok: paths.append((path, exist_ok)))
    monkeypatch.setattr(
        memory_module,
        "chromadb",
        SimpleNamespace(PersistentClient=lambda *, path: client),
        raising=False,
    )
    enabled = memory_module.VectorMemory("session", store)
    assert enabled.enabled is True
    assert enabled.collection is collection
    assert enabled.collection_name == "session_session"
    assert paths == [(str(tmp_path / "memory"), True)]

    get_store_calls = []
    monkeypatch.setattr(
        memory_module,
        "get_secret_store",
        lambda: (get_store_calls.append(True) or store),
    )
    monkeypatch.setattr(
        memory_module,
        "chromadb",
        SimpleNamespace(
            PersistentClient=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("db failure"))
        ),
    )
    with caplog.at_level("ERROR"):
        failed = memory_module.VectorMemory("failed")
    assert failed.enabled is False
    assert get_store_calls == [True]
    assert "db failure" in caplog.text


def test_store_finding_disabled_duplicate_success_and_error(caplog) -> None:
    assert _memory(enabled=False).store_finding("note", "content") is False

    duplicate = _memory(collection=Collection(count=1, query_results={"distances": [[0.01]]}))
    assert duplicate.store_finding("note", "content") is False
    assert duplicate.collection.additions == []

    stored = _memory(collection=Collection(count=0))
    assert stored.store_finding("note", "content", {"source": "tool"}) is True
    addition = stored.collection.additions[0]
    assert addition["documents"] == ["safe:content"]
    assert addition["metadatas"][0]["category"] == "note"
    assert "timestamp" in addition["metadatas"][0]
    assert addition["ids"][0].startswith("note_")

    broken_collection = Collection(count=0)
    broken_collection.raise_add = RuntimeError("secret failure")
    broken = _memory(collection=broken_collection)
    with caplog.at_level("ERROR"):
        assert broken.store_finding("note", "content") is False
    assert "safe:secret failure" in caplog.text


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        (None, False),
        ({}, False),
        ({"distances": []}, False),
        ({"distances": [[]]}, False),
        ({"distances": [[0.14]]}, True),
        ({"distances": [[0.15]]}, False),
    ],
)
def test_duplicate_detection_handles_every_result_shape(results, expected) -> None:
    memory = _memory(collection=Collection(count=1, query_results=results))
    assert memory._is_duplicate("content") is expected


def test_duplicate_detection_empty_collection_and_query_failure() -> None:
    assert _memory(collection=Collection(count=0))._is_duplicate("content") is False
    collection = Collection(count=1)
    collection.raise_query = RuntimeError("query failed")
    assert _memory(collection=collection)._is_duplicate("content") is False


@pytest.mark.parametrize(
    "results",
    [None, {}, {"documents": []}, {"documents": [[]]}],
)
def test_recall_returns_empty_for_disabled_or_empty_results(results) -> None:
    assert _memory(enabled=False).recall("query") == []
    assert _memory(collection=Collection(query_results=results)).recall("query") == []


def test_recall_redacts_sorts_priority_and_supports_sparse_metadata() -> None:
    results = {
        "documents": [["ordinary", "credential"]],
        "metadatas": [[{"category": "note"}, {"category": "credentials"}]],
        "distances": [[0.1, 0.8]],
    }
    memory = _memory(collection=Collection(query_results=results))
    recalled = memory.recall("query", n_results=2, category="credentials")
    assert [item["content"] for item in recalled] == ["safe:credential", "safe:ordinary"]
    assert [item["distance"] for item in recalled] == [0.8, 0.1]
    assert memory.collection.last_query == {
        "query_texts": ["safe:query"],
        "n_results": 2,
        "where": {"category": "credentials"},
    }

    sparse = _memory(collection=Collection(query_results={"documents": [["doc"]]}))
    assert sparse.recall("query", priority_first=False) == [
        {"content": "safe:doc", "metadata": {}, "distance": 0}
    ]
    assert sparse.collection.last_query["where"] is None
    assert sparse.recall_by_category("root_access", n_results=7)[0]["content"] == "safe:doc"


def test_recall_contains_query_errors(caplog) -> None:
    collection = Collection()
    collection.raise_query = RuntimeError("recall secret")
    memory = _memory(collection=collection)
    with caplog.at_level("ERROR"):
        assert memory.recall("query") == []
    assert "safe:recall secret" in caplog.text


def test_convenience_stores_protect_credentials_and_forward_root_access(monkeypatch) -> None:
    memory = _memory()
    calls = []
    memory.store_finding = lambda category, content, metadata=None: (
        calls.append((category, content, metadata)) or True
    )

    assert memory.store_credential("ssh", "host", "alice", "plaintext") is True
    memory.store_root_access("host", "root")
    assert calls == [
        (
            "credentials",
            "CREDENTIALS FOUND: ssh alice:secret://credential-ref@host",
            {
                "service": "ssh",
                "host": "host",
                "user": "alice",
                "password": "secret://credential-ref",
            },
        ),
        (
            "root_access",
            "TARGET IS ROOTED: uid=0 access via root@host",
            {"host": "host", "user": "root"},
        ),
    ]


def test_summary_all_states_and_clear_session_lifecycle(caplog) -> None:
    assert _memory(enabled=False).get_summary() == "Memory disabled (ChromaDB not installed)."
    assert _memory(collection=Collection(count=0)).get_summary() == "Memory is empty."
    assert _memory(collection=Collection(count=3)).get_summary() == "Memory contains 3 stored context items."
    broken_count = Collection()
    broken_count.raise_count = RuntimeError("count failed")
    assert _memory(collection=broken_count).get_summary() == "Memory status unavailable."

    disabled = _memory(enabled=False)
    assert disabled.clear_session() is None

    replacement = Collection()
    memory = _memory()
    deleted = []
    memory.client = SimpleNamespace(
        delete_collection=lambda name: deleted.append(name),
        get_or_create_collection=lambda **kwargs: replacement,
    )
    memory.clear_session()
    assert deleted == ["session_fixture"]
    assert memory.collection is replacement

    memory.client = SimpleNamespace(
        delete_collection=lambda name: (_ for _ in ()).throw(RuntimeError("clear secret"))
    )
    with caplog.at_level("ERROR"):
        memory.clear_session()
    assert "safe:clear secret" in caplog.text


def test_global_memory_initialization_and_lookup(monkeypatch) -> None:
    instance = SimpleNamespace(session_id="session")
    monkeypatch.setattr(memory_module, "VectorMemory", lambda session_id: instance)
    assert memory_module.init_memory("session") is instance
    assert memory_module.get_memory() is instance
