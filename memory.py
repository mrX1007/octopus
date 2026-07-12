#!/usr/bin/env python3


import logging
import os
from datetime import datetime
from typing import Optional

from core.secrets import Redactor, SecretStore, get_secret_store

try:
    import chromadb
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

try:
    from config import CFG
except ImportError:
    CFG = {"paths": {"memory": "~/OCTOPUS/memory"}}


# Categories promoted when priority-first recall is enabled.
_PRIORITY_CATEGORIES = {"credentials", "root_access", "active_session"}

# ChromaDB uses L2 distance; lower values require a closer match.
_DEDUP_THRESHOLD = 0.15


class VectorMemory:
    def __init__(self, session_id: str, secret_store: SecretStore = None):
        self.session_id = str(session_id)
        self.secret_store = secret_store or get_secret_store()
        self.redactor = Redactor(self.secret_store)
        self.enabled = HAS_CHROMA

        if not self.enabled:
            logging.warning("ChromaDB not installed. Vector memory disabled. Install with: pip install chromadb")
            return

        mem_dir = os.path.expanduser(CFG.get("paths", {}).get("memory", "~/OCTOPUS/memory"))
        os.makedirs(mem_dir, exist_ok=True)

        try:
            self.client = chromadb.PersistentClient(path=mem_dir)
            self.collection_name = f"session_{self.session_id}"

            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": f"Memory for session {self.session_id}"}
            )
            logging.info(f"Vector memory initialized for session {self.session_id} at {mem_dir}")
        except Exception as e:
            logging.error(f"Failed to initialize ChromaDB: {e}")
            self.enabled = False

    def store_finding(self, category: str, content: str, metadata: Optional[dict] = None):
        """Store a finding unless a semantically equivalent item exists."""
        if not self.enabled:
            return False

        try:
            safe_content = self.redactor.redact_text(content, kind=f"memory:{category}")
            safe_metadata = self.redactor.redact_data(dict(metadata or {}))
            if self._is_duplicate(safe_content):
                return False

            doc_id = f"{category}_{int(datetime.now().timestamp() * 1000)}"
            safe_metadata["category"] = category
            safe_metadata["timestamp"] = datetime.now().isoformat()

            self.collection.add(
                documents=[safe_content],
                metadatas=[safe_metadata],
                ids=[doc_id]
            )
            return True
        except Exception as e:
            logging.error("Failed to store finding in memory: %s", self.redactor.redact_text(e, kind="error"))
            return False

    def _is_duplicate(self, content: str) -> bool:
        """Return whether semantically similar content already exists."""
        try:
            if self.collection.count() == 0:
                return False

            results = self.collection.query(
                query_texts=[content],
                n_results=1
            )

            return bool(results and results.get("distances") and results["distances"][0] and results["distances"][0][0] < _DEDUP_THRESHOLD)
        except Exception:
            return False

    def recall(self, query: str, n_results: int = 5, category: Optional[str] = None,
               priority_first: bool = True) -> list:
        """Recall relevant findings, optionally promoting priority categories."""
        if not self.enabled:
            return []

        try:
            safe_query = self.redactor.redact_text(query, kind="memory_query")
            where_clause = {"category": category} if category else None

            results = self.collection.query(
                query_texts=[safe_query],
                n_results=n_results,
                where=where_clause
            )

            if not results or not results.get("documents") or not results["documents"][0]:
                return []

            recalled_items = []
            for i, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                recalled_items.append({
                    "content": self.redactor.redact_text(doc, kind="memory_result"),
                    "metadata": self.redactor.redact_data(meta),
                    "distance": results["distances"][0][i] if "distances" in results else 0
                })

            if priority_first:
                recalled_items.sort(key=lambda x: (
                    0 if x["metadata"].get("category", "") in _PRIORITY_CATEGORIES else 1,
                    x["distance"]
                ))

            return recalled_items
        except Exception as e:
            logging.error("Failed to recall from memory: %s", self.redactor.redact_text(e, kind="error"))
            return []

    def recall_by_category(self, category: str, n_results: int = 10) -> list:
        """Recall items from a specific category."""
        return self.recall("", n_results=n_results, category=category)

    def store_credential(self, service: str, host: str, user: str, password: str):
        """Store a credential as a high-priority memory item."""
        secret_ref = self.redactor.protect(password, kind="credential")
        content = f"CREDENTIALS FOUND: {service} {user}:{secret_ref}@{host}"
        return self.store_finding("credentials", content, {
            "service": service, "host": host,
            "user": user, "password": secret_ref
        })

    def store_root_access(self, host: str, user: str):
        """Store root access confirmation."""
        content = f"TARGET IS ROOTED: uid=0 access via {user}@{host}"
        self.store_finding("root_access", content, {
            "host": host, "user": user
        })

    def get_summary(self) -> str:
        """Get a summary of what's in memory by counting categories."""
        if not self.enabled:
            return "Memory disabled (ChromaDB not installed)."

        try:
            count = self.collection.count()
            if count == 0:
                return "Memory is empty."
            return f"Memory contains {count} stored context items."
        except Exception:
            return "Memory status unavailable."

    def clear_session(self):
        """Clear the current session memory."""
        if not self.enabled:
            return
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": f"Memory for session {self.session_id}"}
            )
        except Exception as e:
            logging.error("Failed to clear session memory: %s", self.redactor.redact_text(e, kind="error"))


_current_memory = None

def init_memory(session_id: str) -> VectorMemory:
    global _current_memory
    _current_memory = VectorMemory(session_id)
    return _current_memory

def get_memory() -> VectorMemory:
    return _current_memory
