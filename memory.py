#!/usr/bin/env python3


import os
import json
import logging
from datetime import datetime

try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

try:
    from config import CFG
except ImportError:
    CFG = {"paths": {"memory": "~/OCTOPUS/memory"}}


# v7.0: Priority categories — always returned first in recall
_PRIORITY_CATEGORIES = {"credentials", "root_access", "active_session"}

# v7.0: Dedup similarity threshold (lower = stricter matching)
_DEDUP_THRESHOLD = 0.15  # ChromaDB uses L2 distance — 0.15 = very similar


class VectorMemory:
    def __init__(self, session_id: str):
        self.session_id = str(session_id)
        self.enabled = HAS_CHROMA

        if not self.enabled:
            logging.warning("ChromaDB not installed. Vector memory disabled. Install with: pip install chromadb")
            return

        mem_dir = os.path.expanduser(CFG.get("paths", {}).get("memory", "~/OCTOPUS/memory"))
        os.makedirs(mem_dir, exist_ok=True)

        try:
            self.client = chromadb.PersistentClient(path=mem_dir)
            # Create a collection for this session
            self.collection_name = f"session_{self.session_id}"

            # Use get_or_create to avoid errors on resume
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": f"Memory for session {self.session_id}"}
            )
            logging.info(f"Vector memory initialized for session {self.session_id} at {mem_dir}")
        except Exception as e:
            logging.error(f"Failed to initialize ChromaDB: {e}")
            self.enabled = False

    def store_finding(self, category: str, content: str, metadata: dict = None):
        """Store a finding in the vector database.
        v7.0: Semantic deduplication — skip if very similar content already exists."""
        if not self.enabled:
            return False

        try:
            # v7.0: Semantic dedup — check if similar content exists
            if self._is_duplicate(content):
                return False  # Skip duplicate

            doc_id = f"{category}_{int(datetime.now().timestamp() * 1000)}"
            if metadata is None:
                metadata = {}
            metadata["category"] = category
            metadata["timestamp"] = datetime.now().isoformat()

            self.collection.add(
                documents=[content],
                metadatas=[metadata],
                ids=[doc_id]
            )
            return True
        except Exception as e:
            logging.error(f"Failed to store finding in memory: {e}")
            return False

    def _is_duplicate(self, content: str) -> bool:
        """v7.0: Check if semantically similar content already exists."""
        try:
            if self.collection.count() == 0:
                return False

            results = self.collection.query(
                query_texts=[content],
                n_results=1
            )

            if (results and results.get("distances") and
                    results["distances"][0] and
                    results["distances"][0][0] < _DEDUP_THRESHOLD):
                return True
            return False
        except Exception:
            return False

    def recall(self, query: str, n_results: int = 5, category: str = None,
               priority_first: bool = True) -> list:
        """Recall top N findings relevant to the query.
        v7.0: priority_first=True ensures credentials/root facts come first."""
        if not self.enabled:
            return []

        try:
            where_clause = {"category": category} if category else None

            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause
            )

            if not results or not results.get("documents") or not results["documents"][0]:
                return []

            recalled_items = []
            for i, doc in enumerate(results["documents"][0]):
                meta = results["metadatas"][0][i] if results.get("metadatas") else {}
                recalled_items.append({
                    "content": doc,
                    "metadata": meta,
                    "distance": results["distances"][0][i] if "distances" in results else 0
                })

            # v7.0: Priority sorting — credentials and root access facts first
            if priority_first:
                recalled_items.sort(key=lambda x: (
                    0 if x["metadata"].get("category", "") in _PRIORITY_CATEGORIES else 1,
                    x["distance"]
                ))

            return recalled_items
        except Exception as e:
            logging.error(f"Failed to recall from memory: {e}")
            return []

    def recall_by_category(self, category: str, n_results: int = 10) -> list:
        """v7.0: Recall all items of a specific category."""
        return self.recall("", n_results=n_results, category=category)

    def store_credential(self, service: str, host: str, user: str, password: str):
        """v7.0: Store a credential as a high-priority memory item."""
        content = f"CREDENTIALS FOUND: {service} {user}:{password}@{host}"
        self.store_finding("credentials", content, {
            "service": service, "host": host,
            "user": user, "password": password
        })

    def store_root_access(self, host: str, user: str):
        """v7.0: Store root access confirmation."""
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
        """v7.0: Clear current session memory (for fresh start)."""
        if not self.enabled:
            return
        try:
            self.client.delete_collection(self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"description": f"Memory for session {self.session_id}"}
            )
        except Exception as e:
            logging.error(f"Failed to clear session memory: {e}")


# Singleton instance placeholder for the current scan
_current_memory = None

def init_memory(session_id: str) -> VectorMemory:
    global _current_memory
    _current_memory = VectorMemory(session_id)
    return _current_memory

def get_memory() -> VectorMemory:
    return _current_memory
