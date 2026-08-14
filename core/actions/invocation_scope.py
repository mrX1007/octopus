"""Invocation scope managing cleanup actions and resources in LIFO order."""

from __future__ import annotations

import logging
from typing import Callable

logger = logging.getLogger("octopus.actions.cleanup")


class InvocationScope:
    def __init__(self, scope_id: str) -> None:
        self.scope_id = scope_id
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._closed = False

    def register_cleanup(self, callback: Callable[[], None]) -> None:
        if self._closed:
            raise RuntimeError("Cannot register cleanup on closed InvocationScope")
        self._cleanup_callbacks.append(callback)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Execute callbacks in LIFO order
        for callback in reversed(self._cleanup_callbacks):
            try:
                callback()
            except Exception as exc:
                logger.error(f"Error during invocation scope cleanup: {exc}")


__all__ = [
    "InvocationScope",
]
