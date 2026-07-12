#!/usr/bin/env python3
"""
Cross-plugin Event Bus.

Allows plugins to communicate through typed events without direct coupling.
Events are stored in-memory for the current session and optionally persisted
to the EventStore for audit trail.

Usage:
    bus = PluginEventBus()
    bus.on("credential.found", my_handler)
    bus.emit("credential.found", {"user": "admin", "pass": "123"}, source="hydra_brute")
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class PluginEvent:
    """A single event emitted by a plugin."""
    event_type: str
    data: dict[str, Any]
    source: str            # plugin name that emitted it
    timestamp: float = field(default_factory=time.time)


class PluginEventBus:
    """
    In-memory event bus for cross-plugin communication.

    Supports:
      - Exact match subscriptions: "credential.found"
      - Prefix wildcard: "credential.*"
      - All events: "*"

    Optionally backed by EventStore for persistence.
    """

    def __init__(self, event_store=None):
        self._handlers: dict[str, list[Callable]] = {}
        self._history: list[PluginEvent] = []
        self._event_store = event_store   # core.c2.event_store.EventStore or None

    def on(self, pattern: str, handler: Callable):
        """Subscribe a handler to an event pattern."""
        if pattern not in self._handlers:
            self._handlers[pattern] = []
        self._handlers[pattern].append(handler)

    def off(self, pattern: str, handler: Optional[Callable] = None):
        """Unsubscribe a handler. If handler is None, remove all for pattern."""
        if pattern not in self._handlers:
            return
        if handler is None:
            del self._handlers[pattern]
        else:
            self._handlers[pattern] = [h for h in self._handlers[pattern] if h != handler]

    def emit(self, event_type: str, data: dict[str, Any], source: str = "unknown"):
        """Emit an event to all matching subscribers."""
        event = PluginEvent(event_type=event_type, data=data, source=source)
        self._history.append(event)

        # Persist to EventStore if available
        if self._event_store:
            try:
                self._event_store.append(
                    event_type=f"plugin.{event_type}",
                    aggregate_type="plugin",
                    aggregate_id=source,
                    payload=data
                )
            except Exception as e:
                logging.debug(f"EventBus: failed to persist event: {e}")

        # Dispatch to handlers
        matched = 0
        for pattern, handlers in self._handlers.items():
            if self._matches(pattern, event_type):
                for handler in handlers:
                    try:
                        handler(event)
                        matched += 1
                    except Exception as e:
                        logging.error(f"EventBus: handler error for {event_type}: {e}")

        return matched

    def _matches(self, pattern: str, event_type: str) -> bool:
        """Check if an event type matches a subscription pattern."""
        if pattern == "*":
            return True
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return event_type.startswith(prefix + ".")
        return pattern == event_type

    @property
    def history(self) -> list[PluginEvent]:
        """Return event history for the current session."""
        return list(self._history)

    def get_events(self, event_type: Optional[str] = None, source: Optional[str] = None,
                   since: float = 0) -> list[PluginEvent]:
        """Query event history with optional filters."""
        results = self._history
        if event_type:
            results = [e for e in results if self._matches(event_type, e.event_type)]
        if source:
            results = [e for e in results if e.source == source]
        if since > 0:
            results = [e for e in results if e.timestamp >= since]
        return results

    def clear(self):
        """Clear in-memory event history."""
        self._history.clear()
