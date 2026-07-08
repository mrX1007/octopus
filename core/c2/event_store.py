"""
Append-only SQLite Event Sourcing.

Events are immutable facts. State is a projection.
Subscribers track their own offset. Replay is always possible.

Schema designed for future migration to PostgreSQL/NATS/Kafka
without rewriting the core.
"""

import os
import json
import time
import sqlite3
import threading
from contextlib import contextmanager
from typing import Callable, Dict, Any, List, Optional


class Event:
    """Immutable event record."""
    __slots__ = ('event_id', 'timestamp', 'aggregate_type', 'aggregate_id',
                 'event_type', 'payload', 'causation_id', 'correlation_id')

    def __init__(self, event_id: int, timestamp: float, aggregate_type: str,
                 aggregate_id: str, event_type: str, payload: dict,
                 causation_id: Optional[int] = None,
                 correlation_id: Optional[str] = None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.aggregate_type = aggregate_type
        self.aggregate_id = aggregate_id
        self.event_type = event_type
        self.payload = payload
        self.causation_id = causation_id
        self.correlation_id = correlation_id

    def to_dict(self) -> dict:
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'aggregate_type': self.aggregate_type,
            'aggregate_id': self.aggregate_id,
            'event_type': self.event_type,
            'payload': self.payload,
            'causation_id': self.causation_id,
            'correlation_id': self.correlation_id,
        }


class EventStore:
    """
    Append-only event store backed by SQLite WAL.

    Usage:
        store = EventStore("data/c2.db")
        store.append("agent", "AGT-123", "agent.registered", {"hostname": "box1"})
        store.subscribe("task_scheduler", handler_fn)
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._subscribers: Dict[str, List[Callable]] = {}
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    aggregate_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    causation_id INTEGER,
                    correlation_id TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_aggregate
                ON events(aggregate_type, aggregate_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type)
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subscriber_offsets (
                    subscriber_name TEXT PRIMARY KEY,
                    last_event_id INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.commit()

    def append(self, aggregate_type: str, aggregate_id: str,
               event_type: str, payload: dict,
               causation_id: Optional[int] = None,
               correlation_id: Optional[str] = None) -> Event:
        """Append an immutable event. Returns the created Event."""
        ts = time.time()
        payload_json = json.dumps(payload)

        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("""
                    INSERT INTO events
                        (timestamp, aggregate_type, aggregate_id,
                         event_type, payload, causation_id, correlation_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (ts, aggregate_type, aggregate_id,
                      event_type, payload_json,
                      causation_id, correlation_id))
                conn.commit()
                event_id = cur.lastrowid

        event = Event(
            event_id=event_id, timestamp=ts,
            aggregate_type=aggregate_type, aggregate_id=aggregate_id,
            event_type=event_type, payload=payload,
            causation_id=causation_id, correlation_id=correlation_id
        )

        # Notify in-process subscribers
        self._dispatch(event)
        return event

    def read_stream(self, aggregate_type: Optional[str] = None,
                    aggregate_id: Optional[str] = None,
                    event_type: Optional[str] = None,
                    after_id: int = 0,
                    limit: int = 1000) -> List[Event]:
        """Read events from the stream with optional filters."""
        query = "SELECT * FROM events WHERE event_id > ?"
        params: list = [after_id]

        if aggregate_type:
            query += " AND aggregate_type = ?"
            params.append(aggregate_type)
        if aggregate_id:
            query += " AND aggregate_id = ?"
            params.append(aggregate_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY event_id ASC LIMIT ?"
        params.append(limit)

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [self._row_to_event(r) for r in rows]

    def get_subscriber_offset(self, subscriber_name: str) -> int:
        """Get the last processed event_id for a subscriber."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT last_event_id FROM subscriber_offsets WHERE subscriber_name = ?",
                (subscriber_name,)
            ).fetchone()
        return row["last_event_id"] if row else 0

    def update_subscriber_offset(self, subscriber_name: str, last_event_id: int):
        """Update the subscriber's offset after processing."""
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO subscriber_offsets (subscriber_name, last_event_id)
                VALUES (?, ?)
                ON CONFLICT(subscriber_name) DO UPDATE SET last_event_id = excluded.last_event_id
            """, (subscriber_name, last_event_id))
            conn.commit()

    def subscribe(self, event_type: str, handler: Callable[[Event], None]):
        """Register an in-process handler for an event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(handler)

    def replay(self, subscriber_name: str, handler: Callable[[Event], None],
               event_type: Optional[str] = None):
        """Replay all events from subscriber's last offset. Used for state recovery."""
        offset = self.get_subscriber_offset(subscriber_name)
        events = self.read_stream(event_type=event_type, after_id=offset)
        for event in events:
            handler(event)
            self.update_subscriber_offset(subscriber_name, event.event_id)

    def _dispatch(self, event: Event):
        """Dispatch event to in-process subscribers."""
        handlers = self._subscribers.get(event.event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                # Log but don't crash the event store
                print(f"[EventStore] Handler error for {event.event_type}: {e}")

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Event:
        return Event(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            aggregate_type=row["aggregate_type"],
            aggregate_id=row["aggregate_id"],
            event_type=row["event_type"],
            payload=json.loads(row["payload"]),
            causation_id=row["causation_id"],
            correlation_id=row["correlation_id"],
        )
