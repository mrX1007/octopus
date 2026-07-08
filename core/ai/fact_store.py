#!/usr/bin/env python3

import os
import time
import sqlite3
import json
import hashlib
from contextlib import contextmanager
from typing import List, Dict, Any, Tuple

class FactStore:
    def __init__(self, db_path: str = "data/facts.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
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
            cursor = conn.cursor()
            # Facts Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 100,
                    source TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT 'none',
                    derived_from TEXT DEFAULT '[]',
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL
                )
            ''')
            # Hypotheses Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    required_evidence TEXT DEFAULT '[]',
                    source TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS fact_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fact_id INTEGER NOT NULL,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER NOT NULL DEFAULT 100,
                    source TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT 'none',
                    evidence_hash TEXT DEFAULT '',
                    timestamp REAL NOT NULL,
                    FOREIGN KEY(fact_id) REFERENCES facts(id)
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    command_key TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output_hash TEXT NOT NULL,
                    output_bytes INTEGER NOT NULL DEFAULT 0,
                    parsed_facts INTEGER NOT NULL DEFAULT 0,
                    new_facts INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_host ON facts (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON facts (type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_fact ON fact_observations (fact_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_obs_scan_host ON fact_observations (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_hash ON command_results (scan_id, host, output_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_command_result_key ON command_results (scan_id, host, command_key)')
            conn.commit()

    def add_fact(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                 confidence: int = 100, session_id: str = 'none',
                 derived_from: List[int] = None, evidence_hash: str = "") -> int:
        """Add a fact and return its row id.

        For backward compatibility this returns the existing id when the fact is
        already present. New callers that need to distinguish inserts from
        duplicates should use add_fact_with_status().
        """
        fact_id, _created = self.add_fact_with_status(
            scan_id=scan_id,
            host=host,
            fact_type=fact_type,
            value=value,
            source=source,
            confidence=confidence,
            session_id=session_id,
            derived_from=derived_from,
            evidence_hash=evidence_hash,
        )
        return fact_id

    def add_fact_with_status(self, scan_id: str, host: str, fact_type: str, value: str, source: str,
                             confidence: int = 100, session_id: str = 'none',
                             derived_from: List[int] = None, evidence_hash: str = "") -> Tuple[int, bool]:
        """Add a fact and return (row_id, created).

        The AI pipeline uses the created flag for anti-loop accounting. Without
        it, duplicates look like new facts because add_fact() returns an id for
        both new and existing rows.
        """
        if derived_from is None: derived_from = []
        derived_json = json.dumps(derived_from)
        now = time.time()
        evidence_hash = evidence_hash or self._evidence_hash(
            scan_id, host, fact_type, value, source, session_id
        )

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, confidence FROM facts
                WHERE scan_id = ? AND host = ? AND type = ? AND value = ?
                LIMIT 1
            ''', (scan_id, host, fact_type, value))
            existing = cursor.fetchone()
            if existing:
                fact_id, old_confidence = existing
                cursor.execute('''
                    UPDATE facts
                    SET confidence = ?, timestamp = ?
                    WHERE id = ?
                ''', (max(int(old_confidence or 0), int(confidence or 0)), now, fact_id))
                self._insert_observation(
                    cursor, fact_id, scan_id, host, fact_type, value,
                    confidence, source, session_id, evidence_hash, now,
                )
                conn.commit()
                return fact_id, False

            cursor.execute('''
                INSERT INTO facts (scan_id, host, type, value, confidence, source, session_id, derived_from, evidence_hash, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, host, fact_type, value, confidence, source, session_id, derived_json, evidence_hash, now))
            fact_id = cursor.lastrowid
            self._insert_observation(
                cursor, fact_id, scan_id, host, fact_type, value,
                confidence, source, session_id, evidence_hash, now,
            )
            conn.commit()
            return fact_id, True

    def _insert_observation(self, cursor, fact_id: int, scan_id: str, host: str,
                            fact_type: str, value: str, confidence: int, source: str,
                            session_id: str, evidence_hash: str, timestamp: float) -> None:
        cursor.execute('''
            INSERT INTO fact_observations (
                fact_id, scan_id, host, type, value, confidence, source,
                session_id, evidence_hash, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            fact_id, scan_id, host, fact_type, value, confidence, source,
            session_id, evidence_hash, timestamp,
        ))

    def _evidence_hash(self, scan_id: str, host: str, fact_type: str, value: str,
                       source: str, session_id: str) -> str:
        payload = "\x1f".join(str(part or "") for part in (
            scan_id, host, fact_type, value, source, session_id,
        ))
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
            
    def add_hypothesis(self, scan_id: str, host: str, claim: str, required_evidence: List[str], source: str) -> int:
        """Add a hypothesis to the hypotheses table."""
        req_json = json.dumps(required_evidence)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hypotheses (scan_id, host, claim, required_evidence, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (scan_id, host, claim, req_json, source, time.time()))
            conn.commit()
            return cursor.lastrowid

    def get_facts(self, scan_id: str, host: str = None, fact_type: str = None, session_id: str = None) -> List[Dict[str, Any]]:
        """Retrieve facts matching the given criteria."""
        query = "SELECT id, scan_id, host, type, value, confidence, source, session_id, derived_from, evidence_hash, timestamp FROM facts WHERE scan_id = ?"
        params = [scan_id]

        if host:
            query += " AND host = ?"
            params.append(host)
        if fact_type:
            query += " AND type = ?"
            params.append(fact_type)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)

        query += " ORDER BY timestamp ASC"

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            fact_ids = [row[0] for row in rows]
            observations_by_fact = self._get_observations_for_facts(cursor, fact_ids)

        results = []
        for row in rows:
            observations = observations_by_fact.get(row[0], [])
            if not observations:
                observations = [{
                    "id": None,
                    "confidence": row[5],
                    "source": row[6],
                    "session_id": row[7],
                    "evidence_hash": row[9],
                    "timestamp": row[10],
                }]
            sources = sorted({obs["source"] for obs in observations if obs.get("source")})
            sessions = sorted({obs["session_id"] for obs in observations if obs.get("session_id")})
            results.append({
                "id": row[0],
                "scan_id": row[1],
                "host": row[2],
                "type": row[3],
                "value": row[4],
                "confidence": row[5],
                "source": row[6],
                "session_id": row[7],
                "derived_from": json.loads(row[8]),
                "evidence_hash": row[9],
                "timestamp": row[10],
                "observations": observations,
                "sources": sources,
                "sessions": sessions,
            })
        return results

    def _get_observations_for_facts(self, cursor, fact_ids: List[int]) -> Dict[int, List[Dict[str, Any]]]:
        if not fact_ids:
            return {}
        placeholders = ",".join("?" for _ in fact_ids)
        cursor.execute(f'''
            SELECT id, fact_id, confidence, source, session_id, evidence_hash, timestamp
            FROM fact_observations
            WHERE fact_id IN ({placeholders})
            ORDER BY timestamp ASC
        ''', fact_ids)
        grouped: Dict[int, List[Dict[str, Any]]] = {}
        for row in cursor.fetchall():
            grouped.setdefault(row[1], []).append({
                "id": row[0],
                "confidence": row[2],
                "source": row[3],
                "session_id": row[4],
                "evidence_hash": row[5],
                "timestamp": row[6],
            })
        return grouped

    def get_hypotheses(self, scan_id: str, host: str = None) -> List[Dict[str, Any]]:
        """Retrieve hypotheses matching criteria."""
        query = "SELECT id, scan_id, host, claim, required_evidence, source, timestamp FROM hypotheses WHERE scan_id = ?"
        params = [scan_id]

        if host:
            query += " AND host = ?"
            params.append(host)
            
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "scan_id": row[1],
                "host": row[2],
                "claim": row[3],
                "required_evidence": json.loads(row[4]),
                "source": row[5],
                "timestamp": row[6]
            })
        return results

    def add_command_result(self, scan_id: str, host: str, command_key: str, command: str,
                           output_hash: str, output_bytes: int = 0, parsed_facts: int = 0,
                           new_facts: int = 0, failed: bool = False) -> Tuple[int, bool]:
        now = time.time()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM command_results
                WHERE scan_id = ? AND host = ? AND output_hash = ?
                LIMIT 1
            ''', (scan_id, host, output_hash))
            existing = cursor.fetchone()
            cursor.execute('''
                INSERT INTO command_results (
                    scan_id, host, command_key, command, output_hash, output_bytes,
                    parsed_facts, new_facts, failed, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id, host, command_key, command, output_hash, int(output_bytes or 0),
                int(parsed_facts or 0), int(new_facts or 0), 1 if failed else 0, now,
            ))
            conn.commit()
            return cursor.lastrowid, existing is None

    def get_command_results(self, scan_id: str, host: str = None) -> List[Dict[str, Any]]:
        query = '''
            SELECT id, scan_id, host, command_key, command, output_hash, output_bytes,
                   parsed_facts, new_facts, failed, timestamp
            FROM command_results
            WHERE scan_id = ?
        '''
        params = [scan_id]
        if host:
            query += " AND host = ?"
            params.append(host)
        query += " ORDER BY timestamp ASC"
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "scan_id": row[1],
                "host": row[2],
                "command_key": row[3],
                "command": row[4],
                "output_hash": row[5],
                "output_bytes": row[6],
                "parsed_facts": row[7],
                "new_facts": row[8],
                "failed": bool(row[9]),
                "timestamp": row[10],
            }
            for row in rows
        ]

    def get_all_facts_for_llm(self, scan_id: str, host: str) -> str:
        """Format facts as a JSON string for LLM ingestion. Use ContextBuilder instead for Director."""
        facts = self.get_facts(scan_id, host)
        # Strip internal DB fields to save tokens
        clean_facts = []
        for f in facts:
            clean_facts.append({
                "type": f["type"],
                "value": f["value"],
                "source": f["source"],
                "sources": f.get("sources", []),
                "observations": len(f.get("observations", [])),
                "session_id": f["session_id"],
                "confidence": f["confidence"]
            })
        return json.dumps(clean_facts, indent=2)

    def get_history(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological history of facts for anti-loop and replay."""
        return self.get_facts(scan_id)

    def clear_scan(self, scan_id: str):
        """Remove all facts for a given scan (used for cleanup or restart)."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM facts WHERE scan_id = ?", (scan_id,))
            conn.commit()
