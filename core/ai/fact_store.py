#!/usr/bin/env python3

import os
import time
import sqlite3
import json
from typing import List, Dict, Any, Optional, Tuple

class FactStore:
    def __init__(self, db_path: str = "data/facts.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

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
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_host ON facts (scan_id, host)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON facts (type)')
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

        # Deduplicate by scan_id + host + type + value (NOT session_id)
        # This prevents the same port_open fact from being added every loop
        existing = self.get_facts(scan_id, host, fact_type=fact_type)
        for f in existing:
            if f['value'] == value:
                return f['id'], False  # Already exists, return existing ID

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO facts (scan_id, host, type, value, confidence, source, session_id, derived_from, evidence_hash, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (scan_id, host, fact_type, value, confidence, source, session_id, derived_json, evidence_hash, time.time()))
            conn.commit()
            return cursor.lastrowid, True
            
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

        results = []
        for row in rows:
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
                "timestamp": row[10]
            })
        return results

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
