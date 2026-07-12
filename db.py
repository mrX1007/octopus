#!/usr/bin/env python3

import logging
from contextlib import contextmanager, suppress
from datetime import datetime
from typing import Any, Optional, TypedDict

import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool

from core.secrets import redact_data, redact_text

logger = logging.getLogger("octopus.db")


def _safe_text(value: Any, limit: Optional[int] = None, *, kind: str = "database") -> str:
    safe = redact_text(value, kind=kind)
    return safe[:limit] if limit is not None else safe


# CONNECTION POOL

_pool = None


class SessionReport(TypedDict):
    """Canonical payload returned by :func:`get_session`."""

    history: Optional[Any]
    vulns: list[Any]
    fixes: list[Any]
    exploits: list[Any]
    summary: Optional[Any]


def _get_db_config() -> dict:
    """Load DB config from config.yaml / env vars. No hardcoded fallbacks."""
    try:
        from config import CFG
        return CFG["db"]
    except Exception as e:
        logger.warning(f"Could not load DB config: {e}")
        raise RuntimeError(
            "Database configuration not available. "
            "Check config.yaml or set OCTOPUS_DB_* environment variables."
        ) from e


def get_connection():
    """Returns a MariaDB connection from the pool.

    Uses connection pooling for thread-safe concurrent access
    (important for Shodan parallel scans with ThreadPoolExecutor).
    Falls back to direct connection if pooling fails.
    """
    global _pool
    if _pool is None:
        db_cfg = _get_db_config()
        try:
            _pool = MySQLConnectionPool(
                pool_name="octopus",
                pool_size=5,
                pool_reset_session=True,
                host=db_cfg["host"],
                user=db_cfg["user"],
                password=db_cfg["password"],
                database=db_cfg["database"],
            )
        except mysql.connector.Error:
            # Fallback to direct connection if pooling unavailable
            logger.debug("Connection pool creation failed, using direct connection")
            return mysql.connector.connect(
                host=db_cfg["host"],
                user=db_cfg["user"],
                password=db_cfg["password"],
                database=db_cfg["database"],
            )
    return _pool.get_connection()


@contextmanager
def transaction():
    """Context manager for atomic database operations.

    Usage:
        with transaction() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO ...")
            c.execute("INSERT INTO ...")
        # Auto-commits on success, rolls back on exception.
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def _cursor(write: bool = False):
    """Yield a cursor and always release both cursor and connection."""
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        yield cursor
        if write:
            conn.commit()
    except Exception:
        if write:
            conn.rollback()
        raise
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()


def init_db():
    """Auto-migrate schema: create base tables and add missing columns.
    Safe to call multiple times — uses CREATE IF NOT EXISTS and checks before altering."""
    conn = None
    c = None
    try:
        conn = get_connection()
        c = conn.cursor()

        # ── BASE TABLES (created from scratch if DB is empty) ─────

        c.execute("""
            CREATE TABLE IF NOT EXISTS history (
                sl_no INT AUTO_INCREMENT PRIMARY KEY,
                target VARCHAR(255),
                scan_date DATETIME,
                status VARCHAR(20) DEFAULT 'active'
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sl_no INT,
                vuln_name VARCHAR(100),
                severity VARCHAR(20),
                port VARCHAR(20),
                service VARCHAR(50),
                description VARCHAR(500),
                confidence VARCHAR(20) DEFAULT 'UNCONFIRMED',
                evidence_source VARCHAR(100) DEFAULT '',
                raw_evidence TEXT DEFAULT NULL,
                repro_cmd TEXT DEFAULT NULL,
                cvss_score FLOAT DEFAULT NULL,
                FOREIGN KEY (sl_no) REFERENCES history(sl_no)
                    ON DELETE CASCADE
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS fixes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sl_no INT,
                vuln_id INT,
                fix_text TEXT,
                source VARCHAR(50) DEFAULT 'ai',
                FOREIGN KEY (sl_no) REFERENCES history(sl_no)
                    ON DELETE CASCADE,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
                    ON DELETE CASCADE
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS exploits_attempted (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sl_no INT,
                exploit_name VARCHAR(100),
                tool_used VARCHAR(50),
                payload VARCHAR(100),
                result VARCHAR(100),
                notes VARCHAR(200),
                FOREIGN KEY (sl_no) REFERENCES history(sl_no)
                    ON DELETE CASCADE
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS summary (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sl_no INT,
                raw_scan MEDIUMTEXT,
                ai_analysis MEDIUMTEXT,
                risk_level VARCHAR(20),
                generated_at DATETIME,
                UNIQUE KEY uq_summary_slno (sl_no),
                FOREIGN KEY (sl_no) REFERENCES history(sl_no)
                    ON DELETE CASCADE
            )
        """)

        # ── MIGRATION: Add columns if missing ─────────────────────
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'vulnerabilities'
              AND COLUMN_NAME = 'confidence'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN confidence VARCHAR(20) DEFAULT 'UNCONFIRMED'
            """)

        # ── Add 'evidence_source' to vulnerabilities if missing ───
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'vulnerabilities'
              AND COLUMN_NAME = 'evidence_source'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN evidence_source VARCHAR(100) DEFAULT ''
            """)

        # ── Add 'raw_evidence' to vulnerabilities if missing ──────
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'vulnerabilities'
              AND COLUMN_NAME = 'raw_evidence'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN raw_evidence TEXT DEFAULT NULL
            """)

        # ── Create tool_results table if missing ──────────────────
        c.execute("""
            CREATE TABLE IF NOT EXISTS tool_results (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sl_no INT,
                command TEXT,
                stdout MEDIUMTEXT,
                stderr TEXT,
                exit_code INT DEFAULT -1,
                duration_seconds FLOAT DEFAULT 0.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sl_no) REFERENCES history(sl_no)
                    ON DELETE CASCADE
            )
        """)

        # ── Add 'repro_cmd' to vulnerabilities if missing ─────────
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'vulnerabilities'
              AND COLUMN_NAME = 'repro_cmd'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN repro_cmd TEXT DEFAULT NULL
            """)

        # Add 'cvss_score' to existing vulnerability tables.
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'vulnerabilities'
              AND COLUMN_NAME = 'cvss_score'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE vulnerabilities
                ADD COLUMN cvss_score FLOAT DEFAULT NULL
            """)

        # Add 'facts_extracted' to existing tool-result tables.
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'tool_results'
              AND COLUMN_NAME = 'facts_extracted'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE tool_results
                ADD COLUMN facts_extracted TEXT DEFAULT NULL
            """)

        # Add 'stage' to existing tool-result tables.
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'tool_results'
              AND COLUMN_NAME = 'stage'
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                ALTER TABLE tool_results
                ADD COLUMN stage VARCHAR(30) DEFAULT 'RECON'
            """)

        # Create C2 session storage for existing databases.
        c.execute("""
            CREATE TABLE IF NOT EXISTS c2_sessions (
                agent_id VARCHAR(64) PRIMARY KEY,
                hostname VARCHAR(255),
                os VARCHAR(100),
                user VARCHAR(100),
                ip_address VARCHAR(100),
                status VARCHAR(20) DEFAULT 'active',
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create credential storage for existing databases.
        c.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target_ip VARCHAR(255),
                service VARCHAR(50),
                username VARCHAR(255),
                password VARCHAR(255),
                hash_value TEXT,
                found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(target_ip, service, username, password)
            )
        """)

        # Keep exactly one deterministic summary per session. Existing databases
        # may contain duplicates from the former append-only save_summary().
        c.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
            WHERE TABLE_SCHEMA = DATABASE()
              AND TABLE_NAME = 'summary'
              AND COLUMN_NAME = 'sl_no'
              AND NON_UNIQUE = 0
        """)
        if c.fetchone()[0] == 0:
            c.execute("""
                DELETE older FROM summary AS older
                INNER JOIN summary AS newer
                    ON older.sl_no = newer.sl_no AND older.id < newer.id
            """)
            c.execute("""
                ALTER TABLE summary
                ADD UNIQUE INDEX uq_summary_slno (sl_no)
            """)

        # Backfill performance indices on existing databases.
        _index_stmts = [
            "CREATE INDEX IF NOT EXISTS idx_vuln_slno ON vulnerabilities(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_fix_slno ON fixes(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_exploit_slno ON exploits_attempted(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_tool_results_slno ON tool_results(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_history_target ON history(target)",
            "CREATE INDEX IF NOT EXISTS idx_history_status ON history(status)",
            "CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_ip)",
        ]
        for stmt in _index_stmts:
            with suppress(mysql.connector.Error):
                c.execute(stmt)

        conn.commit()
    except Exception as e:
        if conn is not None:
            with suppress(Exception):
                conn.rollback()
        # Don't crash on migration failure — just warn
        logger.warning(f"DB migration warning: {e}")
        print(f"[!] DB migration warning: {e}")
    finally:
        if c is not None:
            with suppress(Exception):
                c.close()
        if conn is not None:
            with suppress(Exception):
                conn.close()


# Run migration on import
with suppress(Exception):
    init_db()


# WRITE FUNCTIONS

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _cursor(write=True) as c:
        c.execute(
            "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
            (_safe_text(target, 255, kind="target"), now, "active")
        )
        sl_no = c.lastrowid
    return sl_no


def update_session_status(sl_no: int, status: str):
    """Update session status: 'active', 'complete', 'failed', 'interrupted'."""
    allowed = {"active", "complete", "failed", "interrupted"}
    if status not in allowed:
        print(f"[!] Invalid status: {status}. Allowed: {allowed}")
        return
    with _cursor(write=True) as c:
        c.execute("UPDATE history SET status = %s WHERE sl_no = %s", (status, sl_no))


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str,
                       confidence: str = "UNCONFIRMED",
                       evidence_source: str = "",
                       raw_evidence: str = "",
                       repro_cmd: str = "",
                       cvss_score: Optional[float] = None) -> int:
    """Insert a vulnerability and return its identifier.

    Confidence accepts CONFIRMED, POSSIBLE, or UNCONFIRMED.
    """
    # Validate confidence level
    valid_conf = {"CONFIRMED", "POSSIBLE", "UNCONFIRMED"}
    confidence = "UNCONFIRMED" if confidence.upper() not in valid_conf else confidence.upper()

    with _cursor(write=True) as c:
        c.execute("""
            INSERT INTO vulnerabilities
            (sl_no, vuln_name, severity, port, service, description,
             confidence, evidence_source, raw_evidence, repro_cmd, cvss_score)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (sl_no,
              _safe_text(vuln_name, 100),
              _safe_text(severity, 20),
              _safe_text(port, 20),
              _safe_text(service, 50),
              _safe_text(description, 500),
              confidence,
              _safe_text(evidence_source, 100),
              _safe_text(raw_evidence, 5000, kind="evidence"),
              _safe_text(repro_cmd, 5000, kind="command"),
              cvss_score))
        vuln_id = c.lastrowid
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    with _cursor(write=True) as c:
        c.execute("""
            INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
            VALUES (%s, %s, %s, %s)
        """, (sl_no, vuln_id, _safe_text(fix_text, 1000), _safe_text(source, 50)))


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    with _cursor(write=True) as c:
        c.execute("""
            INSERT INTO exploits_attempted (sl_no, exploit_name, tool_used, payload, result, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (sl_no,
              _safe_text(exploit_name, 100),
              _safe_text(tool_used, 50),
              _safe_text(payload, 100, kind="payload"),
              _safe_text(result, 100),
              _safe_text(notes, 200)))


def save_tool_result(sl_no: int, command: str, stdout: str,
                     stderr: str = "", exit_code: int = -1,
                     duration: float = 0.0):
    """Store a normalized tool result in the audit database."""
    with _cursor(write=True) as c:
        c.execute("""
            INSERT INTO tool_results
            (sl_no, command, stdout, stderr, exit_code, duration_seconds)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (sl_no,
              _safe_text(command, 2000, kind="command"),
              _safe_text(stdout, 50000, kind="tool_output"),
              _safe_text(stderr, 5000, kind="tool_error"),
              exit_code,
              duration))


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Create or replace the single summary associated with a session."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _cursor(write=True) as c:
        c.execute("""
            INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                raw_scan = VALUES(raw_scan),
                ai_analysis = VALUES(ai_analysis),
                risk_level = VALUES(risk_level),
                generated_at = VALUES(generated_at)
        """, (
            sl_no,
            _safe_text(raw_scan, kind="raw_scan"),
            _safe_text(ai_analysis, kind="analysis"),
            _safe_text(risk_level, 20),
            now,
        ))


# READ FUNCTIONS

def get_all_history():
    """Return all rows from history ordered by newest first."""
    with _cursor() as c:
        c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
        rows = c.fetchall()
    return redact_data(rows)


def get_session(sl_no: int) -> SessionReport:
    """Return the canonical, deterministically ordered session report."""
    with _cursor() as c:
        c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
        history = c.fetchone()

        c.execute(
            "SELECT * FROM vulnerabilities WHERE sl_no = %s ORDER BY id ASC",
            (sl_no,),
        )
        vulns = c.fetchall()

        c.execute("SELECT * FROM fixes WHERE sl_no = %s ORDER BY id ASC", (sl_no,))
        fixes = c.fetchall()

        c.execute(
            "SELECT * FROM exploits_attempted WHERE sl_no = %s ORDER BY id ASC",
            (sl_no,),
        )
        exploits = c.fetchall()

        c.execute("""
            SELECT * FROM summary WHERE sl_no = %s
            ORDER BY generated_at DESC, id DESC LIMIT 1
        """, (sl_no,))
        summary = c.fetchone()

    report = {
        "history":   history,
        "vulns":     vulns,
        "fixes":     fixes,
        "exploits":  exploits,
        "summary":   summary
    }
    return redact_data(report)


def get_vulnerabilities(sl_no: int):
    with _cursor() as c:
        c.execute(
            "SELECT * FROM vulnerabilities WHERE sl_no = %s ORDER BY id ASC",
            (sl_no,),
        )
        rows = c.fetchall()
    return redact_data(rows)


def get_fixes(sl_no: int):
    with _cursor() as c:
        c.execute("SELECT * FROM fixes WHERE sl_no = %s ORDER BY id ASC", (sl_no,))
        rows = c.fetchall()
    return redact_data(rows)


def get_exploits(sl_no: int):
    with _cursor() as c:
        c.execute(
            "SELECT * FROM exploits_attempted WHERE sl_no = %s ORDER BY id ASC",
            (sl_no,),
        )
        rows = c.fetchall()
    return redact_data(rows)


# EDIT FUNCTIONS

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    with _cursor(write=True) as c:
        c.execute(
            f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s",
            (_safe_text(value, 500), vuln_id)
        )
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    with _cursor(write=True) as c:
        c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (_safe_text(fix_text, 1000), fix_id))
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    with _cursor(write=True) as c:
        c.execute(
            f"UPDATE exploits_attempted SET {field} = %s WHERE id = %s",
            (_safe_text(value, 200), exploit_id)
        )
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    with _cursor(write=True) as c:
        c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (_safe_text(risk_level, 20), sl_no))
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# DELETE FUNCTIONS

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    with _cursor(write=True) as c:
        c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
        c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    with _cursor(write=True) as c:
        c.execute("DELETE FROM exploits_attempted WHERE id = %s", (exploit_id,))
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    with _cursor(write=True) as c:
        c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all session-owned tables.
    Order matters — delete children before parent (FK constraints).
    """
    with _cursor(write=True) as c:
        c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM tool_results      WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# DISPLAY HELPERS

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {row[2]!s:<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


# ENHANCED TOOL RESULT STORAGE

def save_tool_result_v7(sl_no: int, command: str, stdout: str,
                        stderr: str = "", exit_code: int = 0,
                        duration: float = 0.0, facts: Optional[list] = None,
                        stage: str = "RECON") -> int:
    """Save a tool result with extracted facts and kill-chain stage."""
    import json
    facts_json = json.dumps(redact_data(facts)) if facts else None
    try:
        with _cursor(write=True) as c:
            c.execute("""
                INSERT INTO tool_results
                    (sl_no, command, stdout, stderr, exit_code,
                     duration_seconds, facts_extracted, stage)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (sl_no, _safe_text(command, 500, kind="command"),
                  _safe_text(stdout, 50000, kind="tool_output"),
                  _safe_text(stderr, 5000, kind="tool_error"), exit_code,
                  duration, facts_json, stage))
            result_id = c.lastrowid
    except Exception as e:
        print(f"[!] save_tool_result_v7 failed: {e}")
        result_id = -1
    return result_id


def get_session_analytics(sl_no: int) -> dict:
    """Get analytics for a scan session.
    Returns dict with tool counts, success rate, time per stage."""
    analytics = {
        "total_tools": 0,
        "success_count": 0,
        "failure_count": 0,
        "total_duration": 0.0,
        "stages_reached": [],
        "vulns_found": 0,
        "vulns_confirmed": 0,
    }

    try:
        with _cursor() as c:
            # Tool execution stats
            c.execute("""
                SELECT COUNT(*), SUM(exit_code = 0), SUM(exit_code != 0),
                       SUM(duration_seconds)
                FROM tool_results WHERE sl_no = %s
            """, (sl_no,))
            row = c.fetchone()
            if row:
                analytics["total_tools"] = row[0] or 0
                analytics["success_count"] = row[1] or 0
                analytics["failure_count"] = row[2] or 0
                analytics["total_duration"] = round(row[3] or 0, 1)

            # Stages reached
            c.execute("""
                SELECT DISTINCT stage FROM tool_results
                WHERE sl_no = %s AND stage IS NOT NULL
            """, (sl_no,))
            analytics["stages_reached"] = [r[0] for r in c.fetchall()]

            # Vulnerability counts
            c.execute("""
                SELECT COUNT(*),
                       SUM(confidence = 'CONFIRMED')
                FROM vulnerabilities WHERE sl_no = %s
            """, (sl_no,))
            vrow = c.fetchone()
            if vrow:
                analytics["vulns_found"] = vrow[0] or 0
                analytics["vulns_confirmed"] = vrow[1] or 0

    except Exception as e:
        print(f"[!] get_session_analytics failed: {e}")

    return analytics


# QUICK CONNECTION TEST

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: octopus")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
