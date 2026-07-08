#!/usr/bin/env python3

import logging
import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger("octopus.db")


# ─────────────────────────────────────────────
# CONNECTION POOL
# ─────────────────────────────────────────────

_pool = None


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
    except Exception as e:
        conn.rollback()
        raise
    finally:
        conn.close()


# v4.2: Auto-migration — runs on import, idempotent
def init_db():
    """Auto-migrate schema: create base tables and add missing columns.
    Safe to call multiple times — uses CREATE IF NOT EXISTS and checks before altering."""
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

        # ── v7.0: Add 'cvss_score' to vulnerabilities if missing ──
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

        # ── v7.0: Add 'facts_extracted' to tool_results if missing ─
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

        # ── v7.0: Add 'stage' to tool_results if missing ──────────
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

        # ── v8.0: Create c2_sessions table ────────────────────────
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

        # ── v8.0: Create credentials table ────────────────────────
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

        # ── v9.0: Performance indices ─────────────────────────────
        _index_stmts = [
            "CREATE INDEX IF NOT EXISTS idx_vuln_slno ON vulnerabilities(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_fix_slno ON fixes(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_exploit_slno ON exploits_attempted(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_summary_slno ON summary(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_tool_results_slno ON tool_results(sl_no)",
            "CREATE INDEX IF NOT EXISTS idx_history_target ON history(target)",
            "CREATE INDEX IF NOT EXISTS idx_history_status ON history(status)",
            "CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_ip)",
        ]
        for stmt in _index_stmts:
            try:
                c.execute(stmt)
            except mysql.connector.Error:
                pass  # Index may already exist on older MariaDB without IF NOT EXISTS

        conn.commit()
        conn.close()
    except Exception as e:
        # Don't crash on migration failure — just warn
        logger.warning(f"DB migration warning: {e}")
        print(f"[!] DB migration warning: {e}")


# Run migration on import
try:
    init_db()
except Exception as e:
    pass


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
        (target, now, "active")
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def update_session_status(sl_no: int, status: str):
    """Update session status: 'active', 'complete', 'failed', 'interrupted'."""
    allowed = {"active", "complete", "failed", "interrupted"}
    if status not in allowed:
        print(f"[!] Invalid status: {status}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE history SET status = %s WHERE sl_no = %s", (status, sl_no))
    conn.commit()
    conn.close()


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str,
                       confidence: str = "UNCONFIRMED",
                       evidence_source: str = "",
                       raw_evidence: str = "") -> int:
    """Insert a vulnerability. Returns its id.
    v4.2: Added confidence (CONFIRMED/POSSIBLE/UNCONFIRMED) and evidence_source."""
    # Validate confidence level
    valid_conf = {"CONFIRMED", "POSSIBLE", "UNCONFIRMED"}
    if confidence.upper() not in valid_conf:
        confidence = "UNCONFIRMED"
    else:
        confidence = confidence.upper()

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities
        (sl_no, vuln_name, severity, port, service, description,
         confidence, evidence_source, raw_evidence)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (sl_no,
          str(vuln_name or "")[:100],
          str(severity or "")[:20],
          str(port or "")[:20],
          str(service or "")[:50],
          str(description or "")[:500],
          confidence,
          str(evidence_source or "")[:100],
          str(raw_evidence or "")[:5000]))
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (%s, %s, %s, %s)
    """, (sl_no, vuln_id, str(fix_text or "")[:1000], str(source or "")[:50]))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (sl_no,
          str(exploit_name or "")[:100],
          str(tool_used or "")[:50],
          str(payload or "")[:100],
          str(result or "")[:100],
          str(notes or "")[:200]))
    conn.commit()
    conn.close()


def save_tool_result(sl_no: int, command: str, stdout: str,
                     stderr: str = "", exit_code: int = -1,
                     duration: float = 0.0):
    """v4.2: Store normalized tool result in DB for audit trail."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO tool_results
        (sl_no, command, stdout, stderr, exit_code, duration_seconds)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (sl_no,
          str(command or "")[:2000],
          str(stdout or "")[:50000],
          str(stderr or "")[:5000],
          exit_code,
          duration))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()

    conn.close()

    return {
        "history":   history,
        "vulns":     vulns,
        "fixes":     fixes,
        "exploits":  exploits,
        "summary":   summary
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s",
        (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE exploits_attempted SET {field} = %s WHERE id = %s",
        (value, exploit_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = %s", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all 5 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
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


# ─────────────────────────────────────────────
# v7.0: ENHANCED TOOL RESULT STORAGE
# ─────────────────────────────────────────────

def save_tool_result_v7(sl_no: int, command: str, stdout: str,
                        stderr: str = "", exit_code: int = 0,
                        duration: float = 0.0, facts: list = None,
                        stage: str = "RECON") -> int:
    """v7.0: Save tool result with extracted facts and kill chain stage."""
    import json
    conn = get_connection()
    c = conn.cursor()
    facts_json = json.dumps(facts) if facts else None
    try:
        c.execute("""
            INSERT INTO tool_results
                (sl_no, command, stdout, stderr, exit_code,
                 duration_seconds, facts_extracted, stage)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (sl_no, command[:500], stdout[:50000] if stdout else "",
              stderr[:5000] if stderr else "", exit_code,
              duration, facts_json, stage))
        conn.commit()
        result_id = c.lastrowid
    except Exception as e:
        print(f"[!] save_tool_result_v7 failed: {e}")
        result_id = -1
    finally:
        conn.close()
    return result_id


def get_session_analytics(sl_no: int) -> dict:
    """v7.0: Get analytics for a scan session.
    Returns dict with tool counts, success rate, time per stage."""
    conn = get_connection()
    c = conn.cursor()

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
    finally:
        conn.close()

    return analytics


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: octopus")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
