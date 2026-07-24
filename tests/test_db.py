#!/usr/bin/env python3
"""Tests for db.py — CRUD operations, connection pool, transactions."""

import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


class TestGetConnection:
    """Test database connection management."""

    @pytest.mark.contract
    @pytest.mark.integration
    def test_import_does_not_connect_or_run_schema_migration(self):
        project_root = Path(__file__).resolve().parents[1]
        script = textwrap.dedent(
            f"""
            import sys
            import types

            calls = []

            def forbidden(kind):
                def call(*_args, **_kwargs):
                    calls.append(kind)
                    raise AssertionError(f"import attempted {{kind}}")
                return call

            mysql = types.ModuleType("mysql")
            mysql.__path__ = []
            connector = types.ModuleType("mysql.connector")
            connector.__path__ = []
            pooling = types.ModuleType("mysql.connector.pooling")
            connector.connect = forbidden("direct MySQL connection")
            pooling.MySQLConnectionPool = forbidden("MySQL pool")
            connector.pooling = pooling
            mysql.connector = connector
            sys.modules.update({{
                "mysql": mysql,
                "mysql.connector": connector,
                "mysql.connector.pooling": pooling,
            }})
            sys.path.insert(0, {str(project_root)!r})

            import db

            assert calls == []
            """
        )

        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr

    @patch("db.mysql")
    @patch("db._get_db_config")
    @patch("db.MySQLConnectionPool")
    def test_creates_pool_on_first_call(
        self,
        mock_pool_class,
        mock_config,
        _mock_mysql,
    ):
        import db

        db._pool = None  # Reset pool state
        mock_config.return_value = {"host": "localhost", "user": "test", "password": "test", "database": "test_db"}
        mock_pool = MagicMock()
        mock_pool_class.return_value = mock_pool
        mock_pool.get_connection.return_value = MagicMock()

        db.get_connection()

        mock_pool_class.assert_called_once()
        mock_pool.get_connection.assert_called_once()
        db._pool = None  # Cleanup

    @patch("db._get_db_config")
    def test_raises_on_missing_config(self, mock_config):
        import db

        db._pool = None
        mock_config.side_effect = RuntimeError("No config")

        with pytest.raises(RuntimeError, match="No config"):
            db.get_connection()
        db._pool = None

    @pytest.mark.contract
    @pytest.mark.integration
    def test_import_is_safe_without_optional_mysql_connector(self):
        project_root = Path(__file__).resolve().parents[1]
        script = textwrap.dedent(
            f"""
            import importlib.abc
            import sys

            class BlockMysql(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == "mysql" or fullname.startswith("mysql."):
                        raise ModuleNotFoundError(
                            "blocked optional mysql dependency", name=fullname
                        )
                    return None

            sys.meta_path.insert(0, BlockMysql())
            sys.path.insert(0, {str(project_root)!r})

            import db

            assert db.mysql is None
            db._get_db_config = lambda: {{
                "host": "localhost",
                "user": "octopus",
                "password": "unused",
                "database": "octopus",
            }}
            try:
                db.get_connection()
            except RuntimeError as exc:
                assert "requirements/mysql.txt" in str(exc)
            else:
                raise AssertionError("optional MySQL profile did not fail explicitly")
            """
        )

        result = subprocess.run(
            [sys.executable, "-I", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr


class TestTransaction:
    """Test transaction context manager."""

    @patch("db.get_connection")
    def test_commits_on_success(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        with db.transaction() as conn:
            assert conn is mock_conn

        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()

    @patch("db.get_connection")
    def test_rollback_on_exception(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_get_conn.return_value = mock_conn

        with pytest.raises(ValueError), db.transaction():
            raise ValueError("test error")

        mock_conn.rollback.assert_called_once()
        mock_conn.close.assert_called_once()


class TestCreateSession:
    """Test session creation."""

    @patch("db.get_connection")
    def test_create_session_returns_sl_no(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 42
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        sl_no = db.create_session("192.168.1.1")

        assert sl_no == 42
        mock_cursor.execute.assert_called_once()
        mock_conn.commit.assert_called_once()

    @patch("db.get_connection")
    def test_create_session_stores_target(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.lastrowid = 1
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        db.create_session("10.0.0.1")

        call_args = mock_cursor.execute.call_args
        assert "10.0.0.1" in str(call_args)

    @patch("db.get_connection")
    def test_create_session_rolls_back_and_closes_on_error(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = RuntimeError("write failed")
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        with pytest.raises(RuntimeError, match="write failed"):
            db.create_session("10.0.0.1")

        mock_conn.rollback.assert_called_once()
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()


class TestSaveVulnerability:
    """Test vulnerability saving."""

    @patch("db.get_connection")
    def test_save_vulnerability_truncates_long_names(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        long_name = "A" * 200
        db.save_vulnerability(1, long_name, "HIGH", "80", "http", "desc")

        call_args = mock_cursor.execute.call_args[0]
        # The name parameter should be truncated to 100 chars
        params = call_args[1]
        assert len(params[1]) <= 100

    @patch("db.get_connection")
    def test_save_vulnerability_persists_provenance(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        db.save_vulnerability(
            1,
            "finding",
            "HIGH",
            "80",
            "http",
            "desc",
            evidence_source="nmap",
            raw_evidence="evidence",
            repro_cmd="curl target",
            cvss_score=8.4,
        )

        sql, params = mock_cursor.execute.call_args[0]
        assert "repro_cmd" in sql
        assert "cvss_score" in sql
        assert params[-4:] == ("nmap", "evidence", "curl target", 8.4)


class TestSummaryPersistence:
    @patch("db.get_connection")
    def test_save_summary_is_an_upsert(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        db.save_summary(7, "raw", "analysis", "HIGH")

        sql = mock_cursor.execute.call_args[0][0]
        assert "ON DUPLICATE KEY UPDATE" in sql
        mock_conn.commit.assert_called_once()
        mock_conn.close.assert_called_once()


class TestGetSession:
    @patch("db.get_connection")
    def test_returns_canonical_deterministic_contract(self, mock_get_conn):
        import db

        history = (7, "target", datetime.now(), "complete")
        summary = (2, 7, "raw", "analysis", "HIGH", datetime.now())
        vulns = [(1, 7, "finding")]
        fixes = [(1, 7, 1, "fix")]
        exploits = [(1, 7, "exploit")]
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.side_effect = [history, summary]
        mock_cursor.fetchall.side_effect = [vulns, fixes, exploits]
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = db.get_session(7)

        assert result == {
            "history": history,
            "vulns": vulns,
            "fixes": fixes,
            "exploits": exploits,
            "summary": summary,
        }
        assert "vulnerabilities" not in result
        sql = "\n".join(call.args[0] for call in mock_cursor.execute.call_args_list)
        assert "vulnerabilities WHERE sl_no = %s ORDER BY id ASC" in sql
        assert "fixes WHERE sl_no = %s ORDER BY id ASC" in sql
        assert "exploits_attempted WHERE sl_no = %s ORDER BY id ASC" in sql
        assert "ORDER BY generated_at DESC, id DESC LIMIT 1" in sql
        mock_cursor.close.assert_called_once()
        mock_conn.close.assert_called_once()


class TestGetAllHistory:
    """Test history retrieval."""

    @patch("db.get_connection")
    def test_returns_list(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            (1, "192.168.1.1", datetime.now(), "complete"),
        ]
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        result = db.get_all_history()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0][1] == "192.168.1.1"


class TestUpdateSessionStatus:
    """Test session status update."""

    @patch("db.get_connection")
    def test_updates_status(self, mock_get_conn):
        import db

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_get_conn.return_value = mock_conn

        db.update_session_status(1, "complete")

        mock_cursor.execute.assert_called_once()
        call_args = mock_cursor.execute.call_args[0]
        assert "complete" in str(call_args)
