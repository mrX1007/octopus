#!/usr/bin/env python3
"""Tests for db.py — CRUD operations, connection pool, transactions."""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime


class TestGetConnection:
    """Test database connection management."""

    @patch("db._get_db_config")
    @patch("db.MySQLConnectionPool")
    def test_creates_pool_on_first_call(self, mock_pool_class, mock_config):
        import db
        db._pool = None  # Reset pool state
        mock_config.return_value = {
            "host": "localhost", "user": "test",
            "password": "test", "database": "test_db"
        }
        mock_pool = MagicMock()
        mock_pool_class.return_value = mock_pool
        mock_pool.get_connection.return_value = MagicMock()

        conn = db.get_connection()

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

        with pytest.raises(ValueError):
            with db.transaction() as conn:
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
