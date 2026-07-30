"""Hermetic branch coverage for the optional MariaDB persistence facade."""

from __future__ import annotations

import builtins
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import db

pytestmark = [pytest.mark.unit, pytest.mark.security]


class DatabaseError(Exception):
    pass


class Cursor:
    def __init__(
        self,
        *,
        fetchones=(),
        fetchalls=(),
        lastrowid: int = 17,
        execute_error: BaseException | None = None,
        index_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.fetchones = list(fetchones)
        self.fetchalls = list(fetchalls)
        self.lastrowid = lastrowid
        self.execute_error = execute_error
        self.index_error = index_error
        self.close_error = close_error
        self.executions = []
        self.closed = False

    def execute(self, sql, params=None) -> None:
        self.executions.append((sql, params))
        if self.execute_error is not None:
            raise self.execute_error
        if self.index_error is not None and "CREATE INDEX" in sql:
            error = self.index_error
            self.index_error = None
            raise error

    def fetchone(self):
        return self.fetchones.pop(0) if self.fetchones else None

    def fetchall(self):
        return self.fetchalls.pop(0) if self.fetchalls else []

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class Connection:
    def __init__(
        self,
        cursor: Cursor | None = None,
        *,
        cursor_error: BaseException | None = None,
        commit_error: BaseException | None = None,
        rollback_error: BaseException | None = None,
        close_error: BaseException | None = None,
    ) -> None:
        self.selected_cursor = cursor or Cursor()
        self.cursor_error = cursor_error
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.close_error = close_error
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def cursor(self):
        if self.cursor_error is not None:
            raise self.cursor_error
        return self.selected_cursor

    def commit(self) -> None:
        self.commits += 1
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self) -> None:
        self.rollbacks += 1
        if self.rollback_error is not None:
            raise self.rollback_error

    def close(self) -> None:
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class Pool:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.calls = 0

    def get_connection(self):
        self.calls += 1
        return self.connection


def mysql_stub(*, connect=None):
    connector = SimpleNamespace(
        Error=DatabaseError,
        connect=connect or (lambda **_kwargs: Connection()),
    )
    return SimpleNamespace(connector=connector)


class CursorContext:
    def __init__(self, cursor: Cursor, *, error: BaseException | None = None) -> None:
        self.cursor = cursor
        self.error = error
        self.write_values: list[bool] = []

    def __call__(self, write: bool = False):
        self.write_values.append(write)

        @contextmanager
        def selected():
            if self.error is not None:
                raise self.error
            yield self.cursor

        return selected()


def test_safe_text_config_success_and_failure(monkeypatch, caplog) -> None:
    calls = []
    monkeypatch.setattr(
        db,
        "redact_text",
        lambda value, *, kind: calls.append((value, kind)) or f"safe:{value}",
    )
    assert db._safe_text("value") == "safe:value"
    assert db._safe_text("abcdef", 5, kind="target") == "safe:"
    assert calls == [("value", "database"), ("abcdef", "target")]

    import config

    monkeypatch.setattr(config, "CFG", {"db": {"host": "db"}})
    assert db._get_db_config() == {"host": "db"}
    monkeypatch.setattr(config, "CFG", {})
    with caplog.at_level("WARNING"), pytest.raises(RuntimeError, match="configuration not available"):
        db._get_db_config()
    assert "Could not load DB config" in caplog.text


def test_get_connection_existing_pool_optional_dependency_and_direct_fallback(monkeypatch) -> None:
    connection = Connection()
    pool = Pool(connection)
    monkeypatch.setattr(db, "_pool", pool)
    assert db.get_connection() is connection
    assert pool.calls == 1

    config = {"host": "h", "user": "u", "password": "p", "database": "d"}
    monkeypatch.setattr(db, "_get_db_config", lambda: config)
    monkeypatch.setattr(db, "_pool", None)
    monkeypatch.setattr(db, "mysql", None)
    monkeypatch.setattr(db, "MySQLConnectionPool", object)
    with pytest.raises(RuntimeError, match=r"requirements/mysql\.txt"):
        db.get_connection()

    monkeypatch.setattr(db, "mysql", mysql_stub())
    monkeypatch.setattr(db, "MySQLConnectionPool", None)
    with pytest.raises(RuntimeError, match=r"requirements/mysql\.txt"):
        db.get_connection()

    created = []

    def pool_factory(**kwargs):
        created.append(kwargs)
        return pool

    monkeypatch.setattr(db, "_pool", None)
    monkeypatch.setattr(db, "MySQLConnectionPool", pool_factory)
    assert db.get_connection() is connection
    assert created[0]["pool_name"] == "octopus"

    direct = Connection()
    direct_calls = []

    def connect(**kwargs):
        direct_calls.append(kwargs)
        return direct

    def broken_pool(**_kwargs):
        raise DatabaseError("pool unavailable")

    monkeypatch.setattr(db, "_pool", None)
    monkeypatch.setattr(db, "mysql", mysql_stub(connect=connect))
    monkeypatch.setattr(db, "MySQLConnectionPool", broken_pool)
    assert db.get_connection() is direct
    assert direct_calls == [config]


def test_transaction_and_cursor_all_cleanup_paths(monkeypatch) -> None:
    success = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: success)
    with db.transaction() as yielded:
        assert yielded is success
    assert (success.commits, success.rollbacks, success.closes) == (1, 0, 1)

    failed = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: failed)
    with pytest.raises(ValueError), db.transaction():
        raise ValueError("rollback")
    assert (failed.commits, failed.rollbacks, failed.closes) == (0, 1, 1)

    readonly = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: readonly)
    with db._cursor() as yielded:
        assert yielded is readonly.selected_cursor
    assert readonly.commits == 0
    assert readonly.selected_cursor.closed is True

    writable = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: writable)
    with db._cursor(write=True):
        pass
    assert writable.commits == 1

    read_failure = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: read_failure)
    with pytest.raises(RuntimeError), db._cursor():
        raise RuntimeError("read")
    assert read_failure.rollbacks == 0

    write_failure = Connection()
    monkeypatch.setattr(db, "get_connection", lambda: write_failure)
    with pytest.raises(RuntimeError), db._cursor(write=True):
        raise RuntimeError("write")
    assert write_failure.rollbacks == 1

    no_cursor = Connection(cursor_error=RuntimeError("cursor unavailable"))
    monkeypatch.setattr(db, "get_connection", lambda: no_cursor)
    with pytest.raises(RuntimeError, match="cursor unavailable"), db._cursor():
        pass
    assert no_cursor.closes == 1


@pytest.mark.parametrize("existing", [False, True])
def test_init_db_creates_or_preserves_migrations(monkeypatch, existing, capsys) -> None:
    values = [(1 if existing else 0,)] * 8
    cursor = Cursor(fetchones=values, index_error=DatabaseError("duplicate index"))
    connection = Connection(cursor)
    monkeypatch.setattr(db, "get_connection", lambda: connection)
    monkeypatch.setattr(db, "mysql", mysql_stub())
    db.init_db()
    sql = "\n".join(statement for statement, _params in cursor.executions)
    assert "CREATE TABLE IF NOT EXISTS history" in sql
    assert "CREATE TABLE IF NOT EXISTS credentials" in sql
    assert ("ALTER TABLE vulnerabilities" in sql) is (not existing)
    assert ("DELETE older FROM summary" in sql) is (not existing)
    assert connection.commits == 1
    assert cursor.closed is True
    assert connection.closes == 1
    assert "migration warning" not in capsys.readouterr().out


def test_init_db_contains_failures_and_suppresses_cleanup_errors(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        db,
        "get_connection",
        lambda: (_ for _ in ()).throw(RuntimeError("connect failed")),
    )
    db.init_db()
    assert "connect failed" in capsys.readouterr().out

    cursor = Cursor(fetchones=[(1,)] * 8, close_error=RuntimeError("close cursor"))
    connection = Connection(
        cursor,
        commit_error=RuntimeError("commit failed"),
        rollback_error=RuntimeError("rollback failed"),
        close_error=RuntimeError("close connection"),
    )
    monkeypatch.setattr(db, "get_connection", lambda: connection)
    monkeypatch.setattr(db, "mysql", mysql_stub())
    db.init_db()
    assert "commit failed" in capsys.readouterr().out
    assert connection.rollbacks == 1

    cursor_failure = Connection(cursor_error=RuntimeError("cursor failed"))
    monkeypatch.setattr(db, "get_connection", lambda: cursor_failure)
    db.init_db()
    assert "cursor failed" in capsys.readouterr().out
    assert cursor_failure.rollbacks == 1


def test_all_write_read_edit_and_delete_facades(monkeypatch, capsys) -> None:
    cursor = Cursor(
        fetchones=[("history",), ("summary",)],
        fetchalls=[
            [("history-list",)],
            [("vuln-session",)],
            [("fix-session",)],
            [("exploit-session",)],
            [("vulnerability",)],
            [("fix",)],
            [("exploit",)],
        ],
        lastrowid=73,
    )
    cursor_context = CursorContext(cursor)
    monkeypatch.setattr(db, "_cursor", cursor_context)
    monkeypatch.setattr(db, "redact_data", lambda value: value)
    monkeypatch.setattr(db, "redact_text", lambda value, *, kind: str(value))

    assert db.create_session("target") == 73
    db.update_session_status(1, "complete")
    db.update_session_status(1, "invalid")
    assert db.save_vulnerability(1, "v", "HIGH", "80", "http", "d", "bad") == 73
    assert db.save_vulnerability(1, "v", "HIGH", "80", "http", "d", "confirmed") == 73
    db.save_fix(1, 73, "fix")
    db.save_exploit(1, "exploit", "tool", "payload", "result", "notes")
    db.save_tool_result(1, "command", "stdout", "stderr", 2, 1.5)
    db.save_summary(1, "raw", "analysis", "HIGH")
    assert db.get_all_history() == [("history-list",)]
    assert db.get_session(1) == {
        "history": ("history",),
        "vulns": [("vuln-session",)],
        "fixes": [("fix-session",)],
        "exploits": [("exploit-session",)],
        "summary": ("summary",),
    }
    assert db.get_vulnerabilities(1) == [("vulnerability",)]
    assert db.get_fixes(1) == [("fix",)]
    assert db.get_exploits(1) == [("exploit",)]

    db.edit_vulnerability(1, "invalid", "x")
    db.edit_vulnerability(1, "severity", "LOW")
    db.edit_fix(2, "updated")
    db.edit_exploit(3, "invalid", "x")
    db.edit_exploit(3, "notes", "updated")
    db.edit_summary_risk(1, "LOW")
    db.delete_vulnerability(1)
    db.delete_exploit(2)
    db.delete_fix(3)
    db.delete_full_session(1)

    output = capsys.readouterr().out
    assert "Invalid status" in output
    assert "Invalid field" in output
    assert "Full session" in output
    assert all(cursor_context.write_values[:6])
    assert False in cursor_context.write_values


def test_display_helpers_cover_present_empty_short_and_long_sections(capsys) -> None:
    db.print_history([])
    db.print_history([(1, "target", "today", "complete")])
    populated = {
        "history": (1, "target", "today", "complete"),
        "vulns": [(1, 1, "vuln", "HIGH", "80", "http", "description")],
        "fixes": [(2, 1, 1, "fix", "ai")],
        "exploits": [(3, 1, "exploit", "tool", "payload", "success", "notes")],
        "summary": (4, 1, "raw", "a" * 501, "HIGH", "today"),
    }
    db.print_session(populated)
    short = dict(populated, summary=(4, 1, "raw", "short", "LOW", "today"))
    db.print_session(short)
    empty = dict(populated, vulns=[], fixes=[], exploits=[], summary=None)
    db.print_session(empty)
    output = capsys.readouterr().out
    assert "target" in output
    assert "None recorded" in output
    assert "..." in output
    assert "short" in output


def test_v7_result_and_analytics_success_empty_and_failure(monkeypatch, capsys) -> None:
    cursor = Cursor(lastrowid=91)
    selected = CursorContext(cursor)
    monkeypatch.setattr(db, "_cursor", selected)
    monkeypatch.setattr(db, "redact_data", lambda value: value)
    assert db.save_tool_result_v7(1, "cmd", "out", facts=[{"x": 1}]) == 91
    assert db.save_tool_result_v7(1, "cmd", "out", facts=[]) == 91

    monkeypatch.setattr(db, "_cursor", CursorContext(cursor, error=RuntimeError("store failed")))
    assert db.save_tool_result_v7(1, "cmd", "out") == -1
    assert "store failed" in capsys.readouterr().out

    analytics_cursor = Cursor(
        fetchones=[(3, 2, 1, 4.44), (5, 4)],
        fetchalls=[[('RECON',), ('EXPLOIT',)]],
    )
    monkeypatch.setattr(db, "_cursor", CursorContext(analytics_cursor))
    assert db.get_session_analytics(1) == {
        "total_tools": 3,
        "success_count": 2,
        "failure_count": 1,
        "total_duration": 4.4,
        "stages_reached": ["RECON", "EXPLOIT"],
        "vulns_found": 5,
        "vulns_confirmed": 4,
    }

    zero_cursor = Cursor(fetchones=[(0, None, None, None), (0, None)], fetchalls=[[]])
    monkeypatch.setattr(db, "_cursor", CursorContext(zero_cursor))
    zero = db.get_session_analytics(1)
    assert zero["total_tools"] == 0
    assert zero["total_duration"] == 0

    none_cursor = Cursor(fetchones=[None, None], fetchalls=[[]])
    monkeypatch.setattr(db, "_cursor", CursorContext(none_cursor))
    assert db.get_session_analytics(1)["stages_reached"] == []

    monkeypatch.setattr(db, "_cursor", CursorContext(Cursor(), error=RuntimeError("query failed")))
    assert db.get_session_analytics(1)["total_tools"] == 0
    assert "query failed" in capsys.readouterr().out


def test_optional_mysql_import_paths_execute_original_module(monkeypatch) -> None:
    source = Path(db.__file__).read_text(encoding="utf-8")
    original_import = builtins.__import__

    def missing_mysql(name, *args, **kwargs):
        if name == "mysql":
            raise ModuleNotFoundError("mysql absent", name="mysql")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_mysql)
    namespace = {"__name__": "db_without_mysql", "__file__": db.__file__}
    exec(compile(source, db.__file__, "exec"), namespace)
    assert namespace["mysql"] is None

    def unrelated_failure(name, *args, **kwargs):
        if name == "mysql":
            raise ModuleNotFoundError("transitive missing", name="unexpected_dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unrelated_failure)
    with pytest.raises(ModuleNotFoundError, match="transitive missing"):
        exec(
            compile(source, db.__file__, "exec"),
            {"__name__": "db_broken_import", "__file__": db.__file__},
        )


def mysql_modules(pool_factory, connect):
    mysql_module = ModuleType("mysql")
    mysql_module.__path__ = []
    connector = ModuleType("mysql.connector")
    connector.__path__ = []
    pooling = ModuleType("mysql.connector.pooling")
    connector.Error = DatabaseError
    connector.connect = connect
    pooling.MySQLConnectionPool = pool_factory
    connector.pooling = pooling
    mysql_module.connector = connector
    return {
        "mysql": mysql_module,
        "mysql.connector": connector,
        "mysql.connector.pooling": pooling,
    }


@pytest.mark.parametrize("succeed", [True, False])
def test_main_entrypoint_success_and_failure(monkeypatch, capsys, succeed) -> None:
    cursor = Cursor(fetchones=[(1,)] * 8)
    connection = Connection(cursor)
    pool = Pool(connection)

    def pool_factory(**_kwargs):
        if not succeed:
            raise DatabaseError("pool failed")
        return pool

    def connect(**_kwargs):
        if not succeed:
            raise RuntimeError("direct failed")
        return connection

    for name, module in mysql_modules(pool_factory, connect).items():
        monkeypatch.setitem(sys.modules, name, module)
    config_module = ModuleType("config")
    config_module.CFG = {
        "db": {"host": "h", "user": "u", "password": "p", "database": "d"}
    }
    monkeypatch.setitem(sys.modules, "config", config_module)
    source = Path(db.__file__).read_text(encoding="utf-8")
    exec(
        compile(source, db.__file__, "exec"),
        {"__name__": "__main__", "__file__": db.__file__},
    )
    output = capsys.readouterr().out
    assert ("connection successful" in output) is succeed
    assert ("Connection failed" in output) is (not succeed)
