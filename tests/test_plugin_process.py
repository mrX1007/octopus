"""Process-isolation coverage for class-based plugins."""

from __future__ import annotations

import builtins
import os
import textwrap
import time
from pathlib import Path

import pytest

from core.plugins.base import CheckResult, PluginContext, PluginResult
from core.secrets import is_secret_ref, reset_default_secret_store_for_tests


@pytest.fixture(autouse=True)
def _isolated_secret_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    reset_default_secret_store_for_tests()
    monkeypatch.setenv("OCTOPUS_SECRET_STORE", str(tmp_path / "secrets.db"))
    yield
    reset_default_secret_store_for_tests()


def _write_plugin(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.py"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def test_discovery_and_listing_do_not_import_plugin_in_parent(tmp_path: Path):
    from core.plugins.loader import PluginManager

    marker = "_octopus_discovery_side_effect"
    if hasattr(builtins, marker):
        delattr(builtins, marker)
    plugin_dir = tmp_path / "modules"
    _write_plugin(
        plugin_dir,
        "side_effect",
        f"""
        import builtins
        import os
        setattr(builtins, {marker!r}, os.getpid())
        from core.plugins.base import OctopusPlugin, PluginResult

        class SideEffectPlugin(OctopusPlugin):
            name = "side_effect"
            version = "1.2.3"

            def run(self, **kwargs):
                return PluginResult(success=True, data={{"worker_pid": os.getpid()}})
        """,
    )

    manager = PluginManager(str(plugin_dir))

    assert manager.get_plugin("side_effect")
    assert manager.list_plugins()[0]["version"] == "1.2.3"
    assert not hasattr(builtins, marker)
    result = manager.execute("side_effect", timeout=5)
    assert result.success
    assert result.data["worker_pid"] != os.getpid()
    assert not hasattr(builtins, marker)


def test_plugin_crash_is_structured_and_redacted(tmp_path: Path):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    _write_plugin(
        plugin_dir,
        "crash",
        """
        from core.plugins.base import OctopusPlugin

        class CrashPlugin(OctopusPlugin):
            name = "crash"

            def run(self, **kwargs):
                raise RuntimeError("password=hunter2")
        """,
    )

    result = PluginManager(str(plugin_dir)).execute("crash", timeout=5)

    assert isinstance(result, PluginResult)
    assert not result.success
    assert "crashed" in result.error
    assert "hunter2" not in result.error
    assert "secret://" in result.error


def test_plugin_timeout_terminates_ignoring_process_group(tmp_path: Path):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    _write_plugin(
        plugin_dir,
        "hang",
        """
        import signal
        import subprocess
        import sys
        import time
        from core.plugins.base import OctopusPlugin, PluginResult

        class HangPlugin(OctopusPlugin):
            name = "hang"

            def run(self, **kwargs):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                subprocess.Popen([
                    sys.executable,
                    "-c",
                    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
                ])
                while True:
                    time.sleep(0.05)
        """,
    )

    started = time.monotonic()
    result = PluginManager(str(plugin_dir)).execute("hang", timeout=0.2)
    elapsed = time.monotonic() - started

    assert not result.success
    assert "timed out" in result.error
    assert elapsed < 4


def test_plugin_stdout_and_stderr_noise_are_captured(tmp_path: Path):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    _write_plugin(
        plugin_dir,
        "noise",
        """
        import os
        print("import-noise")
        from core.plugins.base import OctopusPlugin, PluginResult

        class NoisePlugin(OctopusPlugin):
            name = "noise"

            def run(self, **kwargs):
                print("run-stdout")
                os.write(2, b"run-stderr\\n")
                return PluginResult(success=True, output="returned-output")
        """,
    )

    manager = PluginManager(str(plugin_dir))
    result = manager.execute("noise", timeout=5)

    assert result.success
    assert "returned-output" in result.output
    assert "import-noise" in result.output
    assert "run-stdout" in result.output
    assert "run-stderr" in result.output


def test_execute_check_bytes_events_and_credentials_cross_json_boundary(tmp_path: Path):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    _write_plugin(
        plugin_dir,
        "happy",
        """
        from core.plugins.base import CheckResult, OctopusPlugin, PluginResult

        class HappyPlugin(OctopusPlugin):
            name = "happy"

            def check(self, target, **kwargs):
                return CheckResult(
                    vulnerable=target == "example.test",
                    confidence=0.9,
                    details="safe check",
                    evidence="token=check-secret",
                )

            def run(self, **kwargs):
                self.emit_event("custom.result", {"token": "event-secret", "ok": True})
                return PluginResult(
                    success=True,
                    data={"blob": b"\\x00\\xffpayload", "answer": 42},
                    credentials=[{"username": "alice", "password": "correct-horse"}],
                )
        """,
    )

    manager = PluginManager(str(plugin_dir))
    result = manager.execute(
        "happy",
        context=PluginContext(target="example.test", config={"enabled": True}),
        timeout=5,
        payload=b"request-bytes",
    )
    checked = manager.check("happy", "example.test", timeout=5)

    assert isinstance(result, PluginResult)
    assert result.success
    assert result.data["answer"] == 42
    assert is_secret_ref(result.data["blob"])
    assert result.credentials[0]["username"] == "alice"
    assert is_secret_ref(result.credentials[0]["password"])
    assert isinstance(checked, CheckResult)
    assert checked.vulnerable
    assert "check-secret" not in checked.evidence
    custom = manager.event_bus.get_events("custom.result")
    assert custom
    assert is_secret_ref(custom[0].data["token"])


def test_duplicate_names_and_symlink_escape_fail_closed(tmp_path: Path):
    from core.plugins.loader import PluginManager

    plugin_dir = tmp_path / "modules"
    source = """
        from core.plugins.base import OctopusPlugin, PluginResult
        class Duplicate(OctopusPlugin):
            name = "duplicate"
            def run(self, **kwargs):
                return PluginResult(success=True)
    """
    _write_plugin(plugin_dir, "one", source)
    _write_plugin(plugin_dir, "two", source)
    outside = _write_plugin(tmp_path / "outside", "escaped", source.replace("duplicate", "escaped"))
    try:
        (plugin_dir / "escaped.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this platform")

    manager = PluginManager(str(plugin_dir))

    assert not manager.get_plugin("duplicate")
    assert not manager.get_plugin("escaped")
    assert any("duplicate plugin name" in item["reason"] for item in manager.list_skipped_plugins())
    assert any("symlinked plugin" in item["reason"] for item in manager.list_skipped_plugins())
