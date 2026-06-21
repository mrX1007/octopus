#!/usr/bin/env python3
"""
Process Supervisor — PID management, crash recovery, health monitoring.

Usage:
    from core.supervisor import Supervisor
    sv = Supervisor()
    sv.start()           # writes PID, registers cleanup
    sv.is_healthy()      # check components
    sv.stop()            # clean shutdown

Architecture:
    ┌──────────────┐
    │  Supervisor  │
    ├──────────────┤
    │  PID file    │ → /tmp/octopus.pid (or $OCTOPUS_PID)
    │  Lock file   │ → /tmp/octopus.lock (flock)
    │  Health      │ → periodic self-check
    │  Watchdog    │ → restarts crashed subsystems
    │  Audit       │ → lifecycle events → event store
    └──────────────┘
"""

import os
import sys
import time
import signal
import atexit
import json
import fcntl
import threading
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Callable, List, Any

logger = logging.getLogger("octopus.supervisor")

# ─── Configuration ───────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
PID_FILE = os.environ.get("OCTOPUS_PID", "/tmp/octopus.pid")
LOCK_FILE = os.environ.get("OCTOPUS_LOCK", "/tmp/octopus.lock")
STATE_FILE = os.path.join(DATA_DIR, "supervisor_state.json")

# Health check interval (seconds)
HEALTH_INTERVAL = int(os.environ.get("OCTOPUS_HEALTH_INTERVAL", "30"))


# ─── Exceptions ──────────────────────────────────────────

class AlreadyRunningError(Exception):
    """Raised when another OCTOPUS instance is already running."""
    pass


class SubsystemCrashError(Exception):
    """Raised when a monitored subsystem crashes."""
    pass


# ─── Subsystem Registry ─────────────────────────────────

class Subsystem:
    """Tracked subsystem with health check and restart capability."""

    __slots__ = (
        "name", "health_fn", "start_fn", "stop_fn",
        "status", "last_check", "last_healthy",
        "crash_count", "max_restarts", "thread",
    )

    def __init__(
        self,
        name: str,
        health_fn: Callable[[], bool],
        start_fn: Optional[Callable] = None,
        stop_fn: Optional[Callable] = None,
        max_restarts: int = 3,
    ):
        self.name = name
        self.health_fn = health_fn
        self.start_fn = start_fn
        self.stop_fn = stop_fn
        self.status = "stopped"     # stopped | running | crashed | restarting
        self.last_check = 0.0
        self.last_healthy = 0.0
        self.crash_count = 0
        self.max_restarts = max_restarts
        self.thread: Optional[threading.Thread] = None

    def check(self) -> bool:
        """Run health check. Returns True if healthy."""
        self.last_check = time.time()
        try:
            ok = self.health_fn()
            if ok:
                self.status = "running"
                self.last_healthy = time.time()
            else:
                if self.status == "running":
                    self.status = "crashed"
                    self.crash_count += 1
                    logger.warning(f"[supervisor] Subsystem '{self.name}' CRASHED (count={self.crash_count})")
            return ok
        except Exception as e:
            self.status = "crashed"
            self.crash_count += 1
            logger.error(f"[supervisor] Health check failed for '{self.name}': {e}")
            return False

    def restart(self) -> bool:
        """Attempt restart if within max_restarts limit."""
        if self.crash_count > self.max_restarts:
            logger.error(f"[supervisor] '{self.name}' exceeded max restarts ({self.max_restarts})")
            return False

        self.status = "restarting"
        logger.info(f"[supervisor] Restarting '{self.name}' (attempt {self.crash_count}/{self.max_restarts})")

        try:
            if self.stop_fn:
                try:
                    self.stop_fn()
                except Exception as _exc:
                    logging.debug(f"Suppressed in supervisor.py: {_exc}")

            if self.start_fn:
                self.start_fn()

            self.status = "running"
            self.last_healthy = time.time()
            logger.info(f"[supervisor] '{self.name}' restarted successfully")
            return True
        except Exception as e:
            self.status = "crashed"
            logger.error(f"[supervisor] Restart failed for '{self.name}': {e}")
            return False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "crash_count": self.crash_count,
            "last_check": self.last_check,
            "last_healthy": self.last_healthy,
        }


# ─── Supervisor ──────────────────────────────────────────

class Supervisor:
    """
    Main OCTOPUS process supervisor.

    Responsibilities:
      1. PID file management — prevents duplicate instances
      2. flock-based file locking — race-condition safe
      3. Subsystem monitoring — watchdog with auto-restart
      4. Crash recovery — state persistence for resume
      5. Graceful shutdown — cleanup on SIGTERM/SIGINT/atexit
    """

    def __init__(self):
        self._pid = os.getpid()
        self._lock_fd: Optional[int] = None
        self._subsystems: Dict[str, Subsystem] = {}
        self._watchdog_thread: Optional[threading.Thread] = None
        self._running = False
        self._start_time = 0.0
        self._shutdown_hooks: List[Callable] = []

        # Lifecycle metrics
        self._metrics = {
            "starts": 0,
            "crashes": 0,
            "restarts": 0,
            "uptime_total": 0.0,
        }

    # ─── PID Management ────────────────────────────────

    def _acquire_lock(self):
        """Acquire exclusive flock. Raises AlreadyRunningError if taken."""
        os.makedirs(os.path.dirname(LOCK_FILE) or "/tmp", exist_ok=True)
        try:
            self._lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR)
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError) as e:
            # Check if the existing PID is actually alive
            existing_pid = self._read_pid()
            if existing_pid and self._is_pid_alive(existing_pid):
                raise AlreadyRunningError(
                    f"OCTOPUS already running (PID {existing_pid}). "
                    f"Use 'octopus stop' or kill {existing_pid}."
                )
            else:
                # Stale lock — force acquire
                logger.warning("[supervisor] Stale lock detected, forcing acquisition")
                self._force_cleanup()
                self._lock_fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR)
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _release_lock(self):
        """Release flock and remove lock file."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                os.close(self._lock_fd)
            except Exception as _exc:
                logging.debug(f"Suppressed in supervisor.py: {_exc}")
            self._lock_fd = None
        try:
            os.remove(LOCK_FILE)
        except FileNotFoundError:
            pass

    def _write_pid(self):
        """Write current PID to file with metadata."""
        os.makedirs(os.path.dirname(PID_FILE) or "/tmp", exist_ok=True)
        pid_data = {
            "pid": self._pid,
            "started_at": datetime.now().isoformat(),
            "version": "11.0",
            "hostname": os.uname().nodename,
        }
        with open(PID_FILE, "w") as f:
            json.dump(pid_data, f)
        logger.info(f"[supervisor] PID {self._pid} written to {PID_FILE}")

    def _read_pid(self) -> Optional[int]:
        """Read PID from file. Returns None if not found or invalid."""
        try:
            with open(PID_FILE, "r") as f:
                data = f.read().strip()
                if data.startswith("{"):
                    return json.loads(data).get("pid")
                return int(data)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            return None

    def _remove_pid(self):
        """Remove PID file."""
        try:
            os.remove(PID_FILE)
            logger.info(f"[supervisor] PID file removed")
        except FileNotFoundError:
            pass

    @staticmethod
    def _is_pid_alive(pid: int) -> bool:
        """Check if a process with given PID exists."""
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def _force_cleanup(self):
        """Remove stale PID and lock files."""
        for f in [PID_FILE, LOCK_FILE]:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

    # ─── State Persistence ─────────────────────────────

    def _save_state(self):
        """Persist supervisor state for crash recovery."""
        os.makedirs(DATA_DIR, exist_ok=True)
        state = {
            "pid": self._pid,
            "started_at": self._start_time,
            "saved_at": time.time(),
            "metrics": self._metrics,
            "subsystems": {
                name: sub.to_dict()
                for name, sub in self._subsystems.items()
            },
        }
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"[supervisor] Failed to save state: {e}")

    def _load_state(self) -> Optional[dict]:
        """Load previous state for crash recovery."""
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def get_crash_info(self) -> Optional[dict]:
        """Get info about the last crash if the previous instance didn't shut down cleanly."""
        state = self._load_state()
        if state is None:
            return None
        # If state exists and PID is dead → crash
        old_pid = state.get("pid")
        if old_pid and not self._is_pid_alive(old_pid):
            return {
                "previous_pid": old_pid,
                "started_at": state.get("started_at", 0),
                "crashed_at": state.get("saved_at", 0),
                "subsystems": state.get("subsystems", {}),
            }
        return None

    # ─── Subsystem Registration ────────────────────────

    def register(
        self,
        name: str,
        health_fn: Callable[[], bool],
        start_fn: Optional[Callable] = None,
        stop_fn: Optional[Callable] = None,
        max_restarts: int = 3,
    ):
        """Register a subsystem for health monitoring."""
        self._subsystems[name] = Subsystem(
            name=name,
            health_fn=health_fn,
            start_fn=start_fn,
            stop_fn=stop_fn,
            max_restarts=max_restarts,
        )
        logger.info(f"[supervisor] Registered subsystem: {name}")

    def unregister(self, name: str):
        """Remove a subsystem from monitoring."""
        self._subsystems.pop(name, None)

    # ─── Watchdog ──────────────────────────────────────

    def _watchdog_loop(self):
        """Background thread that monitors subsystem health."""
        logger.info(f"[supervisor] Watchdog started (interval={HEALTH_INTERVAL}s)")
        while self._running:
            for name, sub in list(self._subsystems.items()):
                if not self._running:
                    break
                if sub.status in ("stopped",):
                    continue

                healthy = sub.check()
                if not healthy and sub.status == "crashed":
                    self._metrics["crashes"] += 1
                    if sub.start_fn and sub.crash_count <= sub.max_restarts:
                        sub.restart()
                        self._metrics["restarts"] += 1

            # Persist state periodically
            self._save_state()

            # Sleep in small increments so we can stop quickly
            for _ in range(HEALTH_INTERVAL * 2):
                if not self._running:
                    break
                time.sleep(0.5)

    # ─── Lifecycle ─────────────────────────────────────

    def start(self):
        """
        Start the supervisor:
          1. Acquire exclusive lock (prevents duplicates)
          2. Write PID file
          3. Check for crash recovery
          4. Start watchdog
          5. Register signal handlers
        """
        # Check for previous crash
        crash_info = self.get_crash_info()
        if crash_info:
            logger.warning(
                f"[supervisor] Previous instance (PID {crash_info['previous_pid']}) "
                f"crashed. Recovery available."
            )
            print(f"\033[93m[!] Previous OCTOPUS instance (PID {crash_info['previous_pid']}) "
                  f"did not shut down cleanly.\033[0m")

        # Acquire lock
        self._acquire_lock()

        # Write PID
        self._start_time = time.time()
        self._write_pid()

        # Start watchdog
        self._running = True
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop,
            name="octopus-watchdog",
            daemon=True,
        )
        self._watchdog_thread.start()

        # Register cleanup
        atexit.register(self.stop)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self._metrics["starts"] += 1
        logger.info(f"[supervisor] Started (PID={self._pid})")

        # Log to event store if available
        self._emit_event("supervisor.start", {
            "pid": self._pid,
            "subsystems": list(self._subsystems.keys()),
        })

    def stop(self):
        """Clean shutdown: stop watchdog, cleanup PID/lock, run hooks."""
        if not self._running:
            return

        self._running = False
        logger.info("[supervisor] Shutting down...")

        # Run shutdown hooks
        for hook in self._shutdown_hooks:
            try:
                hook()
            except Exception as e:
                logger.error(f"[supervisor] Shutdown hook failed: {e}")

        # Stop all subsystems
        for name, sub in self._subsystems.items():
            if sub.stop_fn and sub.status == "running":
                try:
                    sub.stop_fn()
                    logger.info(f"[supervisor] Stopped subsystem: {name}")
                except Exception as e:
                    logger.error(f"[supervisor] Failed to stop {name}: {e}")
            sub.status = "stopped"

        # Update uptime
        if self._start_time:
            self._metrics["uptime_total"] += time.time() - self._start_time

        # Persist final state
        self._save_state()

        # Cleanup files
        self._remove_pid()
        self._release_lock()

        # Emit event
        self._emit_event("supervisor.stop", {
            "pid": self._pid,
            "uptime": time.time() - self._start_time if self._start_time else 0,
        })

        logger.info("[supervisor] Shutdown complete")

    def on_shutdown(self, hook: Callable):
        """Register a function to call during shutdown."""
        self._shutdown_hooks.append(hook)

    def _signal_handler(self, signum, frame):
        """Handle SIGTERM for graceful shutdown."""
        logger.info(f"[supervisor] Received signal {signum}")
        self.stop()
        sys.exit(0)

    # ─── Health API ────────────────────────────────────

    def is_healthy(self) -> bool:
        """Check all subsystems. Returns True if all OK."""
        if not self._running:
            return False
        return all(
            sub.check()
            for sub in self._subsystems.values()
            if sub.status != "stopped"
        )

    def health_report(self) -> dict:
        """Detailed health report for all subsystems."""
        uptime = time.time() - self._start_time if self._start_time else 0
        return {
            "status": "running" if self._running else "stopped",
            "pid": self._pid,
            "uptime_seconds": round(uptime, 1),
            "uptime_human": str(timedelta(seconds=int(uptime))),
            "metrics": self._metrics.copy(),
            "subsystems": {
                name: sub.to_dict()
                for name, sub in self._subsystems.items()
            },
        }

    # ─── Event Emission ────────────────────────────────

    def _emit_event(self, event_type: str, data: dict):
        """Emit lifecycle event to event store (if available)."""
        try:
            from core.c2.event_store import EventStore
            db_path = os.path.join(DATA_DIR, "c2.db")
            if os.path.exists(os.path.dirname(db_path)):
                es = EventStore(db_path=db_path)
                es.append("supervisor", str(self._pid), event_type, data)
        except Exception as e:
            pass  # Event store is optional

    # ─── Class Methods ─────────────────────────────────

    @classmethod
    def is_running(cls) -> bool:
        """Check if OCTOPUS is currently running (static check)."""
        try:
            with open(PID_FILE, "r") as f:
                data = f.read().strip()
                if data.startswith("{"):
                    pid = json.loads(data).get("pid")
                else:
                    pid = int(data)
                return cls._is_pid_alive(pid)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            return False

    @classmethod
    def get_pid(cls) -> Optional[int]:
        """Get PID of running instance."""
        try:
            with open(PID_FILE, "r") as f:
                data = f.read().strip()
                if data.startswith("{"):
                    return json.loads(data).get("pid")
                return int(data)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            return None

    @classmethod
    def kill_running(cls) -> bool:
        """Kill running OCTOPUS instance."""
        pid = cls.get_pid()
        if pid and cls._is_pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait up to 5s for graceful shutdown
                for _ in range(50):
                    if not cls._is_pid_alive(pid):
                        return True
                    time.sleep(0.1)
                # Force kill
                os.kill(pid, signal.SIGKILL)
                return True
            except ProcessLookupError:
                return True
        return False


# ─── Default Health Checks ───────────────────────────────

def _check_ollama() -> bool:
    """Check if Ollama is reachable."""
    try:
        import urllib.request
        url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        req = urllib.request.Request(f"{url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        return False


def _check_database() -> bool:
    """Check if main database is accessible."""
    try:
        from db import get_connection
        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception as e:
        return False


def _check_event_store() -> bool:
    """Check if event store is operational."""
    try:
        from core.c2.event_store import EventStore
        db_path = os.path.join(DATA_DIR, "c2.db")
        if not os.path.exists(db_path):
            return True  # Not initialized yet is OK
        es = EventStore(db_path=db_path)
        # Verify we can read from the stream (count() doesn't exist)
        es.read_stream(limit=1)
        return True
    except Exception as e:
        return False


# ─── Factory ─────────────────────────────────────────────

def create_supervisor(
    monitor_ollama: bool = True,
    monitor_db: bool = True,
    monitor_events: bool = True,
) -> Supervisor:
    """Create a pre-configured supervisor with default health checks."""
    sv = Supervisor()

    if monitor_ollama:
        sv.register("ollama", _check_ollama, max_restarts=0)  # can't restart external

    if monitor_db:
        sv.register("database", _check_database, max_restarts=0)

    if monitor_events:
        sv.register("event_store", _check_event_store, max_restarts=0)

    return sv


# ─── CLI ─────────────────────────────────────────────────

def cli():
    """Standalone supervisor CLI."""
    import argparse
    parser = argparse.ArgumentParser(description="OCTOPUS Supervisor")
    parser.add_argument("action", choices=["status", "stop", "health", "pid"],
                        help="Action to perform")
    args = parser.parse_args()

    if args.action == "pid":
        pid = Supervisor.get_pid()
        if pid and Supervisor._is_pid_alive(pid):
            print(f"OCTOPUS running (PID {pid})")
        else:
            print("OCTOPUS is not running")
            sys.exit(1)

    elif args.action == "status":
        pid = Supervisor.get_pid()
        if pid and Supervisor._is_pid_alive(pid):
            # Read state file for details
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                uptime = time.time() - state.get("started_at", time.time())
                print(f"Status:     RUNNING")
                print(f"PID:        {pid}")
                print(f"Uptime:     {timedelta(seconds=int(uptime))}")
                print(f"Subsystems:")
                for name, sub in state.get("subsystems", {}).items():
                    status = sub.get("status", "unknown")
                    crashes = sub.get("crash_count", 0)
                    marker = "✅" if status == "running" else "❌"
                    print(f"  {marker} {name}: {status} (crashes: {crashes})")
            except Exception as e:
                print(f"OCTOPUS running (PID {pid}), no state file")
        else:
            print("Status: STOPPED")
            sys.exit(1)

    elif args.action == "stop":
        if Supervisor.kill_running():
            print("OCTOPUS stopped")
        else:
            print("OCTOPUS is not running")

    elif args.action == "health":
        pid = Supervisor.get_pid()
        if not pid or not Supervisor._is_pid_alive(pid):
            print("OCTOPUS is not running")
            sys.exit(1)
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
            all_ok = True
            for name, sub in state.get("subsystems", {}).items():
                status = sub.get("status", "unknown")
                if status != "running":
                    all_ok = False
                marker = "✅" if status == "running" else "❌"
                print(f"  {marker} {name}: {status}")
            sys.exit(0 if all_ok else 1)
        except Exception as e:
            print("No health data available")
            sys.exit(1)


if __name__ == "__main__":
    cli()
