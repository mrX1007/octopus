#!/usr/bin/env python3
"""
Shared tool execution utilities used by all tools sub-modules.
Breaks circular dependency between runner ↔ exploit_tools ↔ recon_tools.
"""

import contextlib
import dataclasses
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone

# ANSI COLORS
C_GREY    = "\033[90m"
C_RESET   = "\033[0m"
C_CYAN    = "\033[96m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"

# TOOL AVAILABILITY CACHE
_TOOL_AVAILABLE = {}


def is_tool_available(name: str) -> bool:
    """Check if a system tool is installed. Results are cached."""
    if name not in _TOOL_AVAILABLE:
        _TOOL_AVAILABLE[name] = shutil.which(name) is not None
    return _TOOL_AVAILABLE[name]


# TOOL RESULT DATACLASS
@dataclasses.dataclass
class ToolResult:
    """Structured tool execution result."""
    tool_name: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    timestamp: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        compare=False,
    )

    def __str__(self):
        return self.stdout

    def __repr__(self):
        return f"ToolResult({self.tool_name!r}, len={len(self.stdout)})"

    def __eq__(self, other):
        if isinstance(other, str):
            return self.stdout == other
        if isinstance(other, ToolResult):
            return (
                self.tool_name,
                self.command,
                self.stdout,
                self.stderr,
                self.exit_code,
                self.duration,
            ) == (
                other.tool_name,
                other.command,
                other.stdout,
                other.stderr,
                other.exit_code,
                other.duration,
            )
        return NotImplemented

    def __contains__(self, item):
        return item in self.stdout

    def __len__(self):
        return len(self.stdout)

    def __bool__(self):
        return bool(self.stdout.strip())

    def __iter__(self):
        return iter(self.stdout)

    def __getitem__(self, key):
        return self.stdout[key]

    def __add__(self, other):
        return self.stdout + str(other)

    def __radd__(self, other):
        return str(other) + self.stdout

    def lower(self):
        return self.stdout.lower()

    def __getattr__(self, name):
        if not name.startswith("_"):
            return getattr(self.stdout, name)
        raise AttributeError(name)


# CONFIG LOADER
def get_tool_config(tool_name: str) -> dict:
    """Get tool-specific config from config.yaml."""
    try:
        from config import CFG
        return CFG.get("tools", {}).get(tool_name, {})
    except ImportError:
        return {}


# FORMAT HELPER
def _fmt_elapsed(secs: int) -> str:
    """Format seconds as compact human readable for heartbeat."""
    if secs < 120:
        return f"{secs}s"
    elif secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    else:
        h = secs // 3600
        m = (secs % 3600) // 60
        return f"{h}h{m:02d}m"


# BASE RUNNER
def _terminate_process_tree(
    proc: subprocess.Popen,
    *,
    grace_seconds: float = 0.75,
) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.terminate()
    try:
        proc.wait(timeout=max(0.0, grace_seconds))
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()


def _bounded_process_output(value: str, max_output_bytes: int) -> str:
    encoded = str(value or "").encode("utf-8", "replace")
    if len(encoded) <= max_output_bytes:
        return str(value or "")
    marker = f"\n[OUTPUT LIMIT] truncated at {max_output_bytes} bytes"
    marker_bytes = marker.encode("utf-8")
    kept = encoded[:max(0, max_output_bytes - len(marker_bytes))]
    return kept.decode("utf-8", "ignore") + marker


def run_tool(command: list, timeout: int = 120) -> str:
    """Execute argv with bounded lifetime/output and process-tree cleanup."""

    if not command:
        return "[!] Empty command."

    from core.execution import (
        ExecutionCancelled,
        current_execution_context,
        redact_sensitive_command,
    )

    context = current_execution_context()
    tool_bin = str(command[0])
    if not shutil.which(tool_bin):
        return f"[!] Tool not found: {tool_bin} — install it with: sudo pacman -S {tool_bin}"
    try:
        requested_timeout = int(timeout)
    except (TypeError, ValueError):
        requested_timeout = 120
    effective_timeout = min(
        context.max_runtime_seconds,
        requested_timeout if requested_timeout > 0 else context.max_runtime_seconds,
    )
    effective_timeout = max(1, int(effective_timeout))
    heartbeat_interval = 60 if effective_timeout > 300 else 30
    max_output_bytes = max(1024, int(context.max_output_bytes))

    lines: list[str] = []
    output_bytes = 0
    output_limited = False
    cancel_reason = ""
    start_time = time.monotonic()
    last_heartbeat = 0
    last_hydra_status = [None]
    proc = None
    reader = None

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=(os.name == "posix"),
        )

        def _read_output() -> None:
            nonlocal output_bytes, output_limited
            if proc.stdout is None:
                return
            for raw_line in proc.stdout:
                line = raw_line.rstrip("\n")
                encoded = (line + "\n").encode("utf-8", "replace")
                remaining = max_output_bytes - output_bytes
                if len(encoded) > remaining:
                    if remaining > 0:
                        lines.append(encoded[:remaining].decode("utf-8", "ignore").rstrip("\n"))
                        output_bytes += remaining
                    output_limited = True
                    _terminate_process_tree(proc)
                    break
                output_bytes += len(encoded)
                lines.append(line)
                safe_line = redact_sensitive_command(line)
                if tool_bin == "hydra" and "[STATUS]" in line:
                    last_hydra_status[0] = safe_line.strip()
                    elapsed = int(time.monotonic() - start_time)
                    print(f"      [{elapsed}s] {safe_line[:140]}")
                    continue
                if tool_bin == "nuclei":
                    rendered = _nuclei_live_summary(line)
                    if rendered:
                        elapsed = int(time.monotonic() - start_time)
                        print(f"      [{elapsed}s] {redact_sensitive_command(rendered)[:160]}")
                    continue
                if tool_bin in {
                    "hydra", "nmap", "masscan", "nikto", "sqlmap", "gobuster", "ffuf",
                } and any(
                    keyword in line.lower()
                    for keyword in (
                        "host:", "[22]", "[80]", "valid", "login:", "found",
                        "open", "discovered", "password", "success", "[ssh]",
                        "ports", "vuln", "error", "complete",
                        "1 of 1 target completed", "successfully completed",
                    )
                ):
                    elapsed = int(time.monotonic() - start_time)
                    print(f"      [{elapsed}s] {safe_line[:140]}")

        reader = threading.Thread(target=_read_output, daemon=True)
        reader.start()

        while reader.is_alive():
            reader.join(timeout=1)
            elapsed_float = time.monotonic() - start_time
            elapsed = int(elapsed_float)
            if context.cancellation.cancelled:
                cancel_reason = context.cancellation.reason_code
                _terminate_process_tree(proc)
                reader.join(timeout=2)
                lines.append(f"[CANCELLED] {cancel_reason}")
                break
            if elapsed_float >= effective_timeout:
                _terminate_process_tree(proc)
                reader.join(timeout=2)
                lines.append(
                    f"[PARTIAL OUTPUT - {tool_bin} - {len(lines)} lines captured before timeout]"
                )
                lines.append(f"[TIMEOUT] {tool_bin} killed after {effective_timeout}s")
                print(f"      [TIMEOUT] {tool_bin} killed after {effective_timeout}s")
                break
            if reader.is_alive() and elapsed - last_heartbeat >= heartbeat_interval:
                last_heartbeat = elapsed
                if tool_bin == "hydra" and last_hydra_status[0]:
                    print(
                        f"      [♻ hydra {_fmt_elapsed(elapsed)} / "
                        f"{_fmt_elapsed(effective_timeout)} max]"
                    )
                else:
                    print(
                        f"      [♻ {tool_bin} running... {_fmt_elapsed(elapsed)} / "
                        f"{_fmt_elapsed(effective_timeout)} max]"
                    )

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            proc.wait(timeout=5)
        if proc.stdout is not None:
            proc.stdout.close()
    except KeyboardInterrupt as exc:
        context.cancellation.cancel("keyboard_interrupt")
        if proc is not None:
            _terminate_process_tree(proc)
        if reader is not None:
            reader.join(timeout=2)
        raise ExecutionCancelled(
            context.cancellation.reason_code,
            stdout=_bounded_process_output("\n".join(lines), max_output_bytes),
            returncode=proc.returncode if proc is not None else None,
        ) from exc
    except Exception as exc:
        if proc is not None:
            _terminate_process_tree(proc)
        safe_error = redact_sensitive_command(str(exc))[:1024]
        return f"[!] Unexpected error running {tool_bin}: {type(exc).__name__}: {safe_error}"

    if output_limited:
        lines.append(f"[OUTPUT LIMIT] process killed at {max_output_bytes} bytes")
    output = _bounded_process_output("\n".join(lines), max_output_bytes)
    if cancel_reason:
        raise ExecutionCancelled(
            cancel_reason,
            stdout=output,
            returncode=proc.returncode if proc is not None else None,
        )
    if not output.strip():
        return f"[!] {tool_bin} returned no output."
    return output


def _nuclei_live_summary(line: str) -> str:
    raw = (line or "").strip()
    if not raw:
        return ""
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        lowered = raw.lower()
        if any(marker in lowered for marker in ("error", "warn", "critical", "high", "medium", "low", "info")):
            return raw
        return ""
    info = data.get("info") or {}
    severity = str(info.get("severity") or data.get("severity") or "").lower()
    template = data.get("template-id") or data.get("template") or ""
    name = info.get("name") or ""
    matched = data.get("matched-at") or data.get("host") or data.get("ip") or ""
    if not any((severity, template, name, matched)):
        return ""
    return f"nuclei {severity or 'info'} {template or name} {matched}".strip()
