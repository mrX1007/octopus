#!/usr/bin/env python3
"""
Shared tool execution utilities used by all tools sub-modules.
Breaks circular dependency between runner ↔ exploit_tools ↔ recon_tools.
"""

import subprocess
import shutil
import time
import threading
import dataclasses

# ─────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────
C_GREY    = "\033[90m"
C_RESET   = "\033[0m"
C_CYAN    = "\033[96m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"

# ─────────────────────────────────────────────
# TOOL AVAILABILITY CACHE
# ─────────────────────────────────────────────
_TOOL_AVAILABLE = {}


def is_tool_available(name: str) -> bool:
    """Check if a system tool is installed. Results are cached."""
    if name not in _TOOL_AVAILABLE:
        _TOOL_AVAILABLE[name] = shutil.which(name) is not None
    return _TOOL_AVAILABLE[name]


# ─────────────────────────────────────────────
# TOOL RESULT DATACLASS
# ─────────────────────────────────────────────
@dataclasses.dataclass
class ToolResult:
    """Structured tool execution result."""
    tool_name: str = ""
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0

    def __str__(self):
        return self.stdout

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


# ─────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────
def get_tool_config(tool_name: str) -> dict:
    """Get tool-specific config from config.yaml."""
    try:
        from config import CFG
        return CFG.get("tools", {}).get(tool_name, {})
    except ImportError:
        return {}


# ─────────────────────────────────────────────
# FORMAT HELPER
# ─────────────────────────────────────────────
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


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────
def run_tool(command: list, timeout: int = 120) -> str:
    """
    Execute a shell command with LIVE output streaming.
    v3.7: Dynamic heartbeat, unlimited timeout support, hydra progress parsing.
      - timeout=0 means UNLIMITED — the tool runs until it finishes naturally.
      - Heartbeat interval scales: <5min→30s, 5-30min→60s, >30min→120s
      - Hydra [STATUS] lines are shown as real-time progress.
    Returns combined output, truncated to last 200 lines for AI context.
    """
    if not command:
        return "[!] Empty command."

    tool_bin = command[0]
    if not shutil.which(tool_bin):
        return f"[!] Tool not found: {tool_bin} — install it with: sudo pacman -S {tool_bin}"

    lines = []
    start_time = time.time()
    unlimited = (timeout == 0)

    # Dynamic heartbeat interval based on expected duration
    if unlimited or timeout > 1800:
        heartbeat_interval = 120
    elif timeout > 300:
        heartbeat_interval = 60
    else:
        heartbeat_interval = 30

    _last_hydra_status = [None]

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        def _read_output():
            for line in proc.stdout:
                line = line.rstrip('\n')
                lines.append(line)
                if tool_bin == "hydra" and "[STATUS]" in line:
                    _last_hydra_status[0] = line.strip()
                    elapsed = int(time.time() - start_time)
                    print(f"      [{elapsed}s] {line[:140]}")
                    continue
                if tool_bin in ("hydra", "nmap", "masscan", "nikto", "sqlmap", "gobuster", "ffuf"):
                    if any(kw in line.lower() for kw in [
                        "host:", "[22]", "[80]", "valid", "login:", "found",
                        "open", "discovered", "password", "success", "[ssh]",
                        "ports", "vuln", "error", "complete",
                        "1 of 1 target completed", "successfully completed"
                    ]):
                        elapsed = int(time.time() - start_time)
                        print(f"      [{elapsed}s] {line[:140]}")

        reader = threading.Thread(target=_read_output, daemon=True)
        reader.start()

        while reader.is_alive():
            reader.join(timeout=heartbeat_interval)
            elapsed = int(time.time() - start_time)
            if not unlimited and elapsed > timeout:
                proc.kill()
                proc.wait()
                lines.append(f"[!] Timed out after {timeout}s")
                print(f"      [TIMEOUT] {tool_bin} killed after {timeout}s")
                break
            if reader.is_alive():
                if tool_bin == "hydra" and _last_hydra_status[0]:
                    elapsed_str = _fmt_elapsed(elapsed)
                    if unlimited:
                        print(f"      [♻ hydra {elapsed_str} | no time limit]")
                    else:
                        print(f"      [♻ hydra {elapsed_str} / {_fmt_elapsed(timeout)} max]")
                else:
                    if unlimited:
                        print(f"      [♻ {tool_bin} running... {_fmt_elapsed(elapsed)} | no time limit]")
                    else:
                        print(f"      [♻ {tool_bin} running... {_fmt_elapsed(elapsed)} / {_fmt_elapsed(timeout)} max]")

        proc.wait(timeout=5)

    except Exception as e:
        return f"[!] Unexpected error running {tool_bin}: {e}"

    output = "\n".join(lines)
    if not output.strip():
        return f"[!] {tool_bin} returned no output."

    if len(lines) > 200:
        output = f"[... truncated {len(lines) - 200} lines ...]\n" + "\n".join(lines[-200:])

    return output
