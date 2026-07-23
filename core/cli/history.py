"""Explicit readline/history lifecycle for the interactive CLI."""

from __future__ import annotations

import atexit
import os
import readline
from collections.abc import Sequence

DEFAULT_HISTORY_FILE = os.path.expanduser("~/.octopus_history")
DEFAULT_COMPLETIONS = (
    "1", "2", "3", "4", "5",
    "new", "scan", "history", "resume", "c2", "exit", "quit",
    "nmap", "whois", "whatweb", "curl", "dig", "sslscan", "ffuf",
    "enum4linux", "smbclient", "wpscan", "sqlmap", "nikto",
    "scrapling", "jmx2rce", "bruteforce", "ssh_session", "ssh_exec",
    "killchain", "shodan", "crack_hashes", "cpanel",
    "ad_enum", "asrep_roast", "kerberoast", "dcsync", "psexec", "wmiexec",
    "socks_proxy", "port_forward", "network_recon",
    "build_go_implant", "build_python_implant", "build_ps_stager",
    "all", "default", "help", "back",
)


class OctopusCompleter:
    """Stable tab-completion behavior from the legacy entry point."""

    def __init__(self, options: Sequence[str] | None = None) -> None:
        self.options = sorted(options or DEFAULT_COMPLETIONS)
        self.matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            self.matches = (
                [item for item in self.options if item.startswith(text.lower())]
                if text
                else list(self.options)
            )
        try:
            return self.matches[state]
        except IndexError:
            return None


def _redacted_history_entries() -> list[str]:
    from core.secrets import redact_text

    return [
        redact_text(readline.get_history_item(index), kind="readline_history")
        for index in range(1, readline.get_current_history_length() + 1)
    ]


def _write_redacted_history(history_file: str) -> None:
    entries = _redacted_history_entries()
    readline.clear_history()
    for entry in entries:
        readline.add_history(entry)
    readline.write_history_file(history_file)
    os.chmod(history_file, 0o600)


def setup_readline(
    history_file: str = DEFAULT_HISTORY_FILE,
    *,
    register_exit: bool = True,
) -> None:
    """Configure completion and redacted history only when startup requests it."""

    readline.set_completer(OctopusCompleter().complete)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n;")
    try:
        readline.read_history_file(history_file)
        readline.set_history_length(500)
        _write_redacted_history(history_file)
    except FileNotFoundError:
        pass
    if register_exit:
        atexit.register(_write_redacted_history, history_file)


__all__ = [
    "DEFAULT_COMPLETIONS",
    "DEFAULT_HISTORY_FILE",
    "OctopusCompleter",
    "setup_readline",
]
