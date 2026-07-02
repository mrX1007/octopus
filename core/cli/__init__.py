#!/usr/bin/env python3
"""
OCTOPUS CLI — Banner, helpers, Rich console, readline.

Extracted from octopus.py for cleaner architecture.
All UI primitives live here.
"""

import os
import sys
import atexit
import logging
import readline

__all__ = [
    "banner", "divider", "prompt", "success", "warn", "error", "info",
    "confirm", "run_with_spinner", "print_rich_table", "print_results_table",
    "print_reporting_sections", "setup_readline", "console", "RICH_AVAILABLE",
]

# ─── Rich Console (graceful fallback) ───
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table as RichTable
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

try:
    from config import CFG
except ImportError:
    CFG = {}

import re as _re


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner(version: str = "1.0.0"):
    """Print the OCTOPUS ASCII banner."""
    os.system("clear")
    model = CFG.get("ollama", {}).get("model", "octopus-qwen")
    print(f"""
\033[91m
    ██████╗   ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
    ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
    ██║   ██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗
    ██║   ██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
    ╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
     ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝

\033[0m
    \033[90mAutonomous Strategic AI Pentest Engine  v{version}  |  Model: {model}  |  Athena OS\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m

""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    """Print a horizontal divider with optional label."""
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    """Styled input prompt."""
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    """Print success message (green)."""
    print(f"\033[92m[+] {text}\033[0m")
    logging.info(text)


def warn(text):
    """Print warning message (yellow)."""
    print(f"\033[93m[!] {text}\033[0m")
    logging.warning(text)


def error(text):
    """Print error message (red)."""
    print(f"\033[91m[✗] {text}\033[0m")
    logging.error(text)


def info(text):
    """Print info message (blue)."""
    print(f"\033[94m[*] {text}\033[0m")
    logging.info(text)


def confirm(question: str) -> bool:
    """Ask a yes/no confirmation question."""
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


# ─────────────────────────────────────────────
# READLINE TAB COMPLETION + HISTORY
# ─────────────────────────────────────────────

_HISTORY_FILE = os.path.expanduser("~/.octopus_history")

_COMPLETIONS = [
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
]


class _OctopusCompleter:
    """Tab completer for OCTOPUS CLI."""

    def __init__(self, options=None):
        self.options = sorted(options or _COMPLETIONS)

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [o for o in self.options if o.startswith(text.lower())]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state]
        except IndexError:
            return None


def setup_readline():
    """Initialize readline with tab completion and persistent history."""
    readline.set_completer(_OctopusCompleter().complete)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n;")

    try:
        readline.read_history_file(_HISTORY_FILE)
        readline.set_history_length(500)
    except FileNotFoundError:
        pass

    atexit.register(readline.write_history_file, _HISTORY_FILE)


# ─────────────────────────────────────────────
# RICH PROGRESS HELPERS
# ─────────────────────────────────────────────

def run_with_spinner(description: str, func, *args, **kwargs):
    """Run a function with a Rich spinner. Falls back to plain output."""
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[cyan]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(description, total=None)
            return func(*args, **kwargs)
    else:
        print(f"\033[90m[*] {description}...\033[0m")
        return func(*args, **kwargs)


def print_rich_table(title: str, columns: list, rows: list):
    """Print a Rich-styled table, or plain ASCII fallback."""
    if RICH_AVAILABLE:
        table = RichTable(title=title, border_style="dim", header_style="bold cyan")
        for name, style in columns:
            table.add_column(name, style=style)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
    else:
        header = "  " + "".join(f"{name:<{max(15, len(name)+2)}}" for name, _ in columns)
        print(f"\033[96m{header}\033[0m")
        print(f"  {'─' * (len(columns) * 15)}")
        for row in rows:
            print("  " + "".join(f"{str(c):<15}" for c in row))


# ─────────────────────────────────────────────
# RESULTS TABLE
# ─────────────────────────────────────────────

def _truncate(value, limit=250):
    text = str(value or "")
    return text[:limit]


def _ports_text(group: dict) -> str:
    return ",".join(str(port) for port in (group.get("ports") or []) if port) or "n/a"


def print_reporting_sections(result: dict):
    """Print deterministic reporting blocks shared by all CLI entry points."""
    outcome = result.get("outcome_summary") or []
    if outcome:
        print(f"\n  \033[95m[ FINAL OUTCOME ]\033[0m")
        for line in outcome:
            print(f"  \033[95m  •\033[0m {_truncate(line, 300)}")

    finding_groups = result.get("finding_groups") or []
    if finding_groups:
        print(f"\n  \033[93m[ FINDING STATUS ]\033[0m")
        for group in finding_groups[:10]:
            print(
                f"  \033[93m  •\033[0m {group.get('module')} "
                f"svc={group.get('service')} ports={_ports_text(group)} "
                f"candidate={group.get('candidate')} verified={group.get('verified')} "
                f"exploited={group.get('exploited')} impact={group.get('impact_confirmed')}"
            )

    coverage = result.get("coverage") or {}
    degraded = coverage.get("degraded") or []
    checked = coverage.get("checked_but_not_confirmed") or []
    if degraded or checked:
        print(f"\n  \033[93m[ COVERAGE ]\033[0m confidence={coverage.get('confidence', 'normal')}")
        for item in degraded[:5]:
            print(f"  \033[93m  !\033[0m {item.get('tool')} {item.get('status')}: {item.get('impact')}")
        for item in checked[:8]:
            print(f"  \033[90m  -\033[0m checked: {item.get('status')}")

    attack_path = result.get("attack_path") or []
    if attack_path:
        print(f"\n  \033[95m[ ATTACK PATH ]\033[0m")
        for idx, step in enumerate(attack_path[:10], 1):
            print(
                f"  \033[95m  {idx}.\033[0m {step.get('stage')}: "
                f"{step.get('status')} - {step.get('detail')}"
            )

    remediations = result.get("remediations") or []
    if remediations:
        print(f"\n  \033[92m[ REMEDIATION ]\033[0m")
        for item in remediations[:10]:
            print(f"  \033[92m  •\033[0m {item.get('service', 'unknown')}: {_truncate(item.get('recommendation'), 240)}")


def print_results_table(result: dict):
    """Pretty table of vulnerabilities and confirmed facts."""
    vulns = result.get("vulnerabilities", [])
    facts = result.get("confirmed_facts", [])
    risk  = result.get("risk_level", "UNKNOWN")

    risk_colors = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[92m",
        "UNKNOWN":  "\033[90m",
    }
    rc = risk_colors.get(risk, "\033[0m")

    if RICH_AVAILABLE and vulns:
        table = RichTable(
            title=f"[bold]{rc}RISK: {risk}[/bold]",
            border_style="dim",
            header_style="bold red",
        )
        table.add_column("Severity", style="red", width=10)
        table.add_column("Port", width=8)
        table.add_column("Service", width=18)
        table.add_column("Vulnerability", style="white")

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for v in sorted(vulns, key=lambda x: sev_order.get(x['severity'].lower(), 9)):
            sev = v['severity'].upper()
            sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "dim")
            table.add_row(
                f"[{sev_style}]{sev}[/{sev_style}]",
                v['port'][:8],
                v['service'][:18],
                v['vuln_name'][:40],
            )
        console.print(table)
    else:
        # Plain fallback
        print(f"\n{'═'*70}")
        print(f"  {rc}RISK LEVEL: {risk}\033[0m")
        print(f"{'═'*70}")
        if vulns:
            print(f"\n  \033[91m[ VULNERABILITIES FOUND ]\033[0m")
            print(f"  {'─'*66}")
            print(f"  {'SEVERITY':<12} {'PORT':<10} {'SERVICE':<20} {'NAME'}")
            print(f"  {'─'*66}")
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            for v in sorted(vulns, key=lambda x: sev_order.get(x['severity'].lower(), 9)):
                sev = v['severity'].upper()
                sc  = risk_colors.get(sev, "\033[0m")
                print(f"  {sc}{sev:<12}\033[0m {v['port'][:8]:<10} {v['service'][:18]:<20} {v['vuln_name'][:30]}")
            print(f"  {'─'*66}")
        else:
            print(f"  \033[92m[ No vulnerabilities parsed ]\033[0m")

    print_reporting_sections(result)

    if facts:
        print(f"\n  \033[96m[ CONFIRMED INTELLIGENCE ]\033[0m")
        for f in facts:
            clean = _re.sub(r'<thought>.*?</thought>', '', str(f), flags=_re.DOTALL).strip()
            clean_lines = []
            for line in clean.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith('[TOOL:') and not stripped.startswith('[DELEGATE:'):
                    clean_lines.append(stripped)
            clean = ' '.join(clean_lines).strip()
            if clean and len(clean) > 10:
                print(f"  \033[96m  ✓\033[0m {clean[:250]}")

    print(f"\n{'═'*70}\n")
