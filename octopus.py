#!/usr/bin/env python3
"""
OCTOPUS - octopus.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python octopus.py
"""

__version__ = "1.0.0"

try:
    from export import export_menu
except ImportError as _export_import_error:
    def export_menu(*_args, _err=_export_import_error, **_kwargs):
        print(f"[!] Export module unavailable: {_err}")
import os
import re as _re
import sys
import glob
import json
import signal
import subprocess
import atexit
import logging
import readline
from datetime import datetime

# ─── Import CLI primitives from core/cli ───
try:
    from core.cli import (
        console, RICH_AVAILABLE as _RICH,
        run_with_spinner, print_rich_table, print_reporting_sections as _print_reporting_sections,
    )
except ImportError:
    _RICH = False
    console = None
    def _print_reporting_sections(_result):
        return None

try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table as RichTable
except ImportError:
    Progress = SpinnerColumn = TextColumn = TimeElapsedColumn = RichTable = None

try:
    from db import (
        get_connection,
        create_session,
        update_session_status,
        save_vulnerability,
        save_fix,
        save_exploit,
        save_summary,
        get_all_history,
        get_session,
        get_vulnerabilities,
        get_fixes,
        get_exploits,
        edit_vulnerability,
        edit_fix,
        edit_exploit,
        edit_summary_risk,
        delete_vulnerability,
        delete_exploit,
        delete_fix,
        delete_full_session,
        print_history,
        print_session
    )
except ImportError as _db_import_error:
    def _db_unavailable(*_args, _err=_db_import_error, **_kwargs):
        raise RuntimeError(f"Database module unavailable: {_err}")
    get_connection = create_session = update_session_status = _db_unavailable
    save_vulnerability = save_fix = save_exploit = save_summary = _db_unavailable
    get_all_history = get_session = get_vulnerabilities = get_fixes = get_exploits = _db_unavailable
    edit_vulnerability = edit_fix = edit_exploit = edit_summary_risk = _db_unavailable
    delete_vulnerability = delete_exploit = delete_fix = delete_full_session = _db_unavailable
    print_history = print_session = _db_unavailable
from tools import interactive_tool_run, format_recon_for_llm, run_default_recon
from core.ai.pipeline import AIPipeline
from core.ai.trace_report import TraceReporter
from core.ai.fact_store import FactStore

# Load config
try:
    from config import CFG
except ImportError:
    CFG = {"paths": {"reports": "~/OCTOPUS/reports", "logs": "~/OCTOPUS/logs"}}


# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────

def _setup_logging():
    """Set up dual logging: file + console-critical only."""
    log_dir = os.path.expanduser(CFG.get("paths", {}).get("logs", "~/OCTOPUS/logs"))
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"octopus_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
        ]
    )
    logging.info(f"OCTOPUS v{__version__} started")
    logging.info(f"Log file: {log_file}")
    return log_file


# ─────────────────────────────────────────────
# SIGINT HANDLER (graceful Ctrl+C)
# ─────────────────────────────────────────────

_current_sl_no = None  # track active scan for checkpoint on interrupt
_supervisor = None     # set in __main__ block

def _sigint_handler(signum, frame):
    """Handle Ctrl+C gracefully — save checkpoint if mid-scan."""
    print(f"\n\n\033[93m[!] Interrupted (Ctrl+C). Cleaning up...\033[0m")
    logging.warning("Interrupted by user (SIGINT)")

    if _current_sl_no:
        update_session_status(_current_sl_no, "interrupted")
        print(f"\033[93m[!] Session SL# {_current_sl_no} marked as 'interrupted'.\033[0m")
        print(f"\033[93m[!] Checkpoint may be saved at /tmp/octopus_checkpoint_{_current_sl_no}.json\033[0m")
        logging.info(f"Session SL# {_current_sl_no} interrupted")

    # Clean supervisor shutdown (removes PID/lock files)
    if _supervisor:
        try:
            _supervisor.stop()
        except Exception as _exc:
            logging.debug(f"Suppressed in octopus.py: {_exc}")

    print("\033[91m[*] Shutting down Octopus.\033[0m\n")
    # Use os._exit to avoid threading atexit crash — sys.exit(130) conflicts
    # with concurrent.futures thread pool join during shutdown
    os._exit(130)

signal.signal(signal.SIGINT, _sigint_handler)


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    os.system("clear")
    print(f"""
\033[91m
    ██████╗   ██████╗████████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
    ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗██║   ██║██╔════╝
    ██║   ██║██║        ██║   ██║   ██║██████╔╝██║   ██║███████╗
    ██║   ██║██║        ██║   ██║   ██║██╔═══╝ ██║   ██║╚════██║
    ╚██████╔╝╚██████╗   ██║   ╚██████╔╝██║     ╚██████╔╝███████║
     ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝

\033[0m
    \033[90mAutonomous Strategic AI Pentest Engine  v{__version__}  |  Model: {CFG.get('ollama', {}).get('model', 'octopus-qwen')}  |  Athena OS\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m

""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    print(f"\033[92m[+] {text}\033[0m")
    logging.info(text)


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")
    logging.warning(text)


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")
    logging.error(text)


def info(text):
    print(f"\033[94m[*] {text}\033[0m")
    logging.info(text)


def _save_trace_report(pipeline: AIPipeline, scan_id: str, target: str) -> None:
    try:
        log_dir = os.path.expanduser(CFG.get("paths", {}).get("logs", "~/OCTOPUS/logs"))
        os.makedirs(log_dir, exist_ok=True)
        report = pipeline.trace_report(scan_id, target)
        base = os.path.join(log_dir, f"trace_{scan_id}")
        with open(base + ".json", "w", encoding="utf-8") as fh:
            fh.write(pipeline.trace_reporter.to_json(report))
        with open(base + ".txt", "w", encoding="utf-8") as fh:
            fh.write(pipeline.trace_reporter.to_text(report))
        info(f"Trace report saved: {base}.txt")
    except Exception as exc:
        warn(f"Trace report save failed: {str(exc)[:160]}")


def _print_trace_report_cli(scan_id: str, target: str, fmt: str = "text") -> None:
    store = FactStore()
    reporter = TraceReporter(store)
    try:
        pipeline = AIPipeline()
        context = pipeline.context_builder.build_context(scan_id, target)
    except Exception:
        context = {}
    report = reporter.build(scan_id, target, context=context)
    if fmt == "json":
        print(reporter.to_json(report))
    else:
        print(reporter.to_text(report))


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


# ─────────────────────────────────────────────
# READLINE TAB COMPLETION + HISTORY
# ─────────────────────────────────────────────

_HISTORY_FILE = os.path.expanduser("~/.octopus_history")

# Menu commands for tab completion
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


def _setup_readline():
    """Initialize readline with tab completion and persistent history."""
    readline.set_completer(_OctopusCompleter().complete)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n;")

    # Load history
    try:
        readline.read_history_file(_HISTORY_FILE)
        readline.set_history_length(500)
    except FileNotFoundError:
        pass

    # Save history on exit
    atexit.register(readline.write_history_file, _HISTORY_FILE)


# ─────────────────────────────────────────────
# RICH PROGRESS HELPERS
# ─────────────────────────────────────────────

def run_with_spinner(description: str, func, *args, **kwargs):
    """Run a function with a Rich spinner. Falls back to plain output.

    Args:
        description: What's being done (shown next to spinner).
        func: The function to run.
        *args, **kwargs: Passed to func.

    Returns:
        Whatever func returns.
    """
    if _RICH:
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
    """Print a Rich-styled table, or plain ASCII if Rich unavailable.

    Args:
        title: Table title.
        columns: List of (name, style) tuples.
        rows: List of row tuples.
    """
    if _RICH:
        table = RichTable(title=title, border_style="dim", header_style="bold cyan")
        for name, style in columns:
            table.add_column(name, style=style)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
    else:
        # Plain ASCII fallback
        header = "  " + "".join(f"{name:<{max(15, len(name)+2)}}" for name, _ in columns)
        print(f"\033[96m{header}\033[0m")
        print(f"  {'─' * (len(columns) * 15)}")
        for row in rows:
            print("  " + "".join(f"{str(c):<15}" for c in row))


def print_results_table(result: dict):
    """Pretty ASCII table of vulnerabilities and confirmed facts."""
    vulns = result.get("vulnerabilities", [])
    facts = result.get("confirmed_facts", [])
    risk  = result.get("risk_level", "UNKNOWN")

    risk_colors = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[91m",  # red
        "MEDIUM":   "\033[93m",  # yellow
        "LOW":      "\033[92m",  # green
        "UNKNOWN":  "\033[90m",  # grey
    }
    rc = risk_colors.get(risk, "\033[0m")

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
            name  = v['vuln_name'][:30]
            port  = v['port'][:8]
            svc   = v['service'][:18]
            print(f"  {sc}{sev:<12}\033[0m {port:<10} {svc:<20} {name}")
        print(f"  {'─'*66}")
    else:
        print(f"  \033[92m[ No vulnerabilities parsed — check full AI response above ]\033[0m")

    _print_reporting_sections(result)

    if facts:
        print(f"\n  \033[96m[ CONFIRMED INTELLIGENCE (from real tool output) ]\033[0m")
        for f in facts:
            # v8.1: Strip <thought> tags and raw [TOOL:] lines from display
            clean = _re.sub(r'<thought>.*?</thought>', '', str(f), flags=_re.DOTALL).strip()
            # Remove lines that are just tool tags
            clean_lines = []
            for line in clean.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith('[TOOL:') and not stripped.startswith('[DELEGATE:') and not stripped.startswith('[SUMMARY:'):
                    clean_lines.append(stripped)
            clean = ' '.join(clean_lines).strip()
            if clean and len(clean) > 10:
                print(f"  \033[96m  ✓\033[0m {clean[:250]}")

    print(f"\n{'═'*70}\n")


# ─────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────

def preflight_checks() -> bool:
    """Verify critical dependencies before starting.
    v8.0: Shodan, hashcat, john checks."""
    import shutil
    import requests
    all_ok = True

    divider("PRE-FLIGHT CHECKS")

    # 0. .env file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, ".env")
    if os.path.isfile(env_file):
        success(".env: loaded")
    else:
        warn(".env: not found — copy .env.example to .env and add API keys")

    # 1. MariaDB (non-critical — tool works without DB, results just won't persist)
    try:
        conn = get_connection()
        conn.close()
        success("MariaDB: connected")
    except Exception as e:
        warn(f"MariaDB: {e}")
        warn("  Fix: sudo systemctl start mariadb")
        warn("  Or check credentials in .env / config.yaml (OCTOPUS_DB_USER / OCTOPUS_DB_PASS / OCTOPUS_DB_NAME)")
        warn("  Results will not be saved to DB until connection is fixed.")

    # 2. Ollama
    ollama_url = CFG.get("ollama", {}).get("url", "http://localhost:11434/api/generate")
    base_url = ollama_url.replace("/api/generate", "")
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            model_name = CFG.get("ollama", {}).get("model", "octopus-qwen")
            found = any(model_name in m for m in models)
            if found:
                success(f"Ollama: model '{model_name}' ready")
            else:
                warn(f"Ollama: running but model '{model_name}' not found. Available: {', '.join(models[:5])}")
                warn(f"Fix: ollama create {model_name} -f Modelfile")
        else:
            warn(f"Ollama: unexpected status {resp.status_code}")
    except requests.exceptions.ConnectionError:
        error("Ollama: not running")
        error("Fix: ollama serve")
        all_ok = False
    except Exception as e:
        warn(f"Ollama: check failed -- {e}")

    # 3. Core tools
    core_tools = ["nmap", "curl", "whois"]
    for tool in core_tools:
        if shutil.which(tool):
            success(f"{tool}: found")
        else:
            warn(f"{tool}: NOT found (install with: sudo pacman -S {tool})")

    # 4. Wordlists
    try:
        from config import find_wordlist
        pw = find_wordlist("passwords")
        if pw:
            success(f"Password wordlist: {os.path.basename(pw)}")
        else:
            warn("Password wordlist: NONE found -- bruteforce will fail")

        wd = find_wordlist("web_dirs")
        if wd:
            success(f"Web fuzzing wordlist: {os.path.basename(wd)}")
        else:
            warn("Web fuzzing wordlist: NONE found -- ffuf will fail")
    except ImportError:
        warn("Config module not available -- wordlist check skipped")

    # 5. Scrapling
    try:
        import scrapling
        success(f"Scrapling: available (StealthyFetcher for JS pages)")
    except ImportError:
        warn("Scrapling: NOT installed -- JS page fetching disabled. Fix: pip install scrapling")

    # 6. jmx2rce
    if shutil.which("jmx2rce"):
        success("jmx2rce: available (Tomcat JMX Proxy -> RCE)")
    else:
        warn("jmx2rce: NOT installed")

    # 7. nuclei
    if shutil.which("nuclei"):
        success("nuclei: available (template-based scanning)")
    else:
        warn("nuclei: NOT installed")

    # 8. Shodan (v8.0)
    try:
        import shodan as _shodan_lib
        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        if shodan_key and shodan_key != "YOUR_KEY_HERE":
            success(f"Shodan: API key configured")
        else:
            warn("Shodan: library installed but no API key in .env")
    except ImportError:
        warn("Shodan: NOT installed. Fix: pip install shodan")

    # 9. Hash cracking tools (v8.0)
    if shutil.which("hashcat"):
        success("hashcat: found (GPU cracking)")
    else:
        warn("hashcat: NOT found -- GPU hash cracking disabled")
    if shutil.which("john"):
        success("john: found (CPU cracking)")
    else:
        warn("john: NOT found")

    divider()
    return all_ok


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def new_scan():
    global _current_sl_no
    divider("NEW SCAN")

    print(f"  \033[96m[1]\033[0m  Direct IP / Domain")
    print(f"  \033[95m[2]\033[0m  Shodan Discovery")
    divider()

    mode = prompt("scan mode> ")

    if mode == "1":
        _new_scan_direct()
    elif mode == "2":
        _new_scan_shodan()
    else:
        warn("Invalid choice.")


def _new_scan_direct():
    """Original direct IP/domain scan path."""
    global _current_sl_no
    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    # create session in history table first
    sl_no = create_session(target)
    _current_sl_no = sl_no
    success(f"Session created -- SL# {sl_no}")
    logging.info(f"New scan started: target={target}, sl_no={sl_no}")
    scan_start = datetime.now()

    # run recon tools
    divider("RECON")
    info("Choose recon tools to run:")
    raw_scan = interactive_tool_run(target)

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        _current_sl_no = None
        return

    # send to AI -- pass sl_no for checkpoint support
    divider("AI ANALYSIS")
    pipeline = AIPipeline()
    state = pipeline.run_scan(str(sl_no), target, raw_scan=raw_scan)
    _save_trace_report(pipeline, str(sl_no), target)
    result = _adapt_state_to_result(state, pipeline.fact_store, str(sl_no), target, raw_scan)

    # Calculate duration
    duration = datetime.now() - scan_start
    duration_str = str(duration).split('.')[0]  # HH:MM:SS

    update_session_status(sl_no, "complete")
    _save_and_show_results(sl_no, result, duration_str)
    _current_sl_no = None
    logging.info(f"Scan complete: sl_no={sl_no}, risk={result['risk_level']}, duration={duration_str}")


# ─────────────────────────────────────────────
# v8.1: SHODAN DISCOVERY SCAN
# ─────────────────────────────────────────────

def _new_scan_shodan():
    """Shodan Discovery: flexible search → target list → auto-pipeline."""
    global _current_sl_no

    print(f"\n  \033[95m{'=' * 60}\033[0m")
    print(f"  \033[95m    SHODAN DISCOVERY ENGINE v8.1\033[0m")
    print(f"  \033[95m{'=' * 60}\033[0m")

    try:
        from shodan_module import ShodanRecon
    except ImportError:
        error("shodan_module.py not found. Install: pip install shodan")
        return

    sr = ShodanRecon()
    if not sr.api:
        error("Shodan API not configured. Set SHODAN_API_KEY in .env")
        return

    # ── Search builder ──
    print(f"\n  \033[96m[ SEARCH BUILDER ]\033[0m")
    print(f"  \033[90mBuild your query step by step, or enter a raw dork.\033[0m")
    print()
    print(f"  \033[92m[1]\033[0m  By port            \033[90m(e.g. 22, 3389, 8080)\033[0m")
    print(f"  \033[92m[2]\033[0m  By service/product  \033[90m(e.g. Apache, nginx, OpenSSH)\033[0m")
    print(f"  \033[92m[3]\033[0m  By vulnerability    \033[90m(e.g. CVE-2021-44228)\033[0m")
    print(f"  \033[92m[4]\033[0m  By subnet/range     \033[90m(e.g. 83.166.241.0/24)\033[0m")
    print(f"  \033[92m[5]\033[0m  By organization     \033[90m(e.g. org:\"Google\")\033[0m")
    print(f"  \033[92m[6]\033[0m  By country + port   \033[90m(e.g. country:RU port:22)\033[0m")
    print(f"  \033[92m[7]\033[0m  By tag/label        \033[90m(e.g. tag:ics, tag:webcam)\033[0m")
    print(f"  \033[92m[8]\033[0m  Raw dork            \033[90m(free-form Shodan query)\033[0m")
    print(f"  \033[92m[9]\033[0m  Saved results       \033[90m(load from DB)\033[0m")
    divider()

    mode = prompt("shodan> ")
    query = ""

    if mode == "1":
        port = prompt("  Port(s) [comma-separated, e.g. 22,80,443]: ")
        country = prompt("  Country code [optional, e.g. RU, US, DE]: ").strip()
        if not port:
            warn("No port entered."); return
        # Build multi-port query
        ports = [p.strip() for p in port.split(",") if p.strip()]
        if len(ports) == 1:
            query = f"port:{ports[0]}"
        else:
            query = " ".join(f"port:{p}" for p in ports)
        if country:
            query += f" country:{country.upper()}"

    elif mode == "2":
        product = prompt("  Service/product name: ")
        if not product:
            warn("No service entered."); return
        version = prompt("  Version [optional]: ").strip()
        country = prompt("  Country code [optional]: ").strip()
        query = f'product:"{product}"'
        if version:
            query += f' version:"{version}"'
        if country:
            query += f" country:{country.upper()}"

    elif mode == "3":
        cve = prompt("  CVE ID (e.g. CVE-2021-44228): ")
        if not cve:
            warn("No CVE entered."); return
        query = f"vuln:{cve}"

    elif mode == "4":
        cidr = prompt("  CIDR range (e.g. 83.166.241.0/24): ")
        if not cidr:
            warn("No range entered."); return
        query = f"net:{cidr}" if not cidr.startswith("net:") else cidr

    elif mode == "5":
        org = prompt("  Organization name: ")
        if not org:
            warn("No org entered."); return
        query = f'org:"{org}"'

    elif mode == "6":
        country = prompt("  Country code (RU, US, DE...): ")
        port = prompt("  Port: ")
        if not country or not port:
            warn("Need both country and port."); return
        query = f"country:{country.upper()} port:{port}"

    elif mode == "7":
        tag = prompt("  Tag (ics, webcam, scada, vpn...): ")
        if not tag:
            warn("No tag entered."); return
        query = f"tag:{tag}"

    elif mode == "8":
        query = prompt("  Raw Shodan dork: ")
        if not query:
            warn("No query entered."); return

    elif mode == "9":
        _shodan_load_saved(sr)
        return

    else:
        warn("Invalid choice.")
        return

    # ── Optional filters ──
    print(f"\n  \033[96m[ OPTIONAL FILTERS ]\033[0m")
    extra_os = prompt("  OS filter [optional, e.g. Linux, Windows]: ").strip()
    extra_before = prompt("  Updated before [optional, e.g. 2025-01-01]: ").strip()
    extra_after = prompt("  Updated after [optional, e.g. 2024-01-01]: ").strip()
    max_results = prompt("  Max results [default: 100]: ").strip()

    if extra_os:
        query += f' os:"{extra_os}"'
    if extra_before:
        query += f" before:{extra_before}"
    if extra_after:
        query += f" after:{extra_after}"

    max_res = int(max_results) if max_results.isdigit() else 100

    # ── Execute search ──
    print(f"\n  \033[95m[QUERY]\033[0m {query}")
    print(f"  \033[95m[LIMIT]\033[0m {max_res} results")
    divider()

    results = sr.search(query, max_results=max_res)

    if results.get("error") or not results.get("matches"):
        error(f"No results: {results.get('error', 'empty')}")
        return

    targets = sr.format_for_pipeline(results)
    total = results.get("total", len(targets))

    # ── Display results ──
    print(f"\n  \033[92m[ FOUND: {total} total, showing {len(targets)} unique hosts ]\033[0m")
    print(f"  {'─' * 70}")
    print(f"  {'#':<4} {'IP':<18} {'PORTS':<25} {'ORG':<20} {'CVEs'}")
    print(f"  {'─' * 70}")

    for idx, t in enumerate(targets[:50], 1):
        ip = t["ip"][:16]
        ports = ",".join(str(p) for p in t["ports"][:8])
        org = (t.get("org") or "")[:18]
        vuln_count = len(t.get("vulns", []))
        vuln_tag = f"\033[91m{vuln_count} CVEs\033[0m" if vuln_count else "\033[90m-\033[0m"
        print(f"  {idx:<4} {ip:<18} {ports:<25} {org:<20} {vuln_tag}")

    print(f"  {'─' * 70}")

    # ── Action menu ──
    print(f"\n  \033[96m[ ACTIONS ]\033[0m")
    print(f"  \033[92m[1]\033[0m  Scan ALL targets (auto-pipeline)")
    print(f"  \033[92m[2]\033[0m  Select targets by # (e.g. 1,3,5-10)")
    print(f"  \033[92m[3]\033[0m  Filter: only hosts with CVEs")
    print(f"  \033[92m[4]\033[0m  Filter: only hosts with specific port")
    print(f"  \033[92m[5]\033[0m  View detailed info on one host")
    print(f"  \033[92m[6]\033[0m  Save results only (scan later)")
    print(f"  \033[92m[7]\033[0m  New search")
    print(f"  \033[91m[0]\033[0m  Back to menu")
    divider()

    action = prompt("action> ")

    if action == "0":
        return

    # Determine selected targets
    selected = []

    if action == "1":
        selected = targets[:50]

    elif action == "2":
        sel_str = prompt("  Enter #s (e.g. 1,3,5-10): ")
        selected = _parse_selection(sel_str, targets)

    elif action == "3":
        selected = [t for t in targets if t.get("vulns")]
        if not selected:
            warn("No hosts with known CVEs.")
            return
        success(f"Filtered: {len(selected)} hosts with CVEs")

    elif action == "4":
        filter_port = prompt("  Port to filter by: ")
        if filter_port and filter_port.isdigit():
            fp = int(filter_port)
            selected = [t for t in targets if fp in t.get("ports", [])]
            if not selected:
                warn(f"No hosts with port {fp}.")
                return
            success(f"Filtered: {len(selected)} hosts with port {fp}")

    elif action == "5":
        num = prompt("  Host # to view: ")
        if num and num.isdigit():
            idx = int(num) - 1
            if 0 <= idx < len(targets):
                from shodan_module import run_shodan_host
                print(run_shodan_host(targets[idx]["ip"]))
        return

    elif action == "6":
        success(f"Results saved to DB ({len(targets)} hosts) + JSON in {sr.results_dir}")
        return

    elif action == "7":
        _new_scan_shodan()  # recursive
        return

    else:
        warn("Invalid action.")
        return

    if not selected:
        warn("No targets selected.")
        return

    # ── Auto-pipeline: scan each target ──
    print(f"\n  \033[95m{'=' * 60}\033[0m")
    print(f"  \033[95m  AUTO-PIPELINE: {len(selected)} target(s)\033[0m")
    print(f"  \033[95m{'=' * 60}\033[0m")

    # Confirm
    for i, t in enumerate(selected[:20], 1):
        vuln_str = f" [{len(t.get('vulns',[]))} CVEs]" if t.get("vulns") else ""
        print(f"  {i}. {t['ip']} ports={','.join(str(p) for p in t['ports'][:5])}{vuln_str}")

    if len(selected) > 20:
        print(f"  ... and {len(selected) - 20} more")

    workers_input = prompt("  Concurrent workers [default: 5]: ")
    workers = int(workers_input) if workers_input.isdigit() else 5

    if not confirm(f"\nProceed with scanning {len(selected)} target(s) using {workers} workers?"):
        return

    import concurrent.futures
    import contextlib
    import io
    import tempfile
    
    # Store results safely
    results = []
    
    def _scan_target_worker(i, total, t):
        target_ip = t["ip"]
        log_file = f"/tmp/octopus_scan_{target_ip.replace('.', '_')}.log"
        
        # We redirect stdout so threads don't corrupt the main terminal
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                print(f"[*] Starting scan for {target_ip}...")
                sl_no = create_session(target_ip)
                scan_start = datetime.now()

                shodan_context = f"[SHODAN PRE-SCAN DATA for {target_ip}]\n"
                shodan_context += f"  Ports: {', '.join(str(p) for p in t.get('ports', []))}\n"
                shodan_context += f"  Org: {t.get('org', 'unknown')}\n"
                shodan_context += f"  OS: {t.get('os', 'unknown')}\n"
                if t.get("vulns"):
                    shodan_context += f"  Known CVEs: {', '.join(t['vulns'][:20])}\n"
                for svc in t.get("services", []):
                    shodan_context += f"  {svc['port']}/{svc.get('name','')} {svc.get('version','')}\n"
                shodan_context += "\n"

                try:
                    from core.recon.recon_engine import run_async_recon
                    # run_async_recon returns a dict: {target: combined_output_string}
                    recon_output = run_async_recon([target_ip], concurrency=10)
                    
                    raw_scan = shodan_context
                    if target_ip in recon_output:
                        raw_scan += recon_output[target_ip]
                except Exception as e:
                    raw_scan = shodan_context + f"[RECON ERROR] {e}\n"

                pipeline = AIPipeline()
                state = pipeline.run_scan(str(sl_no), target_ip, raw_scan=raw_scan)
                _save_trace_report(pipeline, str(sl_no), target_ip)
                result = _adapt_state_to_result(state, pipeline.fact_store, str(sl_no), target_ip, raw_scan)
                duration = datetime.now() - scan_start
                duration_str = str(duration).split('.')[0]

                update_session_status(sl_no, "complete")
                _save_and_show_results(sl_no, result, duration_str)
                
                print(f"[*] Scan complete for {target_ip}. Risk: {result.get('risk_level')}")
                
            except Exception as e:
                print(f"[-] FATAL ERROR processing {target_ip}: {e}")
                import traceback
                traceback.print_exc(file=sys.stdout)
                result = {"risk_level": "ERROR", "summary": str(e)}
        
        # Save log
        with open(log_file, "w") as lf:
            lf.write(buf.getvalue())
            
        return i, total, target_ip, result, log_file

    print(f"\n  \033[96m[*] Starting parallel scan ({workers} workers). Output saved to logs.\033[0m\n")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        for i, t in enumerate(selected, 1):
            futures.append(executor.submit(_scan_target_worker, i, len(selected), t))
            
        for future in concurrent.futures.as_completed(futures):
            try:
                i, total, ip, result, log_file = future.result()
                risk = result.get('risk_level', 'UNKNOWN')
                color = "\033[91m" if risk == "CRITICAL" else ("\033[93m" if risk == "HIGH" else "\033[92m")
                print(f"  \033[96m[{i}/{total}]\033[0m {ip} finished → Risk: {color}{risk}\033[0m (Log: {log_file})")
            except Exception as e:
                print(f"  \033[91m[!] Worker error: {e}\033[0m")

    success(f"Pipeline complete: {len(selected)} target(s) scanned in parallel.")


def _parse_selection(sel_str: str, items: list) -> list:
    """Parse selection string like '1,3,5-10' into list of items."""
    selected = []
    if not sel_str:
        return selected
    for part in sel_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for n in range(int(start), int(end) + 1):
                    if 1 <= n <= len(items):
                        selected.append(items[n - 1])
            except ValueError:
                pass
        elif part.isdigit():
            n = int(part)
            if 1 <= n <= len(items):
                selected.append(items[n - 1])
    return selected


def _shodan_load_saved(sr):
    """Load previously saved Shodan results from DB."""
    conn = sr._get_db()
    if not conn:
        error("Database not available.")
        return

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT query, COUNT(*) as cnt, MAX(timestamp) as last_ts
            FROM shodan_results
            GROUP BY query
            ORDER BY last_ts DESC
            LIMIT 20
        """)
        rows = cur.fetchall()
        cur.close()

        if not rows:
            warn("No saved Shodan results in database.")
            return

        print(f"\n  \033[96m[ SAVED SHODAN QUERIES ]\033[0m")
        print(f"  {'─' * 60}")
        print(f"  {'#':<4} {'QUERY':<35} {'HOSTS':<8} {'LAST RUN'}")
        print(f"  {'─' * 60}")

        for idx, (q, cnt, ts) in enumerate(rows, 1):
            print(f"  {idx:<4} {q[:33]:<35} {cnt:<8} {str(ts)[:19]}")
        print(f"  {'─' * 60}")

        choice = prompt("Load query # (or Enter to go back): ")
        if choice and choice.isdigit() and 1 <= int(choice) <= len(rows):
            selected_query = rows[int(choice) - 1][0]
            cur2 = conn.cursor(dictionary=True)
            cur2.execute(
                "SELECT ip, port, service, version, vulns, os_name, org "
                "FROM shodan_results WHERE query = %s",
                (selected_query,)
            )
            db_rows = cur2.fetchall()
            cur2.close()

            # Reformat for pipeline
            print(f"\n  Loaded {len(db_rows)} entries for: {selected_query}")
            for r in db_rows[:20]:
                vulns = r.get("vulns", "[]")
                print(f"    {r['ip']}:{r['port']} - {r['service']} {r['version']} vulns={vulns[:50]}")

    except Exception as e:
        error(f"DB query failed: {e}")


# ─────────────────────────────────────────────
# RESUME UNFINISHED SCAN
# ─────────────────────────────────────────────

def resume_scan():
    """Check /tmp for saved octopus checkpoints and offer to resume them."""
    global _current_sl_no
    divider("RESUME UNFINISHED SCAN")

    # Find all checkpoint files
    ck_dir = CFG.get("paths", {}).get("checkpoints", "/tmp")
    checkpoints = glob.glob(os.path.join(ck_dir, "octopus_checkpoint_*.json"))

    if not checkpoints:
        warn("No unfinished sessions found.")
        info(f"Checkpoint files are stored at {ck_dir}/octopus_checkpoint_<sl_no>.json")
        return

    # Parse and display found checkpoints
    parsed = []
    for path in checkpoints:
        try:
            with open(path) as f:
                data = json.load(f)
            parsed.append((path, data))
        except Exception as e:
            continue

    if not parsed:
        warn("Found checkpoint files but they are corrupted or unreadable.")
        return

    print(f"\n  \033[93m[ UNFINISHED SESSIONS DETECTED ]\033[0m")
    print(f"  {'─'*58}")
    print(f"  {'#':<4} {'SL#':<8} {'TARGET':<30} {'LOOP':<8} {'FACTS'}")
    print(f"  {'─'*58}")

    for idx, (path, data) in enumerate(parsed, 1):
        sl_no   = data.get("sl_no", "?")
        target  = data.get("target", "?")
        loop    = data.get("loop", "?")
        facts   = data.get("facts", [])
        print(f"  {idx:<4} {sl_no:<8} {target:<30} {loop:<8} {len(facts)} facts")

    print(f"  {'─'*58}")

    choice_str = prompt("Enter # to resume (or Enter to go back): ")
    if not choice_str:
        return
    if not choice_str.isdigit() or not (1 <= int(choice_str) <= len(parsed)):
        error("Invalid choice.")
        return

    idx = int(choice_str) - 1
    path, ck_data = parsed[idx]
    sl_no  = ck_data.get("sl_no", 0)
    target = ck_data.get("target", "")
    facts  = ck_data.get("facts", [])
    loop   = ck_data.get("loop", 0)

    if not target:
        error("Checkpoint has no target field — cannot resume.")
        return

    _current_sl_no = sl_no
    info(f"Resuming SL# {sl_no} | Target: {target} | Last loop: {loop} | Facts: {len(facts)}")
    logging.info(f"Resuming scan: sl_no={sl_no}, target={target}")
    scan_start = datetime.now()

    # Re-run recon? Or use last scan data from DB?
    use_new_recon = confirm("Run fresh recon tools before resuming AI analysis?")
    if use_new_recon:
        divider("RECON (FRESH)")
        info("Choose recon tools to run:")
        raw_scan = interactive_tool_run(target)
        if not raw_scan.strip():
            warn("No scan data. Resuming with empty recon.")
            raw_scan = "[RESUMED] No fresh recon data — use previously known facts."
    else:
        # Use last partial raw_scan from DB summary if available
        db_data = get_session(sl_no)
        raw_scan = ""
        if db_data.get("summary"):
            raw_scan = db_data["summary"][2] or ""  # raw_scan column
        if not raw_scan:
            raw_scan = "[RESUMED] No raw scan data available — rely on KNOWN FACTS."
        info("Using scan data from database.")

    # Inject known facts as a prefix into the raw_scan so LLM gets context
    if facts:
        facts_preamble = "CHECKPOINT FACTS (confirmed from previous loops):\n"
        facts_preamble += "\n".join(f"  ✓ {f}" for f in facts)
        raw_scan = facts_preamble + "\n\n" + raw_scan

    divider("AI ANALYSIS (RESUMED)")
    pipeline = AIPipeline()
    state = pipeline.run_scan(str(sl_no), target, raw_scan=raw_scan)
    _save_trace_report(pipeline, str(sl_no), target)
    result = _adapt_state_to_result(state, pipeline.fact_store, str(sl_no), target, raw_scan)

    duration = datetime.now() - scan_start
    duration_str = str(duration).split('.')[0]

    # Save results to DB
    update_session_status(sl_no, "complete")
    _save_and_show_results(sl_no, result, duration_str)
    _current_sl_no = None

    # Clean up checkpoint file after successful resume
    try:
        os.remove(path)
        success(f"Checkpoint file removed: {path}")
    except Exception as _exc:
        logging.debug(f"Suppressed in octopus.py: {_exc}")


def _adapt_state_to_result(state, fact_store, scan_id, target, raw_scan):
    """Adapts the new state/fact format to the old UI result dict format.

    v12: Handles exploit_success, potential_vulnerability, exploit_attempted.
    Adds full_response key to prevent KeyError in save_summary.
    """
    from core.ai.reporting import enrich_result_with_reporting

    facts = fact_store.get_facts(scan_id, target)
    hypotheses = fact_store.get_hypotheses(scan_id, target)

    vulns = []
    exploits = []
    has_exploit_success = any(f['type'] == 'exploit_success' for f in facts)
    has_confirmed_vuln = any(f['type'] == 'vulnerability' for f in facts)
    has_potential_vuln = any(f['type'] == 'potential_vulnerability' for f in facts)
    suppress_potential_vulns = bool(state.get("root_access_confirmed") or has_exploit_success or has_confirmed_vuln)

    for f in facts:
        ftype = f['type']
        fval = f['value']
        fconf = f.get('confidence', 0)

        if ftype == 'vulnerability':
            meta = _vulnerability_metadata(f, facts, state)
            vulns.append({
                "vuln_id": f.get("id", ""),
                "vuln_name": fval,
                "cvss": 0.0,
                "severity": meta["severity"],
                "port": meta["port"],
                "service": meta["service"],
                "description": meta["description"],
                "confidence": meta.get("confidence", "CONFIRMED"),
                "evidence_state": meta.get("evidence_state", "verified"),
                "exploit_executed": meta.get("exploit_executed", False),
                "impact_confirmed": meta.get("impact_confirmed", False),
                "evidence_tool": f.get("source", ""),
            })

        elif ftype == 'exploit_success':
            meta = _exploit_success_metadata(f, facts, state)
            vulns.append({
                "vuln_id": f.get("id", ""),
                "vuln_name": fval,
                "cvss": meta["cvss"],
                "severity": meta["severity"],
                "port": meta["port"],
                "service": meta["service"],
                "description": meta["description"],
                "confidence": "CONFIRMED",
                "evidence_tool": meta["evidence_tool"],
            })
            exploits.append({
                "exploit_name": fval,
                "tool_used": meta["tool_used"],
                "payload": meta["payload"],
                "result": meta["result"],
                "notes": f"Confidence: {fconf}%"
            })

        elif ftype == 'potential_vulnerability':
            if suppress_potential_vulns:
                continue
            vulns.append({
                "vuln_id": f.get("id", ""),
                "vuln_name": fval,
                "cvss": 0.0,
                "severity": "MEDIUM",
                "port": "unknown",
                "service": "unknown",
                "description": "Potential vulnerability (version match, unverified)",
                "confidence": "POSSIBLE",
                "evidence_tool": f.get("source", "vulners"),
            })

        elif ftype == 'exploit_attempted':
            exploits.append({
                "exploit_name": fval,
                "tool_used": "auto_exploit",
                "payload": "default",
                "result": "Success" if fconf >= 80 else "Attempted",
                "notes": f"From tool output (confidence: {fconf}%)"
            })

    # Risk level from state
    risk = "LOW"
    if state.get("root_access_confirmed"): risk = "CRITICAL"
    elif has_exploit_success: risk = "CRITICAL"
    elif has_confirmed_vuln: risk = "HIGH"
    elif state.get("credentials_found") or has_potential_vuln: risk = "MEDIUM"

    # Build summary text
    confirmed_facts = []
    hidden_fact_count = 0
    potential_values = []
    for f in facts:
        if f['type'] == 'potential_vulnerability':
            potential_values.append(str(f['value']))
            if suppress_potential_vulns:
                continue
        if not _should_display_confirmed_fact(f):
            hidden_fact_count += 1
            continue
        if len(confirmed_facts) >= 60:
            hidden_fact_count += 1
            continue
        confirmed_facts.append(_format_confirmed_fact(f))

    if potential_values and suppress_potential_vulns:
        examples = ", ".join(potential_values[:8])
        suffix = f", +{len(potential_values) - 8} more" if len(potential_values) > 8 else ""
        confirmed_facts.append(
            f"potential_vulnerability: {len(potential_values)} candidates observed ({examples}{suffix})"
        )
    if hidden_fact_count:
        confirmed_facts.append(f"internal_noise: {hidden_fact_count} low-level/trace facts hidden from CLI output")
    outcome_summary = _build_outcome_summary(facts, state)
    summary_text = (
        f"AI Pipeline Scan completed.\nTarget: {target}\nState: {_state_summary(state)}\n"
        f"Facts: {len(facts)}\nHypotheses: {len(hypotheses)}\n"
        f"Exploits: {len(exploits)}\nVulns: {len(vulns)}"
    )
    if outcome_summary:
        summary_text += "\n\nOUTCOME SUMMARY:\n" + "\n".join(f"- {line}" for line in outcome_summary)

    result = {
        "vulnerabilities": vulns,
        "exploits": exploits,
        "risk_level": risk,
        "summary": summary_text,
        "raw_scan": raw_scan,
        "full_response": summary_text,  # v12: required by save_summary
        "confirmed_facts": confirmed_facts,
        "outcome_summary": outcome_summary,
    }
    return enrich_result_with_reporting(result, facts, state)


def _mask_secret_value(value: str) -> str:
    text = str(value or "")
    text = _re.sub(
        r'((?:whm|cpanel)_session:)(:?)([A-Za-z0-9_-]{4})[A-Za-z0-9_-]+',
        r'\1\2\3***',
        text,
    )
    text = _re.sub(
        r'\b([^:\s]{1,40}):([^:\s]{3,})(\s+\(cached\))',
        lambda m: f"{m.group(1)}:{m.group(2)[:2]}***{m.group(3)}",
        text,
    )
    text = _re.sub(
        r'((?:ssh|ftp|postgres|mysql|ldap)_credential:[^@\s]+@)',
        r'\1',
        text,
    )
    return text


_HUMAN_FACT_TYPES = {
    "port_open",
    "service_version",
    "credential",
    "application_access",
    "system_access",
    "post_exploit_stage",
    "vulnerability",
    "vulnerability_endpoint",
    "exploit_success",
    "nuclei_finding",
    "web_title",
    "web_server",
    "web_security_note",
    "api_security_note",
    "internal_service",
    "internal_host",
    "internal_subnet",
    "service_status",
}

_NOISY_FACT_TYPES = {
    "check_result",
    "llm_health",
    "network_node",
    "network_edge",
    "external_url",
    "active_command",
    "verification_command",
    "payload_recommendation",
}

_IMPORTANT_STATUS_PREFIXES = (
    "ssh_authenticated",
    "ssh_inventory_completed",
    "network_recon_completed",
    "internal_service_probe_completed",
    "post_access_inventory_completed",
    "msf_login_check_success:",
    "msf_check_not_vulnerable:",
    "msf_check_invalid_options:",
    "tool_timeout:",
)


def _should_display_confirmed_fact(fact: dict) -> bool:
    ftype = str(fact.get("type", ""))
    value = str(fact.get("value", ""))
    if ftype in _NOISY_FACT_TYPES:
        return False
    if ftype == "service_status":
        return value.startswith(_IMPORTANT_STATUS_PREFIXES)
    if ftype == "nuclei_finding" and value.lower().startswith("info:"):
        return False
    return ftype in _HUMAN_FACT_TYPES


def _format_confirmed_fact(fact: dict) -> str:
    ftype = str(fact.get("type", ""))
    value = _mask_secret_value(fact.get("value", ""))
    confidence = fact.get("confidence", 100)
    return f"{ftype}: {value} (Confidence: {confidence})"


def _state_summary(state: dict) -> str:
    ordered = [
        "recon_completed",
        "web_services_found",
        "ssh_service_found",
        "vulnerabilities_found",
        "credentials_found",
        "root_access_confirmed",
        "post_access_inventory_completed",
        "internal_recon_completed",
        "exfiltration_completed",
        "cleanup_completed",
    ]
    flags = [f"{key}={bool(state.get(key))}" for key in ordered if key in state]
    ports = state.get("open_ports") or []
    if ports:
        flags.append(f"open_ports={len(ports)}")
    return ", ".join(flags) or "state unavailable"


def _unique_fact_values(facts, fact_types, limit=8):
    values = []
    wanted = set(fact_types)
    for fact in facts:
        if fact.get("type") not in wanted:
            continue
        value = _mask_secret_value(fact.get("value", ""))
        if value and value not in values:
            values.append(value)
        if len(values) >= limit:
            break
    return values


def _build_outcome_summary(facts, state) -> list:
    """Human-readable final outcome assembled from concrete facts."""
    lines = []
    gates = []
    for label, key in (
        ("recon", "recon_completed"),
        ("credentials", "credentials_found"),
        ("root", "root_access_confirmed"),
        ("post-access", "post_access_inventory_completed"),
        ("persistence", "persistence_established"),
        ("internal recon", "internal_recon_completed"),
        ("exfiltration", "exfiltration_completed"),
        ("cleanup", "cleanup_completed"),
    ):
        gates.append(f"{label}={'yes' if state.get(key) else 'no'}")
    lines.append("Stage gates: " + ", ".join(gates))

    credentials = _unique_fact_values(facts, {"credential"}, limit=10)
    if credentials:
        lines.append("Credentials/access material: " + "; ".join(credentials))

    access = _unique_fact_values(facts, {"application_access", "system_access", "post_exploit_stage"}, limit=10)
    if access:
        lines.append("Access/status: " + "; ".join(access))

    statuses = []
    for fact in facts:
        if fact.get("type") != "service_status":
            continue
        value = str(fact.get("value", ""))
        if not value.startswith(_IMPORTANT_STATUS_PREFIXES):
            continue
        if value not in statuses:
            statuses.append(value)
        if len(statuses) >= 8:
            break
    if statuses:
        lines.append("Tool/status signals: " + "; ".join(statuses))

    ports = _unique_fact_values(facts, {"port_open"}, limit=12)
    if ports:
        lines.append("Open services: " + "; ".join(ports))

    web = _unique_fact_values(
        facts,
        {"web_surface", "web_title", "web_path", "web_server", "web_redirect", "web_powered_by"},
        limit=12,
    )
    if web:
        lines.append("Web surface: " + "; ".join(web))

    internal = _unique_fact_values(
        facts,
        {"internal_host", "internal_subnet", "local_listening_port", "app_stack", "web_root", "app_manifest"},
        limit=12,
    )
    if internal:
        lines.append("Internal/post-access findings: " + "; ".join(internal))

    blocked = [
        fact.get("value")
        for fact in facts
        if fact.get("type") == "stage_status" and "blocked" in str(fact.get("value", ""))
    ]
    if blocked:
        lines.append("Blocked stages: " + "; ".join(dict.fromkeys(map(str, blocked))))
    return lines


def _fact_text(facts) -> str:
    return "\n".join(
        f"{f.get('type', '')}:{f.get('value', '')}:{f.get('source', '')}"
        for f in facts
    ).lower()


def _is_cpanel_evidence(f, facts) -> bool:
    text = _fact_text([f] + list(facts))
    source = str(f.get("source", "")).lower()
    value = str(f.get("value", "")).lower()
    return (
        "cpanel_sniper" in source
        or "cpanel_exploit" in source
        or "cve-2026-41940" in value
        or "cpanel/whm" in value
        or "cpanel_auth_bypass_session" in text
        or "whm_session:" in text
        or "service_version:cpanel" in text
    )


def _is_pwnkit_evidence(f, facts) -> bool:
    text = _fact_text([f] + list(facts))
    value = str(f.get("value", "")).lower()
    return (
        "pwnkit" in value
        or "cve-2021-4034" in value
        or "privesc_vector:suid_pkexec" in text
    )


def _service_for_port(facts, port: str) -> str:
    if not port:
        return "unknown"
    for fact in facts:
        if fact.get("type") != "port_open":
            continue
        value = str(fact.get("value", ""))
        match = _re.match(rf"{_re.escape(str(port))}/(?:tcp|udp)\s+\(([^)]+)\)", value, _re.IGNORECASE)
        if match:
            return match.group(1)
    return "unknown"


def _endpoint_metadata_for_vulnerability(f, facts) -> dict:
    value = str(f.get("value", ""))
    if value.startswith("msf_check_positive:"):
        module = value.split(":", 1)[1]
        for fact in facts:
            endpoint = str(fact.get("value", ""))
            if fact.get("type") != "vulnerability_endpoint":
                continue
            prefix = f"msf_check_positive:{module}:"
            if endpoint.startswith(prefix):
                port = endpoint.rsplit(":", 1)[-1]
                return {
                    "port": port,
                    "service": _service_for_port(facts, port),
                    "description": (
                        f"Metasploit check positive for {module} on port {port}. "
                        "Exploit execution and shell/command impact are not confirmed by this fact."
                    ),
                    "evidence_state": "verified_check",
                    "confidence": "VERIFIED",
                    "exploit_executed": False,
                    "impact_confirmed": False,
                }

    if value == "tomcat_jmx_proxy_exposed":
        for fact in facts:
            endpoint = str(fact.get("value", ""))
            if fact.get("type") != "vulnerability_endpoint":
                continue
            if not endpoint.startswith("tomcat_jmx_proxy_exposed:"):
                continue
            target = endpoint.split(":", 1)[1]
            port = "443" if target.startswith("https://") else "80"
            port_match = _re.search(r":(\d{2,5})(?:/|$)", target)
            if port_match:
                port = port_match.group(1)
            return {
                "port": port,
                "service": _service_for_port(facts, port) if port else "http",
                "description": f"Confirmed Tomcat JMX proxy exposure at {target}",
            }
    return {}


def _vulnerability_metadata(f, facts, state) -> dict:
    if _is_cpanel_evidence(f, facts):
        return {
            "severity": "CRITICAL",
            "port": "2087",
            "service": "cPanel/WHM",
            "description": "Confirmed cPanel/WHM vulnerability",
        }
    if _is_pwnkit_evidence(f, facts):
        return {
            "severity": "HIGH",
            "port": "local",
            "service": "Linux local privilege escalation",
            "description": "Confirmed local privilege escalation vulnerability",
        }
    endpoint_meta = _endpoint_metadata_for_vulnerability(f, facts)
    if endpoint_meta:
        return {
            "severity": "HIGH",
            "port": endpoint_meta.get("port", "unknown"),
            "service": endpoint_meta.get("service", "unknown"),
            "description": endpoint_meta.get("description", "Confirmed vulnerability"),
            "evidence_state": endpoint_meta.get("evidence_state", "verified"),
            "confidence": endpoint_meta.get("confidence", "VERIFIED"),
            "exploit_executed": endpoint_meta.get("exploit_executed", False),
            "impact_confirmed": endpoint_meta.get("impact_confirmed", False),
        }
    return {
        "severity": "HIGH",
        "port": "unknown",
        "service": "unknown",
        "description": "Confirmed vulnerability",
    }


def _exploit_success_metadata(f, facts, state) -> dict:
    if _is_cpanel_evidence(f, facts):
        return {
            "cvss": 9.8,
            "severity": "CRITICAL",
            "port": "2087",
            "service": "cPanel/WHM",
            "description": "Exploit confirmed: cPanel/WHM authenticated session obtained",
            "evidence_tool": f.get("source") or "cpanel_sniper",
            "tool_used": "cpanel_sniper",
            "payload": "auth_bypass",
            "result": "Success — session obtained",
        }
    if _is_pwnkit_evidence(f, facts):
        return {
            "cvss": 7.8,
            "severity": "CRITICAL" if state.get("root_access_confirmed") else "HIGH",
            "port": "local",
            "service": "Linux local privilege escalation",
            "description": "Exploit confirmed: local privilege escalation to root",
            "evidence_tool": f.get("source") or "killchain_privesc",
            "tool_used": "pwnkit",
            "payload": "suid_pkexec",
            "result": "Success — root access confirmed",
        }
    return {
        "cvss": 8.0,
        "severity": "CRITICAL" if state.get("root_access_confirmed") else "HIGH",
        "port": "unknown",
        "service": "unknown",
        "description": "Exploit confirmed by tool output",
        "evidence_tool": f.get("source") or "tool_output",
        "tool_used": f.get("source") or "auto_exploit",
        "payload": "confirmed",
        "result": "Success",
    }

# ─────────────────────────────────────────────
# SAVE & SHOW RESULTS (shared by new_scan + resume_scan)
# ─────────────────────────────────────────────

def _save_and_show_results(sl_no: int, result: dict, duration_str: str = ""):
    """Save AI analysis results to DB and display them."""
    divider("SAVING TO DATABASE")
    remediations = result.get("remediations") or []

    # save vulnerabilities and their fixes
    for vuln in result["vulnerabilities"]:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"],
            confidence=vuln.get("confidence", "UNCONFIRMED"),
            evidence_source=vuln.get("evidence_tool", ""),
            raw_evidence=vuln.get("evidence_snippet", ""),
        )
        fix_text = vuln.get("fix")
        fix_source = "ai"
        if not fix_text:
            fix_text = _remediation_for_vulnerability(vuln, remediations)
            fix_source = "deterministic"
        if fix_text:
            save_fix(sl_no, vuln_id, fix_text, source=fix_source)
        conf_tag = vuln.get("confidence", "UNCONFIRMED")
        ev_src = vuln.get("evidence_tool", "llm")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}] ({conf_tag} via {ev_src})")

    # save exploits
    for exp in result["exploits"]:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"]
        )
        success(f"Saved exploit: {exp['exploit_name']}")

    # save summary (skip if one already exists for this sl_no to avoid duplicates on resume)
    try:
        save_summary(
            sl_no,
            result["raw_scan"],
            result["full_response"],
            result["risk_level"]
        )
    except Exception as e:
        warn(f"Summary save skipped (may already exist): {e}")

    if duration_str:
        success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']} | Duration: {duration_str}")
    else:
        success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    # Print ASCII results table
    print_results_table(result)

    # show full DB session and offer edit/delete
    data = get_session(sl_no)
    print_session(data)

    if confirm("Export this session?"):
        export_menu(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


def _remediation_for_vulnerability(vuln: dict, remediations: list) -> str:
    """Pick the best deterministic remediation for a saved vulnerability."""
    name = str(vuln.get("vuln_name", "")).lower()
    service = str(vuln.get("service", "")).lower()
    for item in remediations:
        finding = str(item.get("finding", "")).lower()
        rec_service = str(item.get("service", "")).lower()
        recommendation = str(item.get("recommendation", "")).strip()
        if not recommendation:
            continue
        if finding and (finding in name or name in finding):
            return recommendation
        if service and rec_service and (service == rec_service or service in rec_service or rec_service in service):
            return recommendation
    return ""


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)

    sl_no_str = prompt("Enter SL# to view details (or press Enter to go back): ")
    if not sl_no_str:
        return

    try:
        sl_no = int(sl_no_str)
    except ValueError:
        error("Invalid SL#.")
        return

    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return

    print_session(data)

    if confirm("Export this session?"):
        export_menu(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1] Edit a vulnerability")
        print("  [2] Edit a fix")
        print("  [3] Edit an exploit")
        print("  [4] Edit risk level")
        print("  [5] Delete a vulnerability")
        print("  [6] Delete a fix")
        print("  [7] Delete an exploit")
        print("  [8] Delete FULL session (all tables)")
        print("  [9] Back")
        divider()

        choice = prompt("Choice: ")

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)
            success(f"Vulnerability id={vid} updated.")

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)
            success(f"Fix id={fid} updated.")

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)
            success(f"Exploit id={eid} updated.")

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)
            success(f"Risk level updated to {risk}.")

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))
                success(f"Vulnerability id={vid} deleted.")

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))
                success(f"Fix id={fid} deleted.")

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")

            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))
                success(f"Exploit id={eid} deleted.")

        # ── DELETE FULL SESSION ───────────────
        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "9":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# CHECKPOINT NOTICE
# ─────────────────────────────────────────────

def _check_pending_checkpoints() -> int:
    """Return the count of pending checkpoint files."""
    ck_dir = CFG.get("paths", {}).get("checkpoints", "/tmp")
    return len(glob.glob(os.path.join(ck_dir, "octopus_checkpoint_*.json")))


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()

        # Alert user if unfinished sessions exist
        pending = _check_pending_checkpoints()
        if pending:
            print(f"  \033[93m[!] {pending} unfinished session(s) detected — choose [3] to resume.\033[0m\n")

        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        if pending:
            print(f"  \033[93m[3]\033[0m  Resume Unfinished Scan  \033[90m({pending} pending)\033[0m")
        else:
            print("  \033[92m[3]\033[0m  Resume Unfinished Scan")
        print("  \033[95m[4]\033[0m  C2 Server Management")
        print("  \033[91m[5]\033[0m  Exit")
        divider()

        choice = prompt("octopus> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "3":
            resume_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")
            
        elif choice == "4":
            c2_management_menu()

        elif choice == "5":
            logging.info("Octopus shutdown by user")
            print("\n\033[91m[*] Shutting down Octopus. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# C2 MANAGEMENT MENU (THIN CLIENT)
# ─────────────────────────────────────────────

def _load_api_key() -> str:
    """Load the operator API key from file or environment."""
    # Check env first
    key = os.environ.get("OCTOPUS_API_KEY", "")
    if key:
        return key
    
    # Try default admin key file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    key_file = os.path.join(base_dir, "data", "default_admin.key")
    if os.path.exists(key_file):
        with open(key_file, "r") as f:
            return f.read().strip()
    
    return ""

_cached_api_key = None

def _send_to_daemon(action: str, **kwargs) -> dict:
    """Send a command to the C2 Daemon via Unix Socket with RBAC auth."""
    import socket
    global _cached_api_key
    
    sock_path = "/tmp/octopus.sock"
    
    if not os.path.exists(sock_path):
        return {"status": "error", "msg": "Daemon socket not found. Is it running?"}
    
    if _cached_api_key is None:
        _cached_api_key = _load_api_key()
    
    req = {"action": action, "api_key": _cached_api_key}
    req.update(kwargs)
    
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall(json.dumps(req).encode('utf-8'))
        data = s.recv(65536)
        s.close()
        return json.loads(data.decode('utf-8'))
    except Exception as e:
        return {"status": "error", "msg": str(e)}

def _start_c2_daemon():
    """Start the C2 Daemon in the background."""
    import subprocess
    sock_path = "/tmp/octopus.sock"
    if os.path.exists(sock_path):
        resp = _send_to_daemon("ping")
        if resp.get("status") == "ok":
            success("Daemon is already running.")
            return

    # Pre-check: ensure FastAPI + uvicorn are installed
    try:
        import fastapi  # noqa: F401
        import uvicorn   # noqa: F401
    except ImportError as e:
        error(f"Missing dependency for C2 daemon: {e}")
        print(f"  \033[93m[!] Install: pip install fastapi uvicorn\033[0m")
        return

    # Ensure data/ directory exists
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(data_dir, "keys"), exist_ok=True)

    print("  \033[96m[*] Starting C2 Daemon in background...\033[0m")
    daemon_path = os.path.join(base_dir, "core", "c2", "daemon.py")
    log_path = os.path.join(data_dir, "c2_daemon.log")

    # Run detached — log stderr to file for debugging
    import sys
    with open(log_path, "w") as log_f:
        proc = subprocess.Popen(
            [sys.executable, daemon_path],
            stdout=log_f, stderr=log_f,
            start_new_session=True, cwd=base_dir,
            env={**os.environ, "PYTHONPATH": base_dir}
        )

    import time
    for i in range(8):
        time.sleep(1)
        if os.path.exists(sock_path):
            resp = _send_to_daemon("ping")
            if resp.get("status") == "ok":
                success(f"Daemon started (PID {proc.pid}).")
                return
        # Check if process died
        if proc.poll() is not None:
            break

    # Daemon failed — show the error
    error("Failed to start daemon.")
    if os.path.isfile(log_path):
        try:
            with open(log_path) as f:
                log_content = f.read().strip()
            if log_content:
                print(f"  \033[91m─── Daemon log ({log_path}) ───\033[0m")
                for line in log_content.splitlines()[-15:]:
                    print(f"  \033[90m{line}\033[0m")
        except Exception as _exc:
            logging.debug(f"Suppressed in octopus.py: {_exc}")

def c2_management_menu():
    """Interact with the C2 Server via Unix Socket (Thin Client)."""
    
    # Auto-start daemon if not running
    resp = _send_to_daemon("ping")
    if resp.get("status") != "ok":
        warn("C2 Daemon is not running.")
        if confirm("Start the daemon now?"):
            _start_c2_daemon()
        else:
            return

    while True:
        divider("C2 SERVER MANAGEMENT v10")
        print("  \033[92m[1]\033[0m  List Active Agents")
        print("  \033[92m[2]\033[0m  Send Command to Agent")
        print("  \033[92m[3]\033[0m  View Task Results")
        print("  \033[92m[4]\033[0m  Build New Implant (Garble)")
        print("  \033[92m[5]\033[0m  Operator Management")
        print("  \033[91m[0]\033[0m  Back")
        divider()
        
        choice = prompt("c2> ")
        
        if choice == "0":
            break
            
        elif choice == "1":
            resp = _send_to_daemon("list_agents")
            if resp.get("status") == "ok":
                agents = resp.get("agents", {})
                if not agents:
                    print("  \033[93m[-] No active agents.\033[0m")
                else:
                    print(f"\n  [ ACTIVE AGENTS: {len(agents)} ]")
                    for a_id, info in agents.items():
                        print(f"  ID: \033[96m{a_id}\033[0m | User: {info['user']}@{info['hostname']} | IP: {info['ip']} | Last Seen: {info['last_seen']}")
            else:
                error(f"Daemon error: {resp.get('msg')}")
                
        elif choice == "2":
            a_id = prompt("Agent ID: ")
            cmd = prompt("Command: ")
            if not a_id or not cmd:
                continue
                
            resp = _send_to_daemon("queue_task", agent_id=a_id, command=cmd)
            if resp.get("status") == "ok":
                success(f"Task queued. ID: {resp.get('task_id')}")
            else:
                error(f"Failed to queue task: {resp.get('msg')}")
                
        elif choice == "3":
            a_id = prompt("Agent ID: ")
            if not a_id:
                continue
                
            resp = _send_to_daemon("get_results", agent_id=a_id)
            if resp.get("status") == "ok":
                results = resp.get("results", [])
                if not results:
                    print("  \033[93m[-] No new results for this agent.\033[0m")
                else:
                    for res in results:
                        print(f"\n  \033[96m[Task: {res['task_id']}]\033[0m")
                        if res.get('error'):
                            print(f"  \033[91mError: {res['error']}\033[0m")
                        print(f"{res['output']}")
            else:
                error(f"Daemon error: {resp.get('msg')}")
                
        elif choice == "4":
            import subprocess
            base_dir = os.path.dirname(os.path.abspath(__file__))
            builder_path = os.path.join(base_dir, "core", "c2", "builder.py")
            os_target = prompt("Target OS (linux/windows/darwin) [linux]: ") or "linux"
            arch_target = prompt("Target Arch (amd64/arm64) [amd64]: ") or "amd64"
            c2_url = prompt("C2 URL(s) (comma-separated) [http://127.0.0.1:8443]: ") or "http://127.0.0.1:8443"
            pins = prompt("SPKI Pins (comma-separated) []: ") or ""
            
            cmd = [sys.executable, builder_path, "--os", os_target, "--arch", arch_target, "--urls", c2_url]
            if pins:
                cmd.extend(["--pins", pins])
                
            subprocess.run(cmd)
            input("\n\033[90mPress Enter to continue...\033[0m")
            
        elif choice == "5":
            # Operator Management (admin only)
            print("\n  \033[96m[ OPERATOR MANAGEMENT ]\033[0m")
            print("  \033[92m[a]\033[0m  List operators")
            print("  \033[92m[b]\033[0m  Create operator")
            print("  \033[92m[c]\033[0m  Deactivate operator")
            print("  \033[92m[d]\033[0m  Rotate API key")
            sub = prompt("  op> ")
            
            if sub == "a":
                resp = _send_to_daemon("manage_operators", sub_action="list")
                if resp.get("status") == "ok":
                    ops = resp.get("operators", [])
                    for op in ops:
                        status = "\033[92mactive\033[0m" if op.get("active") else "\033[91minactive\033[0m"
                        print(f"  {op['name']} | Role: {op['role']} | {status}")
                else:
                    error(resp.get("msg", "Failed"))
            elif sub == "b":
                name = prompt("  Name: ")
                role = prompt("  Role (admin/operator/readonly) [operator]: ") or "operator"
                resp = _send_to_daemon("manage_operators", sub_action="create", name=name, role=role)
                if resp.get("status") == "ok":
                    success(f"Operator created. API Key: {resp['api_key']}")
                    warn("Save this key — it will not be shown again.")
                else:
                    error(resp.get("msg", "Failed"))
            elif sub == "c":
                name = prompt("  Operator name: ")
                resp = _send_to_daemon("manage_operators", sub_action="deactivate", name=name)
                if resp.get("status") == "ok":
                    success(f"Operator '{name}' deactivated.")
                else:
                    error(resp.get("msg", "Failed"))
            elif sub == "d":
                name = prompt("  Operator name: ")
                resp = _send_to_daemon("manage_operators", sub_action="rotate_key", name=name)
                if resp.get("status") == "ok":
                    success(f"New API Key: {resp['api_key']}")
                    warn("Save this key — it will not be shown again.")
                else:
                    error(resp.get("msg", "Failed"))
            
            input("\n\033[90mPress Enter to continue...\033[0m")
            
        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "trace":
        if len(sys.argv) < 4:
            print("Usage: python3 octopus.py trace SCAN_ID TARGET [text|json]")
            sys.exit(2)
        _print_trace_report_cli(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else "text")
        sys.exit(0)

    # ── CLI sub-commands: status, stop, health, pid ──
    if len(sys.argv) > 1 and sys.argv[1] in ("status", "stop", "health", "pid"):
        try:
            from core.supervisor import Supervisor
            sys.argv = [sys.argv[0]] + sys.argv[1:]
            from core.supervisor import cli as _supervisor_cli
            _supervisor_cli()
        except ImportError:
            print("[!] Supervisor module not available")
        sys.exit(0)

    log_file = _setup_logging()
    _setup_readline()


    # ── Supervisor: PID management + health monitoring ──
    try:
        from core.supervisor import create_supervisor, AlreadyRunningError
        _supervisor = create_supervisor(
            monitor_ollama=True,
            monitor_db=True,
            monitor_events=True,
        )

        # Register scan-aware shutdown hook
        def _save_scan_on_shutdown():
            if _current_sl_no:
                update_session_status(_current_sl_no, "interrupted")
                logging.info(f"Session SL# {_current_sl_no} saved on shutdown")
        _supervisor.on_shutdown(_save_scan_on_shutdown)

        try:
            _supervisor.start()
            info(f"Supervisor: PID {_supervisor._pid} locked")
        except AlreadyRunningError as e:
            error(str(e))
            sys.exit(1)

        # Check for crash recovery
        crash = _supervisor.get_crash_info()
        if crash:
            warn(f"Previous instance (PID {crash['previous_pid']}) crashed. "
                 f"Checkpoint recovery available via 'Resume Unfinished Scan'.")

    except ImportError:
        _supervisor = None
        warn("Supervisor not available (core/supervisor.py missing)")

    # Pre-flight checks
    if not preflight_checks():
        error("Critical pre-flight checks failed. Fix issues above and restart.")
        sys.exit(1)

    info(f"Logging to: {log_file}")
    
    # Auto-start C2 daemon (v10: uses core/c2/daemon.py, not c2_server.py)
    _start_c2_daemon()

    # Discover dynamically loaded plugins and modules
    try:
        from core.tools.registry import discover_plugins, print_registry_stats
        _base = os.path.dirname(os.path.abspath(__file__))
        loaded_plugins = discover_plugins(os.path.join(_base, "plugins"))
        loaded_modules = discover_plugins(os.path.join(_base, "modules"))
        if loaded_plugins or loaded_modules:
            info(f"Dynamically loaded {loaded_plugins} plugins and {loaded_modules} modules.")
            print_registry_stats()
    except Exception as e:
        warn(f"Error during plugin discovery: {e}")

    try:
        main_menu()
    finally:
        if _supervisor:
            _supervisor.stop()
