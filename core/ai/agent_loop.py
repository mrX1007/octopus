#!/usr/bin/env python3
"""
Main agent orchestration loop.
Includes tool execution, anti-loop detection, checkpointing, and the
analyse_target() entry point.
Extracted from llm.py lines 1463-1846 and 2260-2392.
"""

import re
import os
import sys
import time
import json
import hashlib
import concurrent.futures

# Lazy imports — these modules have heavy external dependencies
# Imported at call-time in _execute_single_call() and run_tool_calls()
# from tools import run_tool_by_command, run_arbitrary_cmd
# from search import handle_search_dispatch
# from msf import run_msf_module

from .ollama_client import (
    ask_ollama, SUMMARIZE_THRESHOLD, CONCURRENT_TOOLS,
    MAX_TOOL_LOOPS, CONTEXT_WINDOW,
    C_GREY, C_RESET, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_BLUE, C_MAGENTA
)
from .tag_parser import extract_tags, validate_and_fix_cmd
from .fact_engine import (
    extract_facts_from_output, _normalize_for_dedup,
    _extract_open_ports, _extract_filtered_ports,
    _is_all_filtered, _port_is_accessible
)
from .vuln_builder import (
    build_vulns_from_facts, parse_vulnerabilities,
    parse_exploits, parse_risk_level, parse_summary
)

# ─────────────────────────────────────────────
# SUMMARIZER (large outputs → compact)
# ─────────────────────────────────────────────

def summarize_long_log(text: str) -> str:
    """v6.0: Fast truncation of long tool output — NO LLM CALL.
    Old version called Ollama to summarize, which blocked for 30-120s per call.
    Multiple concurrent calls queued in Ollama → total hang of 5+ minutes.
    Now uses regex extraction: <1ms, never blocks."""
    print(f"\n  [*] Truncating {len(text)} chars of output (keeping critical lines)...")

    import re
    critical_lines = []
    seen = set()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped in seen:
            continue

        # Keep lines matching critical patterns
        is_critical = False
        _CRITICAL_PATTERNS = (
            # Ports and services
            r'\d+/tcp', r'open\s', r'closed\s', r'filtered',
            # Credentials
            r'password', r'credential', r'user[=:]', r'pass[=:]',
            # Versions
            r'version', r'OpenSSH', r'Apache', r'nginx', r'MySQL',
            # Errors and important status
            r'\[\+\]', r'\[-\]', r'\[!\]', r'FOUND', r'SUCCESS',
            r'FAIL', r'ERROR', r'denied', r'root:',
            # CVE and exploit
            r'CVE-', r'exploit', r'vuln',
            # Network
            r'\d+\.\d+\.\d+\.\d+', r'LISTEN',
            # Kill chain markers
            r'PROOF', r'uid=', r'SUID', r'PRIVESC', r'shadow',
            # Config file content
            r'DB_', r'MYSQL_', r'API_KEY', r'SECRET',
        )
        stripped_lower = stripped.lower()
        for pat in _CRITICAL_PATTERNS:
            if re.search(pat, stripped, re.IGNORECASE):
                is_critical = True
                break

        if is_critical:
            seen.add(stripped)
            critical_lines.append(stripped[:200])

        # Also keep section headers
        if stripped.startswith('[') or stripped.startswith('═') or stripped.startswith('─'):
            if stripped not in seen:
                seen.add(stripped)
                critical_lines.append(stripped[:120])

    # Cap at 80 lines
    if len(critical_lines) > 80:
        critical_lines = critical_lines[:80]
        critical_lines.append(f"... [{len(text)} chars total, showing 80 critical lines]")

    result = "\n".join(critical_lines)
    if not result:
        # Fallback: just truncate
        result = text[:3000] + f"\n... [TRUNCATED from {len(text)} chars]"

    return result


# ─────────────────────────────────────────────
# CONCURRENT TOOL RUNNER (v3.0)
# ─────────────────────────────────────────────

# v4.2: Active session tracking for tool result DB storage
_active_sl_no = None  # Set by analyse_target() when a session is active

def _save_tool_result_bg(command: str, output, duration: float):
    """Save tool result to DB in background thread. Non-blocking, non-fatal.
    v5.0: Extracts structured fields from ToolResult if available."""
    if _active_sl_no is None:
        return
    import threading
    # v5.0: Extract ToolResult fields if available
    if hasattr(output, 'exit_code'):
        _exit_code = output.exit_code
        _stderr = getattr(output, 'stderr', '')
        _stdout = getattr(output, 'stdout', str(output))
        _duration = getattr(output, 'duration', duration) or duration
    else:
        _exit_code = 0
        _stderr = ""
        _stdout = str(output)
        _duration = duration
    def _save():
        try:
            from db import save_tool_result
            save_tool_result(_active_sl_no, command, _stdout,
                             stderr=_stderr, exit_code=_exit_code, duration=_duration)
        except Exception:
            pass  # Never crash on DB save failure
    threading.Thread(target=_save, daemon=True).start()

def _execute_single_call(call_type: str, call_content: str, accumulated_facts: list) -> tuple:
    """
    Execute a single tool call. Returns (call_type, call_content, output, new_facts).
    Thread-safe — does not modify external state.
    v4.2: Added timing measurement and DB tool_result storage.
    """
    import time as _time
    # Lazy imports of external modules
    from tools import run_tool_by_command, run_arbitrary_cmd
    from search import handle_search_dispatch
    from msf import run_msf_module

    _t0 = _time.time()
    output = ""

    if call_type == "TOOL":
        # Check for scrapling
        if call_content.lower().startswith("scrapling "):
            url = call_content.split(None, 1)[1] if " " in call_content else call_content
            try:
                from tools import run_scrapling_fetch
                output = run_scrapling_fetch(url)
            except (ImportError, AttributeError):
                output = run_tool_by_command(f"curl -sL {url}")
        else:
            output = run_tool_by_command(call_content)
    elif call_type == "CMD":
        # ── HYDRA INTERCEPTION ───────────────────────────────────
        # If AI sends raw hydra command, redirect to smart bruteforce
        cmd_parts = call_content.strip().split()
        if cmd_parts and cmd_parts[0].lower() == "hydra":
            # Extract service and target from hydra command
            service_match = re.search(r'(ssh|ftp|http-\w+|mysql|rdp|smb|telnet)://([\d.]+)', call_content)
            if service_match:
                service = service_match.group(1)
                target_ip = service_match.group(2)
                print(f"  {C_YELLOW}[FIX] Redirecting raw hydra to smart bruteforce system{C_RESET}")
                print(f"  {C_YELLOW}  AI wanted: {call_content[:80]}...{C_RESET}")
                print(f"  {C_GREEN}  Routing to: run_bruteforce('{service}', '{target_ip}'){C_RESET}")
                from tools import run_bruteforce
                output = run_bruteforce(service, target_ip)
                new_facts = extract_facts_from_output(call_content, output)
                _duration = _time.time() - _t0
                _save_tool_result_bg(call_content, output, _duration)
                return (call_type, call_content, output, new_facts)

        # Validate and fix the command before execution
        fixed_cmd = validate_and_fix_cmd(call_type, call_content)
        if fixed_cmd != call_content:
            print(f"  {C_YELLOW}[FIX] Command auto-corrected:{C_RESET}")
            print(f"  {C_RED}  OLD: {call_content}{C_RESET}")
            print(f"  {C_GREEN}  NEW: {fixed_cmd}{C_RESET}")
        output = run_arbitrary_cmd(fixed_cmd)
    elif call_type == "SEARCH":
        output = handle_search_dispatch(call_content)
    elif call_type == "SEARCHSPLOIT":
        output = handle_search_dispatch(f"searchsploit {call_content}")
    elif call_type == "MSF":
        if '|' in call_content:
            mod, opts = call_content.split('|', 1)
            output = run_msf_module(mod.strip(), opts.strip())
        else:
            output = run_msf_module(call_content.strip(), "")
    else:
        output = f"[!] Unknown call type: {call_type}"

    # Measure duration and save to DB
    _duration = _time.time() - _t0
    _save_tool_result_bg(f"[{call_type}] {call_content}", output, _duration)

    # Extract facts from output
    new_facts = extract_facts_from_output(call_content, output)

    return (call_type, call_content, output, new_facts)


def run_tool_calls(calls: list, executed_set: set, accumulated_facts: list) -> str:
    """
    Execute tool calls CONCURRENTLY. Skips duplicates. Port-aware.
    Updates executed_set and accumulated_facts in-place.
    Returns tool results string, or special ALL_SKIPPED marker.
    """
    if not calls:
        return ""

    results = ""
    skipped_count = 0
    blocked_count = 0
    total_count = len(calls)
    executable_calls = []

    # v3.2: Detect if ssh_session is in this batch — skip redundant ssh_exec calls
    has_ssh_session = any(
        ct == "TOOL" and cc.lower().startswith("ssh_session ")
        for ct, cc in calls
    )
    # Commands that ssh_session already runs (don't waste SSH connections on these)
    _SSH_SESSION_COVERS = [
        "uname", "id", "whoami", "cat /etc/passwd", "cat /etc/shadow",
        "sudo -l", "find / -perm -4000", "find / -perm -2000", "crontab",
        "cat /etc/os-release", "cat /etc/crontab", "ss -tlnp", "netstat",
        "ps aux", "env", "cat /etc/hostname", "ifconfig", "ip addr",
        "cat /root/.ssh", "cat /home"
    ]

    # Phase 1: Filter — dedup + port check + ssh_exec dedup
    for call_type, call_content in calls:
        # v3.2: Skip ssh_exec calls that duplicate ssh_session
        if has_ssh_session and call_type == "TOOL" and call_content.lower().startswith("ssh_exec "):
            exec_cmd = " ".join(call_content.split()[4:]).lower() if len(call_content.split()) >= 5 else ""
            if any(covered in exec_cmd for covered in _SSH_SESSION_COVERS):
                print(f"\n{C_YELLOW}  [~] Skipping ssh_exec (ssh_session already runs this): {exec_cmd[:60]}{C_RESET}")
                skipped_count += 1
                continue

        # Smart deduplication
        norm_key = _normalize_for_dedup(call_type, call_content)
        if norm_key in executed_set:
            print(f"\n{C_YELLOW}  [~] Skipping duplicate call: [{call_type}: {call_content}]{C_RESET}")
            skipped_count += 1
            continue

        # Port-aware blocking (skip attacks on filtered ports)
        if call_type in ("CMD", "TOOL") and not _port_is_accessible(call_content, accumulated_facts):
            print(f"\n{C_RED}  [✗] Blocking: [{call_type}: {call_content}] — target port is FILTERED/CLOSED{C_RESET}")
            blocked_count += 1
            results += f"\n[{call_type} BLOCKED: {call_content}]\n"
            results += "Port is FILTERED or CLOSED. Do NOT attempt this service again.\n"
            executed_set.add(norm_key)
            continue

        # HUMAN IN THE LOOP (can't be parallelized)
        if call_type == "ASK":
            print(f"\n{C_CYAN}[AI REQUESTS INPUT] {call_content}{C_RESET}")
            ans = input(f"{C_CYAN}Your Answer (or press Enter to ignore): {C_RESET}")
            output = f"Human replied: {ans}" if ans else "Human provided no answer. Continue with default logic."
            results += f"\n[ASK RESULT: {call_content}]\n{output}\n"
            executed_set.add(norm_key)
            continue

        executable_calls.append((call_type, call_content, norm_key))
        executed_set.add(norm_key)  # Mark as seen WITHIN this batch too!

    # Phase 2: Execute concurrently
    if executable_calls:
        num_workers = min(len(executable_calls), CONCURRENT_TOOLS)
        print(f"\n{C_BLUE}  [⚡] Executing {len(executable_calls)} commands concurrently ({num_workers} workers)...{C_RESET}")

        # v6.0: HARD TIMEOUTS to prevent infinite hangs
        PER_TOOL_TIMEOUT = 90     # max 90s per tool
        BATCH_TIMEOUT = 180       # max 180s for entire batch

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_map = {}
            for call_type, call_content, norm_key in executable_calls:
                future = executor.submit(
                    _execute_single_call, call_type, call_content, accumulated_facts
                )
                future_map[future] = (call_type, call_content, norm_key)

            # Process results with BATCH timeout
            completed_count = 0
            try:
                for future in concurrent.futures.as_completed(future_map, timeout=BATCH_TIMEOUT):
                    call_type, call_content, norm_key = future_map[future]
                    executed_set.add(norm_key)
                    completed_count += 1

                    try:
                        _, _, output, new_facts = future.result(timeout=PER_TOOL_TIMEOUT)
                    except concurrent.futures.TimeoutError:
                        output = f"[!] TIMEOUT: {call_content} took >{PER_TOOL_TIMEOUT}s — killed."
                        new_facts = []
                        print(f"  {C_RED}[!] TIMEOUT: [{call_type}: {call_content[:50]}...] killed after {PER_TOOL_TIMEOUT}s{C_RESET}")
                    except Exception as exc:
                        output = f"[!] Execution error: {exc}"
                        new_facts = []

                    # Merge new facts
                    for f in new_facts:
                        if f not in accumulated_facts:
                            accumulated_facts.append(f)

                    # Summarize if too large — but NOT kill chain output
                    is_killchain = any(kw in output.lower() for kw in [
                        'kill chain', 'post-exploitation', 'privesc', 'persistence',
                        'lateral movement', 'data exfil', 'ssh post-exploitation'
                    ])
                    if len(output) > SUMMARIZE_THRESHOLD and not is_killchain:
                        output = summarize_long_log(output)
                    elif is_killchain and len(output) > SUMMARIZE_THRESHOLD * 3:
                        output = summarize_long_log(output)

                    results += f"\n[{call_type} RESULT: {call_content}]\n"
                    results += output.strip() + "\n"

            except concurrent.futures.TimeoutError:
                # Batch timeout — some tools still running, kill them
                timed_out = len(future_map) - completed_count
                print(f"\n  {C_RED}[!] BATCH TIMEOUT: {timed_out} tools still running after {BATCH_TIMEOUT}s — killing all.{C_RESET}")
                for future in future_map:
                    if not future.done():
                        future.cancel()
                        call_type, call_content, norm_key = future_map[future]
                        results += f"\n[{call_type} TIMEOUT: {call_content}]\n"
                        results += f"Tool killed after {BATCH_TIMEOUT}s batch timeout.\n"
                        executed_set.add(norm_key)

    # If ALL calls were skipped/blocked, signal the AI to stop looping
    if (skipped_count + blocked_count) == total_count:
        results = (
            "\n[ALL COMMANDS SKIPPED OR BLOCKED]\n"
            "ALL your requested commands were already executed or blocked (filtered ports).\n"
            "You MUST now produce your FINAL ANALYSIS using Format B.\n"
            "Output your VULN:, EXPLOIT:, RISK_LEVEL:, and SUMMARY: blocks NOW.\n"
            "Do NOT request any more tools.\n"
        )

    return results


# ─────────────────────────────────────────────
# ANTI-LOOP DETECTOR (v3.1 — EXPLOITATION-AWARE)
# ─────────────────────────────────────────────

def _has_attempted_exploitation(accumulated_facts: list) -> bool:
    """Check if any exploitation has been attempted (not just recon/discovery).
    Note: Finding credentials is NOT exploitation. Using them IS.
    v5.0: Facts are (text, source) tuples."""
    exploit_indicators = [
        "EXPLOITATION SUCCESSFUL", "Exploitation attempted",
        "SSH post-exploitation", "TARGET IS ROOTED",
        "WEB CREDENTIALS FOUND",
        "DEFAULT CREDENTIALS CONFIRMED",
        "Privilege escalation vector found",
        "KILL CHAIN: Exploitation stage",
        "KILL CHAIN: PRIVILEGE ESCALATION SUCCESSFUL",
        "KILL CHAIN: Persistence",
        "KILL CHAIN: Lateral movement",
        "KILL CHAIN: Data exfil",
    ]
    for fact in accumulated_facts:
        # v5.0: fact is (text, source) tuple
        fact_text = fact[0] if isinstance(fact, tuple) else fact
        for indicator in exploit_indicators:
            if indicator in fact_text:
                return True
    return False


def _check_should_stop(loop: int, facts_history: list, skipped_ratio: float,
                       accumulated_facts: list = None) -> tuple:
    """
    Detect if the agent is stuck in a loop.
    v3.1: Won't stop until exploitation has been attempted (not just recon).
    Returns (should_stop: bool, reason: str)
    """
    # Hard limit approaching — always stop
    if loop >= MAX_TOOL_LOOPS - 2:
        return True, "Approaching maximum loop limit"

    # If we have credentials or exploit vectors found but not yet exploited,
    # DON'T stop — let the agent try exploitation first
    if accumulated_facts:
        # v5.0: facts are (text, source) tuples
        fact_texts = [f[0] if isinstance(f, tuple) else f for f in accumulated_facts]
        has_creds = any("CREDENTIALS FOUND" in f or "DEFAULT CREDS" in f for f in fact_texts)
        has_privesc = any("escalation vector" in f for f in fact_texts)
        has_exploited = _has_attempted_exploitation(accumulated_facts)

        if (has_creds or has_privesc) and not has_exploited and loop < MAX_TOOL_LOOPS - 3:
            return False, ""  # Don't stop — still have unexploited findings

    # No new facts for 2 consecutive loops (was 3 — tightened)
    if len(facts_history) >= 2:
        last_two = facts_history[-2:]
        if last_two[-1] == last_two[-2]:
            return True, "No new facts discovered in 2 consecutive loops"

    # v7.0: High skip ratio — tightened from 0.8/loop4 to 0.5/loop3
    # If more than half of commands are being skipped, AI is looping
    if skipped_ratio > 0.5 and loop >= 3:
        return True, f"Over {skipped_ratio*100:.0f}% of commands being skipped (loop {loop})"

    return False, ""




# ─────────────────────────────────────────────
# CHECKPOINT
# ─────────────────────────────────────────────

def save_checkpoint(sl_no: int, target: str, loop: int,
                    accumulated_facts: list, final_response: str):
    """Save session progress to disk so it survives crashes."""
    try:
        from config import CFG as _cfg
        ck_dir = _cfg.get("paths", {}).get("checkpoints", "/tmp")
    except ImportError:
        ck_dir = "/tmp"

    path = os.path.join(ck_dir, f"octopus_checkpoint_{sl_no}.json")
    data = {
        "sl_no": sl_no,
        "target": target,
        "loop": loop,
        "facts": accumulated_facts,
        "last_response": final_response[:5000]
    }
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"  [!] Checkpoint save failed: {e}")


def load_checkpoint(sl_no: int) -> dict:
    """Load existing checkpoint if available."""
    try:
        from config import CFG as _cfg
        ck_dir = _cfg.get("paths", {}).get("checkpoints", "/tmp")
    except ImportError:
        ck_dir = "/tmp"

    path = os.path.join(ck_dir, f"octopus_checkpoint_{sl_no}.json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def clear_checkpoint(sl_no: int):
    """Remove checkpoint file after successful scan."""
    try:
        from config import CFG as _cfg
        ck_dir = _cfg.get("paths", {}).get("checkpoints", "/tmp")
    except ImportError:
        ck_dir = "/tmp"

    path = os.path.join(ck_dir, f"octopus_checkpoint_{sl_no}.json")
    try:
        os.remove(path)
    except Exception:
        pass


# ─────────────────────────────────────────────
# MAIN ANALYSIS LOOP (v5.0 — MULTI-AGENT)
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str, sl_no: int = 0) -> dict:
    """
    Main agent loop v5.0 (Multi-Agent Architecture):
    Delegates to the Director Agent to orchestrate the scan.
    Falls back to single-agent mode if the multi-agent system fails.
    """
    from memory import init_memory
    from agents import DirectorAgent

    print(f"\n\033[96m[*] Initializing Multi-Agent System v9.0 for {target}...\033[0m")

    # Initialize memory for this session
    init_memory(sl_no)
    
    # v11.0: Integrate Knowledge Graph (replaces old CampaignGraph)
    try:
        from core.knowledge import KnowledgeGraph
        graph = KnowledgeGraph()
        context = graph.to_llm_context(target)
        if context and "No prior campaign" not in context:
            raw_scan = f"[CAMPAIGN MEMORY CONTEXT]\n{context}\n\n" + raw_scan
    except ImportError:
        try:
            from core.ai.campaign_memory import CampaignGraph
            graph = CampaignGraph()
            context = graph.get_context_for_target(target)
            raw_scan = f"[CAMPAIGN MEMORY CONTEXT]\n{context}\n\n" + raw_scan
        except ImportError:
            pass

    try:
        director = DirectorAgent()
        result = director.run(target, raw_scan)

        # Validate result has required keys
        required = ["full_response", "vulnerabilities", "exploits", "risk_level", "summary", "raw_scan"]
        for key in required:
            if key not in result:
                result[key] = "" if key != "vulnerabilities" and key != "exploits" else []
        if not result.get("raw_scan"):
            result["raw_scan"] = raw_scan

        return result

    except Exception as e:
        print(f"\n\033[91m[!] Multi-Agent error: {e}\033[0m")
        print(f"\033[93m[*] Falling back to single-pass analysis...\033[0m")

        # Emergency fallback — single LLM call
        fallback_prompt = f"""Analyze this penetration test data and provide results.
Target: {target}
Scan Data:
{raw_scan[:6000]}

Respond with:
RISK_LEVEL: CRITICAL|HIGH|MEDIUM|LOW
SUMMARY: <your analysis>
"""
        response = ask_ollama(fallback_prompt)
        risk = parse_risk_level(response)
        summary = parse_summary(response)
        vulns = parse_vulnerabilities(response)
        exploits = parse_exploits(response)

        return {
            "full_response": response,
            "vulnerabilities": vulns,
            "exploits": exploits,
            "risk_level": risk,
            "summary": summary,
            "raw_scan": raw_scan,
            "confirmed_facts": []
        }
