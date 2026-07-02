#!/usr/bin/env python3

import fnmatch
import hashlib
import ipaddress
import json
import logging
import re
import time
from typing import Dict, Any, List
from urllib.parse import urljoin, urlparse, urlunparse

from core.ai.fact_store import FactStore
from core.ai.state_resolver import StateResolver
from core.ai.context_builder import ContextBuilder
from core.ai.director import DirectorLLM
from core.ai.command_scheduler import CommandScheduler
from core.ai.policy import DeterministicPolicy
from core.ai.trace_report import TraceReporter
from core.ai.planner import MissionPlanner
from core.ai.tool_registry import ToolRegistry
from core.ai.evidence import OutputParser, EvidenceVerifier
from core.ai.task_agents import DiscoveryAgent, AnalysisAgent, VerificationAgent

logger = logging.getLogger("octopus.pipeline")

# Try to import tool runner, else mock it for tests
try:
    from tools import run_arbitrary_cmd
except ImportError:
    def run_arbitrary_cmd(cmd: str) -> str:
        return f"[Mock output for {cmd}]"

class AIPipeline:
    def __init__(self, db_path: str = "data/facts.db"):
        self.fact_store = FactStore(db_path)
        self.state_resolver = StateResolver(self.fact_store)
        self.context_builder = ContextBuilder(self.fact_store, self.state_resolver)
        self.director = DirectorLLM()
        self.command_scheduler = CommandScheduler()
        self.policy = DeterministicPolicy()
        self.planner = MissionPlanner()
        self.tool_registry = ToolRegistry()
        self.output_parser = OutputParser()
        self.evidence_verifier = EvidenceVerifier(self.fact_store)
        self.trace_reporter = TraceReporter(self.fact_store)

        self.discovery_agent = DiscoveryAgent(self.tool_registry)
        self.analysis_agent = AnalysisAgent(self.fact_store, self.context_builder)
        self.verification_agent = VerificationAgent(self.tool_registry, self.evidence_verifier)

        self.MAX_CONSECUTIVE_LLM_FAILURES = 3
        self._reset_runtime_state()

    def _reset_runtime_state(self):
        """Reset per-scan control-plane counters without touching persisted facts."""
        # Anti-loop state
        self.goal_history = []
        self.task_history = []
        self.fact_history_counts = []
        self.completed_tasks = set()
        self.blocked_tasks = set()

        # Budget and quality tracking
        self.tools_run_count = 0
        self.scan_start_time = 0
        self.total_new_facts = 0
        self.task_outcomes = []
        self.failed_commands = []
        self.no_fact_tasks = []
        self.executed_followup_commands = set()
        self.executed_active_commands = set()
        self.executed_post_access_commands = set()
        self.executed_fact_action_commands = set()
        self.executed_command_keys = set()
        self.service_intelligence_evidence_seen = set()
        self.command_trace = []
        self.goal_trace = []

        # LLM health tracking
        self.consecutive_llm_failures = 0

    def run_scan(self, scan_id: str, target: str, max_iterations: int = 0, max_tools: int = 0, max_time_minutes: int = 0, raw_scan: str = ""):
        print(f"\n[*] Starting AI Pipeline for target: {target} (Scan ID: {scan_id})")
        self._reset_runtime_state()
        max_iterations = self._runtime_limit(max_iterations)
        max_tools = self._runtime_limit(max_tools)
        max_time_minutes = self._runtime_limit(max_time_minutes)

        # Parse initial raw scan if provided
        if raw_scan:
            print("[*] Parsing facts from manual tool output...")
            facts = self.output_parser.parse_tool_output("manual_recon", raw_scan)
            seeded = 0
            for f in facts:
                stored = self._store_fact(scan_id, target, f, "manual_run")
                if stored["created"]:
                    seeded += 1
                    self.total_new_facts += stored["new_facts"]
                    print(f"    [+] Seeded: {f['type']} -> {f['value']} (conf={f.get('confidence', 100)})")
            self._sync_runtime_credentials_from_facts(target, facts)
            print(f"[*] Seeded {seeded} facts from manual tool output.")

        credential_seeded = self._seed_known_credentials(scan_id, target)
        if credential_seeded:
            print(f"[*] Seeded {credential_seeded} known credential fact(s) from credential store.")

        # Show available tools at startup
        avail = self.tool_registry.get_available_tools_summary()
        avail_list = [f"{task}: {', '.join(tools) if tools else 'NONE'}" for task, tools in avail.items() if tools]
        print(f"[*] Available tools: {'; '.join(avail_list)}")
        unavailable = self.tool_registry.get_unavailable_tools_summary()
        blocked_capabilities = [
            f"{task}({', '.join(tools)})"
            for task, tools in unavailable.items()
            if tools and not avail.get(task)
        ]
        if blocked_capabilities:
            print(f"[*] Blocked capabilities: {'; '.join(blocked_capabilities[:8])}")
        plugins = self.tool_registry.get_discovered_plugins_summary()
        if plugins:
            plugin_list = [f"{p['name']}({p['type']})" for p in plugins]
            print(f"[*] Discovered plugins: {', '.join(plugin_list)}")
        coverage = self.tool_registry.get_coverage_report()
        if coverage.get("unknown"):
            print(f"[*] Registry coverage gaps: {', '.join(coverage['unknown'])}")
        else:
            print(
                f"[*] Registry coverage: {coverage['covered']}/{coverage['registered']} "
                f"(auto={len(coverage['auto'])}, followup={len(coverage['followup'])}, "
                f"gated={len(coverage['manual_gated'])}, legacy={len(coverage['legacy_wrappers'])})"
            )

        self.scan_start_time = time.time()
        startup_actions = self._run_fact_driven_actions(
            scan_id, target, self.fact_store.get_facts(scan_id, target)
        )
        if startup_actions["commands"]:
            self.total_new_facts += startup_actions["new_facts"]
            print(
                f"[*] Startup actions: {len(startup_actions['commands'])} command(s), "
                f"{startup_actions['new_facts']} new fact(s)."
            )

        loop = 1
        while max_iterations is None or loop <= max_iterations:
            # Budget Checks
            elapsed_minutes = (time.time() - self.scan_start_time) / 60
            if max_time_minutes is not None and elapsed_minutes >= max_time_minutes:
                print(f"[!] BUDGET EXCEEDED: Max time reached ({max_time_minutes} mins). Terminating.")
                break
            if max_tools is not None and self.tools_run_count >= max_tools:
                print(f"[!] BUDGET EXCEEDED: Max tools run ({max_tools}). Terminating.")
                break

            # LLM health check
            if self.consecutive_llm_failures >= self.MAX_CONSECUTIVE_LLM_FAILURES:
                print(f"\n[!] LLM DEAD: {self.consecutive_llm_failures} consecutive failures. Running on fallback only.")
                print(f"    Check: ollama ps / ollama logs / ollama restart")

            loop_label = str(max_iterations) if max_iterations is not None else "unlimited"
            print(f"\n{'='*50}\n[LOOP {loop}/{loop_label}]")

            # 1. State Resolution & Context Building
            state = self.state_resolver.resolve_state(scan_id, target)
            context = self.context_builder.build_context(scan_id, target)
            print(f"[*] Context: state={context['state']}, services={context['services']}, questions={context['open_questions']}")
            self._print_stage_gates(context)

            # 2. Director Goal
            director_res = self.director.decide_goal(context, self.goal_history)
            goal = director_res.get("goal", "conclude")
            thought = director_res.get("thought", "")
            self._record_goal_trace(loop, context, director_res)

            print(f"[*] Director Goal: {goal}")
            print(f"    Thought: {thought}")

            self.goal_history.append(goal)

            if goal == "conclude":
                print("[+] Scan concluded by Director.")
                break

            # Anti-loop check: No new facts for 3 loops
            current_fact_count = len(self.fact_store.get_facts(scan_id, target))
            self.fact_history_counts.append(current_fact_count)
            if len(self.fact_history_counts) >= 4:
                if self.fact_history_counts[-1] == self.fact_history_counts[-4]:
                    print("[!] ANTI-LOOP: No new facts for 3 loops. Terminating scan.")
                    break

            # 3. Mission Planner (pass context instead of raw state)
            plan_res = self.planner.create_plan(goal, context, self.task_history)
            plan = plan_res.get("plan", [])
            plan = self._normalize_plan(plan, goal)
            plan = self._optimize_plan(plan, goal, context)

            if not plan:
                print(f"[!] Planner returned empty plan for goal '{goal}'. Concluding.")
                break

            print(f"[*] Planner generated {len(plan)} tasks.")

            # Check if ALL tasks in this plan are already completed or blocked.
            all_skipped = all(self._task_exhausted(step.get("task")) for step in plan)
            if all_skipped:
                print(f"[!] All tasks in plan already completed/blocked. Goal '{goal}' exhausted.")
                # Don't break — let the Director pick the next goal
                loop += 1
                continue

            # 4. Agent Execution
            new_facts_this_loop = 0
            for step in plan:
                agent_name = step.get("agent")
                task = step.get("task")

                # Skip tasks that have already been completed
                if self._task_exhausted(task):
                    reason = "blocked" if task in self.blocked_tasks else "already completed"
                    print(f"  -> [{agent_name}] Task: {task} - SKIPPED ({reason})")
                    continue

                print(f"  -> [{agent_name}] Task: {task}")
                self.task_history.append(f"{agent_name}:{task}")
                task_started = time.time()

                if agent_name == "DiscoveryAgent":
                    cmds = self.discovery_agent.execute_task(task, target)
                    if not cmds:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        self.blocked_tasks.add(task)
                        self._record_task_outcome(agent_name, task, "blocked", "no_available_tools", 0, 0, [], time.time() - task_started)
                        continue

                    task_result = self._run_task_commands(scan_id, target, cmds, fact_label="Fact")
                    new_facts_this_loop += task_result["new_facts"]
                    status = self._classify_task_result(task_result)
                    reason = task_result["reason"]
                    if status == "blocked":
                        self.blocked_tasks.add(task)
                    else:
                        self.completed_tasks.add(task)
                    self._record_task_outcome(
                        agent_name, task, status, reason,
                        task_result["new_facts"], task_result["parsed_facts"],
                        task_result["commands"], time.time() - task_started
                    )

                elif agent_name == "AnalysisAgent":
                    # AnalysisAgent uses LLM — track failures
                    analysis = self.analysis_agent.analyze(scan_id, target)
                    hypotheses = analysis.get("hypotheses", [])
                    accepted_count = 0
                    task_new_facts = 0

                    if not hypotheses:
                        self.consecutive_llm_failures += 1
                        print(f"     [!] AnalysisAgent returned 0 hypotheses (LLM failures: {self.consecutive_llm_failures})")
                    else:
                        self.consecutive_llm_failures = 0  # Reset on success

                    for hyp in hypotheses:
                        claim = hyp.get('claim')
                        req_evidence = hyp.get('required_evidence', [])
                        print(f"     [?] Hypothesis: {claim}")

                        self.fact_store.add_hypothesis(scan_id, target, claim, req_evidence, "AnalysisAgent")

                        verify_res = self.verification_agent.verify_hypothesis(
                            scan_id, target, claim, req_evidence
                        )
                        print(f"         Status: {verify_res.get('status')} - {verify_res.get('reason')}")

                        if verify_res.get('status') == 'accepted':
                            accepted_count += 1
                            if verify_res.get("created", True):
                                task_new_facts += 1
                                new_facts_this_loop += 1

                    self.completed_tasks.add(task)
                    if not hypotheses:
                        status = "failed"
                        reason = "analysis_returned_no_hypotheses"
                    elif accepted_count:
                        status = "completed"
                        reason = f"{accepted_count}_hypotheses_accepted"
                    else:
                        status = "no_new_facts"
                        reason = "hypotheses_rejected_or_duplicate"
                    self.total_new_facts += task_new_facts
                    self._record_task_outcome(
                        agent_name, task, status, reason,
                        task_new_facts, accepted_count, [], time.time() - task_started
                    )

                elif agent_name == "VerificationAgent":
                    cmds = self.verification_agent.execute_task(task, target)
                    if not cmds:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        self.blocked_tasks.add(task)
                        self._record_task_outcome(agent_name, task, "blocked", "no_available_tools", 0, 0, [], time.time() - task_started)
                        continue
                    task_result = self._run_task_commands(scan_id, target, cmds, fact_label="Verified Fact", verification=True)
                    new_facts_this_loop += task_result["new_facts"]
                    status = self._classify_task_result(task_result)
                    reason = task_result["reason"]
                    if status == "blocked":
                        self.blocked_tasks.add(task)
                    else:
                        self.completed_tasks.add(task)
                    self._record_task_outcome(
                        agent_name, task, status, reason,
                        task_result["new_facts"], task_result["parsed_facts"],
                        task_result["commands"], time.time() - task_started
                    )

                else:
                    print(f"     [!] Unknown agent '{agent_name}'. Skipping task.")
                    self.blocked_tasks.add(task)
                    self._record_task_outcome(agent_name, task, "blocked", "unknown_agent", 0, 0, [], time.time() - task_started)

            # If this loop produced zero new facts, note it
            if new_facts_this_loop == 0:
                print(f"[*] Loop {loop} produced 0 new facts.")
            loop += 1

        elapsed = time.time() - self.scan_start_time
        print(f"\n[*] Pipeline finished for {target}. ({self.tools_run_count} tools run, {elapsed:.0f}s elapsed)")
        print(f"[*] LLM failures: {self.consecutive_llm_failures} consecutive, completed tasks: {sorted(self.completed_tasks)}")
        self._print_efficiency_report(scan_id, target, elapsed)
        return self.state_resolver.resolve_state(scan_id, target)

    def replay_outputs(self, scan_id: str, target: str, outputs: List[Dict[str, str]]) -> Dict[str, Any]:
        """Replay saved raw tool outputs through the parser and fact bus.

        Each entry is {"tool": "...", "output": "..."} or
        {"command": "...", "raw_output": "..."}.
        """
        stored = 0
        parsed = 0
        for entry in outputs or []:
            tool = entry.get("tool") or entry.get("command") or "replay"
            raw_output = entry.get("output") or entry.get("raw_output") or ""
            facts = self.output_parser.parse_tool_output(tool, raw_output)
            parsed += len(facts)
            for fact in facts:
                result = self._store_fact(scan_id, target, fact, f"replay:{tool}")
                stored += result["new_facts"]
        context = self.context_builder.build_context(scan_id, target)
        return {
            "parsed_facts": parsed,
            "new_facts": stored,
            "context": context,
            "snapshot_actions": self.snapshot_actions(scan_id, target),
        }

    def snapshot_actions(self, scan_id: str, target: str) -> List[Dict[str, str]]:
        """Return the deterministic next actions without executing them."""
        facts = self.fact_store.get_facts(scan_id, target)
        executed_fact_actions = set(self.executed_fact_action_commands)
        service_evidence_seen = set(self.service_intelligence_evidence_seen)
        try:
            commands = self._fact_driven_action_commands(scan_id, target, facts)
        finally:
            self.executed_fact_action_commands = executed_fact_actions
            self.service_intelligence_evidence_seen = service_evidence_seen
        decisions = []
        all_facts = self.fact_store.get_facts(scan_id, target)
        for command in commands:
            decision = self.command_scheduler.decide(command, all_facts, self.executed_command_keys)
            decisions.append(decision.to_dict())
        return decisions

    def trace_report(self, scan_id: str, target: str) -> Dict[str, Any]:
        context = self.context_builder.build_context(scan_id, target)
        return self.trace_reporter.build(
            scan_id,
            target,
            goal_trace=self.goal_trace,
            command_trace=self.command_trace,
            task_outcomes=self.task_outcomes,
            context=context,
        )

    def trace_report_text(self, scan_id: str, target: str) -> str:
        return self.trace_reporter.to_text(self.trace_report(scan_id, target))

    def _runtime_limit(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in {"", "0", "-1", "none", "unlimited", "false"}:
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return None if parsed <= 0 else parsed

    def _normalize_plan(self, plan, goal: str = ""):
        """Normalize LLM task names before execution and history tracking."""
        normalized = []
        for step in plan:
            if not isinstance(step, dict):
                continue
            agent = step.get("agent")
            task = step.get("task")
            if not agent or not task:
                continue
            task_key = (task or "").strip().lower().replace("-", "_").replace(" ", "_")
            if goal == "privilege_escalation" and task_key in {"verify_exploit", "exploit", "run_exploit"}:
                task = "exploit_privesc"
            elif goal == "data_exfiltration" and task_key in {
                "directory_bruteforce", "dir_bruteforce", "find_sensitive_files",
                "data_discovery", "discover_data", "enumerate_files"
            }:
                task = "exfiltrate_data"
            normalized.append({
                **step,
                "agent": agent,
                "task": self.tool_registry.canonical_task(task),
            })
        return normalized

    def _optimize_plan(self, plan, goal: str, context: Dict[str, Any]):
        """Apply deterministic guardrails around LLM plans.

        The LLM is useful for flexible planning, but the kill-chain state is the
        source of truth. Once access is confirmed, post-exploitation goals should
        not drift back into scanning or generic analysis.
        """
        state = context.get("state", "initial_recon")
        forced_plan = self._post_exploit_plan(goal, state)
        if forced_plan is not None:
            if plan != forced_plan:
                tasks = ", ".join(step["task"] for step in forced_plan)
                print(f"[*] Plan optimized for state={state}, goal={goal}: {tasks}")
            return forced_plan

        optimized = []
        seen_tasks = set()
        for step in plan:
            agent = step.get("agent")
            task = self.tool_registry.canonical_task(step.get("task"))
            if not agent or not task:
                continue
            if task in seen_tasks:
                continue
            if agent != "AnalysisAgent" and not self.tool_registry.has_task(task):
                print(f"     [!] Dropping unknown planner task: {task}")
                continue
            seen_tasks.add(task)
            optimized.append({**step, "task": task})

        return self._enrich_plan(optimized, goal, context)


    def _post_exploit_plan(self, goal: str, state: str):
        post_states = {"root_access_confirmed", "persistence_established", "internal_recon_completed", "exfiltration_completed"}
        if goal == "post_access_inventory" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "post_access_inventory"}]
        if goal == "persistence" and state in post_states:
            if not self._strategy_enabled("auto_persistence", False):
                return []
            plan = []
            if self._strategy_enabled("auto_payload_generation", False):
                plan.append({"agent": "VerificationAgent", "task": "payload_generation"})
            plan.append({"agent": "VerificationAgent", "task": "establish_persistence"})
            return plan
        if goal == "internal_reconnaissance" and state in post_states:
            if not self._strategy_enabled("auto_internal_recon", True):
                return []
            return [{"agent": "VerificationAgent", "task": "internal_network_recon"}]
        if goal == "data_exfiltration" and state in post_states:
            if not self._strategy_enabled("auto_data_exfil", False):
                return []
            return [{"agent": "VerificationAgent", "task": "exfiltrate_data"}]
        if goal == "cleanup" and state in post_states:
            if not self._strategy_enabled("auto_cleanup", False):
                return []
            return [{"agent": "VerificationAgent", "task": "stealth_cleanup"}]
        return None

    def _task_exhausted(self, task: str) -> bool:
        task = self.tool_registry.canonical_task(task)
        return task in self.completed_tasks or task in self.blocked_tasks

    def _enrich_plan(self, plan, goal: str, context: Dict[str, Any]):
        """Add one high-value context-specific task when the plan has room."""
        services = set(context.get("services") or [])
        open_questions = set(context.get("open_questions") or [])
        target_model = context.get("target_model") or {}
        surface_states = target_model.get("surface_states") or context.get("surface_states") or {}
        assets = target_model.get("assets") or {}
        candidates = []
        critical_candidates = set()
        if goal == "vulnerability_assessment":
            if surface_states.get("asm") != "confirmed_present" and self._target_looks_domain(context.get("host", "")):
                candidates.append("asm_discovery")
            if "cpanel_auth_bypass_unknown" in open_questions:
                candidates.append("cpanel_assessment")
                critical_candidates.add("cpanel_assessment")
            if services.intersection({"http", "https"}):
                candidates.append("web_application_mapping")
                candidates.append("web_app_deep_testing")
                candidates.append("template_verification")
                candidates.append("web_vulnerability_testing")
                if surface_states.get("api") != "confirmed_absent":
                    candidates.append("api_security_testing")
            if "https" in services:
                candidates.append("transport_security_assessment")
            if "smb" in services:
                candidates.append("windows_enumeration")
            if services.intersection({"ldap", "kerberos", "winrm", "rdp"}):
                candidates.append("active_directory_enumeration")
                candidates.append("ad_security_review")
            if assets.get("urls") and surface_states.get("web") == "confirmed_present":
                candidates.append("template_verification")
            if surface_states.get("cloud") == "unknown" and assets.get("domains"):
                candidates.append("cloud_security_assessment")
        elif goal == "credential_harvesting":
            if services.intersection({"ldap", "kerberos", "winrm", "rdp", "smb"}):
                candidates.append("active_directory_enumeration")
                candidates.append("kerberos_assessment")
            if "web_credentials_unknown" in context.get("open_questions", []):
                candidates.append("web_credential_testing")
            if "ssh" in services:
                candidates.append("ssh_user_enumeration")
            if "smb" in services:
                candidates.append("windows_enumeration")

        if not candidates:
            return plan

        present = {step.get("task") for step in plan}
        enriched = list(plan)
        short_specialized_vuln_plan = (
            goal == "vulnerability_assessment"
            and len(plan) <= 3
            and "cpanel_assessment" in candidates
        )
        for task in candidates:
            task = self.tool_registry.canonical_task(task)
            if short_specialized_vuln_plan and "cpanel_assessment" in present and task in {
                "web_vulnerability_testing",
                "web_app_deep_testing",
                "template_verification",
                "api_security_testing",
            }:
                continue
            is_critical = task in critical_candidates
            if len(enriched) >= self._plan_enrichment_limit() and not is_critical:
                break
            if task in present or self._task_exhausted(task):
                continue
            if not self.tool_registry.task_has_available_tools(task):
                continue
            insert_at = next(
                (idx for idx, step in enumerate(enriched) if step.get("agent") != "DiscoveryAgent"),
                len(enriched),
            )
            enriched.insert(insert_at, {"agent": "DiscoveryAgent", "task": task})
            present.add(task)
            print(f"[*] Plan enriched with {task} from context services={sorted(services)}")
            if short_specialized_vuln_plan and task == "cpanel_assessment":
                self._trim_low_priority_enrichment(enriched, protected={task})
            elif len(enriched) > self._plan_enrichment_limit():
                self._trim_low_priority_enrichment(enriched, protected={task})

        return self.policy.validate_plan(enriched, context)

    def _plan_enrichment_limit(self) -> int:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        raw = (CFG.get("strategy") or {}).get("plan_enrichment_limit", 8)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return 8
        return max(3, value)

    def _target_looks_domain(self, target: str) -> bool:
        host = (target or "").strip().split("://")[-1].split("/", 1)[0].split(":", 1)[0]
        return bool(re.search(r"[A-Za-z]", host) and "." in host)

    def _trim_low_priority_enrichment(self, plan: List[Dict[str, Any]], protected: set) -> None:
        """Keep plans short while preserving critical context-specific checks."""
        low_priority = [
            "web_application_mapping",
            "web_vulnerability_testing",
            "transport_security_assessment",
            "windows_enumeration",
        ]
        for task in low_priority:
            if task in protected:
                continue
            for idx, step in enumerate(plan):
                if step.get("task") == task:
                    plan.pop(idx)
                    return
        if len(plan) > 3:
            plan.pop(-2)

    def _run_task_commands(self, scan_id: str, target: str, cmds: List[str], fact_label: str, verification: bool = False) -> Dict[str, Any]:
        new_facts = 0
        parsed_facts = 0
        command_results = []
        prefix = "[Running Verification]" if verification else "[Running]"

        for raw_cmd in cmds:
            for cmd in self._expand_command_with_context(raw_cmd, scan_id, target):
                cmd = self._augment_command_with_context(cmd, scan_id, target)
                result = self._execute_pipeline_command(scan_id, target, cmd, fact_label, prefix)
                parsed_facts += result["parsed_facts"]
                new_facts += result["new_facts"]
                command_results.append(result["command_result"])
                active_candidates = self._active_commands_from_facts(result["facts"])

                post_result = self._run_controlled_post_access_followups(scan_id, target, result["facts"])
                parsed_facts += post_result["parsed_facts"]
                new_facts += post_result["new_facts"]
                command_results.extend(post_result["commands"])

                action_result = self._run_fact_driven_actions(scan_id, target, result["facts"])
                parsed_facts += action_result["parsed_facts"]
                new_facts += action_result["new_facts"]
                command_results.extend(action_result["commands"])

                followups = self._followup_commands_from_facts(result["facts"])
                for followup_cmd in followups:
                    follow_result = self._execute_pipeline_command(
                        scan_id, target, followup_cmd, "Verified Fact", "[Running Follow-up]"
                    )
                    parsed_facts += follow_result["parsed_facts"]
                    new_facts += follow_result["new_facts"]
                    command_results.append(follow_result["command_result"])

                    post_result = self._run_controlled_post_access_followups(scan_id, target, follow_result["facts"])
                    parsed_facts += post_result["parsed_facts"]
                    new_facts += post_result["new_facts"]
                    command_results.extend(post_result["commands"])

                    action_result = self._run_fact_driven_actions(scan_id, target, follow_result["facts"])
                    parsed_facts += action_result["parsed_facts"]
                    new_facts += action_result["new_facts"]
                    command_results.extend(action_result["commands"])

                    for active_cmd in self._active_followups_after_verification(
                        target, active_candidates, follow_result["facts"]
                    ):
                        active_result = self._execute_pipeline_command(
                            scan_id, target, active_cmd, "Active Fact", "[Running Active]"
                        )
                        parsed_facts += active_result["parsed_facts"]
                        new_facts += active_result["new_facts"]
                        command_results.append(active_result["command_result"])

                        post_result = self._run_controlled_post_access_followups(scan_id, target, active_result["facts"])
                        parsed_facts += post_result["parsed_facts"]
                        new_facts += post_result["new_facts"]
                        command_results.extend(post_result["commands"])

                        action_result = self._run_fact_driven_actions(scan_id, target, active_result["facts"])
                        parsed_facts += action_result["parsed_facts"]
                        new_facts += action_result["new_facts"]
                        command_results.extend(action_result["commands"])

        self.total_new_facts += new_facts
        return {
            "new_facts": new_facts,
            "parsed_facts": parsed_facts,
            "commands": command_results,
            "reason": self._command_result_reason(command_results, parsed_facts, new_facts),
        }

    def _execute_pipeline_command(self, scan_id: str, target: str, cmd: str,
                                  fact_label: str, prefix: str) -> Dict[str, Any]:
        decision = self.command_scheduler.decide(
            cmd,
            self.fact_store.get_facts(scan_id, target),
            self.executed_command_keys,
        )
        if decision.action == "skip":
            print(f"     [Skipped] {cmd} ({decision.reason})")
            self._record_command_trace(decision.to_dict(), None)
            return self._skipped_command_result(cmd, decision.reason)

        self.executed_command_keys.add(decision.key)
        print(f"     {prefix} {cmd}")
        output = run_arbitrary_cmd(cmd)
        self.tools_run_count += 1
        if cmd.startswith("ssh_inventory "):
            self.executed_post_access_commands.add(cmd)
        output_str = self._output_text(output)
        output_hash = self._output_fingerprint(output_str)
        failed = self._command_failed(output, output_str)
        facts = self.output_parser.parse_tool_output(cmd, output_str)
        stored_facts = list(facts)
        command_new_facts = 0

        for f in facts:
            stored = self._store_fact(scan_id, target, f, cmd)
            stored_facts.extend(stored["derived_facts"])
            if stored["created"]:
                print(f"     [+] {fact_label}: {f['type']} -> {f['value']}")
            command_new_facts += stored["new_facts"]
        self._sync_runtime_credentials_from_facts(target, facts)
        _result_id, unique_output = self.fact_store.add_command_result(
            scan_id=scan_id,
            host=target,
            command_key=decision.key,
            command=cmd,
            output_hash=output_hash,
            output_bytes=len(output_str.encode("utf-8", "ignore")),
            parsed_facts=len(facts),
            new_facts=command_new_facts,
            failed=failed,
        )

        result = {
            "facts": stored_facts,
            "new_facts": command_new_facts,
            "parsed_facts": len(facts),
            "command_result": {
                "command": cmd,
                "failed": failed,
                "output_hash": output_hash,
                "duplicate_output": not unique_output,
                "parsed_facts": len(facts),
                "new_facts": command_new_facts,
                "fact_pairs": [(fact.get("type"), fact.get("value")) for fact in facts],
            },
        }
        self._record_command_trace(decision.to_dict(), result["command_result"])
        return result

    def _skipped_command_result(self, cmd: str, reason: str) -> Dict[str, Any]:
        return {
            "facts": [],
            "new_facts": 0,
            "parsed_facts": 0,
            "command_result": {
                "command": cmd,
                "failed": False,
                "skipped": True,
                "skip_reason": reason,
                "parsed_facts": 0,
                "new_facts": 0,
                "fact_pairs": [],
            },
        }

    def _output_fingerprint(self, output: str) -> str:
        normalized = re.sub(r"\s+", " ", output or "").strip()
        return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()

    def _store_fact(self, scan_id: str, target: str, fact: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Store a parsed fact plus normalized derived facts.

        The canonical fact remains deduplicated; repeated sightings are kept by
        FactStore as observations. Derived facts give later stages stable
        endpoint and graph objects instead of reparsing free-form strings.
        """
        fact = self._scope_normalized_fact(target, fact)
        _fact_id, created = self.fact_store.add_fact_with_status(
            scan_id, target, fact["type"], fact["value"], source,
            confidence=fact.get("confidence", 100),
            session_id=fact.get("session_id", "none"),
        )
        new_facts = 1 if created else 0
        derived_facts = self._derived_facts_from_fact(target, fact, source)
        for derived in derived_facts:
            _derived_id, derived_created = self.fact_store.add_fact_with_status(
                scan_id, target, derived["type"], derived["value"], f"derived:{source}",
                confidence=derived.get("confidence", fact.get("confidence", 80)),
                session_id=fact.get("session_id", "none"),
                derived_from=[_fact_id],
            )
            if derived_created:
                new_facts += 1
        return {
            "created": created,
            "new_facts": new_facts,
            "derived_facts": derived_facts,
        }

    def _scope_normalized_fact(self, target: str, fact: Dict[str, Any]) -> Dict[str, Any]:
        """Prevent external links from becoming in-scope web endpoints.

        Browser/crawler outputs often include vendor/documentation links. They
        are useful context, but they must not enter the target endpoint graph or
        drive follow-up tools unless they are the target host or a subdomain of
        the target domain.
        """
        ftype = str(fact.get("type", "")).strip().lower()
        if ftype not in {"web_endpoint", "web_link", "web_redirect", "browser_rendered"}:
            return fact
        endpoint = self._endpoint_url_from_value(str(fact.get("value", "")))
        if not endpoint or self._endpoint_in_target_scope(endpoint, target):
            return fact
        normalized = dict(fact)
        normalized["type"] = "external_url"
        normalized["value"] = endpoint
        normalized["confidence"] = min(int(normalized.get("confidence", 60) or 60), 70)
        return normalized

    def _derived_facts_from_fact(self, target: str, fact: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
        ftype = str(fact.get("type", "")).lower()
        value = str(fact.get("value", "")).strip()
        derived = []

        endpoint = ""
        if ftype == "port_open":
            endpoint = self._endpoint_from_port_fact(target, value)
        elif ftype == "browser_rendered":
            endpoint = self._canonical_endpoint_value(value)
        elif ftype in {
            "web_title", "web_server", "web_surface", "web_link",
            "web_redirect", "web_powered_by", "web_input",
        }:
            endpoint = self._endpoint_from_command_source(source)
        if endpoint:
            derived.append({"type": "web_endpoint", "value": endpoint, "confidence": 90})

        graph_facts = self._network_graph_facts(target, ftype, value)
        derived.extend(graph_facts)
        return derived

    def _endpoint_from_port_fact(self, target: str, value: str) -> str:
        match = re.match(r"(\d+)/(?:tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value.lower())
        if not match:
            return ""
        port, service, banner = match.groups()
        text = f"{service or ''} {banner or ''}"
        if not self._service_fact_looks_web(service, text):
            return ""
        scheme = "https" if self._service_fact_looks_tls(text) else "http"
        host = self._target_host(target)
        if not host:
            return ""
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            url = f"{scheme}://{host}/"
        else:
            url = f"{scheme}://{host}:{port}/"
        return self._canonical_endpoint_value(url, service=service, port=port)

    def _endpoint_from_command_source(self, source: str) -> str:
        match = re.search(r'\bhttps?://[^\s]+', source or "", re.IGNORECASE)
        if not match:
            return ""
        return self._canonical_endpoint_value(match.group(0))

    def _canonical_endpoint_value(self, url: str, service: str = "", port: str = "") -> str:
        raw = (url or "").strip()
        if not raw:
            return ""
        if not re.match(r"^https?://", raw, re.IGNORECASE):
            raw = f"http://{raw}"
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        parsed_port = parsed.port
        if parsed_port is None:
            parsed_port = 443 if parsed.scheme.lower() == "https" else 80
        path = parsed.path or "/"
        netloc = parsed.hostname.lower()
        if not ((parsed.scheme.lower() == "http" and parsed_port == 80)
                or (parsed.scheme.lower() == "https" and parsed_port == 443)):
            netloc = f"{netloc}:{parsed_port}"
        canonical_url = urlunparse((
            parsed.scheme.lower(), netloc, path, "", parsed.query, "",
        ))
        return json.dumps({
            "url": canonical_url,
            "scheme": parsed.scheme.lower(),
            "host": parsed.hostname.lower(),
            "port": str(port or parsed_port),
            "path": path,
            "service": service or "",
            "status": "",
            "title": "",
        }, sort_keys=True)

    def _network_graph_facts(self, target: str, ftype: str, value: str) -> List[Dict[str, Any]]:
        host = self._target_host(target)
        if not host:
            return []
        facts = []
        if ftype == "internal_host":
            facts.append({
                "type": "network_node",
                "value": json.dumps({"kind": "host", "id": value}, sort_keys=True),
                "confidence": 85,
            })
            facts.append({
                "type": "network_edge",
                "value": json.dumps({
                    "from": host, "to": value, "type": "observed_internal_host",
                }, sort_keys=True),
                "confidence": 85,
            })
        elif ftype == "internal_subnet":
            subnet_ip = value.split("/", 1)[0]
            interface_id = f"{host}:iface:{subnet_ip}"
            facts.append({
                "type": "network_node",
                "value": json.dumps({"kind": "interface", "id": interface_id, "host": host, "address": subnet_ip, "subnet": value}, sort_keys=True),
                "confidence": 85,
            })
            facts.append({
                "type": "network_node",
                "value": json.dumps({"kind": "subnet", "id": value}, sort_keys=True),
                "confidence": 85,
            })
            facts.append({
                "type": "network_edge",
                "value": json.dumps({
                    "from": host, "to": interface_id, "type": "has_interface",
                }, sort_keys=True),
                "confidence": 85,
            })
            facts.append({
                "type": "network_edge",
                "value": json.dumps({
                    "from": interface_id, "to": value, "type": "attached_to_subnet",
                }, sort_keys=True),
                "confidence": 85,
            })
            facts.append({
                "type": "network_edge",
                "value": json.dumps({
                    "from": host, "to": value, "type": "attached_subnet",
                }, sort_keys=True),
                "confidence": 85,
            })
        elif ftype == "port_open":
            match = re.match(r"(\d+)/(tcp|udp)\s+\(([^)]*)\)", value.lower())
            if match:
                port, proto, service = match.groups()
                facts.append({
                    "type": "network_node",
                    "value": json.dumps({"kind": "service", "host": host, "port": port, "proto": proto, "service": service}, sort_keys=True),
                    "confidence": 85,
                })
                facts.append({
                    "type": "network_edge",
                    "value": json.dumps({"from": host, "to": f"{host}:{port}/{proto}", "type": "listens_on"}, sort_keys=True),
                    "confidence": 85,
                })
        return facts

    def _followup_commands_from_facts(self, facts: List[Dict[str, Any]]) -> List[str]:
        """Run safe verification commands emitted by earlier tools once."""
        commands = []
        allowed_prefixes = ("msf_check ", "searchsploit ", "plugin ")
        limit = self._strategy_limit("verification_followup_commands", None)
        for fact in facts:
            if fact.get("type") != "verification_command":
                continue
            cmd = str(fact.get("value", "")).strip()
            if not cmd or not cmd.startswith(allowed_prefixes):
                continue
            if cmd.startswith("msf_check ") and not self.tool_registry._is_tool_available("msf_check"):
                continue
            if cmd.startswith("plugin ") and not any(token in cmd for token in (" scan", " check", " list")):
                continue
            if cmd in self.executed_followup_commands:
                continue
            self.executed_followup_commands.add(cmd)
            commands.append(cmd)
            if limit is not None and len(commands) >= limit:
                break
        return commands

    def _run_fact_driven_actions(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run deterministic next actions implied by concrete facts.

        New facts are fed back into the selector for a bounded number of layers
        so crawl, inventory, and verification outputs can naturally drive the
        next concrete step without waiting for another Director loop.
        """
        parsed_facts = 0
        new_facts = 0
        command_results = []

        max_depth = self._fact_action_max_depth()
        max_commands = self._fact_action_max_commands()
        commands_started = 0
        pending_batches = [(0, facts or [])]

        def enqueue_result(result: Dict[str, Any], depth: int) -> None:
            if max_depth is not None and depth >= max_depth:
                return
            if result.get("new_facts", 0) <= 0:
                return
            result_facts = result.get("facts") or []
            if result_facts:
                pending_batches.append((depth + 1, result_facts))

        while pending_batches and (max_commands is None or commands_started < max_commands):
            depth, batch_facts = pending_batches.pop(0)
            if (max_depth is not None and depth > max_depth) or not batch_facts:
                continue

            for cmd in self._fact_driven_action_commands(scan_id, target, batch_facts):
                if max_commands is not None and commands_started >= max_commands:
                    break
                result = self._execute_pipeline_command(
                    scan_id, target, cmd, "Action Fact", "[Running Action]"
                )
                commands_started += 1
                parsed_facts += result["parsed_facts"]
                new_facts += result["new_facts"]
                command_results.append(result["command_result"])
                enqueue_result(result, depth)
                active_candidates = self._active_commands_from_facts(result["facts"])

                post_result = self._run_controlled_post_access_followups(scan_id, target, result["facts"])
                parsed_facts += post_result["parsed_facts"]
                new_facts += post_result["new_facts"]
                command_results.extend(post_result["commands"])
                if post_result.get("commands"):
                    commands_started += len(post_result["commands"])
                enqueue_result(post_result, depth)

                for followup_cmd in self._followup_commands_from_facts(result["facts"]):
                    if max_commands is not None and commands_started >= max_commands:
                        break
                    follow_result = self._execute_pipeline_command(
                        scan_id, target, followup_cmd, "Verified Fact", "[Running Follow-up]"
                    )
                    commands_started += 1
                    parsed_facts += follow_result["parsed_facts"]
                    new_facts += follow_result["new_facts"]
                    command_results.append(follow_result["command_result"])
                    enqueue_result(follow_result, depth)

                    post_result = self._run_controlled_post_access_followups(scan_id, target, follow_result["facts"])
                    parsed_facts += post_result["parsed_facts"]
                    new_facts += post_result["new_facts"]
                    command_results.extend(post_result["commands"])
                    if post_result.get("commands"):
                        commands_started += len(post_result["commands"])
                    enqueue_result(post_result, depth)

                    for active_cmd in self._active_followups_after_verification(
                        target, active_candidates, follow_result["facts"]
                    ):
                        if max_commands is not None and commands_started >= max_commands:
                            break
                        active_result = self._execute_pipeline_command(
                            scan_id, target, active_cmd, "Active Fact", "[Running Active]"
                        )
                        commands_started += 1
                        parsed_facts += active_result["parsed_facts"]
                        new_facts += active_result["new_facts"]
                        command_results.append(active_result["command_result"])
                        enqueue_result(active_result, depth)

                        post_result = self._run_controlled_post_access_followups(scan_id, target, active_result["facts"])
                        parsed_facts += post_result["parsed_facts"]
                        new_facts += post_result["new_facts"]
                        command_results.extend(post_result["commands"])
                        if post_result.get("commands"):
                            commands_started += len(post_result["commands"])
                        enqueue_result(post_result, depth)
        return {
            "parsed_facts": parsed_facts,
            "new_facts": new_facts,
            "commands": command_results,
        }

    def _fact_action_max_depth(self):
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        raw = CFG.get("strategy", {}).get("fact_action_max_depth", 0)
        if str(raw).strip().lower() in {"", "0", "-1", "none", "unlimited", "false"}:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return None if value <= 0 else max(1, value)

    def _fact_action_max_commands(self):
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        raw = CFG.get("strategy", {}).get("fact_action_max_commands", 0)
        if str(raw).strip().lower() in {"", "0", "-1", "none", "unlimited", "false"}:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return None if value <= 0 else max(1, value)

    def _fact_driven_action_commands(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]]
    ) -> List[str]:
        """Map facts to safe deterministic follow-up actions."""
        commands = []
        all_facts = self.fact_store.get_facts(scan_id, target)
        all_pairs = {
            (str(fact.get("type", "")).lower(), str(fact.get("value", "")).lower())
            for fact in all_facts
        }

        inventory_seen = self._post_access_inventory_seen(all_pairs)
        ssh_creds_available = self._facts_include_cached_ssh_credential(facts)
        ssh_access_confirmed = (
            self._facts_confirm_ssh_access(facts)
            or self._facts_confirm_ssh_access(all_facts)
        )
        if self._auto_ssh_inventory_enabled() and not inventory_seen and (ssh_creds_available or ssh_access_confirmed):
            commands.append(f"ssh_inventory {target}")

        if self._facts_indicate_cpanel_surface(facts) and not self._cpanel_already_verified(all_pairs):
            commands.append(f"plugin cpanel_auth_bypass {target} scan")

        commands.extend(self._service_intelligence_commands(scan_id, target, facts, all_pairs))
        commands.extend(self._service_action_commands(target, facts, all_pairs))
        commands.extend(self._web_path_action_commands(scan_id, target, facts))
        commands.extend(self._web_link_action_commands(scan_id, target, facts))
        commands.extend(self._web_surface_action_commands(scan_id, target, facts, all_pairs))

        deduped = []
        for cmd in commands:
            cmd = self._augment_command_with_context(cmd, scan_id, target)
            if cmd in self.executed_fact_action_commands:
                continue
            self.executed_fact_action_commands.add(cmd)
            deduped.append(cmd)
            batch_limit = self._strategy_limit("fact_action_batch_commands", None)
            if batch_limit is not None and len(deduped) >= batch_limit:
                break
        return deduped

    def _facts_include_cached_ssh_credential(self, facts: List[Dict[str, Any]]) -> bool:
        for fact in facts:
            if str(fact.get("type", "")).lower() != "credential":
                continue
            value = str(fact.get("value", "")).strip()
            if value.startswith("ssh_key_available:"):
                return True
            if value.startswith("ssh_login_success:"):
                return True
            if re.match(r"[^:\s]+:[^\s]+\s+\(cached\)", value):
                return True
        return False

    def _service_intelligence_commands(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]], all_pairs: set
    ) -> List[str]:
        """Run version-to-exploit intelligence for newly observed services."""
        evidence_keys = [
            key for key in (
                self._service_intelligence_evidence_key(fact)
                for fact in facts
            )
            if key
        ]
        new_evidence = [
            key for key in evidence_keys
            if key not in self.service_intelligence_evidence_seen
        ]
        if not new_evidence:
            return []
        self.service_intelligence_evidence_seen.update(new_evidence)

        commands = []
        commands.append(f"exploit_select {target}")

        for query in self._searchsploit_queries_from_facts(facts):
            if self._searchsploit_query_seen(all_pairs, query):
                continue
            if not self.tool_registry._is_tool_available("searchsploit"):
                continue
            commands.append(f"searchsploit {query}")
            query_limit = self._strategy_limit("searchsploit_followup_queries", None)
            if query_limit is not None and len(commands) >= query_limit:
                break

        return commands

    def _service_intelligence_evidence_key(self, fact: Dict[str, Any]) -> str:
        ftype = str(fact.get("type", "")).lower()
        value = str(fact.get("value", "")).strip().lower()
        service_types = {
            "port_open", "service_version", "web_server", "web_powered_by",
            "app_stack", "browser_rendered", "local_listening_port",
            "web_title", "web_surface", "web_input", "web_link",
            "web_endpoint", "web_root", "app_manifest", "config_candidate",
        }
        if ftype not in service_types or not value:
            return ""
        if ftype == "web_link" and not self._web_link_looks_interesting(value):
            return ""
        return f"{ftype}:{value[:220]}"

    def _facts_include_service_evidence(self, facts: List[Dict[str, Any]]) -> bool:
        service_types = {
            "port_open", "service_version", "web_server", "web_powered_by",
            "app_stack", "browser_rendered", "local_listening_port",
            "web_title", "web_surface", "web_input", "web_link",
            "web_endpoint", "web_root", "app_manifest", "config_candidate",
        }
        return any(str(fact.get("type", "")).lower() in service_types for fact in facts)

    def _searchsploit_query_seen(self, fact_pairs: set, query: str) -> bool:
        normalized = self._normalize_query_token(query)
        return any(
            ftype == "service_status" and value == f"searchsploit_queried:{normalized}"
            for ftype, value in fact_pairs
        )

    def _searchsploit_queries_from_facts(self, facts: List[Dict[str, Any]]) -> List[str]:
        queries = []
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).strip()
            query = ""
            if ftype == "service_version":
                parts = value.split(":", 2)
                if len(parts) == 3:
                    service, _port, version = parts
                    query = f"{service} {version}"
                else:
                    query = value
            elif ftype == "port_open":
                match = re.match(r"\d+/(?:tcp|udp)\s+\(([^)]*)\)(?:\s+\[(.*?)\])?", value, re.IGNORECASE)
                if match:
                    service, version = match.groups()
                    query = f"{service} {version or ''}".strip()
            elif ftype == "web_server":
                query = value
            elif ftype == "app_stack":
                query = value
            elif ftype == "local_listening_port":
                query = self._service_name_for_common_port(value)
            elif ftype == "web_title":
                lowered = value.lower()
                if "nginx" in lowered:
                    query = "nginx"
                elif "apache" in lowered:
                    query = "apache"
                elif "wordpress" in lowered:
                    query = "wordpress"
            elif ftype == "app_manifest":
                query = self._query_from_manifest_path(value)
            elif ftype == "config_candidate":
                query = self._query_from_config_path(value)
            query = self._sanitize_searchsploit_query(query)
            if query and query not in queries:
                queries.append(query)
        return queries

    def _service_name_for_common_port(self, port: str) -> str:
        mapping = {
            "21": "ftp", "22": "openssh", "25": "smtp", "53": "dns",
            "80": "http", "110": "pop3", "143": "imap", "443": "https",
            "445": "smb", "587": "smtp", "993": "imap", "995": "pop3",
            "3000": "node express", "3306": "mysql", "5432": "postgresql",
            "6379": "redis", "8000": "http", "8080": "http",
            "8443": "https", "9000": "http", "9200": "elasticsearch",
            "27017": "mongodb",
        }
        return mapping.get(str(port).strip(), "")

    def _query_from_manifest_path(self, path: str) -> str:
        name = (path or "").rsplit("/", 1)[-1].lower()
        mapping = {
            "package.json": "nodejs",
            "composer.json": "php",
            "requirements.txt": "python",
            "pyproject.toml": "python",
            "go.mod": "golang",
            "gemfile": "ruby",
            "pom.xml": "java",
        }
        return mapping.get(name, "")

    def _query_from_config_path(self, path: str) -> str:
        name = (path or "").rsplit("/", 1)[-1].lower()
        mapping = {
            ".env": "environment file disclosure",
            "wp-config.php": "wordpress",
            "config.php": "php",
            "settings.py": "django",
            "database.yml": "rails",
            "application.yml": "spring",
        }
        return mapping.get(name, "")

    def _sanitize_searchsploit_query(self, query: str) -> str:
        query = re.sub(r"[^A-Za-z0-9._:+ /-]+", " ", query or "")
        query = re.sub(r"\s+", " ", query).strip()
        stopwords = {"unknown", "tcpwrapped"}
        parts = [part for part in query.split() if part.lower() not in stopwords]
        return " ".join(parts[:6])

    def _normalize_query_token(self, query: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", (query or "").lower()).strip("_")[:120]

    def _post_access_inventory_seen(self, fact_pairs: set) -> bool:
        for ftype, value in fact_pairs:
            if ftype == "post_exploit_stage" and value == "post_access_inventory_completed":
                return True
            if ftype == "service_status" and value == "ssh_inventory_completed":
                return True
        return False

    def _facts_indicate_cpanel_surface(self, facts: List[Dict[str, Any]]) -> bool:
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).lower()
            if ftype == "application_access" and "cpanel" in value:
                return False
            if ftype in {"port_open", "web_surface", "web_server", "web_redirect"}:
                if any(marker in value for marker in ("cpanel", "whm", ":2082", ":2083", ":2086", ":2087")):
                    return True
        return False

    def _cpanel_already_verified(self, fact_pairs: set) -> bool:
        for ftype, value in fact_pairs:
            if ftype == "application_access" and "cpanel_whm_authenticated" in value:
                return True
            if ftype == "vulnerability" and "cpanel_auth_bypass" in value:
                return True
            if ftype == "credential" and ("whm_session:" in value or "cpanel_session:" in value):
                return True
        return False

    def _service_action_commands(
        self, target: str, facts: List[Dict[str, Any]], all_pairs: set
    ) -> List[str]:
        """Add deterministic protocol-specific probes for newly observed services."""
        commands = []
        for port, service, value in self._open_service_ports(facts):
            if self._is_ftp_service(port, service, value):
                if not self._service_status_seen(all_pairs, ("ftp_anonymous_allowed", "ftp_anonymous_denied", "ftp_probe_failed"), port):
                    commands.append(f"ftp_anonymous_check {target} {port}")
                continue

            if self._is_smtp_service(port, service, value):
                if not self._service_status_seen(all_pairs, ("smtp_probe_completed", "smtp_probe_failed"), port):
                    commands.append(f"smtp_probe {target} {port}")
                continue

            db_service = self._database_service_for_port(port, service, value)
            if db_service:
                if not self._database_inventory_seen(all_pairs, db_service, port):
                    if self._has_database_credentials(target, db_service):
                        commands.append(f"db_inventory {target} {port} {db_service}")
        return commands

    def _open_service_ports(self, facts: List[Dict[str, Any]]) -> List[tuple]:
        ports = []
        for fact in facts:
            if str(fact.get("type", "")).lower() != "port_open":
                continue
            value = str(fact.get("value", ""))
            match = re.match(r"(\d+)/(?:tcp|udp)\s+\(([^)]*)\)", value, re.IGNORECASE)
            if not match:
                continue
            ports.append((match.group(1), match.group(2).lower(), value.lower()))
        return ports

    def _service_status_seen(self, fact_pairs: set, prefixes: tuple, port: str) -> bool:
        for ftype, value in fact_pairs:
            if ftype != "service_status":
                continue
            if any(value.startswith(prefix) and (value.endswith(f":{port}") or f":{port}:" in value) for prefix in prefixes):
                return True
        return False

    def _is_ftp_service(self, port: str, service: str, value: str) -> bool:
        if port == "21":
            return True
        return "ftp" in service and "sftp" not in service and "ssh" not in value

    def _is_smtp_service(self, port: str, service: str, value: str) -> bool:
        if port in {"25", "465", "587", "2525"}:
            return True
        return any(marker in service or marker in value for marker in ("smtp", "submission", "smtps"))

    def _database_service_for_port(self, port: str, service: str, value: str) -> str:
        if port == "5432" or "postgres" in service or "postgres" in value:
            return "postgresql"
        if port in {"3306", "33060"} or "mysql" in service or "mariadb" in service or "mysql" in value or "mariadb" in value:
            return "mysql"
        return ""

    def _database_inventory_seen(self, fact_pairs: set, service: str, port: str) -> bool:
        for ftype, value in fact_pairs:
            if ftype != "service_status":
                continue
            if value.startswith(("db_inventory_completed:", "db_inventory_failed:")):
                if f":{service}:{port}" in value or value.endswith(f":{port}"):
                    return True
        return False

    def _has_database_credentials(self, target: str, service: str) -> bool:
        creds = self._known_credentials_for_target(target)
        candidate_keys = {service}
        if service == "postgresql":
            candidate_keys.add("postgres")
            candidate_keys.add("pgsql")
        if service == "mysql":
            candidate_keys.add("mariadb")
        return any(creds.get(key) for key in candidate_keys)

    def _web_path_action_commands(self, scan_id: str, target: str, facts: List[Dict[str, Any]]) -> List[str]:
        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
            endpoints = [f"http://{host}"]
        base = endpoints[0].rstrip("/")
        commands = []
        for fact in facts:
            if fact.get("type") != "web_path":
                continue
            value = str(fact.get("value", ""))
            path, _, status = value.partition(":")
            path = "/" + path.strip().lstrip("/")
            if path in {"/", ""}:
                continue
            is_interesting = (
                status in {"200", "301", "302", "401", "403"}
                or any(word in path.lower() for word in self._interesting_web_words())
            )
            if not is_interesting:
                continue
            url = f"{base}{path}"
            commands.append(f"curl_headers {url}")
            commands.append(f"scrapling {url}")
            path_limit = self._strategy_limit("web_path_followup_commands", None)
            if path_limit is not None and len(commands) >= path_limit:
                break
        return commands

    def _web_link_action_commands(self, scan_id: str, target: str, facts: List[Dict[str, Any]]) -> List[str]:
        urls = self._normalized_web_link_urls(scan_id, target, facts)
        commands = []
        limit = self._web_link_followup_command_limit()
        for url in urls:
            if self._url_looks_javascript_asset(url):
                commands.append(f"js_route_extract {url}")
                if limit is not None and len(commands) >= limit:
                    break
                continue
            commands.append(f"curl_headers {url}")
            if limit is not None and len(commands) >= limit:
                break
            commands.append(f"scrapling {url}")
            if limit is not None and len(commands) >= limit:
                break
            if self._url_looks_openapi_spec(url):
                commands.append(f"openapi_import {url}")
                if limit is not None and len(commands) >= limit:
                    break
            if self._url_looks_graphql_endpoint(url):
                commands.append(f"graphql_check {url}")
                if limit is not None and len(commands) >= limit:
                    break
        return commands

    def _normalized_web_link_urls(self, scan_id: str, target: str, facts: List[Dict[str, Any]]) -> List[str]:
        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            host = self._target_host(target)
            endpoints = [f"http://{host}"] if host else []
        if not endpoints:
            return []

        allowed_hosts = {
            parsed.hostname.lower()
            for parsed in (urlparse(endpoint) for endpoint in endpoints)
            if parsed.hostname
        }
        target_host = self._target_host(target)
        if target_host:
            allowed_hosts.add(target_host.lower())

        urls = []
        seen = set()
        for fact in facts:
            if str(fact.get("type", "")).lower() != "web_link":
                continue
            raw_link = str(fact.get("value", "")).strip()
            if not self._web_link_looks_interesting(raw_link):
                continue
            candidate_urls = []
            if re.match(r"^https?://", raw_link, re.IGNORECASE) or raw_link.startswith("//"):
                candidate_urls.append(self._normalize_web_link_url(raw_link, endpoints[0], allowed_hosts))
            else:
                for endpoint in endpoints:
                    candidate_urls.append(self._normalize_web_link_url(raw_link, endpoint, allowed_hosts))

            for url in candidate_urls:
                if not url or url in seen:
                    continue
                seen.add(url)
                urls.append(url)
                url_limit = self._strategy_limit("web_link_url_limit", None)
                if url_limit is not None and len(urls) >= url_limit:
                    return urls
        return urls

    def _normalize_web_link_url(self, raw_link: str, base: str, allowed_hosts: set) -> str:
        link = (raw_link or "").strip().strip("\"'<>")
        link = re.sub(r"[\s)\],;]+$", "", link)
        if not link:
            return ""
        if link.startswith("#"):
            return ""
        if re.match(r"^(?:javascript|mailto|tel|data):", link, re.IGNORECASE):
            return ""

        base_url = base.rstrip("/") + "/"
        if link.startswith("//"):
            base_scheme = urlparse(base_url).scheme or "http"
            url = f"{base_scheme}:{link}"
        elif re.match(r"^https?://", link, re.IGNORECASE):
            url = link
        else:
            url = urljoin(base_url, link)

        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.hostname.lower() not in allowed_hosts:
            return ""

        path = parsed.path or "/"
        if path == "/" and not parsed.query:
            return ""
        if self._web_path_is_static(path) and not path.lower().endswith((".js", ".mjs")):
            return ""

        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            "",
            parsed.query,
            "",
        ))

    def _web_link_looks_interesting(self, raw_link: str) -> bool:
        link = (raw_link or "").strip().strip("\"'<>").lower()
        if not link or link.startswith("#"):
            return False
        if re.match(r"^(?:javascript|mailto|tel|data):", link):
            return False
        path = urlparse(link).path if re.match(r"^https?://", link) else link.split("?", 1)[0].split("#", 1)[0]
        if path.lower().endswith((".js", ".mjs")):
            return True
        if self._web_path_is_static(path):
            return False
        if any(word in link for word in self._interesting_web_words()):
            return True
        return path not in {"", "/", "./", "../"}

    def _web_path_is_static(self, path: str) -> bool:
        return (path or "").lower().endswith((
            ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg",
            ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov",
        ))

    def _interesting_web_words(self) -> tuple:
        return (
            "admin", "login", "signin", "auth", "account", "report",
            "_reports", "api", "dashboard", "cpanel", "whm", "wp-admin",
            "phpmyadmin", "grafana", "metrics", "health", "status",
            "config", "setup", "install",
            "swagger", "openapi", "api-docs", "graphql",
        )

    def _url_looks_openapi_spec(self, url: str) -> bool:
        path = (urlparse(url or "").path or "").lower()
        return any(marker in path for marker in (
            "swagger.json", "openapi.json", "openapi.yaml", "openapi.yml",
            "api-docs", "swagger/v1", "swagger/v2", "swagger/v3",
        ))

    def _url_looks_graphql_endpoint(self, url: str) -> bool:
        return (urlparse(url or "").path or "").lower().rstrip("/") == "/graphql"

    def _url_looks_javascript_asset(self, url: str) -> bool:
        return (urlparse(url or "").path or "").lower().endswith((".js", ".mjs"))

    def _web_link_followup_command_limit(self):
        return self._strategy_limit("web_link_followup_commands", None)

    def _target_host(self, target: str) -> str:
        return (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]

    def _web_surface_action_commands(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]], all_pairs: set
    ) -> List[str]:
        """Render/crawl discovered web surfaces once, using ShardBrowser fallback when needed."""
        if not self._facts_include_web_surface(facts):
            return []
        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
            endpoints = [f"http://{host}"]
        commands = []
        endpoint_limit = self._strategy_limit("web_surface_endpoint_limit", None)
        command_limit = self._strategy_limit("web_surface_followup_commands", None)
        selected_endpoints = endpoints if endpoint_limit is None else endpoints[:endpoint_limit]
        for endpoint in selected_endpoints:
            if not self._browser_render_seen(all_pairs, endpoint):
                commands.append(f"browser_surface_analysis {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if self.tool_registry._is_tool_available("security_headers_check"):
                commands.append(f"security_headers_check {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if self.tool_registry._is_tool_available("cors_check"):
                commands.append(f"cors_check {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if not self._crawl_seen(all_pairs, endpoint):
                commands.append(f"scrapling_crawl {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if self.tool_registry._is_tool_available("nuclei_safe"):
                commands.append(f"nuclei_safe {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if self.tool_registry._is_tool_available("katana_crawl"):
                commands.append(f"katana_crawl {endpoint}")
            if command_limit is not None and len(commands) >= command_limit:
                break
        return commands

    def _facts_include_web_surface(self, facts: List[Dict[str, Any]]) -> bool:
        return any(
            str(fact.get("type", "")).lower() in {
                "port_open", "web_server", "web_title", "web_surface",
                "web_endpoint", "web_link", "web_input", "web_redirect", "browser_rendered",
                "asset_url", "technology", "nuclei_finding",
            }
            and any(marker in str(fact.get("value", "")).lower() for marker in (
                "http", "nginx", "apache", "wordpress", "login", "form", "80", "443",
                "8080", "8443", "3000", "9000",
            ))
            for fact in facts
        )

    def _browser_render_seen(self, fact_pairs: set, endpoint: str) -> bool:
        endpoint_l = endpoint.lower().rstrip("/")
        return any(
            ftype == "browser_rendered" and value.rstrip("/") == endpoint_l
            for ftype, value in fact_pairs
        )

    def _crawl_seen(self, fact_pairs: set, endpoint: str) -> bool:
        endpoint_l = endpoint.lower().rstrip("/")
        return any(
            ftype == "service_status" and value == f"web_crawl_completed:{endpoint_l}"
            for ftype, value in fact_pairs
        )

    def _sync_runtime_credentials_from_facts(self, target: str, facts: List[Dict[str, Any]]) -> None:
        """Mirror concrete SSH credentials from parsed facts into the tool cache."""
        try:
            from core.tools.exploit_tools import register_credential
        except Exception as exc:
            logger.debug("Could not sync runtime credentials: %s", exc)
            return

        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        for fact in facts:
            if fact.get("type") != "credential":
                continue
            value = str(fact.get("value", "")).strip()
            key_match = re.match(r"ssh_key_available:([^@\s]+)@([^\s]+)", value)
            if key_match:
                user, cred_host = key_match.groups()
                if cred_host == host:
                    register_credential("ssh", host, user, "__KEY_AUTH__")
                continue

            cached_match = re.match(r"([^:\s]+):([^\s]+)\s+\(cached\)", value)
            if cached_match and not value.startswith(("whm_session:", "cpanel_session:")):
                user, password = cached_match.groups()
                register_credential("ssh", host, user, password)

    def _known_credentials_for_target(self, target: str) -> Dict[str, List[tuple]]:
        """Read known credentials from the unified store/legacy cache."""
        try:
            from core.tools.exploit_tools import get_all_known_creds_for_target
        except Exception as exc:
            logger.debug("Could not read known credentials: %s", exc)
            return {}
        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        return get_all_known_creds_for_target(host) or {}

    def _seed_known_credentials(self, scan_id: str, target: str) -> int:
        """Persist cached credentials as facts so state/context can use them."""
        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        seeded = 0
        for service, cred_list in self._known_credentials_for_target(host).items():
            for user, password in cred_list:
                if not user or not password:
                    continue
                if service == "ssh" and password == "__KEY_AUTH__":
                    fact_type = "credential"
                    fact_value = f"ssh_key_available:{user}@{host}"
                elif service == "ssh":
                    fact_type = "credential"
                    fact_value = f"{user}:{password} (cached)"
                else:
                    fact_type = "credential"
                    fact_value = f"{service}_credential:{user}@{host}"
                _fid, created = self.fact_store.add_fact_with_status(
                    scan_id, host, fact_type, fact_value, "credential_store",
                    confidence=90,
                    session_id="credential_store",
                )
                if created:
                    seeded += 1
                    self.total_new_facts += 1
                    print(f"    [+] Known Credential: {service}://{user}@{host}")
        return seeded

    def _run_controlled_post_access_followups(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        parsed_facts = 0
        new_facts = 0
        command_results = []
        result_facts = []
        for cmd in self._controlled_post_access_commands_from_facts(target, facts):
            result = self._execute_pipeline_command(
                scan_id, target, cmd, "Post-Access Fact", "[Running Controlled Post-Access]"
            )
            parsed_facts += result["parsed_facts"]
            new_facts += result["new_facts"]
            command_results.append(result["command_result"])
            result_facts.extend(result["facts"])
        return {
            "parsed_facts": parsed_facts,
            "new_facts": new_facts,
            "commands": command_results,
            "facts": result_facts,
        }

    def _controlled_post_access_commands_from_facts(
        self, target: str, facts: List[Dict[str, Any]]
    ) -> List[str]:
        """Run read-only SSH inventory once after confirmed SSH authentication."""
        if not self._auto_ssh_inventory_enabled():
            return []
        if not self._facts_confirm_ssh_access(facts):
            return []
        cmd = f"ssh_inventory {target}"
        if cmd in self.executed_post_access_commands:
            return []
        self.executed_post_access_commands.add(cmd)
        return [cmd]

    def _facts_confirm_ssh_access(self, facts: List[Dict[str, Any]]) -> bool:
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).lower()
            if ftype == "credential" and value.startswith("ssh_login_success:"):
                return True
            if ftype == "service_status" and value == "ssh_authenticated":
                return True
        return False

    def _auto_ssh_inventory_enabled(self) -> bool:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        strategy = CFG.get("strategy", {})
        return bool(strategy.get(
            "auto_post_access_inventory",
            strategy.get("auto_ssh_inventory", True),
        ))

    def _strategy_enabled(self, key: str, default: bool = False) -> bool:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        return bool(CFG.get("strategy", {}).get(key, default))

    def _strategy_limit(self, key: str, default=None):
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        raw = CFG.get("strategy", {}).get(key, default)
        if raw is None:
            return None
        if str(raw).strip().lower() in {"", "0", "-1", "none", "unlimited", "false"}:
            return None
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return None
        return None if value <= 0 else max(1, value)

    def _active_commands_from_facts(self, facts: List[Dict[str, Any]]) -> List[str]:
        """Collect gated active commands for later execution after verification."""
        commands = []
        for fact in facts:
            if fact.get("type") != "active_command":
                continue
            cmd = str(fact.get("value", "")).strip()
            if not cmd.startswith("msf_run "):
                continue
            if cmd in commands:
                continue
            commands.append(cmd)
        return commands[:3]

    def _active_followups_after_verification(
        self, target: str, candidates: List[str], verification_facts: List[Dict[str, Any]]
    ) -> List[str]:
        """Promote msf_run only after msf_check positively verifies the same module."""
        if not candidates or not self._active_msf_allowed(target):
            return []

        positive_modules = set()
        for fact in verification_facts:
            if fact.get("type") != "vulnerability":
                continue
            value = str(fact.get("value", ""))
            if value.startswith("msf_check_positive:"):
                positive_modules.add(value.split(":", 1)[1])

        commands = []
        for cmd in candidates:
            parts = cmd.split()
            module = parts[2] if len(parts) >= 3 else ""
            if module not in positive_modules:
                continue
            if cmd in self.executed_active_commands:
                continue
            if len(self.executed_active_commands) >= self._max_active_msf_runs():
                break
            self.executed_active_commands.add(cmd)
            commands.append(cmd)
        return commands

    def _active_msf_allowed(self, target: str) -> bool:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        strategy = CFG.get("strategy", {})
        if not strategy.get("allow_active_msf", False):
            return False
        if not strategy.get("active_authorized", False):
            return False
        return self._target_in_authorized_scope(target, strategy.get("authorized_targets", []))

    def _max_active_msf_runs(self) -> int:
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        return max(0, int(CFG.get("strategy", {}).get("max_active_msf_runs_per_scan", 1)))

    def _target_in_authorized_scope(self, target: str, scopes: List[str]) -> bool:
        if not scopes:
            return False
        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        for scope in scopes:
            scope = str(scope or "").strip()
            if not scope:
                continue
            if scope in {"*", "all"}:
                return True
            if fnmatch.fnmatch(host, scope):
                return True
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(scope, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _expand_command_with_context(self, cmd: str, scan_id: str, target: str) -> List[str]:
        """Expand generic web commands across discovered HTTP endpoints."""
        parts = (cmd or "").strip().split(maxsplit=1)
        if len(parts) != 2:
            return [cmd]
        tool, arg = parts[0], parts[1].strip()
        if tool == "bruteforce" and arg == f"ssh {target}":
            if self._known_credentials_for_target(target).get("ssh"):
                return [f"ssh_session {target}"]
        if arg != target:
            return [cmd]

        web_mapping_tools = {
            "whatweb", "curl_headers", "scrapling", "browser_surface_analysis",
            "scrapling_crawl", "ffuf", "nikto", "jmx2rce_scan", "wpscan", "sqlmap",
        }
        if tool not in web_mapping_tools:
            return [cmd]

        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            return [cmd]
        limit = self._strategy_limit(f"{tool}_endpoint_limit", None)
        selected = endpoints if limit is None else endpoints[:limit]
        return [f"{tool} {endpoint}" for endpoint in selected]

    def _web_endpoints_from_facts(self, scan_id: str, target: str) -> List[str]:
        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        endpoints = []
        endpoint_keys = set()
        default_ports = {"80", "443"}  # URL formatting only, not discovery logic.
        def add_endpoint(endpoint: str) -> None:
            endpoint = self._display_endpoint_url(endpoint)
            if not endpoint:
                return
            if not self._endpoint_in_target_scope(endpoint, target):
                return
            key = endpoint.rstrip("/")
            if key in endpoint_keys:
                return
            endpoint_keys.add(key)
            endpoints.append(endpoint)

        for fact in self.fact_store.get_facts(scan_id, target):
            if fact.get("type") == "web_endpoint":
                endpoint = self._endpoint_url_from_value(str(fact.get("value", "")))
                add_endpoint(endpoint)
                continue
            if fact.get("type") in {"web_title", "web_server", "web_surface", "web_link", "web_redirect"}:
                add_endpoint(f"http://{host}")
                continue
            if fact.get("type") != "port_open":
                continue
            value = str(fact.get("value", "")).lower()
            match = re.match(r"(\d+)/(?:tcp|udp)\s+\(([^)]*)\)", value)
            if not match:
                continue
            port, service = match.groups()
            if not self._service_fact_looks_web(service, value):
                continue
            scheme = "https" if self._service_fact_looks_tls(value) else "http"
            endpoint = f"{scheme}://{host}" if port in default_ports else f"{scheme}://{host}:{port}"
            add_endpoint(endpoint)
        return endpoints

    def _endpoint_in_target_scope(self, endpoint: str, target: str) -> bool:
        parsed = urlparse(endpoint or "")
        endpoint_host = (parsed.hostname or "").lower()
        target_host = self._target_host(target).lower()
        if not endpoint_host or not target_host:
            return False
        if endpoint_host == target_host:
            return True
        try:
            target_ip = ipaddress.ip_address(target_host)
            ipaddress.ip_address(endpoint_host)
            return False
        except ValueError:
            pass
        return endpoint_host.endswith(f".{target_host}")

    def _endpoint_url_from_value(self, value: str) -> str:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return value if re.match(r"^https?://", value or "", re.IGNORECASE) else ""
        url = str(parsed.get("url", "")).strip()
        return url if re.match(r"^https?://", url, re.IGNORECASE) else ""

    def _display_endpoint_url(self, endpoint: str) -> str:
        parsed = urlparse(endpoint or "")
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        if (parsed.path or "") in {"", "/"} and not parsed.query:
            netloc = parsed.netloc.lower()
            return f"{parsed.scheme.lower()}://{netloc}"
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            "",
            parsed.query,
            "",
        ))

    def _service_fact_looks_web(self, service: str, value: str = "") -> bool:
        text = f"{service or ''} {value or ''}".lower()
        web_markers = (
            "http", "httpd", "web server", "nginx", "apache", "cowboy",
            "golang net/http", "node.js", "express", "php", "wordpress",
            "tomcat", "jetty", "gunicorn", "uwsgi", "werkzeug", "flask",
            "django", "rails", "sinatra", "grafana", "kibana", "prometheus",
            "cpanel", "whm",
        )
        return any(marker in text for marker in web_markers)

    def _service_fact_looks_tls(self, value: str = "") -> bool:
        text = (value or "").lower()
        return any(marker in text for marker in ("ssl/http", "https", "tls", "ssl ", "cpanel", "whm"))

    def _augment_command_with_context(self, cmd: str, scan_id: str, target: str) -> str:
        """Attach known recon evidence to tools that can consume it."""
        parts = (cmd or "").strip().split(maxsplit=2)
        if parts and parts[0] in {"plugin", "cpanel_exploit"}:
            return self._augment_cpanel_command(cmd, scan_id, target)
        if len(parts) != 2 or parts[0] != "exploit_select":
            return cmd

        facts = self.fact_store.get_facts(scan_id, target)
        useful_types = {
            "port_open",
            "service_version",
            "potential_vulnerability",
            "vulnerability",
            "web_server",
            "web_powered_by",
            "local_listening_port",
            "app_stack",
        }
        recon_bits = []
        for fact in facts:
            if fact.get("type") not in useful_types:
                continue
            value = str(fact.get("value", "")).replace("\n", " ").replace("\r", " ").strip()
            if fact.get("type") in {"web_endpoint", "web_link", "browser_rendered"}:
                if not self._web_fact_in_target_scope(value, target):
                    continue
            if value:
                recon_bits.append(f"{fact['type']} -> {value}")

        if not recon_bits:
            return cmd
        fact_limit = self._strategy_limit("exploit_select_context_facts", None)
        selected_bits = recon_bits if fact_limit is None else recon_bits[:fact_limit]
        return f"{cmd} {' | '.join(selected_bits)}"

    def _web_fact_in_target_scope(self, value: str, target: str) -> bool:
        value = (value or "").strip()
        if not value:
            return False
        endpoint = self._endpoint_url_from_value(value)
        if endpoint:
            return self._endpoint_in_target_scope(endpoint, target)
        if value.startswith("/"):
            return True
        if re.match(r"^https?://", value, re.IGNORECASE):
            return self._endpoint_in_target_scope(value, target)
        return True

    def _augment_cpanel_command(self, cmd: str, scan_id: str, target: str) -> str:
        """Use the discovered WHM/cPanel port instead of blindly defaulting to 2087."""
        port = self._best_cpanel_port(scan_id, target)
        if not port:
            return cmd
        target_with_port = f"{target}:{port}"
        parts = cmd.split()
        if len(parts) >= 4 and parts[0] == "plugin" and parts[1] == "cpanel_auth_bypass":
            parts[2] = target_with_port
            return " ".join(parts)
        if len(parts) >= 2 and parts[0] == "cpanel_exploit":
            parts[1] = target_with_port
            return " ".join(parts)
        return cmd

    def _best_cpanel_port(self, scan_id: str, target: str) -> str:
        preferred = ["2087", "2083", "2086", "2082", "2096", "2095"]
        found = set()
        for fact in self.fact_store.get_facts(scan_id, target):
            value = str(fact.get("value", "")).lower()
            if fact.get("type") != "port_open":
                continue
            for port in preferred:
                if value.startswith(f"{port}/") or f":{port}" in value:
                    found.add(port)
        for port in preferred:
            if port in found:
                return port
        return ""

    def _output_text(self, output: Any) -> str:
        stdout = getattr(output, "stdout", None)
        stderr = getattr(output, "stderr", "")
        if stdout is not None:
            parts = [str(stdout)]
            if stderr:
                parts.append(str(stderr))
            return "\n".join(p for p in parts if p)
        return str(output)

    def _command_failed(self, output: Any, output_str: str) -> bool:
        exit_code = getattr(output, "exit_code", 0)
        if isinstance(exit_code, int) and exit_code != 0:
            return True

        text = (output_str or "").lower()
        success_markers = (
            "[+]", "open", "connected", "login_success", "uid=0", "root access",
            "confirmed", "cve-", "vulnerable", "exfil", "persistence", "cleanup"
        )
        if any(marker in text for marker in success_markers):
            return False

        failure_markers = (
            "[!] tool not found", "[!] error", "traceback", "timed out",
            "returned no output", "requires credentials", "connection failed",
            "permission denied", "unknown tool", "missing dependency",
            "no such file or directory"
        )
        return any(marker in text for marker in failure_markers)

    def _classify_task_result(self, task_result: Dict[str, Any]) -> str:
        commands = task_result["commands"]
        parsed_facts = task_result["parsed_facts"]
        if self._has_blocked_stage_fact(commands):
            return "blocked"
        if commands and all(c["failed"] for c in commands) and parsed_facts == 0:
            return "failed"
        if parsed_facts == 0:
            return "no_new_facts"
        return "completed"

    def _command_result_reason(self, command_results: List[Dict[str, Any]], parsed_facts: int, new_facts: int) -> str:
        if not command_results:
            return "no_commands"
        if self._has_blocked_stage_fact(command_results):
            return "missing_credentials_or_manual_gate"
        failed_count = sum(1 for c in command_results if c["failed"])
        if failed_count == len(command_results) and parsed_facts == 0:
            return "all_commands_failed"
        if parsed_facts == 0:
            return "commands_ran_but_no_facts"
        if new_facts == 0:
            return "facts_seen_but_already_known"
        return f"{new_facts}_new_facts"

    def _has_blocked_stage_fact(self, command_results: List[Dict[str, Any]]) -> bool:
        for command in command_results:
            for ftype, value in command.get("fact_pairs", []):
                if ftype == "stage_status" and str(value).endswith(":blocked_missing_credentials"):
                    return True
        return False

    def _record_task_outcome(
        self,
        agent: str,
        task: str,
        status: str,
        reason: str,
        new_facts: int,
        parsed_facts: int,
        commands: List[Dict[str, Any]],
        duration: float,
    ):
        outcome = {
            "agent": agent,
            "task": task,
            "status": status,
            "reason": reason,
            "new_facts": new_facts,
            "parsed_facts": parsed_facts,
            "commands": commands,
            "duration": duration,
        }
        self.task_outcomes.append(outcome)
        if status == "failed":
            self.failed_commands.extend(c["command"] for c in commands if c.get("failed"))
        elif status == "no_new_facts":
            self.no_fact_tasks.append(task)

    def _record_goal_trace(self, loop: int, context: Dict[str, Any], decision: Dict[str, Any]) -> None:
        self.goal_trace.append({
            "loop": loop,
            "goal": decision.get("goal", "conclude"),
            "thought": decision.get("thought", ""),
            "state": context.get("state"),
            "next_required_capability": context.get("next_required_capability"),
            "stage_gates": context.get("stage_gates") or {},
            "open_questions": context.get("open_questions") or [],
        })

    def _record_command_trace(self, decision: Dict[str, Any], result: Dict[str, Any] = None) -> None:
        item = {
            "command": decision.get("command"),
            "key": decision.get("key"),
            "action": decision.get("action"),
            "reason": decision.get("reason"),
            "prerequisite": decision.get("prerequisite", ""),
        }
        if result:
            item.update({
                "failed": result.get("failed", False),
                "output_hash": result.get("output_hash", ""),
                "duplicate_output": result.get("duplicate_output", False),
                "parsed_facts": result.get("parsed_facts", 0),
                "new_facts": result.get("new_facts", 0),
                "facts": result.get("fact_pairs", []),
            })
        self.command_trace.append(item)

    def _print_stage_gates(self, context: Dict[str, Any]):
        gates = context.get("stage_gates") or {}
        if not gates:
            return
        ordered = [
            "recon", "credentials", "root", "post_access_inventory",
            "persistence", "internal_recon", "exfiltration", "cleanup",
        ]
        gate_text = ", ".join(f"{name}={'yes' if gates.get(name) else 'no'}" for name in ordered)
        print(f"[*] Stage gates: {gate_text}; next={context.get('next_required_capability', 'conclude')}")

    def _print_efficiency_report(self, scan_id: str, target: str, elapsed: float):
        fact_total = len(self.fact_store.get_facts(scan_id, target))
        failed = [o for o in self.task_outcomes if o["status"] == "failed"]
        blocked = [o for o in self.task_outcomes if o["status"] == "blocked"]
        no_fact = [o for o in self.task_outcomes if o["status"] == "no_new_facts"]

        print(
            f"[*] Efficiency report: tasks={len(self.task_outcomes)}, "
            f"new_facts={self.total_new_facts}, total_facts={fact_total}, "
            f"failed={len(failed)}, blocked={len(blocked)}, no_fact={len(no_fact)}, "
            f"elapsed={elapsed:.1f}s"
        )

        if blocked:
            preview = ", ".join(f"{o['task']}({o['reason']})" for o in blocked[:5])
            print(f"    Blocked tasks: {preview}")
        if failed:
            preview = ", ".join(o["task"] for o in failed[:5])
            print(f"    Failed tasks: {preview}")
        if no_fact:
            preview = ", ".join(o["task"] for o in no_fact[:5])
            print(f"    No-fact tasks: {preview}")
        if self.goal_trace:
            last = self.goal_trace[-1]
            print(
                f"    Last goal trace: goal={last['goal']} state={last['state']} "
                f"next={last['next_required_capability']}"
            )
        if self.command_trace:
            skipped = [t for t in self.command_trace if t.get("action") == "skip"]
            print(f"    Command trace: decisions={len(self.command_trace)}, skipped={len(skipped)}")

# For testing
if __name__ == "__main__":
    pipeline = AIPipeline("/tmp/pipeline_test.db")
    pipeline.run_scan("test_scan_1", "127.0.0.1", max_iterations=3)
