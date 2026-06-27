#!/usr/bin/env python3

import logging
import time
from typing import Dict, Any, List

from core.ai.fact_store import FactStore
from core.ai.state_resolver import StateResolver
from core.ai.context_builder import ContextBuilder
from core.ai.director import DirectorLLM
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
        self.planner = MissionPlanner()
        self.tool_registry = ToolRegistry()
        self.output_parser = OutputParser()
        self.evidence_verifier = EvidenceVerifier(self.fact_store)

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

        # LLM health tracking
        self.consecutive_llm_failures = 0

    def run_scan(self, scan_id: str, target: str, max_iterations: int = 20, max_tools: int = 50, max_time_minutes: int = 15, raw_scan: str = ""):
        print(f"\n[*] Starting AI Pipeline for target: {target} (Scan ID: {scan_id})")
        self._reset_runtime_state()

        # Parse initial raw scan if provided
        if raw_scan:
            print("[*] Parsing facts from manual tool output...")
            facts = self.output_parser.parse_tool_output("manual_recon", raw_scan)
            seeded = 0
            for f in facts:
                _fid, created = self.fact_store.add_fact_with_status(
                    scan_id, target, f['type'], f['value'], "manual_run",
                    confidence=f.get('confidence', 100),
                    session_id=f.get('session_id', 'none')
                )
                if created:
                    seeded += 1
                    self.total_new_facts += 1
                    print(f"    [+] Seeded: {f['type']} -> {f['value']} (conf={f.get('confidence', 100)})")
            print(f"[*] Seeded {seeded} facts from manual tool output.")

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

        self.scan_start_time = time.time()

        for loop in range(1, max_iterations + 1):
            # Budget Checks
            elapsed_minutes = (time.time() - self.scan_start_time) / 60
            if elapsed_minutes >= max_time_minutes:
                print(f"[!] BUDGET EXCEEDED: Max time reached ({max_time_minutes} mins). Terminating.")
                break
            if self.tools_run_count >= max_tools:
                print(f"[!] BUDGET EXCEEDED: Max tools run ({max_tools}). Terminating.")
                break

            # LLM health check
            if self.consecutive_llm_failures >= self.MAX_CONSECUTIVE_LLM_FAILURES:
                print(f"\n[!] LLM DEAD: {self.consecutive_llm_failures} consecutive failures. Running on fallback only.")
                print(f"    Check: ollama ps / ollama logs / ollama restart")

            print(f"\n{'='*50}\n[LOOP {loop}/{max_iterations}]")

            # 1. State Resolution & Context Building
            state = self.state_resolver.resolve_state(scan_id, target)
            context = self.context_builder.build_context(scan_id, target)
            print(f"[*] Context: state={context['state']}, services={context['services']}, questions={context['open_questions']}")

            # 2. Director Goal
            director_res = self.director.decide_goal(context, self.goal_history)
            goal = director_res.get("goal", "conclude")
            thought = director_res.get("thought", "")

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

        elapsed = time.time() - self.scan_start_time
        print(f"\n[*] Pipeline finished for {target}. ({self.tools_run_count} tools run, {elapsed:.0f}s elapsed)")
        print(f"[*] LLM failures: {self.consecutive_llm_failures} consecutive, completed tasks: {sorted(self.completed_tasks)}")
        self._print_efficiency_report(scan_id, target, elapsed)
        return self.state_resolver.resolve_state(scan_id, target)

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
        if goal == "persistence" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "establish_persistence"}]
        if goal == "internal_reconnaissance" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "internal_network_recon"}]
        if goal == "data_exfiltration" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "exfiltrate_data"}]
        if goal == "cleanup" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "stealth_cleanup"}]
        return None

    def _task_exhausted(self, task: str) -> bool:
        task = self.tool_registry.canonical_task(task)
        return task in self.completed_tasks or task in self.blocked_tasks

    def _enrich_plan(self, plan, goal: str, context: Dict[str, Any]):
        """Add one high-value context-specific task when the plan has room."""
        if len(plan) >= 3:
            return plan

        services = set(context.get("services") or [])
        candidates = []
        if goal == "vulnerability_assessment":
            if services.intersection({"http", "https"}):
                candidates.append("web_application_mapping")
            if "https" in services:
                candidates.append("transport_security_assessment")
            if "smb" in services:
                candidates.append("windows_enumeration")
        elif goal == "credential_harvesting":
            if "ssh" in services:
                candidates.append("ssh_user_enumeration")
            if "smb" in services:
                candidates.append("windows_enumeration")

        if not candidates:
            return plan

        present = {step.get("task") for step in plan}
        enriched = list(plan)
        for task in candidates:
            task = self.tool_registry.canonical_task(task)
            if len(enriched) >= 3:
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

        return enriched

    def _run_task_commands(self, scan_id: str, target: str, cmds: List[str], fact_label: str, verification: bool = False) -> Dict[str, Any]:
        new_facts = 0
        parsed_facts = 0
        command_results = []
        prefix = "[Running Verification]" if verification else "[Running]"

        for cmd in cmds:
            print(f"     {prefix} {cmd}")
            output = run_arbitrary_cmd(cmd)
            self.tools_run_count += 1
            output_str = self._output_text(output)
            failed = self._command_failed(output, output_str)
            facts = self.output_parser.parse_tool_output(cmd, output_str)
            parsed_facts += len(facts)
            command_new_facts = 0

            for f in facts:
                _fact_id, created = self.fact_store.add_fact_with_status(
                    scan_id, target, f['type'], f['value'], cmd,
                    confidence=f.get('confidence', 100),
                    session_id=f.get('session_id', 'none')
                )
                if created:
                    print(f"     [+] {fact_label}: {f['type']} -> {f['value']}")
                    new_facts += 1
                    command_new_facts += 1

            command_results.append({
                "command": cmd,
                "failed": failed,
                "parsed_facts": len(facts),
                "new_facts": command_new_facts,
            })

        self.total_new_facts += new_facts
        return {
            "new_facts": new_facts,
            "parsed_facts": parsed_facts,
            "commands": command_results,
            "reason": self._command_result_reason(command_results, parsed_facts, new_facts),
        }

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
        if commands and all(c["failed"] for c in commands) and parsed_facts == 0:
            return "failed"
        if parsed_facts == 0:
            return "no_new_facts"
        return "completed"

    def _command_result_reason(self, command_results: List[Dict[str, Any]], parsed_facts: int, new_facts: int) -> str:
        if not command_results:
            return "no_commands"
        failed_count = sum(1 for c in command_results if c["failed"])
        if failed_count == len(command_results) and parsed_facts == 0:
            return "all_commands_failed"
        if parsed_facts == 0:
            return "commands_ran_but_no_facts"
        if new_facts == 0:
            return "facts_seen_but_already_known"
        return f"{new_facts}_new_facts"

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

# For testing
if __name__ == "__main__":
    pipeline = AIPipeline("/tmp/pipeline_test.db")
    pipeline.run_scan("test_scan_1", "127.0.0.1", max_iterations=3)
