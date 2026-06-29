#!/usr/bin/env python3

import fnmatch
import ipaddress
import logging
import re
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
        self.executed_followup_commands = set()
        self.executed_active_commands = set()
        self.executed_post_access_commands = set()
        self.executed_fact_action_commands = set()

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
            self._print_stage_gates(context)

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
        if goal == "post_access_inventory" and state in post_states:
            return [{"agent": "VerificationAgent", "task": "post_access_inventory"}]
        if goal == "persistence" and state in post_states:
            return [
                {"agent": "VerificationAgent", "task": "payload_generation"},
                {"agent": "VerificationAgent", "task": "establish_persistence"},
            ]
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
        services = set(context.get("services") or [])
        open_questions = set(context.get("open_questions") or [])
        candidates = []
        critical_candidates = set()
        if goal == "vulnerability_assessment":
            if "cpanel_auth_bypass_unknown" in open_questions:
                candidates.append("cpanel_assessment")
                critical_candidates.add("cpanel_assessment")
            if services.intersection({"http", "https"}):
                candidates.append("web_application_mapping")
                candidates.append("web_vulnerability_testing")
            if "https" in services:
                candidates.append("transport_security_assessment")
            if "smb" in services:
                candidates.append("windows_enumeration")
            if services.intersection({"ldap", "kerberos", "winrm", "rdp"}):
                candidates.append("active_directory_enumeration")
        elif goal == "credential_harvesting":
            if services.intersection({"ldap", "kerberos", "winrm", "rdp", "smb"}):
                candidates.append("active_directory_enumeration")
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
        for task in candidates:
            task = self.tool_registry.canonical_task(task)
            is_critical = task in critical_candidates
            if len(enriched) >= 3 and not is_critical:
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
            if len(enriched) > 3:
                self._trim_low_priority_enrichment(enriched, protected={task})

        return enriched

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
        print(f"     {prefix} {cmd}")
        output = run_arbitrary_cmd(cmd)
        self.tools_run_count += 1
        if cmd.startswith("ssh_inventory "):
            self.executed_post_access_commands.add(cmd)
        output_str = self._output_text(output)
        failed = self._command_failed(output, output_str)
        facts = self.output_parser.parse_tool_output(cmd, output_str)
        command_new_facts = 0

        for f in facts:
            _fact_id, created = self.fact_store.add_fact_with_status(
                scan_id, target, f['type'], f['value'], cmd,
                confidence=f.get('confidence', 100),
                session_id=f.get('session_id', 'none')
            )
            if created:
                print(f"     [+] {fact_label}: {f['type']} -> {f['value']}")
                command_new_facts += 1
        self._sync_runtime_credentials_from_facts(target, facts)

        return {
            "facts": facts,
            "new_facts": command_new_facts,
            "parsed_facts": len(facts),
            "command_result": {
                "command": cmd,
                "failed": failed,
                "parsed_facts": len(facts),
                "new_facts": command_new_facts,
                "fact_pairs": [(fact.get("type"), fact.get("value")) for fact in facts],
            },
        }

    def _followup_commands_from_facts(self, facts: List[Dict[str, Any]]) -> List[str]:
        """Run safe verification commands emitted by earlier tools once."""
        commands = []
        allowed_prefixes = ("msf_check ", "searchsploit ", "plugin ")
        for fact in facts:
            if fact.get("type") != "verification_command":
                continue
            cmd = str(fact.get("value", "")).strip()
            if not cmd or not cmd.startswith(allowed_prefixes):
                continue
            if cmd.startswith("plugin ") and not any(token in cmd for token in (" scan", " check", " list")):
                continue
            if cmd in self.executed_followup_commands:
                continue
            self.executed_followup_commands.add(cmd)
            commands.append(cmd)
            if len(commands) >= 3:
                break
        return commands

    def _run_fact_driven_actions(
        self, scan_id: str, target: str, facts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Run deterministic next actions implied by concrete facts."""
        parsed_facts = 0
        new_facts = 0
        command_results = []
        for cmd in self._fact_driven_action_commands(scan_id, target, facts):
            result = self._execute_pipeline_command(
                scan_id, target, cmd, "Action Fact", "[Running Action]"
            )
            parsed_facts += result["parsed_facts"]
            new_facts += result["new_facts"]
            command_results.append(result["command_result"])

            post_result = self._run_controlled_post_access_followups(scan_id, target, result["facts"])
            parsed_facts += post_result["parsed_facts"]
            new_facts += post_result["new_facts"]
            command_results.extend(post_result["commands"])
        return {
            "parsed_facts": parsed_facts,
            "new_facts": new_facts,
            "commands": command_results,
        }

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

        if self._facts_include_cached_ssh_credential(facts) and not self._facts_confirm_ssh_access(all_facts):
            commands.append(f"ssh_session {target}")

        if self._facts_indicate_cpanel_surface(facts) and not self._cpanel_already_verified(all_pairs):
            commands.append(f"plugin cpanel_auth_bypass {target} scan")

        commands.extend(self._service_action_commands(target, facts, all_pairs))
        commands.extend(self._web_path_action_commands(scan_id, target, facts))

        deduped = []
        for cmd in commands:
            cmd = self._augment_command_with_context(cmd, scan_id, target)
            if cmd in self.executed_fact_action_commands:
                continue
            self.executed_fact_action_commands.add(cmd)
            deduped.append(cmd)
            if len(deduped) >= 10:
                break
        return deduped

    def _facts_include_cached_ssh_credential(self, facts: List[Dict[str, Any]]) -> bool:
        for fact in facts:
            if str(fact.get("type", "")).lower() != "credential":
                continue
            value = str(fact.get("value", "")).strip()
            if value.startswith("ssh_key_available:"):
                return True
            if re.match(r"[^:\s]+:[^\s]+\s+\(cached\)", value):
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
        interesting_words = (
            "admin", "login", "report", "_reports", "api", "dashboard",
            "cpanel", "whm", "wp-admin", "phpmyadmin", "grafana",
        )
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
                or any(word in path.lower() for word in interesting_words)
            )
            if not is_interesting:
                continue
            url = f"{base}{path}"
            commands.append(f"curl_headers {url}")
            commands.append(f"scrapling {url}")
            if len(commands) >= 4:
                break
        return commands

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
        for cmd in self._controlled_post_access_commands_from_facts(target, facts):
            result = self._execute_pipeline_command(
                scan_id, target, cmd, "Post-Access Fact", "[Running Controlled Post-Access]"
            )
            parsed_facts += result["parsed_facts"]
            new_facts += result["new_facts"]
            command_results.append(result["command_result"])
        return {
            "parsed_facts": parsed_facts,
            "new_facts": new_facts,
            "commands": command_results,
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
        return bool(CFG.get("strategy", {}).get("auto_ssh_inventory", True))

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
            "whatweb": 8,
            "curl_headers": 8,
            "scrapling": 6,
            "browser_surface_analysis": 4,
            "ffuf": 3,
            "nikto": 3,
            "jmx2rce_scan": 4,
        }
        if tool not in web_mapping_tools:
            return [cmd]

        endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            return [cmd]
        limit = web_mapping_tools[tool]
        return [f"{tool} {endpoint}" for endpoint in endpoints[:limit]]

    def _web_endpoints_from_facts(self, scan_id: str, target: str) -> List[str]:
        host = (target or "").strip().split("://")[-1].split("/")[0].split(":")[0]
        endpoints = []
        default_ports = {"80", "443"}
        https_ports = {"443", "8443", "2083", "2087", "2096", "9443"}
        web_ports = {
            "80", "443", "8000", "8080", "8081", "8082", "8443",
            "3000", "3030", "5000", "5601", "8008", "8888", "9000",
            "9090", "2082", "2083", "2086", "2087", "2095", "2096",
        }
        for fact in self.fact_store.get_facts(scan_id, target):
            if fact.get("type") != "port_open":
                continue
            value = str(fact.get("value", "")).lower()
            match = re.match(r"(\d+)/(?:tcp|udp)\s+\(([^)]*)\)", value)
            if not match:
                continue
            port, service = match.groups()
            is_web = (
                port in web_ports
                or "http" in service
                or "cpanel" in value
                or "whm" in value
                or "node.js" in value
                or "golang net/http" in value
                or "php" in value
            )
            if not is_web:
                continue
            scheme = "https" if port in https_ports or "ssl/http" in value else "http"
            endpoint = f"{scheme}://{host}" if port in default_ports else f"{scheme}://{host}:{port}"
            if endpoint not in endpoints:
                endpoints.append(endpoint)
        return endpoints

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
            "web_title",
            "web_surface",
        }
        recon_bits = []
        for fact in facts:
            if fact.get("type") not in useful_types:
                continue
            value = str(fact.get("value", "")).replace("\n", " ").replace("\r", " ").strip()
            if value:
                recon_bits.append(f"{fact['type']} -> {value}")

        if not recon_bits:
            return cmd
        return f"{cmd} {' | '.join(recon_bits[:30])}"

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

# For testing
if __name__ == "__main__":
    pipeline = AIPipeline("/tmp/pipeline_test.db")
    pipeline.run_scan("test_scan_1", "127.0.0.1", max_iterations=3)
