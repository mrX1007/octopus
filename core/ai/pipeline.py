#!/usr/bin/env python3

import time
import os
import json
import shutil
import logging
from typing import Dict, Any

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

        # Anti-loop state
        self.goal_history = []
        self.task_history = []
        self.fact_history_counts = []
        self.completed_tasks = set()

        # Budget tracking
        self.tools_run_count = 0
        self.scan_start_time = 0

        # LLM health tracking
        self.consecutive_llm_failures = 0
        self.MAX_CONSECUTIVE_LLM_FAILURES = 3

    def run_scan(self, scan_id: str, target: str, max_iterations: int = 20, max_tools: int = 50, max_time_minutes: int = 15, raw_scan: str = ""):
        print(f"\n[*] Starting AI Pipeline for target: {target} (Scan ID: {scan_id})")

        # Parse initial raw scan if provided
        if raw_scan:
            print("[*] Parsing facts from manual tool output...")
            facts = self.output_parser.parse_tool_output("manual_recon", raw_scan)
            seeded = 0
            for f in facts:
                fid = self.fact_store.add_fact(scan_id, target, f['type'], f['value'], "manual_run",
                                         confidence=f.get('confidence', 100),
                                         session_id=f.get('session_id', 'none'))
                if fid > 0:
                    seeded += 1
                    print(f"    [+] Seeded: {f['type']} -> {f['value']} (conf={f.get('confidence', 100)})")
            print(f"[*] Seeded {seeded} facts from manual tool output.")

        # Show available tools at startup
        avail = self.tool_registry.get_available_tools_summary()
        avail_list = [f"{task}: {', '.join(tools) if tools else 'NONE'}" for task, tools in avail.items() if tools]
        print(f"[*] Available tools: {'; '.join(avail_list)}")

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

            if not plan:
                print(f"[!] Planner returned empty plan for goal '{goal}'. Concluding.")
                break

            print(f"[*] Planner generated {len(plan)} tasks.")

            # Check if ALL tasks in this plan are already completed
            all_skipped = all(step.get("task") in self.completed_tasks for step in plan)
            if all_skipped:
                print(f"[!] All tasks in plan already completed. Goal '{goal}' exhausted.")
                # Don't break — let the Director pick the next goal
                continue

            # 4. Agent Execution
            new_facts_this_loop = 0
            for step in plan:
                agent_name = step.get("agent")
                task = step.get("task")

                # Skip tasks that have already been completed
                if task in self.completed_tasks:
                    print(f"  -> [{agent_name}] Task: {task} — SKIPPED (already completed)")
                    continue

                print(f"  -> [{agent_name}] Task: {task}")
                self.task_history.append(f"{agent_name}:{task}")

                if agent_name == "DiscoveryAgent":
                    cmds = self.discovery_agent.execute_task(task, target)
                    if not cmds:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        self.completed_tasks.add(task)
                        continue

                    for cmd in cmds:
                        print(f"     [Running] {cmd}")
                        output = run_arbitrary_cmd(cmd)
                        self.tools_run_count += 1
                        output_str = str(output) if not hasattr(output, 'stdout') else output.stdout
                        facts = self.output_parser.parse_tool_output(cmd, output_str)
                        for f in facts:
                            fact_id = self.fact_store.add_fact(scan_id, target, f['type'], f['value'], cmd,
                                                               confidence=f.get('confidence', 100),
                                                               session_id=f.get('session_id', 'none'))
                            if fact_id > 0:
                                print(f"     [+] Fact: {f['type']} -> {f['value']}")
                                new_facts_this_loop += 1

                    # Always mark completed
                    self.completed_tasks.add(task)

                elif agent_name == "AnalysisAgent":
                    # AnalysisAgent uses LLM — track failures
                    analysis = self.analysis_agent.analyze(scan_id, target)
                    hypotheses = analysis.get("hypotheses", [])

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
                            self.fact_store.add_fact(scan_id, target, "vulnerability", claim, "VerificationAgent")
                            new_facts_this_loop += 1

                    # Always mark completed
                    self.completed_tasks.add(task)

                elif agent_name == "VerificationAgent":
                    cmds = self.verification_agent.execute_task(task, target)
                    if not cmds:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        self.completed_tasks.add(task)
                        continue
                    for cmd in cmds:
                        print(f"     [Running Verification] {cmd}")
                        output = run_arbitrary_cmd(cmd)
                        self.tools_run_count += 1
                        output_str = str(output) if not hasattr(output, 'stdout') else output.stdout
                        facts = self.output_parser.parse_tool_output(cmd, output_str)
                        for f in facts:
                            self.fact_store.add_fact(scan_id, target, f['type'], f['value'], cmd,
                                                     confidence=f.get('confidence', 100),
                                                     session_id=f.get('session_id', 'none'))
                            print(f"     [+] Verified Fact: {f['type']} -> {f['value']}")
                            new_facts_this_loop += 1

                    # Always mark completed
                    self.completed_tasks.add(task)

            # If this loop produced zero new facts, note it
            if new_facts_this_loop == 0:
                print(f"[*] Loop {loop} produced 0 new facts.")

        elapsed = time.time() - self.scan_start_time
        print(f"\n[*] Pipeline finished for {target}. ({self.tools_run_count} tools run, {elapsed:.0f}s elapsed)")
        print(f"[*] LLM failures: {self.consecutive_llm_failures} consecutive, completed tasks: {sorted(self.completed_tasks)}")
        return self.state_resolver.resolve_state(scan_id, target)

# For testing
if __name__ == "__main__":
    pipeline = AIPipeline("/tmp/pipeline_test.db")
    pipeline.run_scan("test_scan_1", "127.0.0.1", max_iterations=3)
