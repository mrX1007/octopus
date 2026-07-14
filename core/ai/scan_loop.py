#!/usr/bin/env python3
"""Iteration lifecycle for :class:`core.ai.pipeline.AIPipeline`.

The public pipeline remains the composition root and compatibility facade.
This module owns only scan-loop lifecycle, stop conditions, and bookkeeping;
all decisions and execution continue through the injected pipeline services.
"""

from __future__ import annotations

import time
from typing import Any


class ToolBudgetReached(RuntimeError):
    """Stop the scan without terminalizing the active durable task attempt."""


class ScanLifecycle:
    """Run the existing pipeline lifecycle against an injected facade."""

    @staticmethod
    def run(
        pipeline: Any,
        scan_id: str,
        target: str,
        max_iterations: int = 0,
        max_tools: int = 0,
        max_time_minutes: int = 0,
        raw_scan: str = "",
    ):
        current = pipeline.mission_store.get_mission_by_scan_id(scan_id)
        if (
            current is not None
            and current.status == "completed"
            and current.mission_id == pipeline.mission_id
        ):
            pipeline.mission_store.open_mission(scan_id, target)
            return pipeline.state_resolver.resolve_state(scan_id, target)
        pipeline._reset_runtime_state()
        mission = pipeline._start_mission(scan_id, target)
        if mission.status == "completed":
            return pipeline.state_resolver.resolve_state(scan_id, target)

        pipeline._mission_stop_reason = ""
        try:
            result = ScanLifecycle._run_active(
                pipeline,
                scan_id,
                target,
                max_iterations,
                max_tools,
                max_time_minutes,
                raw_scan,
            )
        except ToolBudgetReached:
            pipeline._mission_stop_reason = "max_tools_reached"
            result = pipeline.state_resolver.resolve_state(scan_id, target)
        except BaseException as exc:
            pipeline._interrupt_mission(f"scan_exception:{type(exc).__name__}")
            raise

        stop_reason = pipeline._mission_stop_reason or "scan_loop_finished"
        if stop_reason in {
            "max_iterations_reached",
            "max_tools_reached",
            "max_time_reached",
        }:
            pipeline._interrupt_mission(stop_reason)
        else:
            pipeline._complete_mission(stop_reason)
        return result

    @staticmethod
    def _run_active(
        pipeline: Any,
        scan_id: str,
        target: str,
        max_iterations: int = 0,
        max_tools: int = 0,
        max_time_minutes: int = 0,
        raw_scan: str = "",
    ):
        print(f"\n[*] Starting AI Pipeline for target: {target} (Scan ID: {scan_id})")
        max_iterations = pipeline._runtime_limit(max_iterations)
        max_tools = pipeline._runtime_limit(max_tools)
        max_time_minutes = pipeline._runtime_limit(max_time_minutes)
        pipeline._max_tools_budget = max_tools

        if raw_scan:
            print("[*] Parsing facts from manual tool output...")
            facts = pipeline.output_parser.parse_tool_output("manual_recon", raw_scan)
            seeded = 0
            for fact in facts:
                stored = pipeline._store_fact(scan_id, target, fact, "manual_run")
                if stored["created"]:
                    seeded += 1
                    pipeline.total_new_facts += stored["new_facts"]
                    safe_fact = stored["fact"]
                    print(
                        f"    [+] Seeded: {safe_fact['type']} -> {safe_fact['value']} "
                        f"(conf={safe_fact.get('confidence', 100)})"
                    )
            pipeline._sync_runtime_credentials_from_facts(target, facts)
            print(f"[*] Seeded {seeded} facts from manual tool output.")

        credential_seeded = pipeline._seed_known_credentials(scan_id, target)
        if credential_seeded:
            print(f"[*] Seeded {credential_seeded} known credential fact(s) from credential store.")

        avail = pipeline.tool_registry.get_available_tools_summary()
        avail_list = [
            f"{task}: {', '.join(tools) if tools else 'NONE'}"
            for task, tools in avail.items()
            if tools
        ]
        print(f"[*] Available tools: {'; '.join(avail_list)}")
        unavailable = pipeline.tool_registry.get_unavailable_tools_summary()
        blocked_capabilities = [
            f"{task}({', '.join(tools)})"
            for task, tools in unavailable.items()
            if tools and not avail.get(task)
        ]
        if blocked_capabilities:
            print(f"[*] Blocked capabilities: {'; '.join(blocked_capabilities[:8])}")
        plugins = pipeline.tool_registry.get_discovered_plugins_summary()
        if plugins:
            plugin_list = [f"{plugin['name']}({plugin['type']})" for plugin in plugins]
            print(f"[*] Discovered plugins: {', '.join(plugin_list)}")
        coverage = pipeline.tool_registry.get_coverage_report()
        if coverage.get("unknown"):
            print(f"[*] Registry coverage gaps: {', '.join(coverage['unknown'])}")
        else:
            print(
                f"[*] Registry coverage: {coverage['covered']}/{coverage['registered']} "
                f"(auto={len(coverage['auto'])}, followup={len(coverage['followup'])}, "
                f"gated={len(coverage['manual_gated'])}, legacy={len(coverage['legacy_wrappers'])})"
            )

        pipeline.scan_start_time = time.time()
        if max_tools is not None and pipeline.tools_run_count >= max_tools:
            pipeline._mission_stop_reason = "max_tools_reached"
            print(
                f"[!] BUDGET EXCEEDED: Max tools run ({max_tools}). Terminating."
            )
            return pipeline.state_resolver.resolve_state(scan_id, target)
        startup_actions = pipeline._run_fact_driven_actions(
            scan_id, target, pipeline.fact_store.get_facts(scan_id, target)
        )
        if startup_actions["commands"]:
            pipeline.total_new_facts += startup_actions["new_facts"]
            print(
                f"[*] Startup actions: {len(startup_actions['commands'])} command(s), "
                f"{startup_actions['new_facts']} new fact(s)."
            )

        loop = 1
        while max_iterations is None or loop <= max_iterations:
            elapsed_minutes = (time.time() - pipeline.scan_start_time) / 60
            if max_time_minutes is not None and elapsed_minutes >= max_time_minutes:
                pipeline._mission_stop_reason = "max_time_reached"
                print(
                    f"[!] BUDGET EXCEEDED: Max time reached "
                    f"({max_time_minutes} mins). Terminating."
                )
                break
            if max_tools is not None and pipeline.tools_run_count >= max_tools:
                pipeline._mission_stop_reason = "max_tools_reached"
                print(
                    f"[!] BUDGET EXCEEDED: Max tools run "
                    f"({max_tools}). Terminating."
                )
                break

            llm_fallback_only = pipeline._llm_fallback_only()
            if llm_fallback_only:
                print(
                    f"\n[!] LLM DEAD: {pipeline.consecutive_llm_failures} consecutive "
                    "failures. Running on fallback only."
                )
                print("    Check: ollama ps / ollama logs / ollama restart")

            loop_label = str(max_iterations) if max_iterations is not None else "unlimited"
            print(f"\n{'=' * 50}\n[LOOP {loop}/{loop_label}]")

            pipeline.state_resolver.resolve_state(scan_id, target)
            context = pipeline.context_builder.build_context(scan_id, target)
            print(
                f"[*] Context: state={context['state']}, services={context['services']}, "
                f"questions={context['open_questions']}"
            )
            pipeline._print_stage_gates(context)

            resume_plan = pipeline._resumable_mission_plan()
            durable_resuming = bool(resume_plan)
            if resume_plan:
                goal = "resume_durable_tasks"
                thought = "draining persisted pending/interrupted mission work"
                director_res = {
                    "goal": goal,
                    "thought": thought,
                    "llm_status": "skipped",
                    "durable_resume": True,
                }
                pipeline._record_goal_trace(loop, context, director_res)
                pipeline.goal_history.append(goal)
                plan = resume_plan
                print(f"[*] Durable Resume: {len(plan)} task(s)")
            else:
                if llm_fallback_only:
                    director_res = pipeline._director_fallback_result(context)
                else:
                    director_res = pipeline.director.decide_goal(
                        context,
                        pipeline.goal_history,
                    )
                goal = director_res.get("goal", "conclude")
                thought = director_res.get("thought", "")
                pipeline._record_goal_trace(loop, context, director_res)
                pipeline._record_llm_health(
                    scan_id,
                    target,
                    "director",
                    director_res,
                    loop,
                )
                if not llm_fallback_only:
                    pipeline._update_llm_failure_counter(director_res)

                print(f"[*] Director Goal: {goal}")
                print(f"    Thought: {thought}")
                pipeline.goal_history.append(goal)

                if goal == "conclude":
                    pipeline._mission_stop_reason = "director_concluded"
                    print("[+] Scan concluded by Director.")
                    break

                current_fact_count = len(
                    pipeline.fact_store.get_facts(scan_id, target)
                )
                pipeline.fact_history_counts.append(current_fact_count)
                if (
                    len(pipeline.fact_history_counts) >= 4
                    and pipeline.fact_history_counts[-1]
                    == pipeline.fact_history_counts[-4]
                ):
                    pipeline._mission_stop_reason = "anti_loop_no_new_facts"
                    print("[!] ANTI-LOOP: No new facts for 3 loops. Terminating scan.")
                    break

                if pipeline._llm_fallback_only():
                    plan_res = pipeline._planner_fallback_result(goal)
                else:
                    plan_res = pipeline.planner.create_plan(
                        goal,
                        context,
                        pipeline.task_history,
                    )
                pipeline._record_llm_health(scan_id, target, "planner", plan_res, loop)
                if not pipeline._llm_fallback_only():
                    pipeline._update_llm_failure_counter(plan_res)
                plan = pipeline._extract_plan_steps(plan_res)
                plan = pipeline._normalize_plan(plan, goal)
                plan = pipeline._optimize_plan(plan, goal, context)
                plan = pipeline._compile_plan(plan, scan_id, target, context)

            if not plan:
                pipeline._mission_stop_reason = "planner_empty"
                print(f"[!] Planner returned empty plan for goal '{goal}'. Concluding.")
                break

            print(f"[*] Planner generated {len(plan)} tasks.")
            plan = pipeline._register_mission_plan(plan)
            pipeline._terminalize_compatibility_exhausted_tasks(plan)
            all_skipped = all(pipeline._task_exhausted(step.get("task")) for step in plan)
            if all_skipped:
                print(f"[!] All tasks in plan already completed/blocked. Goal '{goal}' exhausted.")
                loop += 1
                continue

            new_facts_this_loop = 0
            for step in plan:
                agent_name = step.get("agent")
                task = step.get("task")

                if pipeline._task_exhausted(task):
                    reason = "blocked" if task in pipeline.blocked_tasks else "already completed"
                    print(f"  -> [{agent_name}] Task: {task} - SKIPPED ({reason})")
                    continue

                print(f"  -> [{agent_name}] Task: {task}")
                pipeline.task_history.append(f"{agent_name}:{task}")
                attempt = pipeline._begin_task_attempt(agent_name, task)
                if attempt is not None and attempt.status == "blocked":
                    print(
                        f"     [!] Task blocked by durable dependency state: "
                        f"{attempt.reason}"
                    )
                    continue
                task_started = time.time()

                if agent_name == "DiscoveryAgent":
                    commands = pipeline.discovery_agent.execute_task(task, target)
                    if not commands:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        pipeline.blocked_tasks.add(task)
                        pipeline._record_task_outcome(
                            agent_name,
                            task,
                            "blocked",
                            "no_available_tools",
                            0,
                            0,
                            [],
                            time.time() - task_started,
                        )
                        continue

                    task_result = pipeline._run_task_commands(
                        scan_id, target, commands, fact_label="Fact"
                    )
                    new_facts_this_loop += task_result["new_facts"]
                    status = pipeline._classify_task_result(task_result)
                    reason = task_result["reason"]
                    if status == "blocked":
                        pipeline.blocked_tasks.add(task)
                    else:
                        pipeline.completed_tasks.add(task)
                    pipeline._record_task_outcome(
                        agent_name,
                        task,
                        status,
                        reason,
                        task_result["new_facts"],
                        task_result["parsed_facts"],
                        task_result["commands"],
                        time.time() - task_started,
                    )

                elif agent_name == "AnalysisAgent":
                    if pipeline._llm_fallback_only():
                        print("     [!] AnalysisAgent skipped: LLM unavailable, fallback mode active")
                        pipeline.completed_tasks.add(task)
                        pipeline._record_llm_health(
                            scan_id,
                            target,
                            "analysis",
                            {
                                "llm_status": "skipped",
                                "llm_error": "llm_dead_fallback_only",
                                "fallback": True,
                                "hypotheses": 0,
                            },
                            loop,
                        )
                        pipeline._record_task_outcome(
                            agent_name,
                            task,
                            "no_new_facts",
                            "llm_unavailable_fallback_mode",
                            0,
                            0,
                            [],
                            time.time() - task_started,
                        )
                        continue

                    analysis = pipeline.analysis_agent.analyze(scan_id, target)
                    hypotheses = analysis.get("hypotheses", [])
                    accepted_count = 0
                    accepted_fact_ids = []
                    task_new_facts = 0

                    if not hypotheses:
                        pipeline.consecutive_llm_failures += 1
                        pipeline._record_llm_health(
                            scan_id,
                            target,
                            "analysis",
                            {
                                "llm_status": "failed",
                                "llm_error": "returned_no_hypotheses",
                                "fallback": False,
                            },
                            loop,
                        )
                        print(
                            "     [!] AnalysisAgent returned 0 hypotheses "
                            f"(LLM failures: {pipeline.consecutive_llm_failures})"
                        )
                    else:
                        pipeline.consecutive_llm_failures = 0
                        pipeline._record_llm_health(
                            scan_id,
                            target,
                            "analysis",
                            {"llm_status": "ok", "hypotheses": len(hypotheses)},
                            loop,
                        )

                    for hypothesis in hypotheses:
                        claim = hypothesis.get("claim")
                        required_evidence = hypothesis.get("required_evidence", [])
                        print(f"     [?] Hypothesis: {claim}")
                        pipeline.fact_store.add_hypothesis(
                            scan_id,
                            target,
                            claim,
                            required_evidence,
                            "AnalysisAgent",
                        )
                        verify_res = pipeline.verification_agent.verify_hypothesis(
                            scan_id, target, claim, required_evidence
                        )
                        print(
                            f"         Status: {verify_res.get('status')} - "
                            f"{verify_res.get('reason')}"
                        )
                        if verify_res.get("status") == "accepted":
                            accepted_count += 1
                            if verify_res.get("fact_id"):
                                accepted_fact_ids.append(int(verify_res["fact_id"]))
                            if verify_res.get("created", True):
                                task_new_facts += 1
                                new_facts_this_loop += 1

                    pipeline.completed_tasks.add(task)
                    if not hypotheses:
                        status = "failed"
                        reason = "analysis_returned_no_hypotheses"
                    elif accepted_count:
                        status = "completed"
                        reason = f"{accepted_count}_hypotheses_accepted"
                    else:
                        status = "no_new_facts"
                        reason = "hypotheses_rejected_or_duplicate"
                    pipeline.total_new_facts += task_new_facts
                    pipeline._record_task_outcome(
                        agent_name,
                        task,
                        status,
                        reason,
                        task_new_facts,
                        accepted_count,
                        [],
                        time.time() - task_started,
                        fact_ids=tuple(accepted_fact_ids),
                    )

                elif agent_name == "VerificationAgent":
                    commands = pipeline.verification_agent.execute_task(task, target)
                    if not commands:
                        print(f"     [!] No tools available for '{task}'. Skipping.")
                        pipeline.blocked_tasks.add(task)
                        pipeline._record_task_outcome(
                            agent_name,
                            task,
                            "blocked",
                            "no_available_tools",
                            0,
                            0,
                            [],
                            time.time() - task_started,
                        )
                        continue
                    task_result = pipeline._run_task_commands(
                        scan_id,
                        target,
                        commands,
                        fact_label="Verified Fact",
                        verification=True,
                    )
                    new_facts_this_loop += task_result["new_facts"]
                    status = pipeline._classify_task_result(task_result)
                    reason = task_result["reason"]
                    if status == "blocked":
                        pipeline.blocked_tasks.add(task)
                    else:
                        pipeline.completed_tasks.add(task)
                    pipeline._record_task_outcome(
                        agent_name,
                        task,
                        status,
                        reason,
                        task_result["new_facts"],
                        task_result["parsed_facts"],
                        task_result["commands"],
                        time.time() - task_started,
                    )

                else:
                    print(f"     [!] Unknown agent '{agent_name}'. Skipping task.")
                    pipeline.blocked_tasks.add(task)
                    pipeline._record_task_outcome(
                        agent_name,
                        task,
                        "blocked",
                        "unknown_agent",
                        0,
                        0,
                        [],
                        time.time() - task_started,
                    )

            if new_facts_this_loop == 0:
                print(f"[*] Loop {loop} produced 0 new facts.")
            if not durable_resuming:
                loop += 1

        if not pipeline._mission_stop_reason and max_iterations is not None:
            pipeline._mission_stop_reason = "max_iterations_reached"

        elapsed = time.time() - pipeline.scan_start_time
        print(
            f"\n[*] Pipeline finished for {target}. "
            f"({pipeline.tools_run_count} tools run, {elapsed:.0f}s elapsed)"
        )
        print(
            f"[*] LLM failures: {pipeline.consecutive_llm_failures} consecutive, "
            f"completed tasks: {sorted(pipeline.completed_tasks)}"
        )
        pipeline._print_efficiency_report(scan_id, target, elapsed)
        return pipeline.state_resolver.resolve_state(scan_id, target)


__all__ = ["ScanLifecycle", "ToolBudgetReached"]
