"""Planning, capability compilation, and execution-context seams.

This mixin keeps deterministic plan shaping outside the main pipeline facade.
It owns no state and delegates every availability, policy, persistence, and
trace decision to the canonical components held by ``AIPipeline``.
"""

from __future__ import annotations

from typing import Any

from core.ai.pipeline_types import PipelineMixinBase
from core.ai.task_scoring import TaskScoringSignals
from core.execution import (
    CAP_ACTIVE_TOOL,
    CAP_DIRECT_BINARY,
    CAP_REGISTERED_TOOL,
    ExecutionContext,
)


class PipelinePlanningMixin(PipelineMixinBase):
    def _runtime_limit(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in {
            "",
            "0",
            "-1",
            "none",
            "unlimited",
            "false",
        }:
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return None if parsed <= 0 else parsed

    def _execution_context(self, scan_id: str, target: str) -> ExecutionContext:
        """Bind automatic commands to the current scan target and origin."""
        try:
            from config import CFG
        except ImportError:
            CFG = {}
        strategy = CFG.get("strategy", {})
        active_authorized = bool(
            strategy.get("active_authorized", False)
        ) and self._target_in_authorized_scope(
            target,
            strategy.get("authorized_targets", []),
        )
        if active_authorized:
            return ExecutionContext(
                actor=f"scan:{scan_id}",
                origin="ai_pipeline",
                target_scope=(target,),
                capabilities=frozenset(
                    {
                        CAP_REGISTERED_TOOL,
                        CAP_DIRECT_BINARY,
                        CAP_ACTIVE_TOOL,
                    }
                ),
                approved=True,
                approval_id=f"config:active_authorized:{scan_id}",
                cancellation=self.cancellation,
            )
        return ExecutionContext.automatic(
            target_scope=(target,),
            actor=f"scan:{scan_id}",
            origin="ai_pipeline",
            cancellation=self.cancellation,
        )

    def _llm_fallback_only(self) -> bool:
        return self.consecutive_llm_failures >= self.MAX_CONSECUTIVE_LLM_FAILURES

    def _director_fallback_result(self, context: dict[str, Any]) -> dict[str, Any]:
        result = self.director._fallback_logic(context, self.goal_history)
        result.update(
            {
                "llm_status": "skipped",
                "llm_error": "llm_dead_fallback_only",
                "fallback": True,
            }
        )
        return result

    def _planner_fallback_result(self, goal: str) -> dict[str, Any]:
        result = self.planner._fallback_logic(goal)
        result.update(
            {
                "llm_status": "skipped",
                "llm_error": "llm_dead_fallback_only",
                "fallback": True,
            }
        )
        return result

    def _compile_plan(
        self,
        plan: list[dict[str, Any]],
        scan_id: str,
        target: str,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Reject hard provider failures before final execution policy checks."""
        compilation = self.plan_compiler.compile(
            plan,
            target=target,
            facts=self.fact_store.get_facts(scan_id, target),
            context=context,
            execution_context=self._execution_context(scan_id, target),
        )
        for rejection in compilation.rejected:
            rejection_dict = dict(rejection)
            self.plan_rejections.append(rejection_dict)
            task = self.tool_registry.canonical_task(
                rejection_dict.get("task", "")
            )
            if task:
                self.blocked_tasks.add(task)
            reasons = ", ".join(rejection_dict.get("blocking_reasons") or [])
            durable_reason = str(
                rejection_dict.get("reason") or "capability_unavailable"
            )
            if reasons:
                durable_reason += ":" + reasons
            self._persist_plan_rejection(
                str(rejection_dict.get("agent") or ""),
                task,
                durable_reason,
            )
            print(
                f"     [!] Planner task rejected: {task or '<unknown>'} "
                f"({rejection_dict.get('reason')}"
                f"{': ' + reasons if reasons else ''})"
            )
        return [dict(step) for step in compilation.plan]

    def _normalize_plan(self, plan, goal: str = ""):
        """Normalize LLM task names before execution and history tracking."""
        normalized = []
        for step in self._coerce_plan_steps(plan):
            if not isinstance(step, dict):
                continue
            task = (
                step.get("task")
                or step.get("tool")
                or step.get("action")
                or step.get("name")
                or self._task_from_planner_command(step.get("command", ""))
            )
            agent = step.get("agent") or self._agent_for_task(task, goal)
            if not agent or not task:
                continue
            task_key = (
                (task or "").strip().lower().replace("-", "_").replace(" ", "_")
            )
            if goal == "privilege_escalation" and task_key in {
                "verify_exploit",
                "exploit",
                "run_exploit",
            }:
                task = "exploit_privesc"
            elif goal == "data_exfiltration" and task_key in {
                "directory_bruteforce",
                "dir_bruteforce",
                "find_sensitive_files",
                "data_discovery",
                "discover_data",
                "enumerate_files",
            }:
                task = "exfiltrate_data"
            normalized.append(
                {
                    **step,
                    "agent": agent,
                    "task": self.tool_registry.canonical_task(task),
                }
            )
        return normalized

    def _extract_plan_steps(
        self,
        plan_res: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if not isinstance(plan_res, dict):
            return self._coerce_plan_steps(plan_res)
        if isinstance(plan_res.get("plan"), (list, dict)):
            return self._coerce_plan_steps(plan_res.get("plan"))
        return self._coerce_plan_steps(plan_res)

    def _coerce_plan_steps(self, raw_plan) -> list[dict[str, Any]]:
        if isinstance(raw_plan, list):
            return [step for step in raw_plan if isinstance(step, dict)]
        if not isinstance(raw_plan, dict):
            return []
        for key in ("plan", "tasks", "actions", "steps"):
            nested = raw_plan.get(key)
            if isinstance(nested, list):
                return [step for step in nested if isinstance(step, dict)]
            if isinstance(nested, dict):
                return self._coerce_plan_steps(nested)
        if any(
            key in raw_plan
            for key in ("agent", "task", "tool", "action", "name", "command")
        ):
            return [raw_plan]
        return []

    def _task_from_planner_command(self, command: str) -> str:
        return (command or "").strip().split(None, 1)[0]

    def _agent_for_task(self, task: str, goal: str = "") -> str:
        canonical = self.tool_registry.canonical_task(task)
        if canonical in {
            "post_access_inventory",
            "find_privesc_vectors",
            "exploit_privesc",
            "internal_network_recon",
            "internal_service_discovery",
            "metasploit_verification",
            "establish_persistence",
            "pivot_setup",
            "lateral_movement",
            "exfiltrate_data",
            "stealth_cleanup",
        }:
            return "VerificationAgent"
        if canonical == "analyze_vulnerabilities":
            return "AnalysisAgent"
        if goal in {
            "post_access_inventory",
            "internal_reconnaissance",
            "data_exfiltration",
            "cleanup",
            "persistence",
        }:
            return "VerificationAgent"
        return "DiscoveryAgent"

    def _optimize_plan(
        self,
        plan,
        goal: str,
        context: dict[str, Any],
    ):
        """Apply deterministic guardrails around LLM plans."""
        state = context.get("state", "initial_recon")
        forced_plan = self._post_exploit_plan(goal, state, context)
        if forced_plan is not None:
            if plan != forced_plan:
                tasks = ", ".join(step["task"] for step in forced_plan)
                print(
                    f"[*] Plan optimized for state={state}, goal={goal}: {tasks}"
                )
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
            if agent == "AnalysisAgent" and task != "analyze_vulnerabilities":
                print(f"     [!] Dropping incompatible AnalysisAgent task: {task}")
                continue
            if agent != "AnalysisAgent" and not self.tool_registry.has_task(task):
                print(f"     [!] Dropping unknown planner task: {task}")
                continue
            seen_tasks.add(task)
            optimized.append({**step, "task": task})

        return self._enrich_plan(optimized, goal, context)

    def _post_exploit_plan(
        self,
        goal: str,
        state: str,
        context: dict[str, Any] | None = None,
    ):
        context = context or {}
        open_questions = set(context.get("open_questions") or [])
        post_states = {
            "root_access_confirmed",
            "persistence_established",
            "internal_recon_completed",
            "exfiltration_completed",
        }
        if goal == "post_access_inventory" and state in post_states:
            return [
                {"agent": "VerificationAgent", "task": "post_access_inventory"}
            ]
        if goal == "persistence" and state in post_states:
            if not self._strategy_enabled("auto_persistence", False):
                return []
            plan = []
            if self._strategy_enabled("auto_payload_generation", False):
                plan.append(
                    {"agent": "VerificationAgent", "task": "payload_generation"}
                )
            plan.append(
                {"agent": "VerificationAgent", "task": "establish_persistence"}
            )
            return plan
        if goal == "internal_reconnaissance" and state in post_states:
            if not self._strategy_enabled("auto_internal_recon", True):
                return []
            if "internal_service_assessment_pending" in open_questions:
                return [
                    {
                        "agent": "VerificationAgent",
                        "task": "internal_service_discovery",
                    }
                ]
            return [
                {"agent": "VerificationAgent", "task": "internal_network_recon"}
            ]
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

    def _enrich_plan(self, plan, goal: str, context: dict[str, Any]):
        """Add bounded high-value context-specific tasks when the plan has room."""
        services = set(context.get("services") or [])
        open_questions = set(context.get("open_questions") or [])
        target_model = context.get("target_model") or {}
        surface_states = (
            target_model.get("surface_states")
            or context.get("surface_states")
            or {}
        )
        assets = target_model.get("assets") or {}
        explicit_coverage = "coverage_gaps" in context
        coverage_gaps = set(
            context.get("coverage_gaps") or context.get("open_questions") or []
        )
        candidates = []
        critical_candidates = set()
        if goal == "vulnerability_assessment":
            if "external_vulnerability_assessment_pending" in coverage_gaps:
                candidates.append("vulnerability_assessment")
            if "internal_vulnerability_assessment_pending" in coverage_gaps:
                if "external_vulnerability_assessment_pending" not in coverage_gaps:
                    candidates.append("exploit_selection")
                candidates.append("internal_service_discovery")
            if surface_states.get("asm") != "confirmed_present" and self._target_looks_domain(
                context.get("host", "")
            ):
                candidates.append("asm_discovery")
            if "cpanel_auth_bypass_unknown" in open_questions:
                candidates.append("cpanel_assessment")
                critical_candidates.add("cpanel_assessment")
            if services.intersection({"http", "https"}) or coverage_gaps.intersection(
                {
                    "web_mapping_pending",
                    "web_app_deep_testing_pending",
                    "web_content_discovery_pending",
                    "template_verification_pending",
                    "api_security_testing_pending",
                }
            ):
                if "web_mapping_pending" in coverage_gaps or services.intersection(
                    {"http", "https"}
                ):
                    candidates.append("web_application_mapping")
                if "web_app_deep_testing_pending" in coverage_gaps or not explicit_coverage:
                    candidates.append("web_app_deep_testing")
                if "web_content_discovery_pending" in coverage_gaps or not explicit_coverage:
                    candidates.append("web_content_discovery")
                if "template_verification_pending" in coverage_gaps or not explicit_coverage:
                    candidates.append("template_verification")
                candidates.append("web_vulnerability_testing")
                if (
                    "api_security_testing_pending" in coverage_gaps
                    or surface_states.get("api") != "confirmed_absent"
                ):
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
        elif goal == "internal_reconnaissance":
            if "internal_network_recon_pending" in coverage_gaps:
                candidates.append("internal_network_recon")
            if "internal_service_assessment_pending" in coverage_gaps:
                candidates.append("internal_service_discovery")

        if not candidates:
            return plan

        present = {step.get("task") for step in plan}
        enriched = list(plan)
        short_specialized_vuln_plan = (
            goal == "vulnerability_assessment"
            and len(plan) <= 3
            and "cpanel_assessment" in candidates
        )
        for task in self._rank_candidate_tasks(
            candidates,
            context,
            critical_candidates,
        ):
            task = self.tool_registry.canonical_task(task)
            if (
                short_specialized_vuln_plan
                and "cpanel_assessment" in present
                and task
                in {
                    "web_vulnerability_testing",
                    "web_app_deep_testing",
                    "template_verification",
                    "api_security_testing",
                }
            ):
                continue
            is_critical = task in critical_candidates
            if len(enriched) >= self._plan_enrichment_limit() and not is_critical:
                break
            if task in present or self._task_exhausted(task):
                continue
            if not self.tool_registry.task_has_available_tools(task):
                continue
            insert_at = next(
                (
                    idx
                    for idx, step in enumerate(enriched)
                    if step.get("agent") != "DiscoveryAgent"
                ),
                len(enriched),
            )
            enriched.insert(insert_at, {"agent": "DiscoveryAgent", "task": task})
            present.add(task)
            print(
                f"[*] Plan enriched with {task} "
                f"from context services={sorted(services)}"
            )
            if (
                short_specialized_vuln_plan and task == "cpanel_assessment"
            ) or len(enriched) > self._plan_enrichment_limit():
                self._trim_low_priority_enrichment(enriched, protected={task})

        if (
            goal == "vulnerability_assessment"
            and "external_vulnerability_assessment_pending" in coverage_gaps
        ):
            enriched.sort(
                key=lambda step: (
                    0 if step.get("task") == "vulnerability_assessment" else 1
                )
            )

        return self.policy.validate_plan(enriched, context)

    def _rank_candidate_tasks(
        self,
        candidates: list[str],
        context: dict[str, Any],
        critical_candidates: set | None = None,
    ) -> list[str]:
        critical_candidates = {
            self.tool_registry.canonical_task(task)
            for task in (critical_candidates or set())
        }
        seen = set()
        normalized = []
        for task in candidates or []:
            canonical = self.tool_registry.canonical_task(task)
            if canonical in seen:
                continue
            seen.add(canonical)
            normalized.append(canonical)
        scored = self.task_scorer.rank(
            (
                task,
                self._task_scoring_signals(
                    task,
                    context,
                    critical=task in critical_candidates,
                ),
            )
            for task in normalized
        )
        # Critical candidates are a hard orchestration tier, not a tunable
        # score bonus.  Configured scoring still determines order within each
        # tier, but a plan-capacity check must never stop before a critical
        # candidate has even been considered.
        ranked = tuple(
            sorted(
                scored,
                key=lambda item: item.task_id not in critical_candidates,
            )
        )
        self._record_task_scoring_trace(
            ranked,
            context,
            critical_candidates=critical_candidates,
        )
        return [item.task_id for item in ranked]

    def _task_scoring_signals(
        self,
        task: str,
        context: dict[str, Any],
        *,
        critical: bool = False,
    ) -> TaskScoringSignals:
        """Derive normalized signals from current durable/read-model state."""
        profile = self.tool_registry.task_profile(task)
        preconditions = list(profile.get("preconditions") or [])
        unmet = self._unmet_task_preconditions(preconditions, context)
        open_questions = tuple(str(item) for item in context.get("open_questions") or ())
        coverage_gaps = tuple(
            str(item)
            for item in (
                context.get("coverage_gaps")
                or context.get("open_questions")
                or ()
            )
        )
        next_capability = self.tool_registry.canonical_task(
            str(context.get("next_required_capability") or "")
        )
        tokens = tuple(
            token for token in task.split("_") if len(token) >= 3
        )

        def relevant(value: str) -> bool:
            normalized_value = value.lower().replace("-", "_").replace(" ", "_")
            return (
                task in normalized_value
                or normalized_value in task
                or any(token in normalized_value for token in tokens)
            )

        question_match = any(relevant(item) for item in open_questions)
        coverage_match = any(relevant(item) for item in coverage_gaps)
        on_path = bool(task == next_capability or critical)
        information_gain = (
            1.0
            if on_path or question_match
            else 0.65 if open_questions else 0.35
        )
        coverage_value = (
            1.0
            if coverage_match
            else 0.45 if coverage_gaps else 0.15
        )
        verification_markers = (
            "verify",
            "verification",
            "test",
            "assessment",
            "exploit_selection",
        )
        is_verification_task = any(
            marker in task for marker in verification_markers
        )
        verification_value = (
            1.0
            if critical
            or str(profile.get("risk")) == "check_only"
            or (
                is_verification_task
                and (question_match or coverage_match or on_path)
            )
            else 0.35
        )
        if on_path:
            path_value = 1.0
        elif preconditions and not unmet:
            path_value = 0.7
        elif not preconditions:
            path_value = 0.45
        else:
            path_value = 0.1

        time_penalty = {"short": 0.0, "medium": 1.0, "long": 2.0}.get(
            str(profile.get("time") or "medium"),
            1.0,
        )
        try:
            raw_cost = float(profile.get("cost", 5) or 5)
        except (TypeError, ValueError):
            raw_cost = 5.0
        cost = self._bounded_scoring_signal((raw_cost + time_penalty) / 10.0)

        history_count = len([
            item
            for item in self.task_history
            if str(item).split(":", 1)[-1] == task
        ])
        if task in self.completed_tasks or task in self.blocked_tasks:
            history_count += 2
        repeat = self._bounded_scoring_signal(history_count / 2.0)
        risk = {
            "passive": 0.0,
            "safe": 0.2,
            "check_only": 0.3,
            "post_access_read": 0.45,
            "local_build": 0.45,
            "active": 0.75,
            "post_access_change": 1.0,
            "unknown": 0.8,
        }.get(str(profile.get("risk") or "unknown"), 0.8)
        uncertainty = (
            self._bounded_scoring_signal(len(unmet) / max(1, len(preconditions)))
            if preconditions
            else 0.0
        )
        if str(profile.get("risk") or "unknown") == "unknown":
            uncertainty = max(uncertainty, 0.5)
        return TaskScoringSignals(
            information_gain=information_gain,
            coverage_value=coverage_value,
            verification_value=verification_value,
            path_value=path_value,
            cost=cost,
            repeat=repeat,
            risk=risk,
            uncertainty=uncertainty,
        )

    @staticmethod
    def _bounded_scoring_signal(value: float) -> float:
        return max(0.0, min(float(value), 1.0))

    def _record_task_scoring_trace(
        self,
        scored,
        context: dict[str, Any],
        *,
        critical_candidates: set[str] | None = None,
    ) -> None:
        if not scored:
            return
        critical_candidates = critical_candidates or set()
        ranked = []
        for item in scored:
            payload = item.to_trace_dict()
            payload["priority_tier"] = (
                "critical" if item.task_id in critical_candidates else "scored"
            )
            ranked.append(payload)
        chosen = scored[0]
        self.decision_trace.record(
            {
                "event_id": (
                    f"task-scoring:{self.mission_id or self._current_scan_id}:"
                    f"{len(self.goal_trace)}:{','.join(item.task_id for item in scored)}"
                ),
                "event_type": "task_scoring",
                "mission_id": self.mission_id or "",
                "scan_id": self._current_scan_id,
                "goal": str(
                    (self.goal_trace[-1] if self.goal_trace else {}).get("goal")
                    or ""
                ),
                "candidates": [item.task_id for item in scored],
                "chosen_action": chosen.task_id,
                "capability_ref": str(
                    context.get("next_required_capability") or ""
                ),
                "supporting_fact_ids": context.get("supporting_fact_ids") or [],
                "expected_outcome": {
                    "weights": self.task_scorer.weights.to_dict(),
                    "critical_candidates": sorted(critical_candidates),
                },
                "actual_outcome": {
                    "ranking": ranked,
                    "explanation": chosen.explanation,
                },
                "cost": {"candidate_count": len(scored)},
                "state_transition": {
                    "from": str(context.get("state") or ""),
                    "to": str(context.get("state") or ""),
                },
            }
        )

    def _unmet_task_preconditions(
        self,
        preconditions: list[str],
        context: dict[str, Any],
    ) -> list[str]:
        return self.capability_resolver.missing_requirements(
            preconditions,
            context,
        )

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
        from core.tools.targeting import target_looks_domain

        return target_looks_domain(target)

    def _trim_low_priority_enrichment(
        self,
        plan: list[dict[str, Any]],
        protected: set,
    ) -> None:
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
            for index, step in enumerate(plan):
                if step.get("task") == task:
                    plan.pop(index)
                    return
        if len(plan) > 3:
            plan.pop(-2)


__all__ = ["PipelinePlanningMixin"]
