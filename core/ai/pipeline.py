#!/usr/bin/env python3

import hashlib
import json
import logging
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from core.ai.capability_assessment import CapabilityResolver
from core.ai.context_builder import ContextBuilder
from core.ai.credential_sync import RuntimeCredentialSynchronizer
from core.ai.director import DirectorLLM
from core.ai.evidence import EvidenceVerifier
from core.ai.exploit_applicability import assess_exploit_command
from core.ai.outcomes import InMemoryTaskOutcomeStore
from core.ai.pipeline_mission import PipelineMissionMixin
from core.ai.pipeline_observability import PipelineObservabilityMixin
from core.ai.pipeline_planning import PipelinePlanningMixin
from core.ai.pipeline_replay import PipelineReplayMixin
from core.ai.planner import MissionPlanCompiler, MissionPlanner
from core.ai.policy import DeterministicPolicy
from core.ai.runtime import PipelineRuntime
from core.ai.scan_loop import ToolBudgetReached
from core.ai.state_resolver import StateResolver
from core.ai.task_agents import AnalysisAgent, DiscoveryAgent, VerificationAgent
from core.ai.task_scoring import TaskScorer
from core.ai.tool_registry import ToolRegistry
from core.execution import (
    CancellationContext,
    ExecutionCancelled,
    ExecutionResult,
    ExecutionStatus,
)

logger = logging.getLogger("octopus.pipeline")

# Try to import tool runner, else mock it for tests
try:
    from tools import run_arbitrary_cmd
except ImportError:
    def run_arbitrary_cmd(cmd: str) -> str:
        raise FileNotFoundError("OCTOPUS tool runtime is unavailable")

class AIPipeline(
    PipelineMissionMixin,
    PipelinePlanningMixin,
    PipelineReplayMixin,
    PipelineObservabilityMixin,
):
    def __init__(self, db_path: str = "data/facts.db"):
        self.runtime = PipelineRuntime(db_path, runner=lambda command: run_arbitrary_cmd(command))
        self.fact_store = self.runtime.facts
        self.fact_assessments = self.runtime.assessments
        self.mission_store = self.runtime.missions
        self.knowledge_graph = self.runtime.knowledge_graph
        self.graph_projector = self.runtime.graph_projector
        self.command_scheduler = self.runtime.scheduler
        self.state_resolver = StateResolver(self.fact_store)
        self.tool_registry = ToolRegistry()
        self.capability_resolver = CapabilityResolver(
            self.tool_registry,
            self.command_scheduler.execution_policy,
        )
        self.context_builder = ContextBuilder(
            self.fact_store,
            self.state_resolver,
            self.capability_resolver,
            self._execution_context,
        )
        self.director = DirectorLLM()
        self.policy = DeterministicPolicy()
        self.planner = MissionPlanner()
        self.plan_compiler = MissionPlanCompiler(self.capability_resolver)
        from config import CFG

        self.task_scorer = TaskScorer.from_config(CFG)
        self.output_parser = self.runtime.parser
        self.evidence_verifier = EvidenceVerifier(
            self.fact_store,
            self.fact_assessments,
            self.graph_projector,
        )
        self.trace_reporter = self.runtime.reporter

        self.discovery_agent = DiscoveryAgent(self.tool_registry)
        self.analysis_agent = AnalysisAgent(self.fact_store, self.context_builder)
        self.verification_agent = VerificationAgent(self.tool_registry, self.evidence_verifier)
        self.credential_synchronizer = RuntimeCredentialSynchronizer(logger=logger)

        self.MAX_CONSECUTIVE_LLM_FAILURES = 3
        self._reset_runtime_state()

    @property
    def action_catalog(self):
        return self.runtime.action_catalog

    @property
    def action_executor(self):
        return self.runtime.action_executor

    @property
    def provider_telemetry(self):
        return self.runtime.provider_telemetry

    @property
    def provider_selector(self):
        return self.runtime.provider_selector

    @property
    def provider_fallback_executor(self):
        return self.runtime.provider_fallback_executor

    @property
    def decision_trace(self):
        return self.runtime.decision_trace

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
        self.task_outcome_store = InMemoryTaskOutcomeStore(
            self.task_outcomes,
            self.failed_commands,
            self.no_fact_tasks,
        )
        self.executed_followup_commands = set()
        self.executed_active_commands = set()
        self.executed_post_access_commands = set()
        self.executed_fact_action_commands = set()
        self.executed_command_keys = set()
        self.service_intelligence_evidence_seen = set()
        self.command_trace = []
        self.goal_trace = []
        self.plan_rejections = []
        self.retry_scheduled_tasks = set()
        self._active_retry_command_keys = set()
        self._state_replan_count = 0
        self._state_replan_signatures = set()

        # LLM health tracking
        self.consecutive_llm_failures = 0
        self.mission_id = None
        self._active_task_attempt_id = None
        self._active_task_name = ""
        self._active_task_agent = ""
        self._mission_was_completed = False
        self._mission_was_resumed = False
        self._mission_stop_reason = ""
        self._max_tools_budget = None
        self._current_scan_id = ""
        self._current_target = ""
        self._last_decision_state = ""
        self.cancellation = CancellationContext()

    def cancel(self, reason: str = "operator_request") -> bool:
        """Request cooperative cancellation of the active scan."""

        return self.cancellation.cancel(reason)

    def run_scan(
        self,
        scan_id: str,
        target: str,
        max_iterations: int = 0,
        max_tools: int = 0,
        max_time_minutes: int = 0,
        raw_scan: str = "",
        *,
        cancellation: Optional[CancellationContext] = None,
    ):
        from core.ai.scan_loop import ScanLifecycle

        if cancellation is not None:
            # The explicit token is used by bounded integration callers such as
            # the competitor adapter. Ordinary scans keep their existing
            # timeout/retry behavior and do not bind Ollama to a deadline.
            from core.ai.ollama_client import bind_ollama_cancellation

            with bind_ollama_cancellation(cancellation):
                return ScanLifecycle().run(
                    self,
                    scan_id,
                    target,
                    max_iterations,
                    max_tools,
                    max_time_minutes,
                    raw_scan,
                    cancellation=cancellation,
                )
        return ScanLifecycle().run(
            self,
            scan_id,
            target,
            max_iterations,
            max_tools,
            max_time_minutes,
            raw_scan,
        )

    def _run_task_commands(self, scan_id: str, target: str, cmds: list[str], fact_label: str, verification: bool = False) -> dict[str, Any]:
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
                                  fact_label: str, prefix: str) -> dict[str, Any]:
        self._current_scan_id = str(scan_id)
        self._current_target = str(target)
        if (
            self._max_tools_budget is not None
            and self.tools_run_count >= self._max_tools_budget
        ):
            self._mission_stop_reason = "max_tools_reached"
            raise ToolBudgetReached("max_tools_reached")
        execution_context = self._execution_context(scan_id, target)
        current_facts = self.fact_store.get_facts(scan_id, target)
        decision = self.runtime.decide(
            cmd,
            current_facts,
            self.executed_command_keys,
            execution_context,
            self._active_retry_command_keys,
        )
        if decision.action == "execute":
            assessment = assess_exploit_command(cmd, current_facts)
            if not assessment.applicable:
                decision.action = "skip"
                decision.reason = "assessment_blocked:" + ",".join(
                    assessment.missing_requirements
                )
                decision.prerequisite = "canonical_fact_assessment"
                decision.retry = False
        if decision.action == "execute" and decision.retry:
            consumed = bool(
                self.mission_id
                and self._active_task_agent
                and self._active_task_name
                and self.mission_store.consume_retry_command(
                    self.mission_id,
                    self._active_task_agent,
                    self._active_task_name,
                    decision.key,
                )
            )
            if consumed:
                self._active_retry_command_keys.discard(decision.key)
            else:
                decision.action = "skip"
                decision.reason = "retry_command_grant_unavailable"
                decision.retry = False
        audit_decision = decision.to_dict()
        audit_cmd = audit_decision["command"]
        if decision.action == "skip":
            print(f"     [Skipped] {audit_cmd} ({decision.reason})")
            self._record_command_trace(audit_decision, None)
            return self._skipped_command_result(audit_cmd, decision.reason)

        self.executed_command_keys.add(decision.key)
        print(f"     {prefix} {audit_cmd}")
        running_fact = self._command_check_result_fact(
            cmd=audit_cmd,
            target=target,
            command_key=decision.key,
            status="running",
        )
        running_store = self._store_fact(scan_id, target, running_fact, audit_cmd)
        dispatch_result = self.runtime.execute(decision, execution_context)
        if dispatch_result.execution_id:
            for running_fact_id in running_store["fact_ids"]:
                self.fact_assessments.attach_source_executions(
                    int(running_fact_id),
                    (dispatch_result.execution_id,),
                )
            self.runtime.project_fact_ids(running_store["fact_ids"])
        if self._active_task_attempt_id and dispatch_result.execution_id:
            self.mission_store.record_attempt_progress(
                self._active_task_attempt_id,
                execution_ids=(dispatch_result.execution_id,),
            )
        self.tools_run_count += 1
        if cmd.startswith("ssh_inventory "):
            self.executed_post_access_commands.add(cmd)
        output_str = self._output_text(dispatch_result)
        output_hash = self._output_fingerprint(output_str)
        failed = self._command_failed(dispatch_result, output_str)
        facts = self.runtime.parse_output(cmd, dispatch_result)
        parsed_output_facts = len(facts)
        status = self._command_check_status(
            cmd,
            output_str,
            failed,
            parsed_output_facts,
            dispatch_result,
        )
        facts.extend(self._command_end_check_results(audit_cmd, target, decision.key, status, output_str, facts))
        for fact in facts:
            fact.setdefault("source", audit_cmd)
        stored_facts = [running_fact, *list(facts)]
        command_new_facts = running_store["new_facts"]
        command_fact_ids = list(running_store["fact_ids"])

        source_execution_ids = (
            (dispatch_result.execution_id,) if dispatch_result.execution_id else ()
        )
        for f in facts:
            stored = self._store_fact(
                scan_id,
                target,
                f,
                audit_cmd,
                source_execution_ids=source_execution_ids,
            )
            stored_facts.extend(stored["derived_facts"])
            command_fact_ids.extend(stored["fact_ids"])
            if stored["created"] and f.get("type") != "check_result":
                safe_fact = stored["fact"]
                print(f"     [+] {fact_label}: {safe_fact['type']} -> {safe_fact['value']}")
            command_new_facts += stored["new_facts"]
        self._sync_runtime_credentials_from_facts(target, facts)
        _result_id, unique_output = self.fact_store.add_command_result(
            scan_id=scan_id,
            host=target,
            command_key=decision.key,
            command=audit_cmd,
            output_hash=output_hash,
            output_bytes=len(output_str.encode("utf-8", "ignore")),
            parsed_facts=parsed_output_facts,
            new_facts=command_new_facts,
            failed=failed,
            execution_result=dispatch_result,
            idempotency_key=(
                f"execution:{dispatch_result.execution_id}"
                if dispatch_result.execution_id
                else ""
            ),
        )

        result = {
            "facts": stored_facts,
            "new_facts": command_new_facts,
            "parsed_facts": parsed_output_facts,
            "command_result": {
                "command": audit_cmd,
                "failed": failed,
                "schema_version": dispatch_result.schema_version,
                "status": dispatch_result.status.value,
                "partial": dispatch_result.partial,
                "execution_id": dispatch_result.execution_id,
                "request_id": dispatch_result.request_id,
                "policy_decision_ref": dispatch_result.policy_decision_ref,
                "error_class": dispatch_result.error_class,
                "exit_code": dispatch_result.exit_code,
                "duration": dispatch_result.duration,
                "output_bytes": len(dispatch_result.stdout.encode("utf-8", "ignore")),
                "stderr_bytes": len(dispatch_result.stderr.encode("utf-8", "ignore")),
                "output_hash": output_hash,
                "duplicate_output": not unique_output,
                "parsed_facts": parsed_output_facts,
                "new_facts": command_new_facts,
                "fact_ids": list(dict.fromkeys(command_fact_ids)),
                "fact_pairs": [(fact.get("type"), fact.get("value")) for fact in facts],
                "check_status": status,
            },
        }
        if self._active_task_attempt_id:
            self.mission_store.record_attempt_progress(
                self._active_task_attempt_id,
                fact_ids=tuple(dict.fromkeys(command_fact_ids)),
            )
        self._record_command_trace(decision.to_dict(), result["command_result"])
        if dispatch_result.status is ExecutionStatus.CANCELLED:
            raise ExecutionCancelled("provider_cancelled")
        return result

    def _skipped_command_result(self, cmd: str, reason: str) -> dict[str, Any]:
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

    def _command_end_check_results(
        self,
        cmd: str,
        target: str,
        command_key: str,
        status: str,
        output_str: str,
        parsed_facts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        results = [
            self._command_check_result_fact(
                cmd=cmd,
                target=target,
                command_key=command_key,
                status=status,
                output_str=output_str,
            )
        ]
        if self._command_tool_name(cmd) == "internal_service_probe":
            for fact in parsed_facts:
                if fact.get("type") != "internal_service":
                    continue
                scope_value = self._internal_service_scope_value(str(fact.get("value", "")))
                if not scope_value:
                    continue
                results.append(self._command_check_result_fact(
                    cmd=cmd,
                    target=target,
                    command_key=f"{command_key}:{scope_value}",
                    status="completed",
                    kind="internal_service_discovery",
                    scope={"type": "internal_service", "value": scope_value},
                    mode="check_only",
                ))
        if self._command_tool_name(cmd) == "exploit_select":
            for scope_value in self._internal_service_scopes_from_compact_state(cmd):
                results.append(self._command_check_result_fact(
                    cmd=cmd,
                    target=target,
                    command_key=f"{command_key}:{scope_value}",
                    status=status,
                    kind="internal_vulnerability_assessment",
                    scope={"type": "internal_service", "value": scope_value},
                    mode="check_only",
                ))
        return results

    def _command_check_result_fact(
        self,
        cmd: str,
        target: str,
        command_key: str,
        status: str,
        output_str: str = "",
        kind: str = "",
        scope: Optional[dict[str, str]] = None,
        mode: str = "",
    ) -> dict[str, Any]:
        tool = self._command_tool_name(cmd)
        status = self._normalized_check_status(cmd, status, output_str)
        payload: dict[str, Any] = {
            "tool": tool,
            "command_key": command_key,
            "command": cmd,
            "kind": kind or self._command_check_kind(cmd),
            "mode": mode or self._command_check_mode(cmd, status),
            "scope": scope or self._command_check_scope(cmd, target),
            "status": status,
        }
        if "[PARTIAL OUTPUT" in (output_str or ""):
            payload["partial_output"] = True
        return {
            "type": "check_result",
            "value": json.dumps(payload, sort_keys=True),
            "confidence": 90 if status in {"completed", "running"} else 80,
        }

    def _command_check_status(
        self,
        cmd: str,
        output_str: str,
        failed: bool,
        parsed_output_facts: int,
        execution_result: Optional[ExecutionResult] = None,
    ) -> str:
        from core.execution.normalization import command_check_status

        return command_check_status(
            cmd,
            output_str,
            failed,
            parsed_output_facts,
            execution_result,
        )

    def _normalized_check_status(self, cmd: str, status: str, output_str: str = "") -> str:
        from core.execution.normalization import normalized_check_status

        return normalized_check_status(cmd, status, output_str)

    def _command_tool_name(self, cmd: str) -> str:
        from core.execution.normalization import command_tool_name

        return command_tool_name(cmd)

    def _command_check_kind(self, cmd: str) -> str:
        tool = self._command_tool_name(cmd)
        command = (cmd or "").lower()
        if tool in {"nuclei", "nuclei_safe"}:
            return "template_verification"
        if tool in {"whatweb", "curl_headers", "scrapling", "browser_surface_analysis"}:
            return "web_mapping"
        if tool == "security_headers_check":
            return "web_headers"
        if tool == "cors_check":
            return "cors"
        if tool in {"jwt_analyze", "js_route_extract", "session_profile_import", "authenticated_crawl", "burp_import", "zap_import"}:
            return "web_app_deep_testing"
        if tool in {"ffuf", "scrapling_crawl", "katana_crawl"}:
            return "web_content_discovery"
        if tool in {"wpscan", "sqlmap", "nikto", "jmx2rce_scan"}:
            return "web_vulnerability"
        if tool in {"openapi_import", "graphql_check", "api_auth_check"}:
            return "api_security"
        if tool == "exploit_select":
            if self._internal_service_scopes_from_compact_state(cmd):
                return "internal_vulnerability_assessment"
            return "exploit_selection"
        if tool == "searchsploit":
            return "exploit_database"
        if tool == "msf_run":
            return "active_exploitation"
        if tool == "msf_check":
            return "msf_login_check" if "_login" in command or command.endswith("/login") else "msf_check"
        if tool == "ssh_inventory":
            return "post_access_inventory"
        if tool == "network_recon":
            return "internal_network_recon"
        if tool == "internal_service_probe":
            return "internal_service_discovery"
        return tool

    def _command_check_mode(self, cmd: str, status: str) -> str:
        tool = self._command_tool_name(cmd)
        command = (cmd or "").lower()
        if tool == "msf_run":
            return "active_run"
        if tool == "msf_check":
            if "_login" in command or command.endswith("/login"):
                if status == "skipped":
                    return "login_check_missing_creds"
                if re.search(r"\b(username|user|password|pass|db_all_creds|db_all_users)=", command, re.IGNORECASE):
                    return "login_check_with_known_creds"
                return "login_check"
            return "check_only"
        return "check_only"

    def _command_check_scope(self, cmd: str, target: str) -> dict[str, str]:
        url_match = re.search(r"\bhttps?://[^\s'\"<>]+", cmd or "", re.IGNORECASE)
        if url_match:
            return {"type": "endpoint", "value": self._canonical_check_url(url_match.group(0))}
        rport_match = re.search(r"\bRPORT(?:S)?=(\d{1,5})\b", cmd or "", re.IGNORECASE)
        if rport_match:
            return {"type": "service", "value": f"{self._target_host(target).lower()}:{rport_match.group(1)}/tcp"}
        if self._command_tool_name(cmd) in {"ssh_inventory", "network_recon", "internal_service_probe"}:
            return {"type": "host", "value": self._target_host(target).lower()}
        return {"type": "host", "value": self._target_host(target).lower()}

    def _canonical_check_url(self, url: str) -> str:
        from core.tools.targeting import canonical_check_url

        return canonical_check_url(url)

    def _internal_service_scope_value(self, value: str) -> str:
        from core.tools.targeting import internal_service_scope_value

        return internal_service_scope_value(value)

    def _internal_service_scopes_from_compact_state(self, cmd: str) -> list[str]:
        from core.tools.targeting import internal_service_scopes_from_compact_state

        return internal_service_scopes_from_compact_state(cmd)

    def _store_fact(
        self,
        scan_id: str,
        target: str,
        fact: dict[str, Any],
        source: str,
        *,
        source_execution_ids: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        """Store a parsed fact plus normalized derived facts.

        The canonical fact remains deduplicated; repeated sightings are kept by
        FactStore as observations. Derived facts give later stages stable
        endpoint and graph objects instead of reparsing free-form strings.
        """
        fact = self._scope_normalized_fact(target, fact)
        safe_fact = dict(fact)
        safe_value, secret_refs = self.fact_store.redactor.redact_fact(
            safe_fact.get("type", ""), safe_fact.get("value", "")
        )
        safe_fact["value"] = safe_value
        if secret_refs:
            safe_fact["secret_refs"] = list(secret_refs)
        fact_id, created = self.fact_store.add_fact_with_status(
            scan_id, target, safe_fact["type"], safe_fact["value"], source,
            confidence=safe_fact.get("confidence", 100),
            session_id=safe_fact.get("session_id", "none"),
            source_execution_ids=source_execution_ids,
        )
        new_facts = 1 if created else 0
        fact_ids = [fact_id]
        derived_facts = self._derived_facts_from_fact(target, fact, source)
        for derived in derived_facts:
            derived_id, derived_created = self.fact_store.add_fact_with_status(
                scan_id, target, derived["type"], derived["value"], f"derived:{source}",
                confidence=derived.get("confidence", fact.get("confidence", 80)),
                session_id=fact.get("session_id", "none"),
                derived_from=[fact_id],
                source_execution_ids=source_execution_ids,
            )
            fact_ids.append(derived_id)
            if derived_created:
                new_facts += 1
        self.runtime.project_fact_ids(fact_ids)
        return {
            "created": created,
            "new_facts": new_facts,
            "derived_facts": derived_facts,
            "fact": safe_fact,
            "fact_ids": list(dict.fromkeys(fact_ids)),
        }

    def _scope_normalized_fact(self, target: str, fact: dict[str, Any]) -> dict[str, Any]:
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

    def _derived_facts_from_fact(self, target: str, fact: dict[str, Any], source: str) -> list[dict[str, Any]]:
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
        from core.tools.targeting import canonical_endpoint_value

        return canonical_endpoint_value(url, service=service, port=port)

    def _network_graph_facts(self, target: str, ftype: str, value: str) -> list[dict[str, Any]]:
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

    def _followup_commands_from_facts(self, facts: list[dict[str, Any]]) -> list[str]:
        """Run safe verification commands emitted by earlier tools once."""
        from core.ai.followups import ServiceFollowupRules

        candidates = []
        candidate_keys = set(self.executed_followup_commands)
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
            if cmd in candidate_keys:
                continue
            candidate_keys.add(cmd)
            candidates.append(cmd)
            if limit is not None and len(candidates) >= limit:
                break

        proposals = ServiceFollowupRules().propose(
            intelligence_commands=candidates,
            limit=limit,
        )
        commands = [proposal.command for proposal in proposals]
        self.executed_followup_commands.update(commands)
        return commands

    def _run_fact_driven_actions(
        self, scan_id: str, target: str, facts: list[dict[str, Any]]
    ) -> dict[str, Any]:
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

        def enqueue_result(result: dict[str, Any], depth: int) -> None:
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
        self, scan_id: str, target: str, facts: list[dict[str, Any]]
    ) -> list[str]:
        """Map facts to safe deterministic follow-up actions."""
        from core.ai.followups import FollowupRuleFamilies

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
        ssh_inventory_commands = []
        if self._auto_ssh_inventory_enabled() and not inventory_seen and (ssh_creds_available or ssh_access_confirmed):
            ssh_inventory_commands.append(f"ssh_inventory {target}")

        cpanel_commands = []
        if self._facts_indicate_cpanel_surface(facts) and not self._cpanel_already_verified(all_pairs):
            cpanel_commands.append(f"plugin cpanel_auth_bypass {target} scan")

        proposals = FollowupRuleFamilies().from_legacy_groups(
            ssh_inventory_commands=ssh_inventory_commands,
            cpanel_commands=cpanel_commands,
            service_intelligence_commands=self._service_intelligence_commands(
                scan_id, target, facts, all_pairs
            ),
            protocol_service_commands=self._service_action_commands(target, facts, all_pairs),
            web_path_commands=self._web_path_action_commands(scan_id, target, facts),
            web_link_api_commands=self._web_link_action_commands(scan_id, target, facts),
            web_surface_commands=self._web_surface_action_commands(scan_id, target, facts, all_pairs),
        )

        deduped = []
        for proposal in proposals:
            cmd = self._augment_command_with_context(proposal.command, scan_id, target)
            if cmd in self.executed_fact_action_commands:
                continue
            self.executed_fact_action_commands.add(cmd)
            deduped.append(cmd)
            batch_limit = self._strategy_limit("fact_action_batch_commands", None)
            if batch_limit is not None and len(deduped) >= batch_limit:
                break
        return deduped

    def _facts_include_cached_ssh_credential(self, facts: list[dict[str, Any]]) -> bool:
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
        self, scan_id: str, target: str, facts: list[dict[str, Any]], all_pairs: set
    ) -> list[str]:
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

    def _service_intelligence_evidence_key(self, fact: dict[str, Any]) -> str:
        if not self._fact_is_external_service_evidence(fact):
            return ""
        ftype = str(fact.get("type", "")).lower()
        value = str(fact.get("value", "")).strip().lower()
        service_types = {
            "port_open", "service_version", "web_server", "web_powered_by",
            "browser_rendered", "web_title", "web_surface", "web_input", "web_link",
            "web_endpoint", "web_root", "potential_vulnerability", "vulnerability",
        }
        if ftype not in service_types or not value:
            return ""
        if ftype == "web_link" and not self._web_link_looks_interesting(value):
            return ""
        return f"{ftype}:{value[:220]}"

    def _facts_include_service_evidence(self, facts: list[dict[str, Any]]) -> bool:
        return any(self._fact_is_external_service_evidence(fact) for fact in facts)

    def _fact_is_external_service_evidence(self, fact: dict[str, Any]) -> bool:
        ftype = str(fact.get("type", "")).lower()
        value = str(fact.get("value", "")).strip().lower()
        source = str(fact.get("source", "")).lower()
        if not value:
            return False
        if source.startswith(("ssh_inventory ", "controlled_ssh_inventory ", "post_access_inventory ")):
            return False
        if source.startswith("derived:ssh_inventory "):
            return False
        if ftype in {"local_listening_port", "app_stack"}:
            return False
        if ftype == "service_version" and ":local:" in value:
            return False
        return ftype in {
            "port_open", "service_version", "web_server", "web_powered_by",
            "browser_rendered", "web_title", "web_surface", "web_input",
            "web_link", "web_endpoint", "web_root", "potential_vulnerability",
            "vulnerability",
        }

    def _searchsploit_query_seen(self, fact_pairs: set, query: str) -> bool:
        normalized = self._normalize_query_token(query)
        return any(
            ftype == "service_status" and value == f"searchsploit_queried:{normalized}"
            for ftype, value in fact_pairs
        )

    def _searchsploit_queries_from_facts(self, facts: list[dict[str, Any]]) -> list[str]:
        queries = []
        for fact in facts:
            if not self._fact_is_external_service_evidence(fact):
                continue
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).strip()
            query = ""
            if ftype in {
                "web_server", "web_powered_by", "browser_rendered", "web_title",
                "web_surface", "web_input", "web_link", "web_endpoint", "web_root",
            } and "http" not in queries:
                queries.append("http")
            if ftype in {"potential_vulnerability", "vulnerability"}:
                cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", value, re.IGNORECASE)
                for cve in cves:
                    query = self._sanitize_searchsploit_query(cve.upper())
                    if query and query not in queries:
                        queries.append(query)
                continue
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
            elif ftype == "web_title":
                lowered = value.lower()
                if "nginx" in lowered:
                    query = "nginx"
                elif "apache" in lowered:
                    query = "apache"
                elif "wordpress" in lowered:
                    query = "wordpress"
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

    def _facts_indicate_cpanel_surface(self, facts: list[dict[str, Any]]) -> bool:
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).lower()
            if ftype == "application_access" and "cpanel" in value:
                return False
            if ftype in {"port_open", "web_surface", "web_server", "web_redirect"} and any(
                marker in value for marker in ("cpanel", "whm", ":2082", ":2083", ":2086", ":2087")
            ):
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
        self, target: str, facts: list[dict[str, Any]], all_pairs: set
    ) -> list[str]:
        """Add deterministic protocol-specific probes for newly observed services."""
        commands = []
        for port, service, value in self._open_service_ports(facts):
            is_ftp = self._is_ftp_service(port, service, value)
            if is_ftp and not self._service_status_seen(
                all_pairs,
                ("ftp_anonymous_allowed", "ftp_anonymous_denied", "ftp_probe_failed"),
                port,
            ):
                commands.append(f"ftp_anonymous_check {target} {port}")
            if is_ftp:
                continue

            is_smtp = self._is_smtp_service(port, service, value)
            if is_smtp and not self._service_status_seen(
                all_pairs,
                ("smtp_probe_completed", "smtp_probe_failed"),
                port,
            ):
                commands.append(f"smtp_probe {target} {port}")
            if is_smtp:
                continue

            db_service = self._database_service_for_port(port, service, value)
            if (
                db_service
                and not self._database_inventory_seen(all_pairs, db_service, port)
                and self._has_database_credentials(target, db_service)
            ):
                commands.append(f"db_inventory {target} {port} {db_service}")
        return commands

    def _open_service_ports(self, facts: list[dict[str, Any]]) -> list[tuple]:
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
            if value.startswith(("db_inventory_completed:", "db_inventory_failed:")) and (
                f":{service}:{port}" in value or value.endswith(f":{port}")
            ):
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

    def _web_path_action_commands(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
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

    def _web_link_action_commands(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
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

    def _normalized_web_link_urls(self, scan_id: str, target: str, facts: list[dict[str, Any]]) -> list[str]:
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
        from core.tools.targeting import target_host

        return target_host(target)

    def _web_surface_action_commands(
        self, scan_id: str, target: str, facts: list[dict[str, Any]], all_pairs: set
    ) -> list[str]:
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
            if self._web_endpoint_absent_seen(all_pairs, endpoint):
                continue
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
            if self.tool_registry._is_tool_available("nuclei_safe") and not self._nuclei_seen(facts, all_pairs, endpoint):
                commands.append(f"nuclei_safe {endpoint}")
                if command_limit is not None and len(commands) >= command_limit:
                    break
            if self.tool_registry._is_tool_available("katana_crawl"):
                commands.append(f"katana_crawl {endpoint}")
            if command_limit is not None and len(commands) >= command_limit:
                break
        return commands

    def _facts_include_web_surface(self, facts: list[dict[str, Any]]) -> bool:
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

    def _web_endpoint_absent_seen(self, fact_pairs: set, endpoint: str) -> bool:
        endpoint_l = endpoint.lower().rstrip("/")
        return any(
            ftype == "service_status"
            and value.startswith(("web_fetch_failed:", "web_content_discovery_skipped:no_http_response"))
            and endpoint_l in value.rstrip("/")
            for ftype, value in fact_pairs
        )

    def _nuclei_seen(self, facts: list[dict[str, Any]], fact_pairs: set, endpoint: str) -> bool:
        endpoint_l = endpoint.lower().rstrip("/")
        if any(
            ftype == "service_status" and value == f"nuclei_scan_completed:{endpoint_l}"
            for ftype, value in fact_pairs
        ):
            return True
        for fact in facts or []:
            if str(fact.get("type", "")) != "service_status":
                continue
            value = str(fact.get("value", "")).lower()
            if value == f"nuclei_scan_completed:{endpoint_l}":
                return True
            if value != "tool_timeout:nuclei_safe" and value != "tool_timeout:nuclei":
                continue
            sources = [str(fact.get("source", ""))]
            sources.extend(str(item.get("source", "")) for item in fact.get("observations", []) if isinstance(item, dict))
            if any(endpoint_l in source.lower().rstrip("/") for source in sources):
                return True
        return False

    def _sync_runtime_credentials_from_facts(self, target: str, facts: list[dict[str, Any]]) -> None:
        """Mirror concrete SSH credentials from parsed facts into the tool cache."""
        self.credential_synchronizer.sync_from_facts(target, facts)

    def _known_credentials_for_target(self, target: str) -> dict[str, list[tuple]]:
        """Read known credentials from the unified store/legacy cache."""
        return self.credential_synchronizer.known_for_target(target)

    def _seed_known_credentials(self, scan_id: str, target: str) -> int:
        """Persist cached credentials as facts so state/context can use them."""
        result = self.credential_synchronizer.seed_known_credentials(
            scan_id,
            target,
            self.fact_store,
            self._known_credentials_for_target(target),
        )
        self.total_new_facts += result.seeded
        for announcement in result.announcements:
            print(f"    [+] Known Credential: {announcement}")
        return result.seeded

    def _run_controlled_post_access_followups(
        self, scan_id: str, target: str, facts: list[dict[str, Any]]
    ) -> dict[str, Any]:
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
        self, target: str, facts: list[dict[str, Any]]
    ) -> list[str]:
        """Run read-only SSH inventory once after confirmed SSH authentication."""
        from core.ai.followups import PostAccessFollowupRules

        # Preserve the legacy fact predicate while the typed rule becomes the
        # proposal owner.  Cached credentials are intentionally insufficient on
        # this controlled, post-verification path.
        enabled = self._auto_ssh_inventory_enabled()
        confirmed_facts = facts if enabled and self._facts_confirm_ssh_access(facts) else []
        proposals = PostAccessFollowupRules().propose(
            target,
            confirmed_facts,
            enabled=enabled,
            inventory_seen=False,
            already_executed=self.executed_post_access_commands,
            allow_cached_credentials=False,
        )
        commands = [proposal.command for proposal in proposals]
        self.executed_post_access_commands.update(commands)
        return commands

    def _facts_confirm_ssh_access(self, facts: list[dict[str, Any]]) -> bool:
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

    def _active_commands_from_facts(self, facts: list[dict[str, Any]]) -> list[str]:
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
        self, target: str, candidates: list[str], verification_facts: list[dict[str, Any]]
    ) -> list[str]:
        """Promote msf_run only after msf_check positively verifies the same module."""
        from core.ai.followups import ActivePromotionFollowupRules

        if not candidates:
            return []
        authorization_granted = self._active_msf_allowed(target)
        if not authorization_granted:
            return []

        proposals = ActivePromotionFollowupRules().propose(
            candidates,
            verification_facts,
            authorization_granted=authorization_granted,
            max_runs=self._max_active_msf_runs(),
            already_executed=self.executed_active_commands,
            candidate_limit=None,
        )
        commands = [proposal.command for proposal in proposals]
        self.executed_active_commands.update(commands)
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

    def _target_in_authorized_scope(self, target: str, scopes: list[str]) -> bool:
        from core.tools.targeting import target_in_authorized_scope

        return target_in_authorized_scope(target, scopes)

    def _expand_command_with_context(self, cmd: str, scan_id: str, target: str) -> list[str]:
        """Expand generic web commands across discovered HTTP endpoints."""
        parts = (cmd or "").strip().split(maxsplit=1)
        if len(parts) != 2:
            return [cmd]
        tool, arg = parts[0], parts[1].strip()
        if (
            tool == "bruteforce"
            and arg == f"ssh {target}"
            and self._known_credentials_for_target(target).get("ssh")
        ):
            return [f"ssh_session {target}"]
        if arg != target:
            return [cmd]

        web_mapping_tools = {
            "whatweb", "curl_headers", "scrapling", "browser_surface_analysis",
            "scrapling_crawl", "ffuf", "nikto", "jmx2rce_scan", "wpscan", "sqlmap",
        }
        if tool not in web_mapping_tools:
            return [cmd]

        if tool == "jmx2rce_scan":
            endpoints = self._jmx_or_tomcat_endpoints(scan_id, target)
        else:
            endpoints = self._web_endpoints_from_facts(scan_id, target)
        if not endpoints:
            if tool == "jmx2rce_scan":
                return []
            return [cmd]
        if tool == "jmx2rce_scan" and not self._has_jmx_or_tomcat_evidence(scan_id, target):
            return []
        limit = self._strategy_limit(f"{tool}_endpoint_limit", None)
        selected = endpoints if limit is None else endpoints[:limit]
        return [f"{tool} {endpoint}" for endpoint in selected]

    def _jmx_or_tomcat_endpoints(self, scan_id: str, target: str) -> list[str]:
        host = self._target_host(target)
        endpoints = []
        seen = set()
        global_evidence = False

        def add(endpoint: str) -> None:
            endpoint = self._display_endpoint_url(endpoint)
            if not endpoint or not self._endpoint_in_target_scope(endpoint, target):
                return
            key = endpoint.rstrip("/")
            if key in seen:
                return
            seen.add(key)
            endpoints.append(endpoint)

        for fact in self.fact_store.get_facts(scan_id, target):
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", ""))
            lowered = value.lower()
            if ftype in {"service_status", "check_result"} and "jmx2rce_not_vulnerable" in lowered:
                continue
            if not any(marker in lowered for marker in ("tomcat", "jmx", "catalina")):
                continue
            if ftype == "port_open":
                endpoint = self._endpoint_from_port_fact(target, value)
                add(self._endpoint_url_from_value(endpoint) or endpoint)
                continue
            if ftype == "service_version":
                parts = value.split(":", 2)
                if len(parts) == 3 and parts[1].isdigit() and host:
                    service, port, version = parts
                    scheme = "https" if self._service_fact_looks_tls(f"{service} {version}") else "http"
                    add(f"{scheme}://{host}:{port}/")
                    continue
            if ftype in {"web_endpoint", "browser_rendered", "web_root"}:
                add(self._endpoint_url_from_value(value))
                continue
            global_evidence = True

        if endpoints:
            return endpoints
        return self._web_endpoints_from_facts(scan_id, target) if global_evidence else []

    def _has_jmx_or_tomcat_evidence(self, scan_id: str, target: str) -> bool:
        for fact in self.fact_store.get_facts(scan_id, target):
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).lower()
            if ftype in {"service_status", "check_result"} and "jmx2rce_not_vulnerable" in value:
                continue
            if any(marker in value for marker in ("tomcat", "jmx", "catalina")):
                return True
        return False

    def _web_endpoints_from_facts(self, scan_id: str, target: str) -> list[str]:
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
        from core.tools.targeting import endpoint_in_target_scope

        return endpoint_in_target_scope(endpoint, target)

    def _endpoint_url_from_value(self, value: str) -> str:
        from core.tools.targeting import endpoint_url_from_value

        return endpoint_url_from_value(value)

    def _display_endpoint_url(self, endpoint: str) -> str:
        from core.tools.targeting import display_endpoint_url

        return display_endpoint_url(endpoint)

    def _service_fact_looks_web(self, service: str, value: str = "") -> bool:
        from core.tools.targeting import nmap_service_looks_web

        return nmap_service_looks_web(service, value)

    def _service_fact_looks_tls(self, value: str = "") -> bool:
        from core.tools.targeting import service_fact_looks_tls

        return service_fact_looks_tls(value)

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
        }
        recon_bits = []
        for fact in facts:
            if fact.get("type") not in useful_types:
                continue
            if not self._fact_is_external_service_evidence(fact):
                continue
            value = str(fact.get("value", "")).replace("\n", " ").replace("\r", " ").strip()
            if (
                fact.get("type") in {"web_endpoint", "web_link", "browser_rendered"}
                and not self._web_fact_in_target_scope(value, target)
            ):
                continue
            if value:
                recon_bits.append(f"{fact['type']} -> {value}")

        compact_context = self._exploit_select_compact_context(facts)
        if compact_context:
            recon_bits.append(f"compact_state -> {json.dumps(compact_context, sort_keys=True)}")

        if not recon_bits:
            return cmd
        fact_limit = self._strategy_limit("exploit_select_context_facts", None)
        selected_bits = recon_bits if fact_limit is None else recon_bits[:fact_limit]
        return f"{cmd} {' | '.join(selected_bits)}"

    def _exploit_select_compact_context(self, facts: list[dict[str, Any]]) -> dict[str, Any]:
        """Build a bounded recon state for exploit_select when raw recon_data is thin."""
        context: dict[str, Any] = {
            "open_ports": [],
            "internal_services": [],
        }
        seen_ports = set()
        seen_internal = set()
        access = set()
        for fact in facts:
            ftype = str(fact.get("type", "")).lower()
            value = str(fact.get("value", "")).strip()
            value_lower = value.lower()
            if not value:
                continue
            if ftype == "port_open":
                parsed = self._parse_port_fact_for_context(value)
                if parsed:
                    key = (parsed.get("port"), parsed.get("proto"), parsed.get("service"))
                    if key not in seen_ports:
                        seen_ports.add(key)
                        context["open_ports"].append(parsed)
            elif ftype == "internal_service":
                parsed = self._parse_internal_service_for_context(value)
                if parsed:
                    key = (parsed.get("host"), parsed.get("port"), parsed.get("service"))
                    if key not in seen_internal:
                        seen_internal.add(key)
                        context["internal_services"].append(parsed)
            elif ftype == "os_version" and "os" not in context:
                context["os"] = value[:160]
            elif ftype == "kernel_version" and "kernel" not in context:
                context["kernel"] = value[:160]
            elif ftype == "system_access" and value_lower in {"uid=0", "root_access_confirmed"}:
                access.add("root")
            elif ftype == "service_status" and value_lower == "ssh_authenticated":
                access.add("ssh_authenticated")
            elif ftype == "credential" and value_lower.startswith("ssh_login_success:"):
                access.add("ssh_login_success")

        if access:
            context["access"] = sorted(access)
        context["open_ports"] = context["open_ports"][:12]
        context["internal_services"] = context["internal_services"][:20]
        return {key: value for key, value in context.items() if value}

    def _parse_port_fact_for_context(self, value: str) -> dict[str, Any]:
        match = re.match(r"(?:(?P<host>[^:\s]+):)?(?P<port>\d+)/(?:tcp|udp)\s+\((?P<service>[^)]*)\)(?:\s+\[(?P<banner>.*?)\])?", value)
        if not match:
            return {}
        item = {
            "port": int(match.group("port")),
            "proto": "tcp" if "/tcp" in value.lower() else "udp",
            "service": (match.group("service") or "").strip(),
        }
        if match.group("host"):
            item["host"] = match.group("host")
        if match.group("banner"):
            item["banner"] = match.group("banner")[:120]
        return item

    def _parse_internal_service_for_context(self, value: str) -> dict[str, Any]:
        match = re.match(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d+)/(?:tcp|udp)\s+\((?P<service>[^)]*)\)", value)
        if not match:
            return {}
        return {
            "host": match.group("host"),
            "port": int(match.group("port")),
            "proto": "tcp" if "/tcp" in value.lower() else "udp",
            "service": (match.group("service") or "").strip(),
        }

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
        from core.execution.normalization import output_text

        return output_text(output)

    def _command_failed(self, output: Any, output_str: str) -> bool:
        from core.execution.normalization import command_failed

        return command_failed(output, output_str)

# For testing
if __name__ == "__main__":
    pipeline = AIPipeline("/tmp/pipeline_test.db")
    pipeline.run_scan("test_scan_1", "127.0.0.1", max_iterations=3)
