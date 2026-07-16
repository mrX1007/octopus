"""Read-only capability assessment over existing OCTOPUS authorities.

The facade deliberately keeps provider availability, execution authorization,
target-state evidence, and mission prerequisites as separate axes.  It never
invokes a tool, runner, subprocess, or plugin worker, and an assessment is not
an execution permit.  ``CommandScheduler``/``ExecutionPolicy`` remain the
time-of-use authorization boundary.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from core.ai.tool_registry import ToolRegistry
from core.execution import ExecutionContext, ExecutionPolicy

STRATEGIC_TASKS: dict[str, tuple[str, ...]] = {
    "service_discovery": ("service_discovery",),
    "vulnerability_assessment": ("vulnerability_assessment",),
    "credential_harvesting": ("credential_harvesting", "test_credentials"),
    "privilege_escalation": ("find_privesc_vectors", "exploit_privesc"),
    "post_access_inventory": ("post_access_inventory",),
    "persistence": ("establish_persistence",),
    "internal_reconnaissance": ("internal_network_recon", "internal_service_discovery"),
    "data_exfiltration": ("exfiltrate_data",),
    "cleanup": ("stealth_cleanup",),
    "conclude": (),
}

# These names describe the stage/strategy semantics that already gate the
# strategic loop.  They do not grant execution permission.
STRATEGIC_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "service_discovery": (),
    "vulnerability_assessment": ("stage:recon", "services"),
    "credential_harvesting": ("stage:recon", "services"),
    "privilege_escalation": ("stage:credentials", "access"),
    "post_access_inventory": ("stage:root", "access"),
    "persistence": ("stage:root", "access", "policy:auto_persistence"),
    "internal_reconnaissance": ("stage:root", "access", "policy:auto_internal_recon"),
    "data_exfiltration": ("stage:root", "access", "policy:auto_data_exfil"),
    "cleanup": ("stage:exfiltration", "access", "policy:auto_cleanup"),
    "conclude": (),
}

TASK_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "post_access_inventory": ("stage:root",),
    "payload_generation": ("stage:root", "policy:auto_payload_generation"),
    "establish_persistence": ("stage:root", "policy:auto_persistence"),
    "internal_network_recon": ("stage:root", "policy:auto_internal_recon"),
    "internal_service_discovery": ("stage:root", "policy:auto_internal_recon"),
    "exfiltrate_data": ("stage:root", "policy:auto_data_exfil"),
    "stealth_cleanup": ("stage:exfiltration", "policy:auto_cleanup"),
}

_WEB_FACT_TYPES = {
    "browser_rendered",
    "web_endpoint",
    "web_input",
    "web_link",
    "web_powered_by",
    "web_redirect",
    "web_server",
    "web_surface",
    "web_title",
}


@dataclass(frozen=True)
class ProviderAssessment:
    """One concrete provider's dependency and preflight-policy state."""

    task: str
    provider: str
    status: str
    authorization_decision: str = "unknown"
    authorization_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "provider": self.provider,
            "status": self.status,
            "authorization_decision": self.authorization_decision,
            "authorization_reason": self.authorization_reason,
        }


@dataclass(frozen=True)
class FreshnessConfidenceSummary:
    """Observed evidence bounds without inventing a staleness policy."""

    fact_count: int = 0
    oldest_observed_at: float | None = None
    newest_observed_at: float | None = None
    confidence_min: float | None = None
    confidence_max: float | None = None
    confidence_average: float | None = None
    freshness: str = "not_assessed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_count": self.fact_count,
            "oldest_observed_at": self.oldest_observed_at,
            "newest_observed_at": self.newest_observed_at,
            "confidence_min": self.confidence_min,
            "confidence_max": self.confidence_max,
            "confidence_average": self.confidence_average,
            "freshness": self.freshness,
        }


@dataclass(frozen=True)
class CapabilityAssessment:
    """Immutable, JSON-serializable assessment of one named capability."""

    capability: str
    target: str
    scope: tuple[str, ...]
    requested: bool
    providers: tuple[ProviderAssessment, ...]
    provider_availability: str
    authorization_decision: str
    authorization_reason: str
    evidence_state: str
    requirements: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    blocking_reasons: tuple[str, ...]
    supporting_fact_ids: tuple[int, ...]
    freshness_confidence: FreshnessConfidenceSummary

    @property
    def hard_unavailable(self) -> bool:
        """Whether planning has no concrete provider path at this instant."""
        return self.provider_availability in {"unavailable", "no_provider"}

    @property
    def ready(self) -> bool:
        return (
            not self.blocking_reasons
            and self.authorization_decision in {"allowed", "not_applicable"}
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "target": self.target,
            "scope": list(self.scope),
            "requested": self.requested,
            "providers": [provider.to_dict() for provider in self.providers],
            "provider_availability": self.provider_availability,
            "authorization_decision": self.authorization_decision,
            "authorization_reason": self.authorization_reason,
            "evidence_state": self.evidence_state,
            "requirements": list(self.requirements),
            "missing_requirements": list(self.missing_requirements),
            "blocking_reasons": list(self.blocking_reasons),
            "supporting_fact_ids": list(self.supporting_fact_ids),
            "freshness_confidence": self.freshness_confidence.to_dict(),
            "hard_unavailable": self.hard_unavailable,
            "ready": self.ready,
        }


class CapabilityResolver:
    """Aggregate capability state without dispatching any provider."""

    def __init__(
        self,
        tool_registry: ToolRegistry | None = None,
        execution_policy: ExecutionPolicy | None = None,
    ) -> None:
        self.tool_registry = tool_registry if tool_registry is not None else ToolRegistry()
        self.execution_policy = execution_policy if execution_policy is not None else ExecutionPolicy()

    def resolve(
        self,
        capability: str,
        *,
        target: str,
        facts: Iterable[Mapping[str, Any]],
        context: Mapping[str, Any],
        execution_context: ExecutionContext | None,
        agent: str = "",
        requested: bool | None = None,
    ) -> CapabilityAssessment:
        canonical = self._canonical_capability(capability)
        fact_list = [
            dict(fact)
            for fact in facts or []
            if str(fact.get("assessment_status") or "observed") != "contradicted"
        ]
        tasks = self._tasks_for_capability(canonical)
        requirements = self._requirements_for(canonical, tasks)
        missing = tuple(
            requirement
            for requirement in requirements
            if not self.requirement_met(requirement, context)
        )
        supporting_facts = self._supporting_facts(
            fact_list,
            requirements,
            missing,
        )
        providers = self._resolve_providers(
            canonical,
            tasks,
            target,
            execution_context,
            agent,
        )
        provider_availability = self._provider_availability(canonical, providers, agent)
        authorization_decision, authorization_reason = self._aggregate_authorization(
            providers,
            provider_availability,
        )
        blocking_reasons = self._blocking_reasons(
            provider_availability,
            authorization_decision,
            authorization_reason,
            missing,
        )
        requested_value = (
            self._is_requested(canonical, context)
            if requested is None
            else bool(requested)
        )
        scope = tuple(execution_context.target_scope) if execution_context else ()

        return CapabilityAssessment(
            capability=canonical,
            target=str(target or ""),
            scope=scope,
            requested=requested_value,
            providers=providers,
            provider_availability=provider_availability,
            authorization_decision=authorization_decision,
            authorization_reason=authorization_reason,
            evidence_state=self._evidence_state(context, requirements, missing, supporting_facts),
            requirements=requirements,
            missing_requirements=missing,
            blocking_reasons=blocking_reasons,
            supporting_fact_ids=self._supporting_fact_ids(supporting_facts),
            freshness_confidence=self._freshness_confidence(supporting_facts),
        )

    # Compatibility-friendly verb for callers that read the model as an
    # assessment rather than a state resolution.
    assess = resolve

    def requirement_met(self, requirement: str, context: Mapping[str, Any]) -> bool:
        services = set(context.get("services") or [])
        target_model = context.get("target_model") or {}
        surface_states = target_model.get("surface_states") or context.get("surface_states") or {}
        access = target_model.get("access") or {}
        internal_graph = target_model.get("internal_graph") or context.get("network_graph") or {}

        if requirement.startswith("stage:"):
            stage = requirement.split(":", 1)[1]
            return bool((context.get("stage_gates") or {}).get(stage, False))
        if requirement.startswith("policy:"):
            flag = requirement.split(":", 1)[1]
            return bool((context.get("automation_policy") or {}).get(flag, False))
        if requirement == "services":
            return bool(services)
        if requirement == "web":
            return bool(
                services.intersection({"http", "https", "cpanel", "tomcat"})
                or target_model.get("endpoints")
                or surface_states.get("web") == "confirmed_present"
            )
        if requirement == "tls":
            return bool(
                "https" in services
                or any(
                    isinstance(endpoint, Mapping) and endpoint.get("scheme") == "https"
                    for endpoint in target_model.get("endpoints") or []
                )
            )
        if requirement == "domain":
            from core.tools.targeting import target_looks_domain

            return target_looks_domain(str(context.get("host", "")))
        if requirement == "ad_surface":
            return bool(services.intersection({"ldap", "kerberos", "winrm", "rdp", "smb"}))
        if requirement == "smb":
            return "smb" in services
        if requirement == "ssh":
            return "ssh" in services
        if requirement == "access":
            return bool(
                context.get("state") in {
                    "root_access_confirmed",
                    "persistence_established",
                    "internal_recon_completed",
                    "exfiltration_completed",
                }
                or access.get("ssh_authenticated")
                or access.get("root_confirmed")
            )
        if requirement == "internal_hosts":
            return bool(
                internal_graph.get("nodes")
                or (target_model.get("internal_graph") or {}).get("nodes")
            )
        if requirement == "internal_services":
            return bool(target_model.get("internal_services"))
        return False

    def missing_requirements(
        self,
        requirements: Iterable[str],
        context: Mapping[str, Any],
    ) -> list[str]:
        return [
            requirement
            for requirement in requirements or []
            if not self.requirement_met(str(requirement), context)
        ]

    def _canonical_capability(self, capability: str) -> str:
        normalized = str(capability or "").strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in STRATEGIC_TASKS:
            return normalized
        return self.tool_registry.canonical_task(normalized)

    def _tasks_for_capability(self, capability: str) -> tuple[str, ...]:
        if capability in STRATEGIC_TASKS:
            return STRATEGIC_TASKS[capability]
        return (self.tool_registry.canonical_task(capability),) if capability else ()

    def _requirements_for(
        self,
        capability: str,
        tasks: tuple[str, ...],
    ) -> tuple[str, ...]:
        if capability in STRATEGIC_REQUIREMENTS:
            return STRATEGIC_REQUIREMENTS[capability]

        requirements: list[str] = []
        for task in tasks:
            profile = self.tool_registry.task_profile(task)
            requirements.extend(str(item) for item in profile.get("preconditions") or [])
            requirements.extend(TASK_REQUIREMENTS.get(task, ()))
        return tuple(dict.fromkeys(requirements))

    def _resolve_providers(
        self,
        capability: str,
        tasks: tuple[str, ...],
        target: str,
        execution_context: ExecutionContext | None,
        agent: str,
    ) -> tuple[ProviderAssessment, ...]:
        if capability == "conclude":
            return (
                ProviderAssessment(
                    task=capability,
                    provider="control_plane",
                    status="not_applicable",
                    authorization_decision="not_applicable",
                    authorization_reason="in_process_control_flow",
                ),
            )
        if agent == "AnalysisAgent" and capability == "analyze_vulnerabilities":
            return (
                ProviderAssessment(
                    task=capability,
                    provider="analysis_agent",
                    status="not_applicable",
                    authorization_decision="not_applicable",
                    authorization_reason="in_process_control_flow",
                ),
            )
        if (
            (agent == "AnalysisAgent" and capability != "analyze_vulnerabilities")
            or (capability == "analyze_vulnerabilities" and agent != "AnalysisAgent")
            or (agent and agent not in {"DiscoveryAgent", "VerificationAgent", "AnalysisAgent"})
        ):
            return ()

        records: list[dict[str, Any]] = []
        for task in tasks:
            for raw_record in self.tool_registry.get_provider_statuses_for_task(task):
                record = dict(raw_record)
                record["task"] = task
                records.append(record)

        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            key = (str(record.get("task", "")), str(record.get("provider", "")))
            item = grouped.setdefault(key, {"available": False, "templates": []})
            item["available"] = bool(item["available"] or record.get("available"))
            template = str(record.get("command_template", ""))
            if template and template not in item["templates"]:
                item["templates"].append(template)

        providers: list[ProviderAssessment] = []
        for (task, provider), metadata in grouped.items():
            if not metadata["available"]:
                providers.append(ProviderAssessment(
                    task=task,
                    provider=provider,
                    status="unavailable",
                    authorization_decision="unknown",
                    authorization_reason="provider_unavailable",
                ))
                continue
            authorization, reason = self._authorize_templates(
                metadata["templates"],
                target,
                execution_context,
            )
            providers.append(ProviderAssessment(
                task=task,
                provider=provider,
                status="available",
                authorization_decision=authorization,
                authorization_reason=reason,
            ))
        return tuple(providers)

    def _authorize_templates(
        self,
        templates: Iterable[str],
        target: str,
        execution_context: ExecutionContext | None,
    ) -> tuple[str, str]:
        if execution_context is None:
            return "unknown", "execution_context_not_supplied"

        decisions: list[tuple[bool, str]] = []
        for template in templates:
            try:
                command = str(template).format(target=target, user="root", password="")
            except (IndexError, KeyError, ValueError):
                continue
            decision = self.execution_policy.authorize_command(command, execution_context)
            decisions.append((bool(decision.allowed), str(decision.reason)))

        if not decisions:
            return "unknown", "provider_command_not_assessable"
        for allowed, reason in decisions:
            if allowed:
                return "allowed", reason
        reasons = tuple(dict.fromkeys(reason for _allowed, reason in decisions if reason))
        return "denied", ";".join(reasons) or "execution_policy_denied"

    @staticmethod
    def _provider_availability(
        capability: str,
        providers: tuple[ProviderAssessment, ...],
        _agent: str,
    ) -> str:
        if capability == "conclude" or (
            providers and all(provider.status == "not_applicable" for provider in providers)
        ):
            return "not_applicable"
        if not providers:
            return "no_provider"
        if any(provider.status == "available" for provider in providers):
            return "available"
        return "unavailable"

    @staticmethod
    def _aggregate_authorization(
        providers: tuple[ProviderAssessment, ...],
        provider_availability: str,
    ) -> tuple[str, str]:
        if provider_availability == "not_applicable":
            return "not_applicable", "in_process_control_flow"
        available = [provider for provider in providers if provider.status == "available"]
        if any(provider.authorization_decision == "allowed" for provider in available):
            reason = next(
                provider.authorization_reason
                for provider in available
                if provider.authorization_decision == "allowed"
            )
            return "allowed", reason
        if available and all(provider.authorization_decision == "denied" for provider in available):
            reasons = tuple(dict.fromkeys(
                f"{provider.provider}:{provider.authorization_reason}"
                for provider in available
            ))
            return "denied", ";".join(reasons)
        if provider_availability in {"unavailable", "no_provider"}:
            return "unknown", "no_available_provider"
        return "unknown", "execution_context_not_supplied"

    @staticmethod
    def _blocking_reasons(
        provider_availability: str,
        authorization_decision: str,
        authorization_reason: str,
        missing_requirements: tuple[str, ...],
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if provider_availability == "no_provider":
            reasons.append("provider:no_provider")
        elif provider_availability == "unavailable":
            reasons.append("provider:unavailable")
        if authorization_decision == "denied":
            reasons.append(f"authorization:denied:{authorization_reason}")
        elif authorization_decision == "unknown" and provider_availability == "available":
            reasons.append(f"authorization:unknown:{authorization_reason}")
        reasons.extend(f"requirement:missing:{item}" for item in missing_requirements)
        return tuple(dict.fromkeys(reasons))

    def _is_requested(self, capability: str, context: Mapping[str, Any]) -> bool:
        requested = self._canonical_capability(str(context.get("next_required_capability", "")))
        if requested == capability:
            return True
        return capability in self._tasks_for_capability(requested)

    def _supporting_facts(
        self,
        facts: list[dict[str, Any]],
        requirements: tuple[str, ...],
        missing_requirements: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        satisfied = [item for item in requirements if item not in missing_requirements]
        if not satisfied:
            return []
        return [
            fact
            for fact in facts
            if any(self._fact_supports_requirement(fact, requirement) for requirement in satisfied)
        ]

    def _fact_supports_requirement(self, fact: Mapping[str, Any], requirement: str) -> bool:
        fact_type = str(fact.get("type", "")).lower()
        value = str(fact.get("value", "")).lower()

        if requirement.startswith("policy:"):
            return False
        if requirement.startswith("stage:"):
            stage = requirement.split(":", 1)[1]
            if stage == "recon":
                return fact_type == "port_open" or fact_type in _WEB_FACT_TYPES
            if stage == "credentials":
                return "credential" in fact_type or "login_success" in value
            if stage == "root":
                return (
                    "uid=0" in value
                    or "root_access_confirmed" in value
                    or (fact_type == "credential" and value.startswith("ssh_login_success:root@"))
                    or (
                        "exploit_success" in fact_type
                        and self._is_system_access_exploit_value(value)
                    )
                )
            if stage == "post_access_inventory":
                return fact_type == "post_exploit_stage" and value == "post_access_inventory_completed"
            if stage == "persistence":
                return "persistence" in fact_type or "mechanism_planted" in value
            if stage == "internal_recon":
                return (
                    fact_type == "internal_network"
                    or "internal_network_recon_completed" in value
                    or (fact_type == "service_status" and value == "network_recon_completed")
                )
            if stage == "exfiltration":
                return fact_type in {"data_exfiltration", "data_exfiltration_status"} or (
                    fact_type == "post_exploit_stage" and value == "data_exfiltration_completed"
                )
            if stage == "cleanup":
                return "cleanup" in fact_type and value in {"success", "partial", "completed"}
            return False
        if requirement == "services":
            return fact_type == "port_open" or fact_type in _WEB_FACT_TYPES
        if requirement == "web":
            return fact_type in _WEB_FACT_TYPES or (
                fact_type == "port_open"
                and any(marker in value for marker in ("http", "cpanel", "tomcat"))
            )
        if requirement == "tls":
            return (
                fact_type == "web_endpoint" and "https" in value
            ) or (
                fact_type == "port_open" and any(marker in value for marker in ("https", "ssl/http"))
            )
        if requirement == "domain":
            return fact_type in {"domain", "subdomain", "dns_record"}
        if requirement == "ad_surface":
            return fact_type == "port_open" and any(
                marker in value for marker in ("ldap", "kerberos", "winrm", "rdp", "smb", "microsoft-ds")
            )
        if requirement in {"smb", "ssh"}:
            return fact_type == "port_open" and requirement in value
        if requirement == "access":
            return (
                fact_type in {"application_access", "system_access"}
                or "login_success" in value
                or "ssh_authenticated" in value
                or "uid=0" in value
            )
        if requirement == "internal_hosts":
            return fact_type in {"internal_host", "internal_subnet", "network_node"}
        if requirement == "internal_services":
            return fact_type == "internal_service" or value.startswith("internal_service_probe_completed")
        return False

    @staticmethod
    def _is_system_access_exploit_value(value: str) -> bool:
        app_only_markers = ("cpanel", "whm", "webmin", "joomla", "wordpress")
        if any(marker in value for marker in app_only_markers):
            return False
        return any(marker in value for marker in (
            "uid=0",
            "root access",
            "root shell",
            "pwnkit",
            "dirtycow",
            "dirty pipe",
            "baron samedit",
            "local privilege escalation",
        ))

    @staticmethod
    def _supporting_fact_ids(facts: Iterable[Mapping[str, Any]]) -> tuple[int, ...]:
        ids: set[int] = set()
        for fact in facts:
            raw_id = fact.get("id")
            if raw_id is None:
                continue
            try:
                fact_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if fact_id > 0:
                ids.add(fact_id)
        return tuple(sorted(ids))

    @staticmethod
    def _freshness_confidence(
        facts: Iterable[Mapping[str, Any]],
    ) -> FreshnessConfidenceSummary:
        fact_list = list(facts)
        timestamps: list[float] = []
        confidences: list[float] = []
        freshness_states: list[str] = []
        coverage_states: list[str] = []
        for fact in fact_list:
            freshness_state = str(fact.get("freshness_status") or "").strip().lower()
            if freshness_state:
                freshness_states.append(freshness_state)
            coverage_state = str(fact.get("coverage_status") or "").strip().lower()
            execution_status = str(fact.get("execution_status") or "").strip().lower()
            if execution_status == "timeout":
                coverage_state = "degraded"
            if coverage_state:
                coverage_states.append(coverage_state)
            observations = fact.get("observations") or []
            samples = [item for item in observations if isinstance(item, Mapping)] or [fact]
            for sample in samples:
                raw_timestamp = sample.get("timestamp")
                try:
                    timestamp = float(raw_timestamp) if raw_timestamp is not None else math.nan
                except (TypeError, ValueError):
                    timestamp = math.nan
                if math.isfinite(timestamp) and timestamp >= 0:
                    timestamps.append(timestamp)
                raw_confidence = sample.get("confidence")
                try:
                    confidence = float(raw_confidence) if raw_confidence is not None else math.nan
                except (TypeError, ValueError):
                    confidence = math.nan
                if math.isfinite(confidence):
                    confidences.append(confidence)

        if "degraded" in coverage_states:
            freshness = "degraded"
        elif freshness_states and all(state == "stale" for state in freshness_states):
            freshness = "stale"
        elif "fresh" in freshness_states:
            freshness = "fresh"
        elif freshness_states:
            freshness = "unknown"
        else:
            freshness = "not_assessed"

        return FreshnessConfidenceSummary(
            fact_count=len(fact_list),
            oldest_observed_at=min(timestamps) if timestamps else None,
            newest_observed_at=max(timestamps) if timestamps else None,
            confidence_min=min(confidences) if confidences else None,
            confidence_max=max(confidences) if confidences else None,
            confidence_average=(
                round(sum(confidences) / len(confidences), 2)
                if confidences
                else None
            ),
            freshness=freshness,
        )

    @staticmethod
    def _evidence_state(
        context: Mapping[str, Any],
        requirements: tuple[str, ...],
        missing_requirements: tuple[str, ...],
        supporting_facts: list[dict[str, Any]],
    ) -> str:
        if missing_requirements:
            surface_states = (
                (context.get("target_model") or {}).get("surface_states")
                or context.get("surface_states")
                or {}
            )
            absent_surfaces = {
                requirement
                for requirement in missing_requirements
                if surface_states.get(requirement) == "confirmed_absent"
            }
            if absent_surfaces:
                return "confirmed_absent"
            return "unknown"
        if requirements and supporting_facts:
            return "confirmed_present"
        return "unknown"
