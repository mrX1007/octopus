#!/usr/bin/env python3

from typing import Any, Dict, List


class DeterministicPolicy:
    """State-gated policy for goals and task plans.

    LLMs may suggest work, but this layer decides whether the work is allowed
    by current facts, surface states and automation flags.
    """

    CATEGORY_TASKS = {
        "asm": {"asm_discovery", "asm_http_probe", "asm_dns_resolution", "asm_port_discovery", "asm_url_discovery"},
        "web": {"web_application_mapping", "web_vulnerability_testing", "web_app_deep_testing", "web_content_discovery", "browser_surface_analysis", "template_verification"},
        "api": {"api_security_testing"},
        "ad": {"active_directory_enumeration", "ad_security_review", "bloodhound_ingest", "password_policy_review", "delegation_analysis", "gpo_review", "adcs_review", "local_admin_paths", "acl_review", "kerberos_assessment"},
        "cloud": {"cloud_security_assessment"},
        "secrets": {"secrets_scanning"},
        "code": {"code_security_assessment"},
    }

    def validate_goal(self, proposed_goal: str, context: Dict[str, Any], goal_history: List[str]) -> Dict[str, str]:
        required = context.get("next_required_capability")
        if required and required != "conclude":
            return {
                "goal": required,
                "reason": f"state_gate_required:{required}",
            }
        if proposed_goal in goal_history and proposed_goal != "conclude":
            return {"goal": "conclude", "reason": "goal_already_attempted_without_state_change"}
        return {"goal": proposed_goal or "conclude", "reason": "accepted"}

    def validate_plan(self, plan: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        surface_states = (context.get("target_model") or {}).get("surface_states") or {}
        filtered: List[Dict[str, Any]] = []
        seen = set()
        for step in plan or []:
            task = step.get("task")
            if not task or task in seen:
                continue
            category = self.category_for_task(task)
            if category and surface_states.get(category) == "confirmed_absent":
                continue
            if not self._allowed_by_state(task, context):
                continue
            filtered.append(step)
            seen.add(task)
        return filtered

    def category_for_task(self, task: str) -> str:
        for category, tasks in self.CATEGORY_TASKS.items():
            if task in tasks:
                return category
        return ""

    def _allowed_by_state(self, task: str, context: Dict[str, Any]) -> bool:
        state = context.get("state", "initial_recon")
        policy = context.get("automation_policy") or {}
        if task in {"establish_persistence", "payload_generation"}:
            return state in {"root_access_confirmed", "persistence_established"} and bool(policy.get("auto_persistence", False))
        if task in {"internal_network_recon", "internal_service_discovery"}:
            return state in {
                "root_access_confirmed", "persistence_established",
                "internal_recon_completed", "exfiltration_completed",
            } and bool(policy.get("auto_internal_recon", True))
        if task == "exfiltrate_data":
            return state in {"persistence_established", "internal_recon_completed"} and bool(policy.get("auto_data_exfil", False))
        if task == "stealth_cleanup":
            return state == "exfiltration_completed" and bool(policy.get("auto_cleanup", False))
        return True
