#!/usr/bin/env python3

import contextlib
import json
import logging
from typing import Any

from core.ai.llm_context import compact_context_for_llm

with contextlib.suppress(ImportError):
    from core.ai.ollama_client import ask_ollama

logger = logging.getLogger("octopus.planner")

class MissionPlanner:
    def __init__(self):
        self.system_prompt = """You are the MISSION PLANNER of OCTOPUS, an autonomous penetration testing system.
YOUR ONLY JOB is to take a high-level GOAL from the Director and decompose it into a sequence of agent assignments.

Available Agents:
- DiscoveryAgent: Collects data (e.g. service_discovery, web_content_discovery, active_directory_enumeration)
- AnalysisAgent: Builds hypotheses from data (e.g. analyze_vulnerabilities, identify_cves)
- VerificationAgent: Attempts to confirm hypotheses (e.g. verify_exploit, test_credentials)

You MUST output your response in STRICT JSON format matching this schema:
{
  "thought": "Brief explanation of the plan",
  "plan": [
    {"agent": "DiscoveryAgent", "task": "service_discovery"},
    {"agent": "AnalysisAgent", "task": "analyze_services"}
  ]
}

RULES:
1. Do NOT specify exact tools like 'nmap' or 'whatweb'. Use high-level conceptual tasks.
2. Keep the plan focused. A maximum of 3 steps per plan.
3. Include an AnalysisAgent step for discovery/vulnerability goals. Do NOT add AnalysisAgent for persistence, data_exfiltration, or cleanup goals.
4. VALID TASKS ONLY: service_discovery, vulnerability_assessment, exploit_selection, metasploit_verification, web_application_mapping, browser_surface_analysis, web_vulnerability_testing, web_content_discovery, web_credential_testing, transport_security_assessment, firewall_detection, external_intelligence, browser_osint, windows_enumeration, active_directory_enumeration, kerberos_assessment, ssh_user_enumeration, credential_harvesting, hash_cracking, test_credentials, find_privesc_vectors, exploit_privesc, post_access_inventory, payload_generation, establish_persistence, internal_network_recon, internal_service_discovery, pivot_setup, lateral_movement, domain_credential_extraction, ad_remote_execution, cpanel_assessment, plugin_assessment, exfiltrate_data, stealth_cleanup.
"""

    def create_plan(self, goal: str, context: dict[str, Any], task_history: list[str]) -> dict[str, Any]:
        """Query the LLM to create a mission plan. Falls back to deterministic plans."""
        llm_context = compact_context_for_llm(context, role="planner")
        prompt = f"""Current Context JSON:
{json.dumps(llm_context, ensure_ascii=False, separators=(",", ":"))}

Recent Task History (do not repeat failed tasks):
{json.dumps(task_history[-5:], ensure_ascii=False, separators=(",", ":"))}

Director's Goal: {goal}

Output your plan in JSON format. Keep thought under 180 characters."""

        try:
            full_prompt = self.system_prompt + "\n\n" + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # v12: check the error contract
            if response.startswith("[!]"):
                raise ValueError(response)

            result = json.loads(response)
            if isinstance(result, list):
                result = {"plan": result}
            elif not isinstance(result, dict):
                raise ValueError(f"Planner returned {type(result).__name__}, expected object or plan list")
            result["llm_status"] = "ok"
            return result
        except Exception as e:
            logger.warning(f"Planner LLM failed: {e}")
            print(f"[!] Planner LLM Error: {e}")
            result = self._fallback_logic(goal)
            result.update({"llm_status": "failed", "llm_error": str(e), "fallback": True})
            return result

    def _fallback_logic(self, goal: str) -> dict[str, Any]:
        """Deterministic plan logic if LLM fails. Each goal gets a proper multi-step plan."""
        plans = {
            "service_discovery": {"thought": "fallback: discover services then analyze", "plan": [
                {"agent": "DiscoveryAgent", "task": "service_discovery"},
                {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"}
            ]},
            "vulnerability_assessment": {"thought": "fallback: vuln scan, web mapping, then analyze", "plan": [
                {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
                {"agent": "DiscoveryAgent", "task": "web_application_mapping"},
                {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"}
            ]},
            "credential_harvesting": {"thought": "fallback: harvest then test creds", "plan": [
                {"agent": "DiscoveryAgent", "task": "credential_harvesting"},
                {"agent": "VerificationAgent", "task": "test_credentials"}
            ]},
            "privilege_escalation": {"thought": "fallback: find and exploit privesc", "plan": [
                {"agent": "DiscoveryAgent", "task": "find_privesc_vectors"},
                {"agent": "VerificationAgent", "task": "exploit_privesc"}
            ]},
            "post_access_inventory": {"thought": "fallback: controlled post-access SSH inventory", "plan": [
                {"agent": "VerificationAgent", "task": "post_access_inventory"}
            ]},
            "persistence": {"thought": "fallback: establish persistence", "plan": [
                {"agent": "VerificationAgent", "task": "establish_persistence"}
            ]},
            "internal_reconnaissance": {"thought": "fallback: map internal network from established access", "plan": [
                {"agent": "VerificationAgent", "task": "internal_network_recon"}
            ]},
            "data_exfiltration": {"thought": "fallback: exfiltrate data", "plan": [
                {"agent": "VerificationAgent", "task": "exfiltrate_data"}
            ]},
            "cleanup": {"thought": "fallback: stealth cleanup", "plan": [
                {"agent": "VerificationAgent", "task": "stealth_cleanup"}
            ]},
        }

        return plans.get(goal, {"thought": "fallback: unknown goal, concluding", "plan": []})
