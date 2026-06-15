#!/usr/bin/env python3

import json
import logging
from typing import Dict, Any, List

try:
    from core.ai.ollama_client import ask_ollama
except ImportError:
    pass

logger = logging.getLogger("octopus.planner")

class MissionPlanner:
    def __init__(self):
        self.system_prompt = """You are the MISSION PLANNER of OCTOPUS, an autonomous penetration testing system.
YOUR ONLY JOB is to take a high-level GOAL from the Director and decompose it into a sequence of agent assignments.

Available Agents:
- DiscoveryAgent: Collects data (e.g. service_discovery, port_scan, directory_bruteforce)
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
3. Always include an AnalysisAgent step to process findings.
"""

    def create_plan(self, goal: str, context: Dict[str, Any], task_history: List[str]) -> Dict[str, Any]:
        """Query the LLM to create a mission plan. Falls back to deterministic plans."""
        prompt = f"""Current Context:
{json.dumps(context, indent=2)}

Recent Task History (do not repeat failed tasks):
{json.dumps(task_history[-5:], indent=2)}

Director's Goal: {goal}

Output your plan in JSON format."""

        try:
            full_prompt = self.system_prompt + "\n\n" + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # v12: check the error contract
            if response.startswith("[!]"):
                raise ValueError(response)

            return json.loads(response)
        except Exception as e:
            logger.warning(f"Planner LLM failed: {e}")
            print(f"[!] Planner LLM Error: {e}")
            return self._fallback_logic(goal)

    def _fallback_logic(self, goal: str) -> Dict[str, Any]:
        """Deterministic plan logic if LLM fails. Each goal gets a proper multi-step plan."""
        if goal == "service_discovery":
            return {"thought": "fallback: discover services then analyze", "plan": [
                {"agent": "DiscoveryAgent", "task": "service_discovery"},
                {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"}
            ]}
        elif goal == "vulnerability_assessment":
            return {"thought": "fallback: vuln scan then analyze", "plan": [
                {"agent": "DiscoveryAgent", "task": "vulnerability_assessment"},
                {"agent": "AnalysisAgent", "task": "analyze_vulnerabilities"}
            ]}
        elif goal == "credential_harvesting":
            return {"thought": "fallback: harvest then test creds", "plan": [
                {"agent": "DiscoveryAgent", "task": "credential_harvesting"},
                {"agent": "VerificationAgent", "task": "test_credentials"}
            ]}
        elif goal == "privilege_escalation":
            return {"thought": "fallback: find and exploit privesc", "plan": [
                {"agent": "DiscoveryAgent", "task": "find_privesc_vectors"},
                {"agent": "VerificationAgent", "task": "exploit_privesc"}
            ]}
        elif goal == "persistence":
            return {"thought": "fallback: establish persistence", "plan": [
                {"agent": "VerificationAgent", "task": "establish_persistence"}
            ]}
        elif goal == "data_exfiltration":
            return {"thought": "fallback: exfiltrate data", "plan": [
                {"agent": "VerificationAgent", "task": "exfiltrate_data"}
            ]}
        elif goal == "cleanup":
            return {"thought": "fallback: stealth cleanup", "plan": [
                {"agent": "VerificationAgent", "task": "stealth_cleanup"}
            ]}

        return {"thought": "fallback: unknown goal, concluding", "plan": []}
