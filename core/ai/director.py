#!/usr/bin/env python3

import json
import logging
from typing import Dict, Any, List
from core.ai.policy import DeterministicPolicy

try:
    from core.ai.ollama_client import ask_ollama
except ImportError:
    pass

logger = logging.getLogger("octopus.director")

# Ordered kill chain progression
KILL_CHAIN = [
    "service_discovery",
    "vulnerability_assessment",
    "credential_harvesting",
    "privilege_escalation",
    "post_access_inventory",
    "persistence",
    "internal_reconnaissance",
    "data_exfiltration",
    "cleanup",
    "conclude",
]

class DirectorLLM:
    def __init__(self):
        self.policy = DeterministicPolicy()
        self.system_prompt = """You are the DIRECTOR of OCTOPUS, an autonomous penetration testing system.
YOUR ONLY JOB is to decide the NEXT HIGH-LEVEL GOAL based on the current state.
You DO NOT select tools. You DO NOT execute commands.
You MUST output your response in STRICT JSON format matching this schema:
{
  "thought": "Brief explanation of why this is the next logical step",
  "goal": "The high-level goal, e.g. service_discovery, vulnerability_assessment, credential_harvesting, privilege_escalation, post_access_inventory, persistence, internal_reconnaissance, data_exfiltration, cleanup, or conclude"
}

RULES:
1. If root_access_confirmed is true, run post_access_inventory first when needed, then use open_questions and automation_policy to decide internal_reconnaissance, persistence, data_exfiltration, cleanup, or conclude.
2. If recon is incomplete, your goal is service_discovery.
3. If recon IS complete but vulnerabilities are unknown, your goal is vulnerability_assessment.
4. If no new facts have been discovered for several loops, or the goal is repeating, your goal MUST be 'conclude'.
5. NEVER repeat a goal that has already been successfully completed.
6. NEVER select persistence, data_exfiltration, cleanup, or active exploitation unless the matching automation_policy flag and open_question allow it.
"""

    def decide_goal(self, context: Dict[str, Any], goal_history: List[str]) -> Dict[str, str]:
        """Query the LLM to decide the next goal. Falls back to deterministic logic."""

        # Anti-loop check: same goal 3 times in a row
        if len(goal_history) >= 3 and len(set(goal_history[-3:])) == 1:
            if goal_history[-1] != "conclude":
                print("\n[!] DIRECTOR LOOP DETECTED: Forcing conclusion.")
                return {"thought": "Loop detected — same goal 3x", "goal": "conclude"}

        prompt = f"""Current Context:
{json.dumps(context, indent=2)}

Recent Goal History:
{json.dumps(goal_history[-5:], indent=2)}

Based on the context, output the next goal in JSON format."""

        # Try to query LLM in JSON mode
        try:
            full_prompt = self.system_prompt + "\n\n" + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # v12: check the error contract
            if response.startswith("[!]"):
                raise ValueError(response)

            result = json.loads(response)
            goal = result.get("goal", "conclude")

            # Validate goal against context to prevent nonsensical LLM output
            policy_decision = self.policy.validate_goal(goal, context, goal_history)
            if policy_decision["goal"] != goal:
                result["thought"] = f"LLM suggested '{goal}' but policy forced '{policy_decision['goal']}' ({policy_decision['reason']})"
                result["goal"] = policy_decision["goal"]
                return result

            validated = self._validate_goal(goal, context, goal_history)
            if validated != goal:
                result["thought"] = f"LLM suggested '{goal}' but overridden to '{validated}'"
                result["goal"] = validated

            return result
        except Exception as e:
            logger.warning(f"Director LLM failed: {e}")
            print(f"[!] Director LLM Error: {e}")
            return self._fallback_logic(context, goal_history)

    def _validate_goal(self, goal: str, context: Dict[str, Any], goal_history: List[str]) -> str:
        """Validate the LLM suggestion against deterministic state gates."""
        state = context.get("state", "initial_recon")
        required = context.get("next_required_capability", "conclude")

        if required and required != "conclude":
            if (
                self._goal_allowed_for_state(required, state)
                and self._goal_allowed_by_policy(required, context)
            ):
                if goal != required:
                    return required

        if not self._goal_allowed_for_state(goal, state):
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        if not self._goal_allowed_by_policy(goal, context):
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        # Don't re-run service_discovery if recon is already done
        if goal == "service_discovery" and state != "initial_recon":
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        if goal == "data_exfiltration" and "internal_network_recon_pending" in context.get("open_questions", []):
            return "internal_reconnaissance"

        if "post_access_inventory_needed" in context.get("open_questions", []):
            return "post_access_inventory"
        if goal in {"persistence", "internal_reconnaissance", "data_exfiltration", "cleanup"}:
            required = {
                "persistence": "persistence_needed",
                "internal_reconnaissance": "internal_network_recon_pending",
                "data_exfiltration": "data_exfiltration_pending",
                "cleanup": "cleanup_needed",
            }
            if required[goal] not in context.get("open_questions", []):
                return self._fallback_logic(context, goal_history).get("goal", "conclude")
        if goal == "post_access_inventory":
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        completed_by_state = {
            "recon_completed": {"service_discovery"},
            "vulnerabilities_found": {"service_discovery", "vulnerability_assessment"},
            "credentials_found": {"service_discovery", "vulnerability_assessment", "credential_harvesting"},
            "root_access_confirmed": {
                "service_discovery", "vulnerability_assessment",
                "credential_harvesting", "privilege_escalation",
            },
            "persistence_established": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "post_access_inventory", "persistence",
            },
            "internal_recon_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "post_access_inventory", "persistence", "internal_reconnaissance",
            },
            "exfiltration_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "post_access_inventory", "persistence", "internal_reconnaissance", "data_exfiltration",
            },
            "cleanup_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "post_access_inventory", "persistence", "internal_reconnaissance", "data_exfiltration", "cleanup",
            },
        }
        if goal in completed_by_state.get(state, set()):
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        # Don't repeat goals that already ran
        if goal in goal_history and goal not in ("conclude",):
            return "conclude"

        return goal

    def _goal_allowed_by_policy(self, goal: str, context: Dict[str, Any]) -> bool:
        policy = context.get("automation_policy") or {}
        if goal == "persistence":
            return bool(policy.get("auto_persistence", False))
        if goal == "internal_reconnaissance":
            return bool(policy.get("auto_internal_recon", True))
        if goal == "data_exfiltration":
            return bool(policy.get("auto_data_exfil", False))
        if goal == "cleanup":
            return bool(policy.get("auto_cleanup", False))
        return True

    def _goal_allowed_for_state(self, goal: str, state: str) -> bool:
        """Prevent kill-chain drift when the state has not actually advanced."""
        allowed = {
            "initial_recon": {"service_discovery", "conclude"},
            "recon_completed": {
                "vulnerability_assessment", "credential_harvesting",
                "service_discovery", "conclude",
            },
            "vulnerabilities_found": {
                "service_discovery",
                "credential_harvesting",
                "vulnerability_assessment", "conclude",
            },
            "credentials_found": {
                "service_discovery", "vulnerability_assessment",
                "credential_harvesting", "privilege_escalation",
                "conclude",
            },
            "root_access_confirmed": {
                "post_access_inventory", "persistence", "internal_reconnaissance",
                "data_exfiltration", "cleanup", "conclude",
            },
            "persistence_established": {
                "post_access_inventory", "internal_reconnaissance", "data_exfiltration",
                "cleanup", "conclude",
            },
            "internal_recon_completed": {
                "post_access_inventory", "data_exfiltration", "cleanup", "conclude",
            },
            "exfiltration_completed": {"cleanup", "conclude"},
            "cleanup_completed": {"conclude"},
        }
        return goal in allowed.get(state, {"conclude"})

    def _next_in_chain(self, current_goal: str, goal_history: List[str]) -> str:
        """Find the next goal in the kill chain that hasn't been tried yet."""
        if current_goal not in KILL_CHAIN:
            return "conclude"

        idx = KILL_CHAIN.index(current_goal)
        for next_goal in KILL_CHAIN[idx + 1:]:
            if next_goal not in goal_history:
                return next_goal
        return "conclude"

    def _fallback_logic(self, context: Dict[str, Any], goal_history: List[str] = None) -> Dict[str, str]:
        """Deterministic fallback that reads actual context state.

        v12: Uses goal_history to avoid repeating ANY goal. Progresses through
        the kill chain even if the LLM is completely dead.
        """
        goal_history = goal_history or []
        state = context.get("state", "initial_recon")
        services = context.get("services", [])
        open_questions = context.get("open_questions", [])

        # State machine progression
        if state == "initial_recon":
            return self._pick("service_discovery", goal_history, "no recon data yet")

        if state == "recon_completed":
            if any("vulnerabilit" in q for q in open_questions):
                return self._pick("vulnerability_assessment", goal_history, "recon done, checking vulns")
            if any("credential" in q for q in open_questions):
                return self._pick("credential_harvesting", goal_history, "recon done, trying creds")
            if services:
                return self._pick("vulnerability_assessment", goal_history, "services found, assessing vulns")
            return {"thought": "fallback: recon done, no services", "goal": "conclude"}

        if state == "vulnerabilities_found":
            if "service_discovery_needed" in open_questions:
                return self._pick("service_discovery", goal_history, "vulns exist but service recon is incomplete")
            if any("verification" in q or "vulnerabilit" in q for q in open_questions):
                return self._pick("vulnerability_assessment", goal_history, "potential vulns need verification")
            return self._pick("credential_harvesting", goal_history, "vulns found, trying creds")

        if state == "credentials_found":
            if "service_discovery_needed" in open_questions:
                return self._pick("service_discovery", goal_history, "credentials exist but service recon is incomplete")
            if any("vulnerabilit" in q or "cpanel" in q for q in open_questions):
                return self._pick("vulnerability_assessment", goal_history, "application credentials need scoped verification")
            if "privilege_escalation" in goal_history:
                return {"thought": "fallback: privilege escalation already tried without confirmed root", "goal": "conclude"}
            if "privilege_escalation_path_unknown" in open_questions:
                return self._pick("privilege_escalation", goal_history, "SSH creds found, escalating")
            return self._pick("vulnerability_assessment", goal_history, "credentials found, verifying scope")

        if state == "root_access_confirmed":
            if "post_access_inventory_needed" in open_questions:
                return self._pick("post_access_inventory", goal_history, "root confirmed, collecting controlled post-access inventory")
            if "persistence_needed" in open_questions:
                return self._pick("persistence", goal_history, "root confirmed and persistence automation is enabled")
            if "internal_network_recon_pending" in open_questions:
                return self._pick("internal_reconnaissance", goal_history, "root confirmed, mapping internal network")
            return {"thought": "fallback: root confirmed and required controlled inventory is complete", "goal": "conclude"}

        if state == "persistence_established":
            if "internal_network_recon_pending" in open_questions:
                return self._pick("internal_reconnaissance", goal_history, "persistence established, mapping internal network")
            if "data_exfiltration_pending" in open_questions:
                return self._pick("data_exfiltration", goal_history, "persistence established and data collection automation is enabled")
            return {"thought": "fallback: persistence established, no further automated stage enabled", "goal": "conclude"}

        if state == "internal_recon_completed":
            if "data_exfiltration_pending" in open_questions:
                return self._pick("data_exfiltration", goal_history, "internal network mapped and data collection automation is enabled")
            if "persistence_needed" in open_questions:
                return self._pick("persistence", goal_history, "internal network mapped and persistence automation is enabled")
            return {"thought": "fallback: internal inventory complete, no further automated stage enabled", "goal": "conclude"}

        if state == "exfiltration_completed":
            if "cleanup_needed" in open_questions:
                return self._pick("cleanup", goal_history, "data collection complete and cleanup automation is enabled")
            return {"thought": "fallback: data collection complete, cleanup automation disabled", "goal": "conclude"}

        if state == "cleanup_completed":
            return self._pick("conclude", goal_history, "cleanup complete")

        return {"thought": "fallback: unknown state, concluding", "goal": "conclude"}

    def _pick(self, preferred: str, goal_history: List[str], reason: str) -> Dict[str, str]:
        """Pick the preferred goal, or the next untried one in the kill chain."""
        if preferred not in goal_history:
            return {"thought": f"fallback: {reason}", "goal": preferred}
        return {"thought": f"fallback: '{preferred}' already tried and state did not advance", "goal": "conclude"}
