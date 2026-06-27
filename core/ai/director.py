#!/usr/bin/env python3

import json
import logging
from typing import Dict, Any, List

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
    "persistence",
    "internal_reconnaissance",
    "data_exfiltration",
    "cleanup",
    "conclude",
]

class DirectorLLM:
    def __init__(self):
        self.system_prompt = """You are the DIRECTOR of OCTOPUS, an autonomous penetration testing system.
YOUR ONLY JOB is to decide the NEXT HIGH-LEVEL GOAL based on the current state.
You DO NOT select tools. You DO NOT execute commands.
You MUST output your response in STRICT JSON format matching this schema:
{
  "thought": "Brief explanation of why this is the next logical step",
  "goal": "The high-level goal, e.g. service_discovery, vulnerability_assessment, credential_harvesting, privilege_escalation, persistence, internal_reconnaissance, data_exfiltration, cleanup, or conclude"
}

RULES:
1. If root_access_confirmed is true, your goal should advance to persistence, then internal_reconnaissance, then data_exfiltration, then cleanup, then conclude.
2. If recon is incomplete, your goal is service_discovery.
3. If recon IS complete but vulnerabilities are unknown, your goal is vulnerability_assessment.
4. If no new facts have been discovered for several loops, or the goal is repeating, your goal MUST be 'conclude'.
5. NEVER repeat a goal that has already been successfully completed.
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
        """Prevent the LLM from suggesting already-completed goals."""
        state = context.get("state", "initial_recon")

        # Don't re-run service_discovery if recon is already done
        if goal == "service_discovery" and state != "initial_recon":
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        if goal == "data_exfiltration" and "internal_network_recon_pending" in context.get("open_questions", []):
            return "internal_reconnaissance"

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
                "privilege_escalation", "persistence",
            },
            "internal_recon_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "persistence", "internal_reconnaissance",
            },
            "exfiltration_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "persistence", "internal_reconnaissance", "data_exfiltration",
            },
            "cleanup_completed": {
                "service_discovery", "vulnerability_assessment", "credential_harvesting",
                "privilege_escalation", "persistence", "internal_reconnaissance", "data_exfiltration", "cleanup",
            },
        }
        if goal in completed_by_state.get(state, set()):
            return self._fallback_logic(context, goal_history).get("goal", "conclude")

        # Don't repeat goals that already ran
        if goal in goal_history and goal not in ("conclude",):
            return self._next_in_chain(goal, goal_history)

        return goal

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
            return self._pick("credential_harvesting", goal_history, "vulns found, trying creds")

        if state == "credentials_found":
            return self._pick("privilege_escalation", goal_history, "creds found, escalating")

        if state == "root_access_confirmed":
            return self._pick("persistence", goal_history, "root confirmed, post-exploit")

        if state == "persistence_established":
            if "internal_network_recon_pending" in open_questions:
                return self._pick("internal_reconnaissance", goal_history, "persistence established, mapping internal network")
            return self._pick("data_exfiltration", goal_history, "persistence established, collect target data")

        if state == "internal_recon_completed":
            return self._pick("data_exfiltration", goal_history, "internal network mapped, collect target data")

        if state == "exfiltration_completed":
            return self._pick("cleanup", goal_history, "data exfiltration complete, cleanup artifacts")

        if state == "cleanup_completed":
            return self._pick("conclude", goal_history, "cleanup complete")

        return {"thought": "fallback: unknown state, concluding", "goal": "conclude"}

    def _pick(self, preferred: str, goal_history: List[str], reason: str) -> Dict[str, str]:
        """Pick the preferred goal, or the next untried one in the kill chain."""
        if preferred not in goal_history:
            return {"thought": f"fallback: {reason}", "goal": preferred}
        # Already tried this goal — advance in the kill chain
        next_goal = self._next_in_chain(preferred, goal_history)
        return {"thought": f"fallback: '{preferred}' already tried, advancing to '{next_goal}'", "goal": next_goal}
