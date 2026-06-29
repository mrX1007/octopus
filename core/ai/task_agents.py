#!/usr/bin/env python3

import json
import logging
from typing import Dict, Any, List
from core.ai.tool_registry import ToolRegistry
from core.ai.evidence import EvidenceVerifier
from core.ai.ollama_client import ask_ollama

logger = logging.getLogger("octopus.agents")

class DiscoveryAgent:
    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry

    def execute_task(self, task: str, target: str) -> List[str]:
        """Returns a list of commands to run for discovery."""
        return self.tool_registry.get_commands_for_task(task, target)

class AnalysisAgent:
    def __init__(self, fact_store, context_builder):
        self.fact_store = fact_store
        self.context_builder = context_builder
        self.system_prompt = """You are the ANALYSIS AGENT of OCTOPUS.
Your job is to read the current context and build hypotheses (claims) about vulnerabilities or next steps.
You MUST output your response in STRICT JSON format WITHOUT ANY trailing commas, extra braces, or comments.
Ensure the format matches EXACTLY:
{
  "hypotheses": [
    {
      "claim": "The specific claim (e.g. vulnerable_to_cve_2021_4034)",
      "required_evidence": ["list", "of", "facts", "that", "support", "this"]
    }
  ]
}
"""

    def analyze(self, scan_id: str, host: str) -> Dict[str, Any]:
        """Reads context and returns hypotheses."""
        context = self.context_builder.build_context(scan_id, host)
        prompt = f"Current Context for {host}:\n{context}\nGenerate hypotheses in JSON format."

        try:
            full_prompt = self.system_prompt + "\n\n" + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # v12: check the error contract
            if response.startswith("[!]"):
                logger.warning(f"AnalysisAgent LLM error: {response}")
                print(f"[!] AnalysisAgent: LLM returned error, skipping analysis")
                return {"hypotheses": []}

            return json.loads(response)
        except Exception as e:
            logger.warning(f"AnalysisAgent Error: {e}")
            print(f"[!] AnalysisAgent Error: {e}")
            return {"hypotheses": []}

class VerificationAgent:
    def __init__(self, tool_registry: ToolRegistry, verifier: EvidenceVerifier):
        self.tool_registry = tool_registry
        self.verifier = verifier

    def execute_task(self, task: str, target: str) -> List[str]:
        """Returns commands to run to verify a task."""
        return self.tool_registry.get_commands_for_task(task, target)

    def verify_hypothesis(self, scan_id: str, host: str, claim: str, required_evidence: List[str]) -> Dict[str, Any]:
        """Delegates to the Evidence Verifier."""
        return self.verifier.verify_claim(scan_id, host, claim, required_evidence)
