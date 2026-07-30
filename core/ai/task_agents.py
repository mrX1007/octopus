#!/usr/bin/env python3

import json
import logging
from typing import Any

from core.ai.evidence import EvidenceVerifier
from core.ai.llm_context import compact_context_for_llm
from core.ai.ollama_client import ask_ollama
from core.ai.tool_registry import ToolRegistry

logger = logging.getLogger("octopus.agents")


class _AnalysisResponseError(ValueError):
    """Stable validation error for an AnalysisAgent response contract."""


def _validate_analysis_payload(payload: Any) -> list[dict[str, Any]]:
    """Validate and normalize the strict AnalysisAgent JSON response."""

    if not isinstance(payload, dict):
        raise _AnalysisResponseError("response_not_object")
    if set(payload) != {"hypotheses"}:
        raise _AnalysisResponseError("unexpected_top_level_fields")

    hypotheses = payload["hypotheses"]
    if not isinstance(hypotheses, list):
        raise _AnalysisResponseError("hypotheses_not_list")

    validated: list[dict[str, Any]] = []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            raise _AnalysisResponseError("hypothesis_not_object")
        if set(hypothesis) != {"claim", "required_evidence"}:
            raise _AnalysisResponseError("unexpected_hypothesis_fields")

        claim = hypothesis["claim"]
        required_evidence = hypothesis["required_evidence"]
        if not isinstance(claim, str) or not claim.strip():
            raise _AnalysisResponseError("claim_not_nonempty_string")
        if not isinstance(required_evidence, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in required_evidence
        ):
            raise _AnalysisResponseError("required_evidence_not_string_list")

        validated.append(
            {
                "claim": claim.strip(),
                "required_evidence": [item.strip() for item in required_evidence],
            }
        )
    return validated


def _analysis_failure(error: str) -> dict[str, Any]:
    return {
        "hypotheses": [],
        "llm_status": "failed",
        "llm_error": error,
    }


class DiscoveryAgent:
    def __init__(self, tool_registry: ToolRegistry):
        self.tool_registry = tool_registry

    def execute_task(self, task: str, target: str) -> list[str]:
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

    def analyze(self, scan_id: str, host: str) -> dict[str, Any]:
        """Reads context and returns hypotheses."""
        try:
            context = self.context_builder.build_context(scan_id, host)
            llm_context = compact_context_for_llm(context, role="analysis")
            prompt = (
                f"Current Context JSON for {host}:\n"
                f"{json.dumps(llm_context, ensure_ascii=False, separators=(',', ':'))}\n"
                "Generate only evidence-backed hypotheses in JSON format. "
                "Return an empty hypotheses array if no useful hypothesis exists."
            )
            full_prompt = self.system_prompt + "\n\n" + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # v12: check the error contract
            if not isinstance(response, str):
                logger.warning("AnalysisAgent returned a non-text response")
                print("[!] AnalysisAgent: invalid response type, skipping analysis")
                return _analysis_failure("invalid_response_type")
            if response.startswith("[!]"):
                logger.warning("AnalysisAgent LLM request failed")
                print("[!] AnalysisAgent: LLM returned error, skipping analysis")
                return _analysis_failure("ollama_error")

            try:
                payload = json.loads(response)
            except json.JSONDecodeError:
                logger.warning("AnalysisAgent returned invalid JSON")
                print("[!] AnalysisAgent: invalid JSON response, skipping analysis")
                return _analysis_failure("invalid_json")

            try:
                hypotheses = _validate_analysis_payload(payload)
            except _AnalysisResponseError as exc:
                logger.warning("AnalysisAgent response schema invalid: %s", exc)
                print("[!] AnalysisAgent: invalid response schema, skipping analysis")
                return _analysis_failure(f"invalid_schema:{exc}")

            return {"hypotheses": hypotheses, "llm_status": "ok"}
        except Exception as exc:
            logger.warning("AnalysisAgent error: %s", type(exc).__name__)
            print(f"[!] AnalysisAgent Error: {type(exc).__name__}")
            return _analysis_failure("analysis_exception")


class VerificationAgent:
    def __init__(self, tool_registry: ToolRegistry, verifier: EvidenceVerifier):
        self.tool_registry = tool_registry
        self.verifier = verifier

    def execute_task(self, task: str, target: str) -> list[str]:
        """Returns commands to run to verify a task."""
        return self.tool_registry.get_commands_for_task(task, target)

    def verify_hypothesis(self, scan_id: str, host: str, claim: str, required_evidence: list[str]) -> dict[str, Any]:
        """Delegates to the Evidence Verifier."""
        return self.verifier.verify_claim(scan_id, host, claim, required_evidence)
