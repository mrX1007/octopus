#!/usr/bin/env python3

import json
import logging
from collections.abc import Callable, Mapping
from typing import Any, Optional

from core.ai.evidence import EvidenceVerifier
from core.ai.llm_context import compact_context_for_llm, mission_contract_preamble
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
        if set(hypothesis) != {"claim"}:
            raise _AnalysisResponseError("unexpected_hypothesis_fields")

        claim = hypothesis["claim"]
        if not isinstance(claim, str) or not claim.strip():
            raise _AnalysisResponseError("claim_not_nonempty_string")

        validated.append({"claim": claim.strip()})
    return validated


def _analysis_failure(error: str) -> dict[str, Any]:
    return {
        "hypotheses": [],
        "llm_status": "failed",
        "llm_error": error,
    }


class DiscoveryAgent:
    def __init__(
        self,
        tool_registry: ToolRegistry,
        task_input_provider: Optional[Callable[[str, str], Mapping[str, Any]]] = None,
    ):
        self.tool_registry = tool_registry
        self.task_input_provider = task_input_provider

    def execute_task(self, task: str, target: str) -> list[str]:
        """Returns a list of commands to run for discovery."""
        inputs = self.task_input_provider(task, target) if self.task_input_provider is not None else {}
        return self.tool_registry.get_commands_for_task(task, target, task_inputs=inputs)


class AnalysisAgent:
    def __init__(self, fact_store, context_builder):
        self.fact_store = fact_store
        self.context_builder = context_builder
        self.mission_contract: dict[str, Any] = {}
        self.system_prompt = """You are the ANALYSIS AGENT of OCTOPUS.
Your job is to read the current context and build hypotheses (claims) about vulnerabilities or next steps.
You MUST output your response in STRICT JSON format WITHOUT ANY trailing commas, extra braces, or comments.
Ensure the format matches EXACTLY:
{
  "hypotheses": [
    {
      "claim": "The specific claim (e.g. vulnerable_to_cve_2021_4034)"
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
            full_prompt = self.system_prompt + "\n\n" + mission_contract_preamble(self.mission_contract) + prompt
            response = ask_ollama(full_prompt, json_mode=True)

            # Enforce the current LLM error contract.
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
    def __init__(
        self,
        tool_registry: ToolRegistry,
        verifier: EvidenceVerifier,
        task_input_provider: Optional[Callable[[str, str], Mapping[str, Any]]] = None,
    ):
        self.tool_registry = tool_registry
        self.verifier = verifier
        self.task_input_provider = task_input_provider

    def execute_task(self, task: str, target: str) -> list[str]:
        """Returns commands to run to verify a task."""
        inputs = self.task_input_provider(task, target) if self.task_input_provider is not None else {}
        return self.tool_registry.get_commands_for_task(task, target, task_inputs=inputs)

    def verify_hypothesis(
        self,
        scan_id: str,
        host: str,
        claim: str,
        required_evidence: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Delegates to the Evidence Verifier."""
        return self.verifier.verify_claim(scan_id, host, claim, required_evidence)
