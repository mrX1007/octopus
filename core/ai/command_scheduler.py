#!/usr/bin/env python3

import hashlib
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from core.execution import (
    ExecutionContext,
    ExecutionPolicy,
    ToolInvocation,
    redact_sensitive_command,
)


@dataclass
class CommandDecision:
    command: str
    key: str
    action: str
    reason: str
    prerequisite: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    retry: bool = False
    invocation: Optional[ToolInvocation] = field(
        default=None,
        repr=False,
        compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # ``ToolInvocation.raw_command`` may contain a short-lived secret.  The
        # typed object crosses scheduler/runtime boundaries in memory only; the
        # policy payload already carries its bounded, secret-free audit view.
        payload.pop("invocation", None)
        payload["command"] = self._redacted_command()
        return payload

    def _redacted_command(self) -> str:
        return redact_sensitive_command(self.command)


class CommandScheduler:
    """Deterministic command de-duplication and negative-fact gating."""

    def __init__(self, execution_policy: Optional[ExecutionPolicy] = None):
        self.execution_policy = execution_policy or ExecutionPolicy()

    def decide(
        self,
        command: str,
        facts: Iterable[dict[str, Any]],
        executed_keys: set[str],
        execution_context: Optional[ExecutionContext] = None,
        retry_command_keys: Iterable[str] = (),
    ) -> CommandDecision:
        context = execution_context or ExecutionContext.automatic(
            actor="command_scheduler",
            origin="automation",
        )
        policy_decision = self.execution_policy.authorize_command(command, context)
        invocation = getattr(policy_decision, "invocation", None)
        key = self.command_key(command)
        retry_allowed = key in set(retry_command_keys)
        if not policy_decision.allowed:
            return CommandDecision(
                command,
                key,
                "skip",
                f"policy_denied:{policy_decision.reason}",
                "execution_authorization",
                policy_decision.to_dict(),
                invocation=invocation,
            )
        if key in executed_keys and not retry_allowed:
            return CommandDecision(
                command,
                key,
                "skip",
                "duplicate_command_key",
                policy=policy_decision.to_dict(),
                invocation=invocation,
            )

        block_reason = self._negative_fact_block(command, facts)
        if block_reason and not self._retry_bypasses_negative_gate(
            retry_allowed,
            block_reason,
        ):
            return CommandDecision(
                command,
                key,
                "skip",
                block_reason,
                "confirmed_absent",
                policy_decision.to_dict(),
                invocation=invocation,
            )

        return CommandDecision(
            command,
            key,
            "execute",
            "durable_retry_command" if retry_allowed else "state_changed_or_unseen",
            policy=policy_decision.to_dict(),
            retry=retry_allowed,
            invocation=invocation,
        )

    @staticmethod
    def _retry_bypasses_negative_gate(retry_allowed: bool, reason: str) -> bool:
        """Retries bypass only timeout-derived degraded-state suppression."""
        return retry_allowed and reason in {
            "already_degraded:nuclei_timeout",
            "already_degraded:nikto_timeout",
        }

    def command_key(self, command: str) -> str:
        command = redact_sensitive_command(command)
        command = re.sub(r"\s+", " ", (command or "").strip())
        parts = command.split()
        if not parts:
            return ""
        tool = parts[0]

        if tool in {"nuclei", "nuclei_safe"}:
            target = self._extract_nuclei_target(parts)
            if target:
                return f"nuclei_safe {self._canonical_url(target)}"

        if tool == "exploit_select" and len(parts) >= 2:
            # The command carries large contextual evidence after the target.
            # Key by target plus a stable hash of that context.
            target = parts[1]
            context = command.split(target, 1)[1].strip()
            digest = hashlib.sha256(context.encode("utf-8", "ignore")).hexdigest()[:16] if context else "noctx"
            return f"exploit_select {target} {digest}"

        if len(parts) >= 2 and re.match(r"^https?://", parts[1], re.IGNORECASE):
            return " ".join([tool, self._canonical_url(parts[1]), *parts[2:]])

        return command

    def _negative_fact_block(self, command: str, facts: Iterable[dict[str, Any]]) -> str:
        parts = re.sub(r"\s+", " ", (command or "").strip()).split()
        if not parts:
            return ""
        tool = parts[0]
        url = self._command_url(parts)
        canonical = self._canonical_url(url) if url else ""

        if tool in {"nuclei", "nuclei_safe"} and canonical:
            endpoint_l = canonical.rstrip("/").lower()
            for fact in facts:
                if str(fact.get("type", "")) != "service_status":
                    continue
                value = str(fact.get("value", "")).lower()
                if value == f"nuclei_scan_completed:{endpoint_l}":
                    return "already_completed:nuclei_scan"
                if value not in {"tool_timeout:nuclei", "tool_timeout:nuclei_safe"}:
                    continue
                sources = [str(fact.get("source", ""))]
                sources.extend(str(item.get("source", "")) for item in fact.get("observations", []) if isinstance(item, dict))
                if any(endpoint_l in source.lower().rstrip("/") for source in sources):
                    return "already_degraded:nuclei_timeout"

        if tool == "nikto" and canonical:
            endpoint_l = canonical.rstrip("/").lower()
            for fact in facts:
                if str(fact.get("type", "")) != "service_status":
                    continue
                value = str(fact.get("value", "")).lower()
                if value == f"nikto_scan_completed:{endpoint_l}":
                    return "already_completed:nikto_scan"
                if value != "tool_timeout:nikto":
                    continue
                sources = [str(fact.get("source", ""))]
                sources.extend(str(item.get("source", "")) for item in fact.get("observations", []) if isinstance(item, dict))
                if any(endpoint_l in source.lower().rstrip("/") for source in sources):
                    return "already_degraded:nikto_timeout"

        if tool == "sqlmap" and canonical:
            endpoint_l = canonical.rstrip("/").lower()
            for fact in facts:
                if str(fact.get("type", "")) != "service_status":
                    continue
                if str(fact.get("value", "")).lower() != "sqlmap_no_get_parameters_found":
                    continue
                sources = [str(fact.get("source", ""))]
                sources.extend(str(item.get("source", "")) for item in fact.get("observations", []) if isinstance(item, dict))
                if any(endpoint_l in source.lower().rstrip("/") for source in sources):
                    return "already_checked:sqlmap_no_input_surface"

        if tool in {
            "ffuf", "scrapling_crawl", "scrapling", "browser_surface_analysis",
            "curl_headers", "security_headers_check", "cors_check", "nuclei_safe",
            "nuclei", "katana_crawl", "wpscan", "sqlmap", "nikto",
            "graphql_check", "api_auth_check",
        } and canonical:
            for fact in facts:
                if str(fact.get("type", "")) != "service_status":
                    continue
                value = str(fact.get("value", "")).lower()
                if not value.startswith(("web_content_discovery_skipped:no_http_response", "web_fetch_failed:")):
                    continue
                if self._negative_status_matches_url(value, canonical):
                    return "confirmed_absent:no_http_response"
        return ""

    def _command_url(self, parts: list[str]) -> str:
        if not parts:
            return ""
        if parts[0] in {"nuclei", "nuclei_safe"}:
            return self._extract_nuclei_target(parts)
        if parts[0] == "nikto":
            for idx, part in enumerate(parts[1:], start=1):
                if part in {"-h", "-host", "--host"} and idx + 1 < len(parts):
                    return parts[idx + 1]
                if not part.startswith("-"):
                    return part
            return ""
        if parts[0] == "sqlmap":
            for idx, part in enumerate(parts[1:], start=1):
                if part in {"-u", "--url"} and idx + 1 < len(parts):
                    return parts[idx + 1]
                if part.startswith("--url="):
                    return part.split("=", 1)[1]
            return ""
        if parts[0] == "wpscan":
            for idx, part in enumerate(parts[1:], start=1):
                if part == "--url" and idx + 1 < len(parts):
                    return parts[idx + 1]
                if part.startswith("--url="):
                    return part.split("=", 1)[1]
            return ""
        for part in parts[1:]:
            if re.match(r"^https?://", part, re.IGNORECASE):
                return part
        return parts[1] if len(parts) > 1 else ""

    def _extract_nuclei_target(self, parts: list[str]) -> str:
        target_flags = {"-u", "-url", "-target"}
        value_flags = {
            "-severity", "-exclude-tags", "-tags", "-t", "-templates",
            "-timeout", "-retries", "-rl", "-rate-limit", "-c", "-bs",
            "-headless-bulk-size", "-page-timeout", "-proxy",
        }
        skip_next = False
        for idx, part in enumerate(parts[1:], start=1):
            if skip_next:
                skip_next = False
                continue
            for flag in target_flags:
                if part.startswith(flag + "="):
                    return part.split("=", 1)[1]
            if part in target_flags and idx + 1 < len(parts):
                return parts[idx + 1]
            if part in value_flags:
                skip_next = True
                continue
            if part.startswith("-"):
                continue
            if re.match(r"^https?://", part, re.IGNORECASE):
                return part
            return part
        return ""

    def _canonical_url(self, value: str) -> str:
        raw = (value or "").strip().strip("'\"")
        if raw and not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE):
            raw = f"http://{raw}"
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return raw
        path = parsed.path or "/"
        netloc = parsed.hostname.lower()
        if parsed.port and not ((parsed.scheme.lower() == "http" and parsed.port == 80)
                                or (parsed.scheme.lower() == "https" and parsed.port == 443)):
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, "")).rstrip("/")

    def _negative_status_matches_url(self, status_value: str, canonical_url: str) -> bool:
        urls = re.findall(r"https?://[^\s,;]+", status_value or "", re.IGNORECASE)
        if not urls:
            return False
        candidate = urlparse(canonical_url or "")
        if candidate.scheme.lower() not in {"http", "https"} or not candidate.hostname:
            return False
        candidate_path = (candidate.path or "/").rstrip("/") or "/"
        for raw in urls:
            negative = urlparse(self._canonical_url(raw))
            if negative.scheme.lower() != candidate.scheme.lower():
                continue
            if (negative.netloc or "").lower() != (candidate.netloc or "").lower():
                continue
            negative_path = (negative.path or "/").rstrip("/") or "/"
            if candidate_path == negative_path or candidate_path.startswith(negative_path.rstrip("/") + "/"):
                return True
        return False
