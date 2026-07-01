#!/usr/bin/env python3

import hashlib
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, Set
from urllib.parse import urlparse, urlunparse


@dataclass
class CommandDecision:
    command: str
    key: str
    action: str
    reason: str
    prerequisite: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CommandScheduler:
    """Deterministic command de-duplication and negative-fact gating."""

    def decide(
        self,
        command: str,
        facts: Iterable[Dict[str, Any]],
        executed_keys: Set[str],
    ) -> CommandDecision:
        key = self.command_key(command)
        if key in executed_keys:
            return CommandDecision(command, key, "skip", "duplicate_command_key")

        block_reason = self._negative_fact_block(command, facts)
        if block_reason:
            return CommandDecision(command, key, "skip", block_reason, "confirmed_absent")

        return CommandDecision(command, key, "execute", "state_changed_or_unseen")

    def command_key(self, command: str) -> str:
        command = re.sub(r"\s+", " ", (command or "").strip())
        parts = command.split()
        if not parts:
            return ""
        tool = parts[0]

        if tool == "exploit_select" and len(parts) >= 2:
            # The command carries large contextual evidence after the target.
            # Key by target plus a stable hash of that context.
            target = parts[1]
            context = command.split(target, 1)[1].strip()
            digest = hashlib.sha1(context.encode("utf-8", "ignore")).hexdigest()[:16] if context else "noctx"
            return f"exploit_select {target} {digest}"

        if len(parts) >= 2 and re.match(r"^https?://", parts[1], re.IGNORECASE):
            return " ".join([tool, self._canonical_url(parts[1]), *parts[2:]])

        return command

    def _negative_fact_block(self, command: str, facts: Iterable[Dict[str, Any]]) -> str:
        parts = re.sub(r"\s+", " ", (command or "").strip()).split()
        if not parts:
            return ""
        tool = parts[0]
        url = parts[1] if len(parts) > 1 else ""
        canonical = self._canonical_url(url) if re.match(r"^https?://", url, re.IGNORECASE) else ""

        if tool in {"ffuf", "scrapling_crawl", "scrapling", "browser_surface_analysis", "curl_headers"} and canonical:
            for fact in facts:
                if str(fact.get("type", "")) != "service_status":
                    continue
                value = str(fact.get("value", "")).lower()
                if not value.startswith(("web_content_discovery_skipped:no_http_response", "web_fetch_failed:")):
                    continue
                if canonical.rstrip("/").lower() in value or url.rstrip("/").lower() in value:
                    return "confirmed_absent:no_http_response"
        return ""

    def _canonical_url(self, value: str) -> str:
        parsed = urlparse(value or "")
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return (value or "").strip()
        path = parsed.path or "/"
        netloc = parsed.netloc.lower()
        return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, "")).rstrip("/")
