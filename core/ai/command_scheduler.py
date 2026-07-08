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

        if tool in {"nuclei", "nuclei_safe"}:
            target = self._extract_nuclei_target(parts)
            if target:
                return f"nuclei_safe {self._canonical_url(target)}"

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
