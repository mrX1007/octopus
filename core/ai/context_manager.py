#!/usr/bin/env python3
"""
Context Window Manager for OCTOPUS AI Pipeline.

Automatically manages the LLM context window to prevent token limit
overflow while preserving the most relevant information.

Architecture:
    ┌──────────────────────────────────────────┐
    │           ContextManager                  │
    ├──────────────────────────────────────────┤
    │  max_tokens       = 8192                 │
    │  reserved_output  = 2048                 │
    │  priority_zones:                         │
    │    1. system_prompt  (always included)    │
    │    2. current_facts  (high confidence)    │
    │    3. recent_output  (last 2 tools)       │
    │    4. scan_context   (compressed)         │
    │    5. history        (oldest first drop)  │
    └──────────────────────────────────────────┘
"""

import logging

logger = logging.getLogger("octopus.ai.context")


class ContextManager:
    """Manages LLM context window to prevent overflow.

    Prioritizes information by relevance and recency, automatically
    compressing or dropping lower-priority content when approaching
    the token limit.
    """

    def __init__(
        self,
        max_tokens: int = 8192,
        reserved_output: int = 2048,
        chars_per_token: float = 3.5,
    ):
        """Initialize context manager.

        Args:
            max_tokens: Maximum tokens for the model's context window.
            reserved_output: Tokens reserved for model's response.
            chars_per_token: Approximate characters per token ratio.
        """
        self.max_tokens = max_tokens
        self.reserved_output = reserved_output
        self.chars_per_token = chars_per_token
        self._available_tokens = max_tokens - reserved_output

    @property
    def available_chars(self) -> int:
        """Maximum characters available for input context."""
        return int(self._available_tokens * self.chars_per_token)

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a text string."""
        return int(len(text) / self.chars_per_token)

    def build_context(
        self,
        system_prompt: str,
        facts: list[dict],
        recent_output: str = "",
        scan_context: str = "",
        history: list[str] | None = None,
        credentials: list[dict] | None = None,
    ) -> str:
        """Build optimized context string within token budget.

        Priority order (highest first):
        1. System prompt (never trimmed)
        2. Active credentials (critical for exploitation)
        3. High-confidence facts (confirmed vulnerabilities)
        4. Recent tool output (last 2 tools)
        5. Scan context (compressed if needed)
        6. Lower-confidence facts
        7. History (oldest dropped first)

        Args:
            system_prompt: Base system prompt (always included).
            facts: List of fact dicts with 'type', 'value', 'confidence'.
            recent_output: Output from the most recent tool execution.
            scan_context: Raw scan data / state summary.
            history: Previous interaction history.
            credentials: Known credentials for the target.

        Returns:
            Assembled context string within token budget.
        """
        budget = self.available_chars
        sections: list[str] = []

        # 1. System prompt (mandatory)
        sections.append(system_prompt)
        budget -= len(system_prompt)

        if budget <= 0:
            logger.warning("System prompt alone exceeds token budget!")
            return system_prompt

        # 2. Credentials (critical, small footprint)
        if credentials:
            creds_text = self._format_credentials(credentials)
            if len(creds_text) < budget:
                sections.append(creds_text)
                budget -= len(creds_text)

        # 3. High-confidence facts
        high_facts = [f for f in facts if f.get("confidence", 0) >= 70]
        low_facts = [f for f in facts if f.get("confidence", 0) < 70]

        high_text = self._format_facts(high_facts, "CONFIRMED FACTS")
        if len(high_text) < budget:
            sections.append(high_text)
            budget -= len(high_text)
        else:
            # Truncate facts if even high-confidence exceeds budget
            trimmed = self._truncate_facts(high_facts, budget)
            sections.append(trimmed)
            budget -= len(trimmed)

        # 4. Recent tool output (most relevant for next decision)
        if recent_output and budget > 500:
            max_output = min(budget // 2, len(recent_output))
            trimmed_output = self._smart_truncate(recent_output, max_output)
            section = f"\n--- LATEST TOOL OUTPUT ---\n{trimmed_output}\n"
            sections.append(section)
            budget -= len(section)

        # 5. Scan context (compressed)
        if scan_context and budget > 300:
            max_scan = min(budget // 2, len(scan_context))
            compressed = self._compress_scan_data(scan_context, max_scan)
            section = f"\n--- SCAN DATA ---\n{compressed}\n"
            sections.append(section)
            budget -= len(section)

        # 6. Lower-confidence facts
        if low_facts and budget > 200:
            low_text = self._format_facts(low_facts, "UNCONFIRMED / LOW CONFIDENCE")
            if len(low_text) < budget:
                sections.append(low_text)
                budget -= len(low_text)

        # 7. History (oldest dropped first)
        if history and budget > 200:
            for entry in reversed(history):
                if len(entry) < budget:
                    sections.append(entry)
                    budget -= len(entry)
                else:
                    break

        total = "\n\n".join(sections)
        used = self.estimate_tokens(total)
        logger.debug(
            f"Context built: {used}/{self.max_tokens} tokens "
            f"({len(facts)} facts, {len(history or [])} history entries)"
        )
        return total

    def _format_facts(self, facts: list[dict], header: str) -> str:
        """Format facts into a structured text block."""
        if not facts:
            return ""
        lines = [f"\n--- {header} ({len(facts)}) ---"]
        for f in facts:
            conf = f.get("confidence", "?")
            src = f.get("source", "unknown")
            lines.append(f"  [{conf}%] [{src}] {f.get('type', '?')}: {f.get('value', '?')}")
        return "\n".join(lines)

    def _truncate_facts(self, facts: list[dict], max_chars: int) -> str:
        """Truncate fact list to fit within char budget."""
        # Sort by confidence descending, take as many as fit
        sorted_facts = sorted(facts, key=lambda f: f.get("confidence", 0), reverse=True)
        result = "\n--- KEY FACTS (truncated) ---\n"
        for f in sorted_facts:
            line = f"  [{f.get('confidence', '?')}%] {f.get('type', '?')}: {f.get('value', '?')}\n"
            if len(result) + len(line) > max_chars:
                break
            result += line
        return result

    def _format_credentials(self, credentials: list[dict]) -> str:
        """Format known credentials for context injection."""
        if not credentials:
            return ""
        lines = ["\n--- KNOWN CREDENTIALS ---"]
        for cred in credentials:
            user = cred.get("username", "?")
            service = cred.get("service", "?")
            lines.append(f"  {service}: {user}:{'*' * 8}")
        return "\n".join(lines)

    def _smart_truncate(self, text: str, max_chars: int) -> str:
        """Truncate text intelligently, keeping beginning and end."""
        if len(text) <= max_chars:
            return text

        # Keep 60% from the beginning, 30% from the end, 10% for separator
        head_len = int(max_chars * 0.6)
        tail_len = int(max_chars * 0.3)
        sep = f"\n\n[... {len(text) - head_len - tail_len} chars truncated ...]\n\n"

        return text[:head_len] + sep + text[-tail_len:]

    def _compress_scan_data(self, scan_data: str, max_chars: int) -> str:
        """Compress scan data by removing noise and keeping findings.

        Prioritizes lines containing: PORT, OPEN, CVE, VULN, SERVICE,
        VERSION, HTTP, SSL, KEY, PASS, USER, ROOT.
        """
        if len(scan_data) <= max_chars:
            return scan_data

        important_keywords = {
            "port", "open", "cve", "vuln", "service", "version",
            "http", "ssl", "key", "pass", "user", "root", "exploit",
            "rce", "lfi", "sqli", "xss", "shell", "admin", "login",
        }

        lines = scan_data.split("\n")
        important = []
        normal = []

        for line in lines:
            lower = line.lower()
            if any(kw in lower for kw in important_keywords):
                important.append(line)
            elif line.strip():
                normal.append(line)

        # Build result: important lines first, then fill with normal
        result_lines = important[:]
        result = "\n".join(result_lines)

        if len(result) < max_chars:
            remaining = max_chars - len(result)
            for line in normal:
                if len(line) + 1 > remaining:
                    break
                result_lines.append(line)
                remaining -= len(line) + 1
            result = "\n".join(result_lines)

        return self._smart_truncate(result, max_chars)
