#!/usr/bin/env python3
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger("octopus.evidence")


class EvidenceVerifier:
    def __init__(self, fact_store):
        self.fact_store = fact_store

    def verify_claim(self, scan_id: str, host: str, claim: str, required_evidence: List[str]) -> Dict[str, Any]:
        """
        Verify if a high-level claim is supported by hard evidence in the Fact Store.
        """
        facts = self.fact_store.get_facts(scan_id, host)
        fact_values = [f['value'].lower() for f in facts]
        fact_types = [f['type'].lower() for f in facts]

        missing_evidence = []
        for req in required_evidence:
            req_lower = req.lower()
            found = any(req_lower in ft for ft in fact_types) or any(req_lower in fv for fv in fact_values)
            if not found:
                missing_evidence.append(req)

        if missing_evidence:
            return {
                "claim": claim,
                "status": "rejected",
                "reason": f"No supporting evidence found for: {', '.join(missing_evidence)}"
            }

        self.fact_store.add_fact(
            scan_id=scan_id,
            host=host,
            fact_type="verified_claim",
            value=claim,
            source="evidence_verifier"
        )

        return {
            "claim": claim,
            "status": "accepted",
            "reason": "All required evidence verified."
        }


class RegexParser:
    """Extract hard facts from raw tool output using regex patterns.

    Fact types:
    - port_open:               100% confidence, from nmap/rustscan
    - hostname:                100% confidence, from nmap Service Info
    - potential_vulnerability:  50% confidence, from CVE version matching
    - vulnerability:           80-100% confidence, from exploit verification
    - exploit_attempted:       100% confidence, from exploit tool output
    - exploit_success:         100% confidence, from confirmed exploitation (VULNERABLE + session)
    - system_access:           100% confidence, from uid=0 / root confirmation
    - credential:              100% confidence, from login success / hydra
    - persistence:             100% confidence, from persistence mechanism confirmation
    """
    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Dict[str, Any]]:
        facts = []
        raw_lower = raw_output.lower()

        # ── Nmap port detection ──
        if "nmap" in tool_name.lower() or "rustscan" in tool_name.lower():
            for m in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', raw_output):
                port = m.group(1)
                service = m.group(2)
                version = m.group(3).strip() if m.group(3) else ""
                value = f"{port}/tcp ({service})"
                if version:
                    value += f" [{version[:60]}]"
                facts.append({"type": "port_open", "value": value, "confidence": 100, "session_id": session_id})

            host_match = re.search(r'Service Info:\s*Host:\s*(\S+)', raw_output)
            if host_match:
                facts.append({"type": "hostname", "value": host_match.group(1), "confidence": 100, "session_id": session_id})

        # ── CVE detection (version match only = potential, NOT confirmed) ──
        for cve in re.finditer(r'(CVE-\d{4}-\d{4,7})', raw_output, re.IGNORECASE):
            facts.append({"type": "potential_vulnerability", "value": cve.group(1).upper(), "confidence": 50, "session_id": session_id})

        # ── cPanel/WHM exploit output (cpanel_sniper) ──
        if "VULNERABLE" in raw_output and ("cpsess" in raw_output or "cPanel" in raw_output or "WHM" in raw_output):
            # Extract the CVE and mark as CONFIRMED exploit
            cve_match = re.search(r'(CVE-\d{4}-\d{4,7})\s*[—\-]+\s*(.+?)(?:\n|$)', raw_output)
            if cve_match:
                facts.append({"type": "exploit_success", "value": f"{cve_match.group(1)} — {cve_match.group(2).strip()}", "confidence": 100, "session_id": session_id})
                facts.append({"type": "vulnerability", "value": cve_match.group(1).upper(), "confidence": 100, "session_id": session_id})

            # Extract session token
            sess_match = re.search(r'Session:\s*(\S+)', raw_output)
            if sess_match:
                facts.append({"type": "credential", "value": f"whm_session:{sess_match.group(1)}", "confidence": 100, "session_id": session_id})

            # Extract cPanel version
            ver_match = re.search(r'Version:\s*([\d.]+)', raw_output)
            if ver_match:
                facts.append({"type": "service_version", "value": f"cPanel {ver_match.group(1)}", "confidence": 100, "session_id": session_id})

            # Mark as authenticated session = credential
            if "authenticated session obtained" in raw_lower:
                facts.append({"type": "credential", "value": "cpanel_auth_bypass_session", "confidence": 100, "session_id": session_id})

        # ── Generic exploit attempt tracking ──
        for m in re.finditer(r'\[\*\] Attempting (?:privesc|exploit) via (.+)', raw_output, re.IGNORECASE):
            facts.append({"type": "exploit_attempted", "value": m.group(1).strip(), "confidence": 100, "session_id": session_id})

        # ── Exploit status lines (CVE — Description) ──
        for m in re.finditer(r'(CVE-\d{4}-\d{4,7})\s+[—\-]+\s+(.+?)(?:\n|$)', raw_output):
            facts.append({"type": "exploit_attempted", "value": m.group(0).strip(), "confidence": 100, "session_id": session_id})

        if "PwnKit exploit" in raw_output:
            facts.append({"type": "exploit_attempted", "value": "CVE-2021-4034 PwnKit", "confidence": 100, "session_id": session_id})

        # ── Root / UID detection ──
        if "uid=0" in raw_lower or "root access confirmed" in raw_lower:
            facts.append({"type": "system_access", "value": "uid=0", "confidence": 100, "session_id": session_id})

        # ── /etc/shadow extraction ──
        if "/etc/shadow" in raw_output and "root:" in raw_output:
            facts.append({"type": "data_exfiltration", "value": "shadow_file_extracted", "confidence": 100, "session_id": session_id})

        # ── SSH key injection ──
        if "authorized_keys" in raw_lower and ("injected" in raw_lower or "planted" in raw_lower or "written" in raw_lower):
            facts.append({"type": "persistence", "value": "ssh_key_injected", "confidence": 100, "session_id": session_id})

        # ── Credential detection ──
        if "login success" in raw_lower or "password found" in raw_lower:
            facts.append({"type": "credential", "value": "login_success", "confidence": 100, "session_id": session_id})

        # ── Hydra / brute force results ──
        for m in re.finditer(r'\[(\d+)\]\[(\w+)\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)', raw_output):
            facts.append({"type": "credential", "value": f"{m.group(3)}:{m.group(4)} ({m.group(2)} port {m.group(1)})", "confidence": 100, "session_id": session_id})

        # ── Persistence ──
        if "persistence" in raw_lower and ("success" in raw_lower or "planted" in raw_lower):
            facts.append({"type": "persistence", "value": "mechanism_planted", "confidence": 100, "session_id": session_id})

        # ── Nikto findings ──
        if "nikto" in tool_name.lower():
            for m in re.finditer(r'\+\s+OSVDB-\d+:\s+(.+)', raw_output):
                facts.append({"type": "potential_vulnerability", "value": m.group(1).strip()[:100], "confidence": 60, "session_id": session_id})

        # ── enum4linux / SMB ──
        if "enum4linux" in tool_name.lower():
            if "server doesn't allow session" in raw_lower or "nt_status_access_denied" in raw_lower:
                facts.append({"type": "smb_status", "value": "null_session_denied", "confidence": 100, "session_id": session_id})

        return facts


class StructuredParser:
    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Dict[str, Any]]:
        """Handles tools that output native JSON or XML."""
        facts = []
        raw_strip = raw_output.strip()
        if raw_strip.startswith('{') and raw_strip.endswith('}'):
            try:
                import json
                data = json.loads(raw_strip)
                if "cve" in data:
                    facts.append({"type": "vulnerability", "value": data["cve"], "confidence": 100, "session_id": session_id})
            except Exception:
                pass
        return facts


class LLMExtractor:
    """Fallback fact extractor using LLM. Only called when regex found ZERO facts."""
    def __init__(self):
        self.system_prompt = """You are a FACT EXTRACTION tool.
Read the raw tool output and extract hard facts.
Output STRICT JSON:
{
  "facts": [
    {"type": "port_open", "value": "22/tcp", "confidence": 90, "session_id": "none"}
  ]
}
Do NOT invent facts. If nothing useful is found, return {"facts": []}.
"""
    def parse(self, tool_name: str, raw_output: str, session_id: str) -> List[Dict[str, Any]]:
        try:
            from core.ai.ollama_client import ask_ollama
            import json
            prompt = f"Tool: {tool_name}\nSession ID: {session_id}\nRaw Output:\n{raw_output[:2000]}\nExtract facts in JSON format."
            response = ask_ollama(self.system_prompt + "\n\n" + prompt, json_mode=True)

            # v12: check the error contract
            if response.startswith("[!]"):
                logger.warning(f"LLM Extractor got error: {response}")
                return []

            data = json.loads(response)
            return data.get("facts", [])
        except Exception as e:
            logger.warning(f"Extraction LLM Error: {e}")
            print(f"[!] Extraction LLM Error: {e}")
            return []


class OutputParser:
    """
    Parses raw tool outputs into basic facts (evidence).
    Uses a ParserChain: RegexParser -> StructuredParser -> LLMExtractor.

    v12: LLMExtractor is ONLY called when regex+structured produced ZERO facts.
    This prevents wasting LLM calls when regex already parsed everything.
    """
    def __init__(self):
        self.regex_parser = RegexParser()
        self.structured_parser = StructuredParser()
        self.llm_extractor = LLMExtractor()

    def parse_tool_output(self, tool_name: str, raw_output: str) -> List[Dict[str, Any]]:
        """
        Extract raw facts from tool output.
        Returns a list of dicts: [{"type": "...", "value": "...", "confidence": int, "session_id": "str"}]
        """
        session_id = "none"
        sess_match = re.search(r'session\s*\[?([a-zA-Z0-9_-]+)\]?', raw_output, re.IGNORECASE)
        if sess_match:
            session_id = sess_match.group(1)

        facts = []

        # 1. Regex Parser (primary)
        facts.extend(self.regex_parser.parse(tool_name, raw_output, session_id))

        # 2. Structured Parser (if regex found nothing)
        if not facts:
            facts.extend(self.structured_parser.parse(tool_name, raw_output, session_id))

        # 3. LLM Extractor — ONLY if regex+structured found ZERO facts and there's meaningful output
        if not facts and len(raw_output.strip()) > 50:
            logger.info(f"Regex found 0 facts for '{tool_name}', trying LLM extractor...")
            llm_facts = self.llm_extractor.parse(tool_name, raw_output, session_id)
            facts.extend(llm_facts)

        return facts
