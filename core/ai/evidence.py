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
        evidence_terms = self._build_evidence_terms(scan_id, host, facts)

        missing_evidence = []
        for req in required_evidence:
            req_norm = self._norm(req)
            if req_norm in {"state", "services", "service", "open_questions", "ports_count"}:
                missing_evidence.append(req)
                continue
            found = any(req_norm == term or req_norm in term or term in req_norm
                        for term in evidence_terms)
            if not found:
                missing_evidence.append(req)

        if missing_evidence:
            return {
                "claim": claim,
                "status": "rejected",
                "reason": f"No supporting evidence found for: {', '.join(missing_evidence)}"
            }

        add_with_status = getattr(self.fact_store, "add_fact_with_status", None)
        if add_with_status:
            _fact_id, created = add_with_status(
                scan_id=scan_id,
                host=host,
                fact_type="verified_claim",
                value=claim,
                source="evidence_verifier"
            )
        else:
            self.fact_store.add_fact(
                scan_id=scan_id,
                host=host,
                fact_type="verified_claim",
                value=claim,
                source="evidence_verifier"
            )
            created = True

        return {
            "claim": claim,
            "status": "accepted",
            "reason": "All required evidence verified.",
            "created": created,
        }

    def _norm(self, value: str) -> str:
        return re.sub(r'[^a-z0-9]+', '_', str(value).lower()).strip('_')

    def _build_evidence_terms(self, scan_id: str, host: str, facts: List[Dict[str, Any]]) -> set:
        terms = {self._norm(f"host:{host}"), self._norm(host)}

        for f in facts:
            ftype = str(f.get("type", ""))
            fval = str(f.get("value", ""))
            terms.add(self._norm(ftype))
            terms.add(self._norm(fval))
            terms.add(self._norm(f"{ftype}:{fval}"))

        try:
            from core.ai.state_resolver import StateResolver
            from core.ai.context_builder import ContextBuilder
            resolver = StateResolver(self.fact_store)
            context = ContextBuilder(self.fact_store, resolver).build_context(scan_id, host)

            terms.add(self._norm(f"state:{context.get('state', '')}"))
            terms.add(self._norm(f"state_{context.get('state', '')}"))
            terms.add(self._norm(f"ports_count:{context.get('ports_count', 0)}"))
            terms.add(self._norm(f"ports_count_{context.get('ports_count', 0)}"))

            for service in context.get("services", []):
                terms.add(self._norm(f"service:{service}"))
                terms.add(self._norm(f"service_{service}"))
                terms.add(self._norm(f"services:{service}"))
                terms.add(self._norm(f"services_{service}"))

            for question in context.get("open_questions", []):
                terms.add(self._norm(f"open_questions:{question}"))
                terms.add(self._norm(f"open_questions_{question}"))
        except Exception as exc:
            logger.debug("Could not build derived evidence terms: %s", exc)

        return terms


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

        if "pwnkit" in raw_lower and ("root via" in raw_lower or "uid=0" in raw_lower or "root access confirmed" in raw_lower):
            facts.append({"type": "exploit_success", "value": "CVE-2021-4034 PwnKit root access", "confidence": 100, "session_id": session_id})
            facts.append({"type": "vulnerability", "value": "CVE-2021-4034", "confidence": 100, "session_id": session_id})

        # ── Root / UID detection ──
        if "uid=0" in raw_lower or "root access confirmed" in raw_lower:
            facts.append({"type": "system_access", "value": "uid=0", "confidence": 100, "session_id": session_id})
        if "root access confirmed" in raw_lower:
            facts.append({"type": "system_access", "value": "root_access_confirmed", "confidence": 100, "session_id": session_id})

        # ── Authenticated SSH-backed killchain stage banners ──
        for m in re.finditer(
            r'(?:Privilege Escalation|Data Exfiltration|Active Persistence|STEALTH CLEANUP)\s*[—:-]\s*([^\s@]+)@([^\s:]+)',
            raw_output,
            re.IGNORECASE
        ):
            user, target = m.groups()
            facts.append({"type": "credential", "value": f"ssh_login_success:{user}@{target}", "confidence": 95, "session_id": session_id})
            facts.append({"type": "port_open", "value": "22/tcp (ssh)", "confidence": 90, "session_id": session_id})
            facts.append({"type": "service_status", "value": "ssh_authenticated", "confidence": 95, "session_id": session_id})

        if "exploitablesuid" in raw_lower.replace(" ", "") or "exploitable suid" in raw_lower or "/usr/bin/pkexec" in raw_lower:
            facts.append({"type": "privesc_vector", "value": "suid_pkexec", "confidence": 100, "session_id": session_id})

        # ── /etc/shadow extraction ──
        if "/etc/shadow" in raw_output and "root:" in raw_output:
            facts.append({"type": "data_exfiltration", "value": "shadow_file_extracted", "confidence": 100, "session_id": session_id})
        if "target report saved" in raw_lower or "loot directory" in raw_lower:
            facts.append({"type": "data_exfiltration", "value": "loot_collected", "confidence": 90, "session_id": session_id})

        # ── SSH key injection ──
        if (("authorized_keys" in raw_lower or "ssh key" in raw_lower)
                and ("injected" in raw_lower or "planted" in raw_lower or "written" in raw_lower)):
            facts.append({"type": "persistence", "value": "ssh_key_injected", "confidence": 100, "session_id": session_id})

        # ── Credential detection ──
        if "login success" in raw_lower or "password found" in raw_lower:
            facts.append({"type": "credential", "value": "login_success", "confidence": 100, "session_id": session_id})

        for m in re.finditer(r'Known:\s*([^\s:]+):([^\s]+)', raw_output, re.IGNORECASE):
            user, pwd = m.groups()
            facts.append({"type": "credential", "value": f"{user}:{pwd} (cached)", "confidence": 95, "session_id": session_id})

        for m in re.finditer(r'SSH connected as\s+([^\s@]+)@([^\s:]+)', raw_output, re.IGNORECASE):
            user, target = m.groups()
            facts.append({"type": "credential", "value": f"ssh_login_success:{user}@{target}", "confidence": 100, "session_id": session_id})
            facts.append({"type": "port_open", "value": "22/tcp (ssh)", "confidence": 90, "session_id": session_id})
            facts.append({"type": "service_status", "value": "ssh_authenticated", "confidence": 100, "session_id": session_id})

        # SSH post-analysis facts. These outputs are generated by ssh_session and
        # are already authenticated host observations, so preserve them for state.
        if "ssh post-exploitation analysis" in raw_lower or "ssh connected as" in raw_lower:
            host_match = re.search(r'\[\+\]\s+Hostname\s*\n\$[^\n]*\n([^\n]+)', raw_output, re.IGNORECASE)
            if host_match:
                hostname = host_match.group(1).strip()
                if hostname and not hostname.startswith("["):
                    facts.append({"type": "hostname", "value": hostname[:100], "confidence": 95, "session_id": session_id})

            pretty_os = re.search(r'^PRETTY_NAME=["\']?([^"\'\n]+)', raw_output, re.MULTILINE)
            if pretty_os:
                facts.append({"type": "os_version", "value": pretty_os.group(1).strip()[:120], "confidence": 95, "session_id": session_id})

            kernel_match = re.search(r'\[\+\]\s+Kernel\s*\n\$[^\n]*\n([^\n]+)', raw_output, re.IGNORECASE)
            if kernel_match:
                kernel = kernel_match.group(1).strip()
                if kernel and not kernel.startswith("["):
                    facts.append({"type": "kernel_version", "value": kernel[:100], "confidence": 95, "session_id": session_id})

            if re.search(r'SUID Binaries.*?(SUID EXPLOIT|/usr/bin|/bin/|/usr/sbin|/sbin)', raw_output, re.IGNORECASE | re.DOTALL):
                facts.append({"type": "privesc_vector", "value": "suid_binaries_present", "confidence": 90, "session_id": session_id})

            if re.search(r'Sudo (?:rights|Permissions).*?(may run|NOPASSWD|ALL\s*=\s*\()', raw_output, re.IGNORECASE | re.DOTALL):
                facts.append({"type": "privesc_vector", "value": "sudo_rights_present", "confidence": 85, "session_id": session_id})

            internal_services = re.search(r'Listening Ports.*?\((\d+)\s+internal services?\)', raw_output, re.IGNORECASE)
            if internal_services:
                facts.append({"type": "service_status", "value": f"internal_services:{internal_services.group(1)}", "confidence": 80, "session_id": session_id})

        # ── Hydra / brute force results ──
        for m in re.finditer(r'\[(\d+)\]\[(\w+)\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)', raw_output):
            facts.append({"type": "credential", "value": f"{m.group(3)}:{m.group(4)} ({m.group(2)} port {m.group(1)})", "confidence": 100, "session_id": session_id})

        # ── Persistence ──
        if "persistence" in raw_lower and ("success" in raw_lower or "planted" in raw_lower):
            facts.append({"type": "persistence", "value": "mechanism_planted", "confidence": 100, "session_id": session_id})

        cleanup_status = re.search(r'CLEANUP STATUS:\s*(SUCCESS|PARTIAL|FAILED)', raw_output, re.IGNORECASE)
        if cleanup_status:
            status = cleanup_status.group(1).lower()
            confidence = 100 if status == "success" else 80 if status == "partial" else 50
            facts.append({"type": "cleanup", "value": status, "confidence": confidence, "session_id": session_id})

        # ── Nikto findings ──
        if "nikto" in tool_name.lower():
            for m in re.finditer(r'\+\s+OSVDB-\d+:\s+(.+)', raw_output):
                facts.append({"type": "potential_vulnerability", "value": m.group(1).strip()[:100], "confidence": 60, "session_id": session_id})

        # ── enum4linux / SMB ──
        if "enum4linux" in tool_name.lower():
            if "server doesn't allow session" in raw_lower or "nt_status_access_denied" in raw_lower:
                facts.append({"type": "smb_status", "value": "null_session_denied", "confidence": 100, "session_id": session_id})

        # ── ShardBrowser / browser-rendered web analysis ──
        tool_lower = tool_name.lower()
        if ("browser_surface" in tool_lower or "shardbrowser" in tool_lower
                or "shardx direct browse" in raw_lower):
            url_match = re.search(r'^URL:\s*(\S+)', raw_output, re.MULTILINE)
            if url_match:
                facts.append({"type": "browser_rendered", "value": url_match.group(1), "confidence": 90, "session_id": session_id})

            title_match = re.search(r'^Page title:\s*(.+)$', raw_output, re.MULTILINE)
            if title_match:
                facts.append({"type": "web_title", "value": title_match.group(1).strip()[:180], "confidence": 90, "session_id": session_id})

            size_match = re.search(r'^Content size:\s*(\d+)\s+bytes', raw_output, re.MULTILINE)
            if size_match:
                facts.append({"type": "web_surface", "value": f"rendered_bytes:{size_match.group(1)}", "confidence": 85, "session_id": session_id})

            forms_match = re.search(r'^Forms:\s*(\d+)', raw_output, re.MULTILINE)
            if forms_match:
                facts.append({"type": "web_surface", "value": f"forms:{forms_match.group(1)}", "confidence": 90, "session_id": session_id})

            for m in re.finditer(r'^\s*input:\s*([^:\s]+):(.+)$', raw_output, re.MULTILINE):
                input_type, input_name = m.groups()
                input_value = f"{input_type.lower()}:{input_name.strip()[:80]}"
                facts.append({"type": "web_input", "value": input_value, "confidence": 90, "session_id": session_id})
                if input_type.lower() == "password":
                    facts.append({"type": "web_surface", "value": "login_form_detected", "confidence": 95, "session_id": session_id})

            for m in re.finditer(r'^\s*link:\s*(\S.+)$', raw_output, re.MULTILINE):
                facts.append({"type": "web_link", "value": m.group(1).strip()[:200], "confidence": 80, "session_id": session_id})

        if "shardx osint search" in raw_lower:
            query_match = re.search(r'\[ShardX OSINT Search\s*-\s*(.+?)\]', raw_output)
            if query_match:
                facts.append({"type": "osint_query", "value": query_match.group(1).strip()[:160], "confidence": 85, "session_id": session_id})
            for m in re.finditer(r'"([^"]+)":\s*\{[^{}]*?"content_length":\s*(\d+)', raw_output, re.DOTALL):
                engine, length = m.groups()
                facts.append({"type": "osint_result", "value": f"{engine}:content_length:{length}", "confidence": 80, "session_id": session_id})
            for m in re.finditer(r'"([^"]+)":\s*\{\s*"error":\s*"([^"]+)"', raw_output, re.DOTALL):
                engine, error = m.groups()
                facts.append({"type": "osint_status", "value": f"{engine}:error:{error[:100]}", "confidence": 70, "session_id": session_id})

        # ── Internal network / pivot reconnaissance ──
        if ("network discovery" in raw_lower or "internal hosts discovered" in raw_lower
                or "lateral movement" in raw_lower):
            subnet_match = re.search(r'^\s*Subnets:\s*(.+)$', raw_output, re.MULTILINE)
            if subnet_match:
                for subnet in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', subnet_match.group(1)):
                    if not subnet.startswith("127."):
                        facts.append({"type": "internal_subnet", "value": subnet, "confidence": 90, "session_id": session_id})

            for m in re.finditer(r'^\s*(?:→|->)\s*((?:\d{1,3}\.){3}\d{1,3})\s*$', raw_output, re.MULTILINE):
                ip = m.group(1)
                if not ip.startswith(("127.", "0.")) and ip != "255.255.255.255":
                    facts.append({"type": "internal_host", "value": ip, "confidence": 85, "session_id": session_id})

            count_match = re.search(r'Internal hosts discovered:\s*(\d+)', raw_output, re.IGNORECASE)
            if count_match:
                facts.append({"type": "internal_network", "value": f"hosts_discovered:{count_match.group(1)}", "confidence": 85, "session_id": session_id})

            for m in re.finditer(r'LATERAL MOVEMENT SUCCESS:\s*([^\s@]+)@((?:\d{1,3}\.){3}\d{1,3})', raw_output, re.IGNORECASE):
                user, ip = m.groups()
                facts.append({"type": "lateral_access", "value": f"{user}@{ip}", "confidence": 100, "session_id": session_id})

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
                if isinstance(data.get("facts"), list):
                    for fact in data["facts"]:
                        if isinstance(fact, dict) and fact.get("type") and fact.get("value"):
                            facts.append({
                                "type": fact.get("type"),
                                "value": fact.get("value"),
                                "confidence": fact.get("confidence", 80),
                                "session_id": fact.get("session_id", session_id),
                            })
                if "cve" in data:
                    facts.append({"type": "vulnerability", "value": data["cve"], "confidence": 100, "session_id": session_id})
            except Exception as _exc:
                logging.debug(f"Suppressed in evidence.py: {_exc}")
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

    def _should_try_llm(self, tool_name: str, raw_output: str) -> bool:
        raw = raw_output.strip()
        if len(raw) <= 50:
            return False

        lower = raw.lower()
        failure_markers = [
            "[!] command failed",
            "[!] command returned no output",
            "returned no output",
            "[!] tool not found",
            "not found:",
            "not installed",
            "timed out after",
            "[!] timed out",
            "do not call hydra directly",
            "blocked command",
            "[!] blocked",
            "no information available for that ip",
            "validation failed",
            "requires valid credentials",
            "requires domain",
            "requires an nt hash",
            "keyerror",
            "traceback",
            "exception",
            "error executing tool",
        ]
        return not any(marker in lower for marker in failure_markers)

    def _sanitize_facts(self, facts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop low-value or malformed facts before they enter the fact store."""
        sanitized = []
        seen = set()
        for fact in facts:
            ftype = str(fact.get("type", "")).strip()
            value = str(fact.get("value", "")).strip()
            if not ftype or not value:
                continue
            if ftype == "port_open" and not re.search(r'\b\d+/(?:tcp|udp)\b', value.lower()):
                continue
            if ftype in {"tool_name", "error_type"}:
                continue
            key = (ftype, value, fact.get("session_id", "none"))
            if key in seen:
                continue
            seen.add(key)
            sanitized.append(fact)
        return sanitized

    def parse_tool_output(self, tool_name: str, raw_output: str) -> List[Dict[str, Any]]:
        """
        Extract raw facts from tool output.
        Returns a list of dicts: [{"type": "...", "value": "...", "confidence": int, "session_id": "str"}]
        """
        session_id = "none"
        sess_match = re.search(r'(?:session_id|session)\s*[:=\[]\s*([a-zA-Z0-9_-]+)\]?', raw_output, re.IGNORECASE)
        if sess_match:
            session_id = sess_match.group(1)

        facts = []

        # 1. Regex Parser (primary)
        facts.extend(self.regex_parser.parse(tool_name, raw_output, session_id))

        # 2. Structured Parser (if regex found nothing)
        if not facts:
            facts.extend(self.structured_parser.parse(tool_name, raw_output, session_id))

        # 3. LLM Extractor — ONLY if regex+structured found ZERO facts and there's meaningful output
        if not facts and self._should_try_llm(tool_name, raw_output):
            logger.info(f"Regex found 0 facts for '{tool_name}', trying LLM extractor...")
            llm_facts = self.llm_extractor.parse(tool_name, raw_output, session_id)
            facts.extend(llm_facts)

        return self._sanitize_facts(facts)
