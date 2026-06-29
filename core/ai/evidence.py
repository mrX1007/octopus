#!/usr/bin/env python3
import re
import logging
import ipaddress
from typing import Dict, Any, List

logger = logging.getLogger("octopus.evidence")


def _is_internal_ip_value(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(value).split("/")[0])
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False


def _is_internal_subnet_value(value: str) -> bool:
    try:
        net = ipaddress.ip_network(str(value), strict=False)
        return net.is_private or net.is_link_local
    except ValueError:
        return False


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
        tool_lower = tool_name.lower()
        raw_lower = raw_output.lower()
        is_exfil_stage = (
            "killchain_exfil" in tool_lower
            or "data_exfil" in tool_lower
            or "exfiltrate_data" in tool_lower
            or "[kill chain" in raw_lower and "data exfiltration" in raw_lower
            or "stage 6: data exfiltration" in raw_lower
        )
        ssh_enum_false_positive = (
            "cve-2018-15473" in raw_lower
            and (
                "all users return valid" in raw_lower
                or "all 4 canary users returned valid" in raw_lower
                or "server is patched" in raw_lower
                or "including fake names" in raw_lower
            )
        )

        # ── Nmap/rustscan-style port detection ──
        # Manual recon blobs are passed as "manual_recon", so detect the table
        # shape in the output too. Otherwise real nmap ports are lost before
        # StateResolver/ContextBuilder can route web/cPanel/MSF follow-ups.
        has_port_table = re.search(r'(?m)^\s*\d+/(?:tcp|udp)\s+open\s+', raw_output) is not None
        if "nmap" in tool_lower or "rustscan" in tool_lower or has_port_table:
            for m in re.finditer(r'(?m)^\s*(\d+)/tcp[ \t]+(open|filtered)[ \t]+(\S+)(?:[ \t]+([^\n]+))?', raw_output):
                port = m.group(1)
                state = m.group(2)
                service = m.group(3)
                version = m.group(4).strip() if m.group(4) else ""
                if state == "filtered":
                    facts.append({
                        "type": "port_filtered",
                        "value": f"{port}/tcp ({service})",
                        "confidence": 85,
                        "session_id": session_id,
                    })
                    continue
                value = f"{port}/tcp ({service})"
                if version:
                    value += f" [{version[:60]}]"
                facts.append({"type": "port_open", "value": value, "confidence": 100, "session_id": session_id})
                if version and version.lower() not in {"tcpwrapped", "unknown"}:
                    facts.append({
                        "type": "service_version",
                        "value": f"{service}:{port}:{version[:120]}",
                        "confidence": 90,
                        "session_id": session_id,
                    })

            host_match = re.search(r'Service Info:\s*Host:\s*(\S+)', raw_output)
            if host_match:
                facts.append({"type": "hostname", "value": host_match.group(1), "confidence": 100, "session_id": session_id})

        # ── CVE detection (version match only = potential, NOT confirmed) ──
        for cve in re.finditer(r'(CVE-\d{4}-\d{4,7})', raw_output, re.IGNORECASE):
            cve_id = cve.group(1).upper()
            if cve_id == "CVE-2018-15473" and ssh_enum_false_positive:
                continue
            facts.append({"type": "potential_vulnerability", "value": cve_id, "confidence": 50, "session_id": session_id})

        if ssh_enum_false_positive:
            facts.append({
                "type": "service_status",
                "value": "ssh_user_enum_unreliable_or_patched",
                "confidence": 95,
                "session_id": session_id,
            })

        # ── cPanel/WHM exploit output (cpanel_sniper) ──
        if "VULNERABLE" in raw_output and ("cpsess" in raw_output or "cPanel" in raw_output or "WHM" in raw_output):
            panel_url = re.search(r'https?://([^/\s:]+):(\d+)(?:/|\s|$)', raw_output)
            if panel_url:
                _panel_host, panel_port = panel_url.groups()
                facts.append({
                    "type": "port_open",
                    "value": f"{panel_port}/tcp (cpanel) [cPanel/WHM]",
                    "confidence": 95,
                    "session_id": session_id,
                })
                facts.append({
                    "type": "web_surface",
                    "value": f"cpanel_whm:{panel_port}",
                    "confidence": 95,
                    "session_id": session_id,
                })

            # Extract the CVE and mark as CONFIRMED exploit
            cve_match = re.search(r'(CVE-\d{4}-\d{4,7})\s*[—\-]+\s*(.+?)(?:\n|$)', raw_output)
            if cve_match:
                facts.append({"type": "exploit_success", "value": f"{cve_match.group(1)} — {cve_match.group(2).strip()}", "confidence": 100, "session_id": session_id})
                facts.append({"type": "vulnerability", "value": cve_match.group(1).upper(), "confidence": 100, "session_id": session_id})

            # Extract session token
            sess_match = re.search(r'(?:Session:\s*|whostmgrsession=)([:A-Za-z0-9_.=/+-]+)', raw_output)
            if sess_match:
                session_value = sess_match.group(1).lstrip(":")
                if session_value:
                    facts.append({"type": "credential", "value": f"whm_session:{session_value}", "confidence": 100, "session_id": session_id})

            # Extract cPanel version
            ver_match = re.search(r'Version:\s*([\d.]+)', raw_output)
            if ver_match:
                facts.append({"type": "service_version", "value": f"cPanel {ver_match.group(1)}", "confidence": 100, "session_id": session_id})

            # Mark as authenticated session = credential
            if "authenticated session obtained" in raw_lower:
                facts.append({"type": "credential", "value": "cpanel_auth_bypass_session", "confidence": 100, "session_id": session_id})
                facts.append({"type": "application_access", "value": "cpanel_whm_authenticated", "confidence": 100, "session_id": session_id})

        # ── Exploit selector / Metasploit planning facts ──
        for m in re.finditer(
            r'^\[EXPLOIT CANDIDATE\s+\d+\]\s+([^:\s]+):(\d+)\s+(.+?)\s+->\s+(\S+)',
            raw_output,
            re.MULTILINE,
        ):
            service, port, version, module = m.groups()
            facts.append({
                "type": "exploit_candidate",
                "value": f"{module} on {service}:{port} [{version.strip()[:80]}]",
                "confidence": 85,
                "session_id": session_id,
            })
            if module.startswith(("exploit/", "auxiliary/")):
                facts.append({"type": "msf_module", "value": module, "confidence": 85, "session_id": session_id})

        for m in re.finditer(r'^\s*Payload recommendation:\s*(\S+)', raw_output, re.MULTILINE):
            facts.append({"type": "payload_recommendation", "value": m.group(1), "confidence": 80, "session_id": session_id})

        for m in re.finditer(r'^\s*MSF check:\s*(msf_check\s+\S+\s+\S+(?:\s+.+)?)$', raw_output, re.MULTILINE):
            facts.append({"type": "verification_command", "value": m.group(1).strip()[:220], "confidence": 80, "session_id": session_id})

        for m in re.finditer(r'^\s*MSF run gated:\s*(msf_run\s+\S+\s+\S+(?:\s+.+)?)$', raw_output, re.MULTILINE):
            facts.append({"type": "active_command", "value": m.group(1).strip()[:260], "confidence": 75, "session_id": session_id})

        for m in re.finditer(r"MSF module '([^']+)' does NOT EXIST", raw_output, re.IGNORECASE):
            facts.append({"type": "service_status", "value": f"msf_module_invalid:{m.group(1)}", "confidence": 95, "session_id": session_id})

        msf_module_match = re.search(r'\b(?:msf_check|msf_run)\s+\S+\s+(\S+)', tool_name, re.IGNORECASE)
        msf_module = msf_module_match.group(1) if msf_module_match else "unknown"
        msf_negative = (
            "does not appear to be vulnerable" in raw_lower
            or "not exploitable" in raw_lower
            or "is not exploitable" in raw_lower
            or "the target is not exploitable" in raw_lower
        )
        msf_positive = (
            "the target appears to be vulnerable" in raw_lower
            or "appears to be vulnerable" in raw_lower
            or "check appears" in raw_lower
            or re.search(r'\bis vulnerable\b', raw_lower) is not None
        )
        if "msf_check" in tool_lower or "metasploit_check" in tool_lower:
            if msf_negative:
                facts.append({"type": "service_status", "value": f"msf_check_not_vulnerable:{msf_module}", "confidence": 90, "session_id": session_id})
            elif msf_positive:
                facts.append({"type": "vulnerability", "value": f"msf_check_positive:{msf_module}", "confidence": 90, "session_id": session_id})
                facts.append({"type": "msf_module", "value": msf_module, "confidence": 90, "session_id": session_id})

        if re.search(r'(?:meterpreter|command shell) session \d+ opened', raw_output, re.IGNORECASE):
            facts.append({"type": "exploit_success", "value": f"msf_session_opened:{msf_module}", "confidence": 100, "session_id": session_id})

        # ── Generic exploit attempt tracking ──
        for m in re.finditer(r'\[\*\] Attempting (?:privesc|exploit) via (.+)', raw_output, re.IGNORECASE):
            facts.append({"type": "exploit_attempted", "value": m.group(1).strip(), "confidence": 100, "session_id": session_id})

        # ── Exploit status lines (CVE — Description) ──
        for m in re.finditer(r'(CVE-\d{4}-\d{4,7})\s+[—\-]+\s+(.+?)(?:\n|$)', raw_output):
            if m.group(1).upper() == "CVE-2018-15473" and (
                    "all users return valid" in m.group(2).lower()
                    or "patched" in raw_lower):
                continue
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

        # ── SSH-backed killchain stage banners ──
        # A stage banner alone is only an attempt. Confirmed SSH auth requires
        # evidence from the command output after connection, otherwise failed
        # post-exploit stages become false root/login facts.
        stage_has_authenticated_output = (
            re.search(r'^Current:\s*uid=\d+', raw_output, re.MULTILINE) is not None
            or "ssh connected as" in raw_lower
            or "already root" in raw_lower
            or "privilege escalation confirmed" in raw_lower
            or "root access confirmed" in raw_lower
            or "root access obtained" in raw_lower
            or "uid=0(root)" in raw_lower
        )
        for m in re.finditer(
            r'(?:Privilege Escalation|Data Exfiltration|Active Persistence|STEALTH CLEANUP)\s*[—:-]\s*([^\s@]+)@([^\s:]+)',
            raw_output,
            re.IGNORECASE
        ):
            user, target = m.groups()
            facts.append({"type": "port_open", "value": "22/tcp (ssh)", "confidence": 90, "session_id": session_id})
            facts.append({"type": "service_status", "value": f"ssh_stage_attempt:{user}@{target}", "confidence": 80, "session_id": session_id})
            if stage_has_authenticated_output:
                facts.append({"type": "credential", "value": f"ssh_login_success:{user}@{target}", "confidence": 95, "session_id": session_id})
                facts.append({"type": "service_status", "value": "ssh_authenticated", "confidence": 95, "session_id": session_id})
            elif "ssh connection failed" in raw_lower or "auth failed" in raw_lower or "key auth failed" in raw_lower:
                facts.append({"type": "service_status", "value": f"ssh_auth_failed:{user}@{target}", "confidence": 95, "session_id": session_id})
            if "ssh key injected for root" in raw_lower and "verified" in raw_lower:
                facts.append({"type": "credential", "value": f"ssh_key_available:root@{target}", "confidence": 95, "session_id": session_id})

        if "exploitablesuid" in raw_lower.replace(" ", "") or "exploitable suid" in raw_lower or "/usr/bin/pkexec" in raw_lower:
            facts.append({"type": "privesc_vector", "value": "suid_pkexec", "confidence": 100, "session_id": session_id})

        # ── Credential material / exfil stage completion ──
        if "/etc/shadow" in raw_output and "root:" in raw_output:
            facts.append({"type": "credential_material", "value": "shadow_file_extracted", "confidence": 100, "session_id": session_id})

        files_exfiltrated = re.search(r'Files exfiltrated:\s*(\d+)', raw_output, re.IGNORECASE)
        if is_exfil_stage and files_exfiltrated:
            count = files_exfiltrated.group(1)
            facts.append({"type": "data_exfiltration", "value": f"files_exfiltrated:{count}", "confidence": 100, "session_id": session_id})
            facts.append({"type": "post_exploit_stage", "value": "data_exfiltration_completed", "confidence": 100, "session_id": session_id})
            if int(count) > 0:
                facts.append({"type": "data_exfiltration", "value": "loot_collected", "confidence": 100, "session_id": session_id})

        if "target report saved" in raw_lower or "report saved to:" in raw_lower:
            facts.append({"type": "loot_artifact", "value": "target_report_saved", "confidence": 90, "session_id": session_id})
        if is_exfil_stage and ("exfil directory:" in raw_lower or "loot directory:" in raw_lower):
            facts.append({"type": "loot_artifact", "value": "exfil_directory_created", "confidence": 90, "session_id": session_id})

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
            if (
                "ssh controlled inventory" in raw_lower
                or "ssh inventory completed" in raw_lower
                or ("ssh_inventory" in tool_lower and "ssh connected as" in raw_lower)
            ) and "ssh connection failed" not in raw_lower:
                facts.append({"type": "post_exploit_stage", "value": "post_access_inventory_completed", "confidence": 95, "session_id": session_id})
                facts.append({"type": "service_status", "value": "ssh_inventory_completed", "confidence": 95, "session_id": session_id})

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

            for ip_match in re.finditer(r'\binet\s+((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?', raw_output):
                ip, prefix = ip_match.groups()
                if ip.startswith("127."):
                    continue
                if _is_internal_ip_value(ip):
                    facts.append({"type": "internal_host", "value": ip, "confidence": 80, "session_id": session_id})
                    if prefix:
                        subnet = f"{ip}/{prefix}"
                        if _is_internal_subnet_value(subnet):
                            facts.append({"type": "internal_subnet", "value": subnet, "confidence": 80, "session_id": session_id})

            internal_services = re.search(r'Listening Ports.*?\((\d+)\s+internal services?\)', raw_output, re.IGNORECASE)
            if internal_services:
                facts.append({"type": "service_status", "value": f"internal_services:{internal_services.group(1)}", "confidence": 80, "session_id": session_id})

            for port in re.findall(r'(?m)\bLISTEN\b.*?:(\d{2,5})\b', raw_output):
                facts.append({"type": "local_listening_port", "value": port, "confidence": 75, "session_id": session_id})

            stack_markers = {
                "nginx": "nginx", "apache2": "apache", "httpd": "apache",
                "php-fpm": "php", "/php": "php", "python3": "python",
                "/node": "nodejs", "/npm": "nodejs", "/go": "go",
                "/java": "java", "docker": "docker", "podman": "podman",
                "psql": "postgresql", "mysql": "mysql", "redis-server": "redis",
                "mongod": "mongodb",
            }
            for marker, stack in stack_markers.items():
                if marker in raw_lower:
                    facts.append({"type": "app_stack", "value": stack, "confidence": 75, "session_id": session_id})

            for m in re.finditer(r'(?m)^(/(?:var/www|srv|opt|home)/[^\s]+/(?:public|html|www|app|current))\s*$', raw_output):
                facts.append({"type": "web_root", "value": m.group(1)[:220], "confidence": 80, "session_id": session_id})

            manifest_pattern = r'(?m)^(/(?:var/www|srv|opt|home)/[^\s]+/(?:package\.json|composer\.json|requirements\.txt|pyproject\.toml|go\.mod|Gemfile|pom\.xml))\s*$'
            for m in re.finditer(manifest_pattern, raw_output):
                facts.append({"type": "app_manifest", "value": m.group(1)[:240], "confidence": 85, "session_id": session_id})

            config_pattern = r'(?m)^(/(?:var/www|srv|opt|home)/[^\s]+/(?:\.env|wp-config\.php|config\.php|settings\.py|database\.yml|application\.yml))(?:\s+\d+\s+bytes)?\s*$'
            for m in re.finditer(config_pattern, raw_output):
                facts.append({"type": "config_candidate", "value": m.group(1)[:240], "confidence": 80, "session_id": session_id})

            if "container runtime" in raw_lower and re.search(r'\b(?:docker|podman)\b', raw_lower):
                facts.append({"type": "container_runtime", "value": "containers_observed_or_runtime_present", "confidence": 75, "session_id": session_id})

            if "scheduled tasks" in raw_lower and re.search(r'(?:/etc/cron|\.timer\b|cron\.|systemd)', raw_lower):
                facts.append({"type": "scheduled_task_surface", "value": "cron_or_systemd_timers_present", "confidence": 75, "session_id": session_id})

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

        # ── Web vulnerability tooling ──
        if "wpscan" in tool_lower:
            wp_version = re.search(r'WordPress version\s+([\d.]+)', raw_output, re.IGNORECASE)
            if wp_version:
                facts.append({"type": "service_version", "value": f"WordPress {wp_version.group(1)}", "confidence": 85, "session_id": session_id})
            if re.search(r'\b(?:vulnerabilit(?:y|ies)|CVE-\d{4}-\d{4,7})\b', raw_output, re.IGNORECASE):
                if "no vulnerabilities identified" not in raw_lower:
                    facts.append({"type": "potential_vulnerability", "value": "wordpress_wpscan_findings", "confidence": 70, "session_id": session_id})

        if "sqlmap" in tool_lower:
            injectable = re.search(r"Parameter:\s*([^\s(]+).*?(?:is vulnerable|appears to be injectable)", raw_output, re.IGNORECASE | re.DOTALL)
            if injectable:
                facts.append({"type": "vulnerability", "value": f"sql_injection:{injectable.group(1)}", "confidence": 90, "session_id": session_id})
            elif "all tested parameters do not appear to be injectable" in raw_lower:
                facts.append({"type": "service_status", "value": "sqlmap_no_injection_found", "confidence": 85, "session_id": session_id})

        if "jmx2rce" in tool_lower:
            if any(marker in raw_lower for marker in ("unauthenticated jmx", "jmx proxy is accessible", "vulnerable")):
                if "not vulnerable" not in raw_lower and "not installed" not in raw_lower:
                    facts.append({"type": "vulnerability", "value": "tomcat_jmx_proxy_exposed", "confidence": 90, "session_id": session_id})
            if "not vulnerable" in raw_lower or "not accessible" in raw_lower:
                facts.append({"type": "service_status", "value": "jmx2rce_not_vulnerable", "confidence": 85, "session_id": session_id})

        if "ffuf" in tool_lower:
            for m in re.finditer(r'(?m)^\s*([A-Za-z0-9._~!$&\'()*+,;=:@%/-]+)\s+\[Status:\s*(\d{3}),', raw_output):
                path, status = m.groups()
                clean_path = "/" + path.strip().lstrip("/")
                facts.append({"type": "web_path", "value": f"{clean_path}:{status}", "confidence": 85, "session_id": session_id})

        if "scrapling" in tool_lower or "scrapling result" in raw_lower or "requests+bs4 result" in raw_lower:
            title_match = re.search(r'^Title:\s*(.+)$', raw_output, re.MULTILINE)
            if title_match:
                facts.append({"type": "web_title", "value": title_match.group(1).strip()[:180], "confidence": 85, "session_id": session_id})
            forms_match = re.search(r'^Forms\s*\((\d+)\):', raw_output, re.MULTILINE)
            if forms_match:
                facts.append({"type": "web_surface", "value": f"forms:{forms_match.group(1)}", "confidence": 85, "session_id": session_id})
            for m in re.finditer(r'^\s+[^→\n]{0,80}→\s*(\S.+)$', raw_output, re.MULTILINE):
                facts.append({"type": "web_link", "value": m.group(1).strip()[:220], "confidence": 75, "session_id": session_id})

        if "curl_headers" in tool_lower or "headers:" in raw_lower:
            for header, fact_type in (("server", "web_server"), ("location", "web_redirect"), ("x-powered-by", "web_powered_by")):
                for m in re.finditer(rf'(?im)^{re.escape(header)}:\s*(.+)$', raw_output):
                    facts.append({"type": fact_type, "value": m.group(1).strip()[:160], "confidence": 80, "session_id": session_id})

        # ── Protocol-specific fact actions ──
        if "ftp_anonymous_check" in tool_lower or "ftp anonymous check" in raw_lower:
            header = re.search(r'\[FTP Anonymous Check\s*-\s*([^\]:]+):(\d+)\]', raw_output, re.IGNORECASE)
            ftp_host = header.group(1) if header else ""
            ftp_port = header.group(2) if header else "21"
            banner = re.search(r'^Banner:\s*(.+)$', raw_output, re.MULTILINE)
            if banner:
                facts.append({
                    "type": "service_version",
                    "value": f"ftp:{ftp_port}:{banner.group(1).strip()[:120]}",
                    "confidence": 80,
                    "session_id": session_id,
                })
            if re.search(r'^Anonymous login:\s*allowed\s*$', raw_output, re.IGNORECASE | re.MULTILINE):
                suffix = f"{ftp_host}:{ftp_port}" if ftp_host else ftp_port
                facts.append({"type": "vulnerability", "value": f"ftp_anonymous_login_allowed:{suffix}", "confidence": 90, "session_id": session_id})
                facts.append({"type": "service_status", "value": f"ftp_anonymous_allowed:{ftp_port}", "confidence": 90, "session_id": session_id})
                facts.append({"type": "credential", "value": f"ftp_anonymous:anonymous@{suffix}", "confidence": 85, "session_id": session_id})
            elif re.search(r'^Anonymous login:\s*denied\s*$', raw_output, re.IGNORECASE | re.MULTILINE):
                facts.append({"type": "service_status", "value": f"ftp_anonymous_denied:{ftp_port}", "confidence": 85, "session_id": session_id})
            elif "ftp probe failed" in raw_lower:
                facts.append({"type": "service_status", "value": f"ftp_probe_failed:{ftp_port}", "confidence": 70, "session_id": session_id})

        if "smtp_probe" in tool_lower or "smtp probe" in raw_lower:
            header = re.search(r'\[SMTP Probe\s*-\s*([^\]:]+):(\d+)\]', raw_output, re.IGNORECASE)
            smtp_port = header.group(2) if header else "25"
            banner = re.search(r'^Banner:\s*(.+)$', raw_output, re.MULTILINE)
            if banner:
                facts.append({
                    "type": "service_version",
                    "value": f"smtp:{smtp_port}:{banner.group(1).strip()[:120]}",
                    "confidence": 75,
                    "session_id": session_id,
                })
            if "smtp probe failed" in raw_lower:
                facts.append({"type": "service_status", "value": f"smtp_probe_failed:{smtp_port}", "confidence": 70, "session_id": session_id})
            else:
                facts.append({"type": "service_status", "value": f"smtp_probe_completed:{smtp_port}", "confidence": 85, "session_id": session_id})
            starttls = re.search(r'^STARTTLS:\s*(\S+)', raw_output, re.IGNORECASE | re.MULTILINE)
            if starttls:
                status = starttls.group(1).strip().lower()
                facts.append({"type": "service_status", "value": f"smtp_starttls_{status}:{smtp_port}", "confidence": 80, "session_id": session_id})
            auth = re.search(r'^AUTH mechanisms:\s*(.+)$', raw_output, re.IGNORECASE | re.MULTILINE)
            if auth:
                mechanisms = re.sub(r'\s+', ',', auth.group(1).strip().upper())
                facts.append({"type": "service_status", "value": f"smtp_auth_mechanisms:{smtp_port}:{mechanisms[:100]}", "confidence": 80, "session_id": session_id})

        if "db_inventory" in tool_lower or "db inventory" in raw_lower:
            header = re.search(r'\[DB Inventory\s*-\s*([^\s]+)\s+([^\]:]+):(\d+)\]', raw_output, re.IGNORECASE)
            db_service = header.group(1).lower() if header else "database"
            db_port = header.group(3) if header else "0"
            if re.search(r'^DB inventory completed:\s*(\S+)', raw_output, re.IGNORECASE | re.MULTILINE):
                facts.append({"type": "service_status", "value": f"db_inventory_completed:{db_service}:{db_port}", "confidence": 90, "session_id": session_id})
                facts.append({"type": "app_stack", "value": db_service, "confidence": 80, "session_id": session_id})
            elif "db inventory failed" in raw_lower:
                facts.append({"type": "service_status", "value": f"db_inventory_failed:{db_service}:{db_port}", "confidence": 75, "session_id": session_id})

            version = re.search(r'^Version:\s*(.+)$', raw_output, re.MULTILINE)
            if version:
                facts.append({
                    "type": "service_version",
                    "value": f"{db_service}:{db_port}:{version.group(1).strip()[:140]}",
                    "confidence": 90,
                    "session_id": session_id,
                })
            current_user = re.search(r'^Current user:\s*(.+)$', raw_output, re.MULTILINE)
            if current_user:
                facts.append({"type": "database_inventory", "value": f"current_user:{db_service}:{current_user.group(1).strip()[:80]}", "confidence": 85, "session_id": session_id})
            db_count = re.search(r'^Databases\s*\((\d+)\):', raw_output, re.MULTILINE)
            if db_count:
                facts.append({"type": "database_inventory", "value": f"databases:{db_service}:{db_count.group(1)}", "confidence": 85, "session_id": session_id})

        if "whatweb" in tool_lower:
            for marker, value in (
                ("wordpress", "wordpress"),
                ("php", "php"),
                ("node.js", "nodejs"),
                ("express", "express"),
                ("nginx", "nginx"),
                ("apache", "apache"),
                ("golang", "golang"),
            ):
                if marker in raw_lower:
                    facts.append({"type": "app_stack", "value": value, "confidence": 75, "session_id": session_id})

        if "searchsploit" in tool_lower:
            for line in raw_output.splitlines():
                if "|" not in line:
                    continue
                title, path = [part.strip() for part in line.rsplit("|", 1)]
                if "exploits/" in path or "shellcodes/" in path:
                    facts.append({"type": "exploit_reference", "value": f"{title[:100]} -> {path}", "confidence": 75, "session_id": session_id})

        # ── Generated local payload / C2 artifacts ──
        for label, artifact_type in (
            ("Python implant generated", "python_implant"),
            ("PowerShell stager generated", "powershell_stager"),
            ("Go implant", "go_implant"),
        ):
            pattern = rf'{re.escape(label)}:\s*(\S+)'
            for m in re.finditer(pattern, raw_output, re.IGNORECASE):
                facts.append({"type": "payload_artifact", "value": f"{artifact_type}:{m.group(1)}", "confidence": 90, "session_id": session_id})

        c2_match = re.search(r'^C2:\s*(\S+)', raw_output, re.MULTILINE)
        if c2_match:
            facts.append({"type": "c2_profile", "value": c2_match.group(1), "confidence": 80, "session_id": session_id})

        if "socks proxy" in raw_lower and any(marker in raw_lower for marker in ("started", "listening", "[+]")):
            facts.append({"type": "pivot", "value": "socks_proxy_started", "confidence": 85, "session_id": session_id})
        if "port forward" in raw_lower and any(marker in raw_lower for marker in ("started", "forward", "[+]")):
            facts.append({"type": "pivot", "value": "port_forward_started", "confidence": 85, "session_id": session_id})

        # ── Legacy killchain stage status normalization ──
        if "killchain_vuln_assess" in tool_lower or "vulnerability assessment" in raw_lower:
            total = re.search(r'Total exploitable findings:\s*(\d+)', raw_output, re.IGNORECASE)
            if total:
                count = int(total.group(1))
                status = f"vulnerability_assessment:findings:{count}"
                facts.append({"type": "stage_status", "value": status, "confidence": 90, "session_id": session_id})
                if count > 0:
                    facts.append({"type": "potential_vulnerability", "value": f"killchain_findings:{count}", "confidence": 75, "session_id": session_id})

        if "killchain_exploit" in tool_lower or "exploitation" in raw_lower:
            summary = re.search(r'Exploits attempted:\s*(\d+)\s*\|\s*Succeeded:\s*(\d+)', raw_output, re.IGNORECASE)
            if summary:
                attempted, succeeded = map(int, summary.groups())
                facts.append({
                    "type": "stage_status",
                    "value": f"exploitation:attempted:{attempted}:succeeded:{succeeded}",
                    "confidence": 90,
                    "session_id": session_id,
                })
                if succeeded > 0:
                    facts.append({"type": "exploit_success", "value": "killchain_auto_exploit_success", "confidence": 90, "session_id": session_id})

        credential_required = re.search(
            r'\[\!\]\s*(Privilege escalation|Persistence|Lateral movement|Data exfiltration|Cleanup|Full killchain|C2 beacon deployment|SSH inventory)\s+requires',
            raw_output,
            re.IGNORECASE,
        )
        if credential_required:
            stage_name = re.sub(r'\s+', '_', credential_required.group(1).lower())
            facts.append({"type": "stage_status", "value": f"{stage_name}:blocked_missing_credentials", "confidence": 95, "session_id": session_id})

        # ── enum4linux / SMB ──
        if "enum4linux" in tool_name.lower():
            if "server doesn't allow session" in raw_lower or "nt_status_access_denied" in raw_lower:
                facts.append({"type": "smb_status", "value": "null_session_denied", "confidence": 100, "session_id": session_id})

        # ── Active Directory enumeration / Kerberos / domain credential flow ──
        if ("ad enumeration" in raw_lower or "[ad users]" in raw_lower
                or "[ad groups]" in raw_lower or "[ad computers]" in raw_lower
                or "[group policy objects]" in raw_lower):
            facts.append({"type": "ad_enumeration", "value": "completed", "confidence": 90, "session_id": session_id})

            for label, fact_type in (
                ("users", "ad_users"),
                ("groups", "ad_groups"),
                ("computers", "ad_computers"),
                ("gpos", "ad_gpos"),
            ):
                pattern = rf'\(via\s+[^—\-\n]+\s+[—-]\s+(\d+)\s+{label}\)'
                for m in re.finditer(pattern, raw_output, re.IGNORECASE):
                    facts.append({"type": fact_type, "value": f"count:{m.group(1)}", "confidence": 90, "session_id": session_id})

            for m in re.finditer(r'\b(?:Domain Name|Domain|Workgroup)\s*[:=]\s*([A-Za-z0-9._-]{2,})', raw_output, re.IGNORECASE):
                domain = m.group(1).strip(".")
                if domain.lower() not in {"unknown", "none", "workgroup"}:
                    facts.append({"type": "ad_domain", "value": domain[:120], "confidence": 80, "session_id": session_id})

            if "admincount=1" in raw_lower or "domain admins" in raw_lower or "enterprise admins" in raw_lower:
                facts.append({"type": "ad_high_value_object", "value": "privileged_group_or_admincount_present", "confidence": 85, "session_id": session_id})

            bh_match = re.search(r'BloodHound data collected\s*(?:→|->)\s*(\S+)', raw_output, re.IGNORECASE)
            if bh_match:
                facts.append({"type": "ad_graph_data", "value": bh_match.group(1)[:220], "confidence": 95, "session_id": session_id})

        if "as-rep roast" in raw_lower or "$krb5asrep$" in raw_lower:
            count_match = re.search(r'(\d+)\s+AS-REP hash\(es\) extracted\s*(?:→|->)\s*(\S+)?', raw_output, re.IGNORECASE)
            count = count_match.group(1) if count_match else "present"
            facts.append({"type": "kerberos_hashes", "value": f"asrep_count:{count}", "confidence": 95, "session_id": session_id})
            if count_match and count_match.group(2):
                facts.append({"type": "credential_material", "value": f"asrep_hash_file:{count_match.group(2)}", "confidence": 90, "session_id": session_id})

        if "kerberoast" in raw_lower or "$krb5tgs$" in raw_lower:
            count_match = re.search(r'(\d+)\s+Kerberoast hash\(es\) extracted\s*(?:→|->)\s*(\S+)?', raw_output, re.IGNORECASE)
            count = count_match.group(1) if count_match else "present"
            facts.append({"type": "kerberos_hashes", "value": f"kerberoast_count:{count}", "confidence": 95, "session_id": session_id})
            if count_match and count_match.group(2):
                facts.append({"type": "credential_material", "value": f"kerberoast_hash_file:{count_match.group(2)}", "confidence": 90, "session_id": session_id})

        if "dcsync successful" in raw_lower:
            count_match = re.search(r'DCSync successful\s+[—-]\s+(\d+)\s+hash\(es\) extracted', raw_output, re.IGNORECASE)
            value = f"count:{count_match.group(1)}" if count_match else "completed"
            facts.append({"type": "domain_hash_dump", "value": value, "confidence": 100, "session_id": session_id})

        if "smb authentication successful via pth" in raw_lower or "pass-the-hash" in raw_lower:
            pth_header = re.search(r'\[PASS-THE-HASH\s+[—-]\s*([^\]@]+)@([^\]]+)\]', raw_output, re.IGNORECASE)
            if pth_header and "successful" in raw_lower:
                user, target = pth_header.groups()
                facts.append({"type": "credential", "value": f"pth_auth_success:{user}@{target}", "confidence": 95, "session_id": session_id})
                facts.append({"type": "lateral_access", "value": f"{user}@{target}", "confidence": 90, "session_id": session_id})

        if any(marker in raw_lower for marker in ("psexec successful", "wmiexec successful", "smbexec successful", "winrm successful", "dcom exec successful")):
            header = re.search(r'\[(PSEXEC|WMIEXEC|SMBEXEC|WINRM|DCOM EXEC)\s+[—-]\s*([^\]]+)\]', raw_output, re.IGNORECASE)
            target = header.group(2).strip() if header else "target"
            user_match = re.search(r'User:\s*([^\n]+)', raw_output, re.IGNORECASE)
            user = user_match.group(1).strip().replace("\\", "/") if user_match else "authenticated"
            facts.append({"type": "remote_execution", "value": f"{user}@{target}", "confidence": 95, "session_id": session_id})
            facts.append({"type": "lateral_access", "value": f"{user}@{target}", "confidence": 95, "session_id": session_id})

        if "hash cracker" in raw_lower or "cracking results" in raw_lower:
            crackable = re.search(r'Crackable hashes:\s*(\d+)', raw_output, re.IGNORECASE)
            if crackable:
                facts.append({"type": "hash_material", "value": f"crackable:{crackable.group(1)}", "confidence": 90, "session_id": session_id})
            summary = re.search(r'Total hashes:\s*(\d+).*?Cracked:\s*(\d+)', raw_output, re.IGNORECASE | re.DOTALL)
            if summary:
                total, cracked = summary.groups()
                facts.append({"type": "hash_cracking", "value": f"cracked:{cracked}/{total}", "confidence": 95, "session_id": session_id})
                if int(cracked) > 0:
                    facts.append({"type": "credential", "value": f"cracked_credentials:{cracked}", "confidence": 95, "session_id": session_id})
            for m in re.finditer(r'^\s*\+\s*([^:\s]+):(.+?)\s*$', raw_output, re.MULTILINE):
                user = m.group(1).strip()
                if user:
                    facts.append({"type": "credential", "value": f"cracked_password_for:{user}", "confidence": 95, "session_id": session_id})

        # ── ShardBrowser / browser-rendered web analysis ──
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
                    if not subnet.startswith("127.") and _is_internal_subnet_value(subnet):
                        facts.append({"type": "internal_subnet", "value": subnet, "confidence": 90, "session_id": session_id})

            for m in re.finditer(r'^\s*(?:→|->)\s*((?:\d{1,3}\.){3}\d{1,3})\s*$', raw_output, re.MULTILINE):
                ip = m.group(1)
                if (not ip.startswith(("127.", "0."))
                        and not ip.endswith((".0", ".255"))
                        and ip != "255.255.255.255"
                        and _is_internal_ip_value(ip)):
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
        json_text = raw_strip
        if "--- plugin output ---" in json_text:
            json_text = json_text.split("--- plugin output ---", 1)[0].strip()
        if not json_text.startswith('{') and "{" in json_text:
            json_text = json_text[json_text.find("{"):].strip()

        if json_text.startswith('{') and json_text.endswith('}'):
            try:
                import json
                data = json.loads(json_text)
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
                if "plugin" in data:
                    plugin_name = str(data.get("plugin", "unknown"))
                    status = "success" if data.get("success") else "failed"
                    facts.append({"type": "plugin_result", "value": f"{plugin_name}:{status}", "confidence": 85, "session_id": session_id})
                    for artifact in data.get("artifacts") or []:
                        facts.append({"type": "plugin_artifact", "value": str(artifact), "confidence": 85, "session_id": session_id})
                    for session in data.get("sessions") or []:
                        if isinstance(session, dict):
                            session_type = session.get("type", plugin_name)
                            session_value = session.get("session") or session.get("id") or session.get("target")
                            if session_value:
                                facts.append({"type": "credential", "value": f"{session_type}_session:{session_value}", "confidence": 90, "session_id": session_id})
                    if data.get("success") and plugin_name == "cpanel_auth_bypass":
                        facts.append({"type": "vulnerability", "value": "cpanel_auth_bypass_confirmed", "confidence": 95, "session_id": session_id})
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
            logger.debug(f"Extraction LLM Error: {e}")
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
            "auth failed",
            "connection failed",
            "connection_status",
            "scan_status",
            "skipped",
            "no http(s) response",
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
            if ftype in {
                "tool_name", "error_type", "target_ip", "target_host",
                "target_port", "auth_method", "connection_status",
                "scan_status", "skip_reason", "ssh_attempt",
                "host_targeted", "user_targeted", "user",
            }:
                continue
            if value.lower() in {"failed", "skipped", "unknown", "none"}:
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
        session_id = self._extract_session_id(raw_output)

        facts = []

        # 1. Regex Parser (primary)
        facts.extend(self.regex_parser.parse(tool_name, raw_output, session_id))

        # 2. Structured Parser. Run it even when regex found facts; mixed
        # plugin JSON often contains CVEs that regex sees first, and skipping
        # structured parsing would lose plugin_result/artifacts/sessions.
        facts.extend(self.structured_parser.parse(tool_name, raw_output, session_id))

        # 3. LLM Extractor — ONLY if regex+structured found ZERO facts and there's meaningful output
        if not facts and self._should_try_llm(tool_name, raw_output):
            logger.info(f"Regex found 0 facts for '{tool_name}', trying LLM extractor...")
            llm_facts = self.llm_extractor.parse(tool_name, raw_output, session_id)
            facts.extend(llm_facts)

        return self._sanitize_facts(facts)

    def _extract_session_id(self, raw_output: str) -> str:
        patterns = [
            r'(?im)^\s*session_id\s*[:=]\s*([a-zA-Z0-9_-]+)\s*$',
            r'(?im)^\s*session\s*[:=]\s*([a-zA-Z0-9_-]+)\s*$',
            r'(?im)\bSession created\s*--\s*SL#\s*([a-zA-Z0-9_-]+)\b',
            r'(?im)\bScan ID:\s*([a-zA-Z0-9_-]+)\b',
        ]
        for pattern in patterns:
            match = re.search(pattern, raw_output)
            if match:
                return match.group(1)
        return "none"
