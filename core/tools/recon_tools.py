#!/usr/bin/env python3
"""
Reconnaissance tool wrappers.
Extracted from tools.py.
"""

import os
import logging
import re
import shutil
import socket
import json
import base64
from urllib.parse import urljoin, urlparse

from core.tools.base import (
    run_tool, get_tool_config,
    C_RESET, C_GREEN, C_YELLOW,
)
from core.tools.registry import tool
from core.tools.targeting import (
    as_url as _as_url,
    coerce_port as _coerce_port,
    ensure_url as _ensure_url,
    split_host_port as _split_host_port,
    target_host as _target_host,
    target_looks_domain as _is_probably_domain,
    url_candidates as _url_candidates,
)

# Config helpers
try:
    from config import CFG, find_wordlist
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""

# Scrapling availability
try:
    from scrapling import StealthyFetcher as _StealthyFetcher
    _SCRAPLING_OK = True
except ImportError:
    _StealthyFetcher = None
    _SCRAPLING_OK = False


def _path_or_target(target: str) -> str:
    return (target or ".").strip() or "."


def _config_int(config: dict, key: str, default: int, minimum: int = 0) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _config_csv(config: dict, key: str, default: str) -> str:
    value = config.get(key, default)
    if isinstance(value, (list, tuple, set)):
        value = ",".join(str(item).strip() for item in value if str(item).strip())
    value = str(value or default).strip()
    return value or default


def _load_session_profile(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"headers": {}, "cookies": {}}
    try:
        data = json.loads(open(path, "r", encoding="utf-8", errors="ignore").read())
    except Exception:
        return {"headers": {}, "cookies": {}}
    return {
        "headers": data.get("headers") or {},
        "cookies": data.get("cookies") or {},
    }


def _decode_jwt_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw.decode("utf-8", "ignore"))
    except Exception:
        return {}


@tool(name="nmap", aliases=["nmap_scan"], category="recon", description="Run Nmap with smart caching and two-phase scanning.", requires=["nmap"])
def run_nmap(target: str, extra_flags: list = None) -> str:
    """nmap with config-driven flags and timeout.
    v7.0: Smart Nmap caching and aggressive 2-phase scanning.
    Prevents duplicate '-p-' scans which waste immense time.
    """
    tc = get_tool_config("nmap")
    flags = list(tc.get("default_flags", ["-sV", "-sC", "-T4", "--open", "-Pn", "-sT"]))
    timeout = tc.get("timeout", 300)  # v4.0: fixed from 180 → 300 to match config.yaml

    if extra_flags:
        flags = extra_flags
        # Ensure -Pn and -sT are always present
        if "-Pn" not in flags:
            flags.insert(0, "-Pn")
        if "-sT" not in flags:
            flags.insert(1, "-sT")

    # v7.0: Smart Nmap Cache + Staged execution
    if "-p-" in flags:
        print(f"  {C_YELLOW}[FIX] Full port scan (-p-) intercepted → using Smart Nmap{C_RESET}")
        
        # Check if we already did a big scan on this target in this run
        cache_file = f"/tmp/nmap_smart_{target.replace('/', '_')}.log"
        if os.path.exists(cache_file):
            print(f"  {C_YELLOW}[CACHE] Reusing previous Nmap results for {target}{C_RESET}")
            with open(cache_file, "r") as f:
                return f.read()

        # Phase 1: Top 1000 ports (Fast)
        print(f"  {C_YELLOW}  Phase 1: Top 1000 ports (fast){C_RESET}")
        flags_stage1 = [f for f in flags if f != "-p-"] + ["--top-ports", "1000"]
        result1 = run_tool(["nmap"] + flags_stage1 + [target], timeout=300)

        # Extract open ports from Phase 1 to decide if we need Phase 2
        open_ports_p1 = re.findall(r"(\d+)/tcp\s+open", result1)

        # Phase 2: Aggressive full scan ONLY IF needed, or run the extended fallback
        if len(open_ports_p1) < 5:
            print(f"  {C_YELLOW}  Phase 2: Few ports found, running full -p- scan{C_RESET}")
            # we do a fast full scan without version detection to find obscure ports quickly
            flags_stage2 = ["-p-", "--min-rate", "1000", "-T4", "-Pn", target]
            result2 = run_tool(["nmap"] + flags_stage2, timeout=600)
        else:
            print(f"  {C_YELLOW}  Phase 2: Many common ports found, using targeted extension{C_RESET}")
            extended_ports = "8443,8000,8888,3000,27017,6379,11211,9200,5601,5985,5986,4444,9090,10000"
            flags_stage2 = [f for f in flags if f != "-p-"] + ["-p", extended_ports]
            result2 = run_tool(["nmap"] + flags_stage2 + [target], timeout=300)

        final_output = f"[PHASE 1 — Top 1000 ports]\n{result1}\n\n[PHASE 2 — Deep Scan]\n{result2}"
        
        # Save to cache
        try:
            with open(cache_file, "w") as f:
                f.write(final_output)
        except Exception as _exc:
            logging.debug(f"Suppressed in recon_tools.py: {_exc}")
            
        return final_output

    print(f"  [*] nmap {' '.join(flags)} {target}")
    return run_tool(["nmap"] + flags + [target], timeout=timeout)


@tool(name="whois", aliases=[], category="recon", description="Run whois against target.", requires=["whois"])
def run_whois(target: str) -> str:
    """whois"""
    tc = get_tool_config("whois")
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=tc.get("timeout", 30))


@tool(name="whatweb", aliases=[], category="recon", description="Run whatweb with configurable aggression.", requires=["whatweb"])
def run_whatweb(target: str) -> str:
    """whatweb with configurable aggression."""
    tc = get_tool_config("whatweb")
    aggr = str(tc.get("aggression", 3))
    print(f"  [*] whatweb -a {aggr} {target}")
    return run_tool(["whatweb", "-a", aggr, target], timeout=tc.get("timeout", 90))


@tool(name="curl_headers", aliases=["curl"], category="recon", description="Run curl -sI for HTTP(S) headers.", requires=["curl"])
def run_curl_headers(target: str) -> str:
    """curl -sI http and https"""
    tc = get_tool_config("curl")
    timeout = tc.get("timeout", 20)
    print(f"  [*] curl -sI {target}")
    parts = []
    for url in _url_candidates(target):
        curl_cmd = ["curl", "-sI", "--max-time", "10", "--location"]
        if url.startswith("https://"):
            curl_cmd.append("-k")
        output = run_tool(curl_cmd + [url], timeout=timeout)
        parts.append(f"[Headers: {url}]\n{output}")
    return "\n\n".join(parts)


@tool(name="dig", aliases=[], category="recon", description="Run dig for DNS records.", requires=["dig"])
def run_dig(target: str) -> str:
    """dig with configurable record types."""
    tc = get_tool_config("dig")
    timeout = tc.get("timeout", 15)
    record_types = tc.get("record_types", ["A", "MX", "NS", "TXT"])
    print(f"  [*] dig {target} {', '.join(record_types)}")

    parts = []
    for rtype in record_types:
        result = run_tool(["dig", "+short", rtype, target], timeout=timeout)
        parts.append(f"[{rtype} Records]\n{result}")

    return "\n\n".join(parts)


@tool(name="subfinder", aliases=["subdomain_discovery"], category="recon", description="Passive subdomain discovery with subfinder.", requires=["subfinder"])
def run_subfinder(target: str) -> str:
    domain = _target_host(target)
    if not _is_probably_domain(domain):
        return f"[ASM] subfinder skipped: target is not a domain: {target}"
    print(f"  [*] subfinder -silent -d {domain}")
    output = run_tool(["subfinder", "-silent", "-d", domain], timeout=180)
    return f"[ASM SUBFINDER - {domain}]\n{output}"


@tool(name="amass_enum", aliases=["amass", "amass_passive"], category="recon", description="Passive subdomain discovery with amass.", requires=["amass"])
def run_amass_enum(target: str) -> str:
    domain = _target_host(target)
    if not _is_probably_domain(domain):
        return f"[ASM] amass skipped: target is not a domain: {target}"
    print(f"  [*] amass enum -passive -d {domain}")
    output = run_tool(["amass", "enum", "-passive", "-d", domain], timeout=300)
    return f"[ASM AMASS - {domain}]\n{output}"


@tool(name="dnsx", aliases=["dns_resolve"], category="recon", description="Resolve domains/subdomains with dnsx.", requires=["dnsx"])
def run_dnsx(target: str) -> str:
    host = _target_host(target)
    print(f"  [*] dnsx -silent -a -aaaa -cname -resp-only {host}")
    output = run_tool(["dnsx", "-silent", "-a", "-aaaa", "-cname", "-resp-only", "-d", host], timeout=120)
    return f"[ASM DNSX - {host}]\n{output}"


@tool(name="httpx_probe", aliases=["httpx", "http_probe"], category="recon", description="HTTP service probing with projectdiscovery httpx.", requires=["httpx"])
def run_httpx_probe(target: str) -> str:
    host = _target_host(target)
    print(f"  [*] httpx -silent -title -tech-detect -status-code {host}")
    output = run_tool([
        "httpx", "-silent", "-title", "-tech-detect", "-status-code",
        "-follow-redirects", "-u", host,
    ], timeout=180)
    return f"[ASM HTTPX - {host}]\n{output}"


@tool(name="naabu", aliases=["port_discovery"], category="recon", description="Fast safe TCP port discovery with naabu.", requires=["naabu"])
def run_naabu(target: str) -> str:
    host = _target_host(target)
    print(f"  [*] naabu -silent -host {host} -top-ports 1000")
    output = run_tool(["naabu", "-silent", "-host", host, "-top-ports", "1000"], timeout=180)
    return f"[ASM NAABU - {host}]\n{output}"


@tool(name="tlsx", aliases=["tls_probe"], category="recon", description="TLS certificate/metadata discovery with tlsx.", requires=["tlsx"])
def run_tlsx(target: str) -> str:
    host = _target_host(target)
    print(f"  [*] tlsx -silent -san -cn -tls-probe {host}")
    output = run_tool(["tlsx", "-silent", "-san", "-cn", "-tls-probe", "-u", host], timeout=120)
    return f"[ASM TLSX - {host}]\n{output}"


@tool(name="wayback_urls", aliases=["wayback"], category="recon", description="Historical URL discovery with waybackurls.", requires=["waybackurls"])
def run_wayback_urls(target: str) -> str:
    domain = _target_host(target)
    print(f"  [*] waybackurls {domain}")
    output = run_tool(["waybackurls", domain], timeout=180)
    return f"[ASM WAYBACK - {domain}]\n{output}"


@tool(name="gau_urls", aliases=["gau"], category="recon", description="Historical URL discovery with gau.", requires=["gau"])
def run_gau_urls(target: str) -> str:
    domain = _target_host(target)
    print(f"  [*] gau --subs {domain}")
    output = run_tool(["gau", "--subs", domain], timeout=180)
    return f"[ASM GAU - {domain}]\n{output}"


@tool(name="nuclei_safe", aliases=["nuclei"], category="recon", description="Safe nuclei template verification.", requires=["nuclei"])
def run_nuclei_safe(target: str) -> str:
    scan_target = _as_url(target)
    tc = get_tool_config("nuclei")
    wall_timeout = _config_int(tc, "timeout", 1200, minimum=0)
    request_timeout = _config_int(tc, "request_timeout", 20, minimum=1)
    retries = _config_int(tc, "retries", 2, minimum=0)
    severity = _config_csv(tc, "severity", "info,low,medium,high,critical")
    exclude_tags = _config_csv(tc, "exclude_tags", "dos,fuzz,bruteforce,intrusive,destructive")
    print(
        "  [*] nuclei -silent -jsonl "
        f"-timeout {request_timeout} -retries {retries} "
        f"-severity {severity} -target {scan_target} "
        f"(wall={wall_timeout or 'unlimited'}s)"
    )
    output = run_tool([
        "nuclei", "-silent", "-jsonl", "-target", scan_target,
        "-severity", severity,
        "-exclude-tags", exclude_tags,
        "-timeout", str(request_timeout),
        "-retries", str(retries),
    ], timeout=wall_timeout)
    if str(output).strip() == "[!] nuclei returned no output.":
        output = "No nuclei findings detected."
    completed = ""
    if "timed out after" not in str(output).lower() and "killed after" not in str(output).lower():
        completed = f"\n[NUCLEI COMPLETE - {scan_target}]"
    return f"[NUCLEI SAFE - {scan_target}]\n{output}{completed}"


@tool(name="katana_crawl", aliases=["katana"], category="recon", description="Passive web crawl and JS route discovery with katana.", requires=["katana"])
def run_katana_crawl(target: str) -> str:
    scan_target = _as_url(target)
    print(f"  [*] katana -silent -js-crawl -known-files all -u {scan_target}")
    output = run_tool(["katana", "-silent", "-js-crawl", "-known-files", "all", "-u", scan_target], timeout=240)
    return f"[KATANA CRAWL - {scan_target}]\n{output}"


@tool(name="openapi_import", aliases=["swagger_import", "openapi"], category="recon", description="Import OpenAPI/Swagger spec and build endpoint map.")
def run_openapi_import(target: str) -> str:
    """Read a local or URL OpenAPI document. URL fetch is read-only."""
    source = (target or "").strip()
    if not source:
        return "[API] OpenAPI import skipped: missing source"
    try:
        if source.startswith(("http://", "https://")):
            import requests
            resp = requests.get(source, timeout=20, verify=False)
            body = resp.text
        else:
            with open(source, "r", encoding="utf-8", errors="ignore") as fh:
                body = fh.read()
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            import yaml
            data = yaml.safe_load(body)
    except Exception as exc:
        return f"[API] OpenAPI import failed: {str(exc)[:180]}"

    paths = data.get("paths") or {}
    lines = [f"[OPENAPI IMPORT - {source}]", f"Title: {data.get('info', {}).get('title', '')}", f"Endpoints: {len(paths)}"]
    for path, methods in list(paths.items())[:300]:
        if isinstance(methods, dict):
            for method in sorted(methods):
                if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    auth = bool((methods.get(method) or {}).get("security") or data.get("security"))
                    lines.append(f"{method.upper()} {path} auth={'required' if auth else 'unknown_or_none'}")
    return "\n".join(lines)


@tool(name="graphql_check", aliases=["graphql_introspection"], category="recon", description="GraphQL endpoint presence/introspection safety check.", requires=["curl"])
def run_graphql_check(target: str) -> str:
    url = _as_url(target).rstrip("/")
    if not url.endswith("/graphql"):
        url = url + "/graphql"
    query = '{"query":"query { __schema { queryType { name } } }"}'
    print(f"  [*] GraphQL introspection check {url}")
    output = run_tool([
        "curl", "-sk", "--max-time", "15", "-H", "Content-Type: application/json",
        "-d", query, url,
    ], timeout=30)
    return f"[GRAPHQL CHECK - {url}]\n{output}"


@tool(name="session_profile_import", aliases=["session_import"], category="recon", description="Import authenticated web session headers/cookies from a local JSON profile.")
def run_session_profile_import(target: str) -> str:
    path = _path_or_target(target)
    profile = _load_session_profile(path)
    headers = profile.get("headers") or {}
    cookies = profile.get("cookies") or {}
    lines = [f"[SESSION PROFILE IMPORT - {path}]", f"Headers: {len(headers)}", f"Cookies: {len(cookies)}"]
    for name in sorted(headers)[:50]:
        lines.append(f"HEADER {name}")
    for name in sorted(cookies)[:50]:
        lines.append(f"COOKIE {name}")
    return "\n".join(lines)


@tool(name="authenticated_crawl", aliases=["auth_crawl"], category="recon", description="Authenticated read-only crawl using a local session profile.", requires=["python:requests"])
def run_authenticated_crawl(target: str, session_profile: str = "") -> str:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = _as_url(target)
    profile = _load_session_profile(session_profile)
    headers = profile.get("headers") or {}
    cookies = profile.get("cookies") or {}
    lines = [f"[AUTHENTICATED CRAWL - {url}]", f"Session profile: {session_profile or 'none'}"]
    try:
        resp = requests.get(url, headers=headers, cookies=cookies, timeout=20, verify=False, allow_redirects=True)
        lines.append(f"Status: {resp.status_code}")
        lines.append(f"Final URL: {resp.url}")
        body = resp.text[:500000]
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title:
            title_text = re.sub(r"\s+", " ", title.group(1)).strip()[:180]
            lines.append(f"Title: {title_text}")
        links = sorted(set(re.findall(r'''href=["']([^"']+)["']''', body, re.IGNORECASE)))[:300]
        forms = re.findall(r"<form\b", body, re.IGNORECASE)
        csrf = re.search(r'(?i)(csrf|xsrf|_token|nonce)', body) is not None
        lines.append(f"Forms: {len(forms)}")
        lines.append(f"CSRF token observed: {'yes' if csrf else 'no'}")
        for link in links:
            lines.append(f"LINK {urljoin(resp.url, link)}")
    except Exception as exc:
        lines.append(f"[!] Authenticated crawl failed: {str(exc)[:180]}")
    return "\n".join(lines)


@tool(name="api_auth_check", aliases=["missing_auth_check"], category="recon", description="Read-only API missing-auth probe with GET/HEAD only.", requires=["python:requests"])
def run_api_auth_check(target: str, session_profile: str = "") -> str:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = _as_url(target)
    profile = _load_session_profile(session_profile)
    lines = [f"[API AUTH CHECK - {url}]", f"Session profile: {session_profile or 'none'}"]
    try:
        anon = requests.get(url, timeout=15, verify=False, allow_redirects=False)
        lines.append(f"Anonymous status: {anon.status_code}")
        if profile.get("headers") or profile.get("cookies"):
            auth = requests.get(
                url,
                headers=profile.get("headers") or {},
                cookies=profile.get("cookies") or {},
                timeout=15,
                verify=False,
                allow_redirects=False,
            )
            lines.append(f"Authenticated status: {auth.status_code}")
            if anon.status_code < 400 and auth.status_code < 400:
                lines.append("NOTE possible_missing_auth")
            elif anon.status_code in {401, 403} and auth.status_code < 400:
                lines.append("NOTE auth_required")
        elif anon.status_code < 400:
            lines.append("NOTE anonymous_accessible")
    except Exception as exc:
        lines.append(f"[!] API auth check failed: {str(exc)[:180]}")
    return "\n".join(lines)


@tool(name="gitleaks_scan", aliases=["gitleaks"], category="recon", description="Secret scanning with gitleaks.", requires=["gitleaks"])
def run_gitleaks_scan(target: str = ".") -> str:
    path = _path_or_target(target)
    print(f"  [*] gitleaks detect --no-git --redact --source {path}")
    output = run_tool(["gitleaks", "detect", "--no-git", "--redact", "--source", path], timeout=240)
    return f"[GITLEAKS SCAN - {path}]\n{output}"


@tool(name="trufflehog_scan", aliases=["trufflehog"], category="recon", description="Secret scanning with TruffleHog.", requires=["trufflehog"])
def run_trufflehog_scan(target: str = ".") -> str:
    path = _path_or_target(target)
    print(f"  [*] trufflehog filesystem --json --no-update {path}")
    output = run_tool(["trufflehog", "filesystem", "--json", "--no-update", path], timeout=300)
    return f"[TRUFFLEHOG SCAN - {path}]\n{output}"


@tool(name="semgrep_scan", aliases=["semgrep"], category="recon", description="Static analysis with Semgrep.", requires=["semgrep"])
def run_semgrep_scan(target: str = ".") -> str:
    path = _path_or_target(target)
    print(f"  [*] semgrep scan --json --config auto {path}")
    output = run_tool(["semgrep", "scan", "--json", "--config", "auto", path], timeout=300)
    return f"[SEMGREP SCAN - {path}]\n{output}"


@tool(name="trivy_scan", aliases=["trivy"], category="recon", description="Filesystem/IaC/dependency scanning with Trivy.", requires=["trivy"])
def run_trivy_scan(target: str = ".") -> str:
    path = _path_or_target(target)
    print(f"  [*] trivy fs --format json --scanners vuln,secret,misconfig {path}")
    output = run_tool(["trivy", "fs", "--format", "json", "--scanners", "vuln,secret,misconfig", path], timeout=420)
    return f"[TRIVY SCAN - {path}]\n{output}"


@tool(name="checkov_scan", aliases=["checkov"], category="recon", description="IaC/cloud misconfiguration scanning with Checkov.", requires=["checkov"])
def run_checkov_scan(target: str = ".") -> str:
    path = _path_or_target(target)
    print(f"  [*] checkov -d {path} -o json")
    output = run_tool(["checkov", "-d", path, "-o", "json"], timeout=300)
    return f"[CHECKOV SCAN - {path}]\n{output}"


@tool(name="prowler_scan", aliases=["prowler"], category="recon", description="Cloud security posture review with Prowler.", requires=["prowler"])
def run_prowler_scan(target: str = "aws") -> str:
    provider = (target or "aws").strip().lower()
    if provider not in {"aws", "azure", "gcp", "kubernetes", "m365"}:
        return f"[CLOUD] Prowler skipped: unsupported provider '{provider}'"
    print(f"  [*] prowler {provider} --output-formats json")
    output = run_tool(["prowler", provider, "--output-formats", "json"], timeout=900)
    return f"[PROWLER SCAN - {provider}]\n{output}"


@tool(name="scoutsuite_scan", aliases=["scoutsuite"], category="recon", description="Cloud security posture review with ScoutSuite.", requires=["scout"])
def run_scoutsuite_scan(target: str = "aws") -> str:
    provider = (target or "aws").strip().lower()
    if provider not in {"aws", "azure", "gcp"}:
        return f"[CLOUD] ScoutSuite skipped: unsupported provider '{provider}'"
    print(f"  [*] scout {provider} --no-browser --report-dir /tmp/octopus_scoutsuite")
    output = run_tool(["scout", provider, "--no-browser", "--report-dir", "/tmp/octopus_scoutsuite"], timeout=900)
    return f"[SCOUTSUITE SCAN - {provider}]\n{output}"


@tool(name="sslscan", aliases=[], category="recon", description="Run sslscan to check for TLS/SSL vulnerabilities.", requires=["sslscan"])
def run_sslscan(target: str) -> str:
    """sslscan to check for TLS/SSL vulnerabilities"""
    tc = get_tool_config("sslscan")
    flags = tc.get("flags", ["--no-colour"])
    print(f"  [*] sslscan {target}")
    return run_tool(["sslscan"] + flags + [target], timeout=tc.get("timeout", 120))


@tool(
    name="ftp_anonymous_check",
    aliases=["ftp_anon", "ftp_anonymous"],
    category="recon",
    description="Check whether FTP allows anonymous login and list a small sample.",
)
def run_ftp_anonymous_check(target: str, port: int = 21) -> str:
    """Single anonymous FTP login probe. No brute force."""
    import ftplib

    port = _coerce_port(port, 21)
    host, parsed_port = _split_host_port(target, port)
    port = parsed_port or port
    print(f"  [*] FTP anonymous check {host}:{port}")

    output = [f"[FTP Anonymous Check - {host}:{port}]"]
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=8)
        banner = (ftp.getwelcome() or "").strip()
        if banner:
            output.append(f"Banner: {banner[:180]}")
        ftp.login("anonymous", "anonymous@")
        output.append("Anonymous login: allowed")
        try:
            entries = ftp.nlst()[:20]
            output.append(f"Entries ({len(entries)}):")
            for entry in entries:
                output.append(f"  {entry[:160]}")
        except Exception as exc:
            output.append(f"Directory listing: unavailable ({str(exc)[:120]})")
        return "\n".join(output)
    except ftplib.error_perm as exc:
        output.append("Anonymous login: denied")
        output.append(f"Reason: {str(exc)[:180]}")
        return "\n".join(output)
    except (OSError, socket.timeout) as exc:
        output.append(f"[!] FTP probe failed: {str(exc)[:180]}")
        return "\n".join(output)
    except Exception as exc:
        output.append(f"[!] FTP probe failed: {str(exc)[:180]}")
        return "\n".join(output)
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception as _exc:
                logging.debug("Suppressed FTP close error: %s", _exc)


@tool(
    name="smtp_probe",
    aliases=["smtp_banner"],
    category="recon",
    description="Collect SMTP banner and EHLO capabilities without sending mail.",
)
def run_smtp_probe(target: str, port: int = 25) -> str:
    """Read-only SMTP capability probe. Does not test relay or send messages."""
    import smtplib

    port = _coerce_port(port, 25)
    host, parsed_port = _split_host_port(target, port)
    port = parsed_port or port
    print(f"  [*] SMTP probe {host}:{port}")

    output = [f"[SMTP Probe - {host}:{port}]"]
    smtp = None
    try:
        if int(port) == 465:
            smtp = smtplib.SMTP_SSL(timeout=10)
            banner = smtp.connect(host, port)
        else:
            smtp = smtplib.SMTP(timeout=10)
            banner = smtp.connect(host, port)
        output.append(f"Banner: {banner[0]} {str(banner[1])[:180]}")

        ehlo_code, ehlo_msg = smtp.ehlo("octopus.local")
        output.append(f"EHLO code: {ehlo_code}")
        ehlo_text = ehlo_msg.decode(errors="ignore") if isinstance(ehlo_msg, bytes) else str(ehlo_msg)
        if ehlo_text:
            output.append(f"EHLO message: {ehlo_text[:300]}")

        features = getattr(smtp, "esmtp_features", {}) or {}
        output.append(f"STARTTLS: {'supported' if smtp.has_extn('starttls') else 'not_supported'}")
        auth = features.get("auth", "")
        if auth:
            output.append(f"AUTH mechanisms: {str(auth).upper()}")
        if features:
            output.append("Capabilities:")
            for key, value in sorted(features.items())[:20]:
                rendered = f"{key}={value}" if value else str(key)
                output.append(f"  {rendered[:160]}")
        output.append("Open relay test: not_performed")
        return "\n".join(output)
    except (OSError, socket.timeout, smtplib.SMTPException) as exc:
        output.append(f"[!] SMTP probe failed: {str(exc)[:180]}")
        return "\n".join(output)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception as _exc:
                    logging.debug("Suppressed SMTP close error: %s", _exc)


@tool(name="ffuf", aliases=["dirb", "dirbuster", "dirb_fuzz"], category="recon", description="Run ffuf for fast directory discovery.", requires=["ffuf"])
def run_ffuf(target: str) -> str:
    """ffuf for fast directory discovery using config-driven wordlists."""
    print(f"  [*] ffuf {target}")
    if not shutil.which("ffuf"):
        return "[!] ffuf is not installed. AI: do NOT attempt dirb_fuzz anymore! Fall back to curl or finding logic bugs."

    tc = get_tool_config("ffuf")
    threads = str(tc.get("threads", 50))
    match_codes = tc.get("match_codes", "200,204,301,302,307,401,403")
    timeout = tc.get("timeout", 120)
    maxtime = str(tc.get("maxtime", min(timeout, 60)))
    request_timeout = str(tc.get("request_timeout", 5))

    base_url = _ensure_url(target)
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        reachable = ""
        for candidate in _url_candidates(target):
            try:
                requests.get(candidate, timeout=(3, 5), verify=False, allow_redirects=True)
                reachable = candidate
                break
            except requests.RequestException:
                continue
        if not reachable:
            return "[!] ffuf skipped: no HTTP(S) response during preflight."
        base_url = reachable
    except Exception as _exc:
        logging.debug(f"Suppressed in recon_tools.py: {_exc}")

    # Find first available web directory wordlist from config
    wordlist = find_wordlist("web_dirs")
    if not wordlist:
        return "[!] No common web wordlists found on system. Add paths to config.yaml → wordlists → web_dirs."

    print(f"  [*] Using wordlist: {os.path.basename(wordlist)}")
    return run_tool([
        "ffuf", "-w", wordlist, "-u", f"{base_url}/FUZZ",
        "-t", threads, "-mc", match_codes, "-c",
        "-timeout", request_timeout, "-maxtime", maxtime,
    ], timeout=timeout)


@tool(name="enum4linux", aliases=[], category="recon", description="Run enum4linux for SMB and Windows enumeration.", requires=["enum4linux"])
def run_enum4linux(target: str) -> str:
    """enum4linux for SMB and Windows enumeration"""
    tc = get_tool_config("enum4linux")
    flags = tc.get("flags", ["-a"])
    print(f"  [*] enum4linux {' '.join(flags)} {target}")
    return run_tool(["enum4linux"] + flags + [target], timeout=tc.get("timeout", 150))


@tool(name="smbclient", aliases=[], category="recon", description="Run smbclient -L to list shares anonymously.", requires=["smbclient"])
def run_smbclient(target: str) -> str:
    """smbclient -L to list shares anonymously"""
    tc = get_tool_config("smbclient")
    flags = tc.get("flags", ["-N"])
    print(f"  [*] smbclient -L {target} {' '.join(flags)}")
    return run_tool(["smbclient", "-L", target] + flags, timeout=tc.get("timeout", 45))


@tool(name="wpscan", aliases=[], category="recon", description="Run wpscan for wordpress targets.", requires=["wpscan"])
def run_wpscan(target: str) -> str:
    """wpscan for wordpress targets"""
    tc = get_tool_config("wpscan")
    flags = tc.get("flags", ["--no-update", "--random-user-agent"])
    url = _ensure_url(target)
    print(f"  [*] wpscan --url {url}")
    return run_tool(["wpscan", "--url", url] + flags, timeout=tc.get("timeout", 180))


@tool(name="sqlmap", aliases=[], category="recon", description="Run sqlmap basic crawl detection.", requires=["sqlmap"])
def run_sqlmap(target: str) -> str:
    """sqlmap basic crawl detection with configurable level/risk."""
    tc = get_tool_config("sqlmap")
    level = str(tc.get("level", 1))
    risk = str(tc.get("risk", 1))
    flags = tc.get("flags", ["--batch", "--crawl=1"])
    url = _ensure_url(target)
    print(f"  [*] sqlmap -u {url} --level={level} --risk={risk}")
    return run_tool(
        ["sqlmap", "-u", url] + flags + [f"--level={level}", f"--risk={risk}"],
        timeout=tc.get("timeout", 180)
    )


@tool(name="nikto", aliases=["nikto_scan"], category="recon", description="Run nikto -h.", requires=["nikto"])
def run_nikto(target: str) -> str:
    """nikto -h"""
    tc = get_tool_config("nikto")
    flags = tc.get("flags", ["-nointeractive"])
    scan_target = _ensure_url(target)
    wall_timeout = tc.get("timeout", 300)
    print(f"  [*] nikto -h {scan_target}  (wall={wall_timeout}s)")
    output = run_tool(["nikto", "-h", scan_target] + flags, timeout=wall_timeout)
    completed = ""
    if "timed out after" not in str(output).lower() and "killed after" not in str(output).lower():
        completed = f"\n[NIKTO COMPLETE - {scan_target}]"
    return f"[NIKTO - {scan_target}]\n{output}{completed}"


@tool(name="security_headers_check", aliases=["security_headers"], category="recon", description="Read-only HTTP security headers and cookie review.", requires=["curl"])
def run_security_headers_check(target: str) -> str:
    url = _as_url(target)
    print(f"  [*] Security headers check {url}")
    output = run_tool(["curl", "-skI", "--max-time", "15", "--location", url], timeout=30)
    return f"[SECURITY HEADERS - {url}]\n{output}"


@tool(name="cors_check", aliases=["cors"], category="recon", description="Read-only CORS preflight check.", requires=["curl"])
def run_cors_check(target: str) -> str:
    url = _as_url(target)
    origin = "https://octopus.invalid"
    print(f"  [*] CORS check {url}")
    output = run_tool([
        "curl", "-skI", "--max-time", "15", "-X", "OPTIONS",
        "-H", f"Origin: {origin}",
        "-H", "Access-Control-Request-Method: GET",
        url,
    ], timeout=30)
    return f"[CORS CHECK - {url}]\nOrigin: {origin}\n{output}"


@tool(name="jwt_analyze", aliases=["jwt"], category="recon", description="Decode JWT header/payload without verifying or brute forcing.")
def run_jwt_analyze(target: str) -> str:
    token = (target or "").strip()
    if os.path.exists(token):
        try:
            token = open(token, "r", encoding="utf-8", errors="ignore").read().strip()
        except Exception as exc:
            return f"[JWT ANALYZE] failed to read token file: {str(exc)[:180]}"
    match = re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', token)
    if not match:
        return "[JWT ANALYZE] no JWT token found"
    jwt_value = match.group(0)
    header_b64, payload_b64, _sig = jwt_value.split(".", 2)
    header = _decode_jwt_segment(header_b64)
    payload = _decode_jwt_segment(payload_b64)
    return "\n".join([
        "[JWT ANALYZE]",
        f"alg: {header.get('alg', '')}",
        f"typ: {header.get('typ', '')}",
        f"kid: {header.get('kid', '')}",
        f"claims: {', '.join(sorted(str(k) for k in payload.keys()))}",
        f"issuer: {payload.get('iss', '')}",
        f"audience: {payload.get('aud', '')}",
        f"expires: {payload.get('exp', '')}",
    ])


@tool(name="js_route_extract", aliases=["js_routes"], category="recon", description="Fetch JavaScript and extract likely client-side/API routes.", requires=["curl"])
def run_js_route_extract(target: str) -> str:
    url = _as_url(target)
    print(f"  [*] JS route extraction {url}")
    body = run_tool(["curl", "-skL", "--max-time", "20", url], timeout=35)
    routes = sorted(set(re.findall(
        r'["\']((?:/[A-Za-z0-9_./{}:-]+|https?://[^"\'\s]+)(?:\?[^"\'\s]*)?)["\']',
        body,
    )))
    lines = [f"[JS ROUTE EXTRACT - {url}]", f"Routes: {len(routes)}"]
    for route in routes[:300]:
        lines.append(route[:300])
    return "\n".join(lines)


@tool(name="burp_import", aliases=["burp"], category="recon", description="Import Burp Suite XML/JSON export into normalized facts.")
def run_burp_import(target: str) -> str:
    path = _path_or_target(target)
    if not os.path.exists(path):
        return f"[BURP IMPORT] file not found: {path}"
    try:
        data = open(path, "r", encoding="utf-8", errors="ignore").read()
    except Exception as exc:
        return f"[BURP IMPORT] failed: {str(exc)[:180]}"
    urls = re.findall(r'<url><!\[CDATA\[(.*?)\]\]></url>|"url"\s*:\s*"([^"]+)"', data, re.IGNORECASE)
    issues = re.findall(r'<name><!\[CDATA\[(.*?)\]\]></name>|"name"\s*:\s*"([^"]+)"', data, re.IGNORECASE)
    lines = [f"[BURP IMPORT - {path}]", f"URLs: {len(urls)}", f"Issues: {len(issues)}"]
    for pair in urls[:500]:
        url = next((p for p in pair if p), "")
        if url:
            lines.append(f"URL {url}")
    for pair in issues[:500]:
        issue = next((p for p in pair if p), "")
        if issue:
            lines.append(f"ISSUE {issue}")
    return "\n".join(lines)


@tool(name="zap_import", aliases=["zap"], category="recon", description="Import OWASP ZAP JSON/XML report into normalized facts.")
def run_zap_import(target: str) -> str:
    path = _path_or_target(target)
    if not os.path.exists(path):
        return f"[ZAP IMPORT] file not found: {path}"
    try:
        data = open(path, "r", encoding="utf-8", errors="ignore").read()
    except Exception as exc:
        return f"[ZAP IMPORT] failed: {str(exc)[:180]}"
    urls = re.findall(r'"uri"\s*:\s*"([^"]+)"|<uri>(.*?)</uri>', data, re.IGNORECASE)
    alerts = re.findall(r'"alert"\s*:\s*"([^"]+)"|<alert>(.*?)</alert>', data, re.IGNORECASE)
    risks = re.findall(r'"riskdesc"\s*:\s*"([^"]+)"|<riskdesc>(.*?)</riskdesc>', data, re.IGNORECASE)
    lines = [f"[ZAP IMPORT - {path}]", f"URLs: {len(urls)}", f"Alerts: {len(alerts)}"]
    for pair in urls[:500]:
        url = next((p for p in pair if p), "")
        if url:
            lines.append(f"URL {url}")
    for idx, pair in enumerate(alerts[:500]):
        alert = next((p for p in pair if p), "")
        risk = ""
        if idx < len(risks):
            risk = next((p for p in risks[idx] if p), "")
        if alert:
            lines.append(f"ALERT {risk} {alert}".strip())
    return "\n".join(lines)


# ─────────────────────────────────────────────
# SCRAPLING INTEGRATION (NEW v3.0)
# ─────────────────────────────────────────────

@tool(name="scrapling", aliases=["scrapling_fetch"], category="recon", description="Fetch a URL using scrapling's StealthyFetcher.")
def run_scrapling_fetch(url: str) -> str:
    """
    Fetch a URL using scrapling's StealthyFetcher for JS-rendered pages and anti-bot bypass.
    v3.1: Falls back to requests+BeautifulSoup (NOT raw curl) to preserve form/link extraction.
    """
    # Ensure URL has protocol
    if not url.startswith("http"):
        url = f"http://{url}"

    print(f"  [*] Scrapling (StealthyFetcher): {url}")

    def _extract_page_data(page_obj=None, html_str=None, status_code=200, source="scrapling"):
        """Unified extraction logic for both scrapling and BS4 fallback."""
        title = ""
        text = ""
        links = []
        forms = []
        meta_info = []

        if page_obj is not None:
            # Scrapling page object
            title_el = page_obj.css_first("title")
            if title_el:
                title = title_el.text()
            body = page_obj.css_first("body")
            text = body.text(separator="\n", strip=True) if body else page_obj.text()
            for a in page_obj.css("a[href]"):
                href = a.attributes.get("href", "")
                link_text = a.text(strip=True)[:50]
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    links.append(f"  {link_text} → {href}")
            for form in page_obj.css("form"):
                action = form.attributes.get("action", "")
                method = form.attributes.get("method", "GET").upper()
                inputs = []
                for inp in form.css("input"):
                    inp_name = inp.attributes.get("name", "")
                    inp_type = inp.attributes.get("type", "text")
                    if inp_name:
                        inputs.append(f"{inp_name}({inp_type})")
                forms.append(f"  {method} {action} → fields: {', '.join(inputs)}")
            for meta in page_obj.css("meta"):
                name = meta.attributes.get("name", meta.attributes.get("property", ""))
                content = meta.attributes.get("content", "")
                if name and content:
                    meta_info.append(f"  {name}: {content[:100]}")

        elif html_str is not None:
            # BeautifulSoup fallback
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_str, "html.parser")
            title_el = soup.find("title")
            if title_el:
                title = title_el.get_text(strip=True)
            body = soup.find("body")
            if body:
                for tag in body(["script", "style", "nav", "aside"]):
                    tag.decompose()
                text = body.get_text(separator="\n", strip=True)
            else:
                text = soup.get_text(separator="\n", strip=True)
            for a in soup.find_all("a", href=True):
                href = a["href"]
                link_text = a.get_text(strip=True)[:50]
                if href and not href.startswith("#") and not href.startswith("javascript:"):
                    links.append(f"  {link_text} → {href}")
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    inp_name = inp.get("name", "")
                    inp_type = inp.get("type", "text")
                    if inp_name:
                        inputs.append(f"{inp_name}({inp_type})")
                forms.append(f"  {method} {action} → fields: {', '.join(inputs)}")
            for meta in soup.find_all("meta"):
                name = meta.get("name", meta.get("property", ""))
                content = meta.get("content", "")
                if name and content:
                    meta_info.append(f"  {name}: {content[:100]}")

        output = f"[{source.upper()} RESULT — {url}]\n"
        output += f"Status: {status_code}\n"
        if title:
            output += f"Title: {title}\n"
        if meta_info:
            output += f"\nMeta Info ({len(meta_info)}):\n" + "\n".join(meta_info[:10]) + "\n"
        if forms:
            output += f"\nForms ({len(forms)}):\n" + "\n".join(forms[:10]) + "\n"
            output += f"\nAI: Login forms detected! Try [TOOL: bruteforce http-post-form {url.split('//')[1].split('/')[0]}]\n"
        if links:
            output += f"\nLinks ({len(links)}):\n" + "\n".join(links[:30]) + "\n"
        if text:
            output += f"\nPage Text (first 3000 chars):\n{text[:3000]}\n"
        return output

    # Try scrapling first
    if _SCRAPLING_OK:
        try:
            fetcher = _StealthyFetcher()
            page = fetcher.fetch(url)
            if page.status == 200:
                return _extract_page_data(page_obj=page, status_code=page.status)
            else:
                return f"[!] Scrapling: HTTP {page.status} from {url}"
        except Exception as e:
            print(f"  {C_YELLOW}[!] Scrapling failed: {str(e)[:100]}, using requests+BS4 fallback{C_RESET}")

    # Fallback: requests + BeautifulSoup with RETRY (preserves forms/links — NOT raw curl)
    print(f"  {C_YELLOW}[!] Using requests+BeautifulSoup fallback (forms+links preserved){C_RESET}")
    import requests as _req
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = _req.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    try:
        resp = session.get(url, timeout=(5, 15), verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"})
        return _extract_page_data(html_str=resp.text, status_code=resp.status_code, source="requests+bs4")
    except Exception as e:
        print(f"  {C_YELLOW}[!] Requests fallback failed: {str(e)[:80]}{C_RESET}")
        # v4.0: Try alternate ports if main URL fails
        base_host = url.split("//")[-1].split("/")[0].split(":")[0]
        alt_ports = [8080, 8443, 443, 1443, 3000, 9090]
        for alt_port in alt_ports:
            alt_url = f"http://{base_host}:{alt_port}"
            if alt_url == url:
                continue
            try:
                resp = session.get(alt_url, timeout=(3, 10), verify=False,
                                  headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    print(f"  {C_GREEN}[+] Alt port {alt_port} responded!{C_RESET}")
                    return _extract_page_data(html_str=resp.text, status_code=resp.status_code,
                                           source=f"requests+bs4 (port {alt_port})")
            except Exception as e:
                continue
        return f"[!] All scrapling/requests attempts failed for {url}. Target web service may be down."


@tool(name="scrapling_crawl", aliases=["crawl"], category="recon", description="Deep crawl a website using scrapling or requests+BeautifulSoup fallback for link discovery.")
def run_scrapling_crawl(url: str, max_pages: int = 10) -> str:
    """
    Deep crawl a website using scrapling for link discovery and content extraction.
    """
    if not url.startswith("http"):
        url = f"http://{url}"

    print(f"  [*] Scrapling Crawl (max {max_pages} pages): {url}")

    def _same_host_link(base_url: str, href: str) -> str:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            return ""
        absolute = urljoin(base_url, href)
        base_host = (urlparse(url).hostname or "").lower()
        link_host = (urlparse(absolute).hostname or "").lower()
        return absolute if base_host and link_host == base_host else ""

    try:
        fetcher = _StealthyFetcher() if _SCRAPLING_OK else None

        visited = set()
        to_visit = [url]
        results = []

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                if fetcher is not None:
                    page = fetcher.fetch(current_url)
                    status = int(getattr(page, "status", 0) or 0)
                    if status == 200:
                        title_el = page.css_first("title")
                        title = title_el.text() if title_el else "No title"
                        results.append(f"  [{status}] {current_url} — {title[:60]}")

                        # Discover new links on same host.
                        for a in page.css("a[href]"):
                            href = a.attributes.get("href", "")
                            next_url = _same_host_link(current_url, href)
                            if next_url and next_url not in visited and next_url not in to_visit:
                                to_visit.append(next_url)
                    else:
                        results.append(f"  [{status or 'ERR'}] {current_url}")
                else:
                    import requests as _req
                    resp = _req.get(
                        current_url,
                        timeout=(5, 15),
                        verify=False,
                        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"},
                    )
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(resp.text, "html.parser")
                        title_el = soup.find("title")
                        title = title_el.get_text(strip=True) if title_el else "No title"
                        hrefs = [a.get("href", "") for a in soup.find_all("a", href=True)]
                    except ImportError:
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text or "", re.IGNORECASE | re.DOTALL)
                        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else "No title"
                        hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text or "", re.IGNORECASE)
                    results.append(f"  [{resp.status_code}] {current_url} — {title[:60]}")
                    for href in hrefs:
                        next_url = _same_host_link(current_url, href)
                        if next_url and next_url not in visited and next_url not in to_visit:
                            to_visit.append(next_url)
            except Exception as e:
                results.append(f"  [ERR] {current_url}")
                continue

        output = f"[SCRAPLING CRAWL — {url}]\n"
        output += f"Mode: {'scrapling' if fetcher is not None else 'requests+bs4 fallback'}\n"
        output += f"Pages crawled: {len(visited)}\n"
        output += "\n".join(results) + "\n"
        return output

    except Exception as e:
        return f"[!] Crawl failed: {e}"


# ─────────────────────────────────────────────
# SSH USER ENUMERATION (CVE-2018-15473)
# ─────────────────────────────────────────────

@tool(name="ssh_user_enum", aliases=["ssh-user-enum", "sshenum"], category="recon", description="Enumerate valid SSH usernames via CVE-2018-15473.", requires=["python:paramiko"])
def run_ssh_user_enum(target: str, port: int = 22) -> str:
    """
    Enumerate valid SSH usernames via CVE-2018-15473 (OpenSSH ≤ 7.7).
    v3.7: Early-abort — tests 5 canary users first. If ALL return valid,
    the server is patched (returns AuthenticationException for everyone).
    Skips remaining users to save time (~30s instead of ~2min).
    """
    print(f"  [*] SSH User Enumeration (CVE-2018-15473): {target}:{port}")

    try:
        import paramiko
    except ImportError:
        return "[!] paramiko not installed. Install with: pip install paramiko"

    import socket

    # Check port is open first
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        if sock.connect_ex((target, port)) != 0:
            return f"[!] SSH port {port} is not open on {target}"
    except Exception as e:
        return f"[!] Cannot connect to {target}:{port}"
    finally:
        sock.close()

    # Trimmed default user list — only the most common ones
    default_users = CFG.get("default_users", [
        "root", "admin", "support", "administrator", "user",
        "test", "guest", "operator", "ftp", "www",
    ])

    # Extended list for full scan (only used if server is vulnerable)
    extended_users = [
        "www-data", "mysql", "postgres", "oracle", "tomcat", "jenkins",
        "git", "nagios", "zabbix", "pi", "ubnt", "deploy", "ansible",
        "backup", "service"
    ]

    def _check_user(username: str) -> bool:
        """Check if username is valid via SSH auth timing/response."""
        try:
            transport = paramiko.Transport((target, port))
            transport.connect()
            try:
                transport.auth_password(username, "octopus_enum_probe_x7q9")
            except paramiko.AuthenticationException:
                # Auth failed = user EXISTS (server tried to authenticate)
                transport.close()
                return True
            except paramiko.ssh_exception.SSHException as e:
                err_str = str(e).lower()
                if "no existing session" in err_str:
                    return False
                transport.close()
                return True
            except Exception as e:
                return False
            finally:
                try:
                    transport.close()
                except Exception as _exc:
                    logging.debug(f"Suppressed in recon_tools.py: {_exc}")
            return False
        except Exception as e:
            return False

    # ── PHASE 1: CANARY TEST (5 users) ────────────────────────────
    # Test 5 diverse users first. If ALL return valid → server is patched.
    canary_users = ["root", "admin", "support", "aaa_fake_user_m7k"]
    canary_valid = 0
    canary_total = 0

    print(f"  [*] Phase 1: Testing {len(canary_users)} canary users for false-positive detection...")
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_check_user, u): u for u in canary_users}
        for future in as_completed(futures):
            username = futures[future]
            canary_total += 1
            try:
                if future.result():
                    canary_valid += 1
                    print(f"      [+] VALID USER: {username}")
                else:
                    print(f"      [-] invalid: {username}")
            except Exception as _exc:
                logging.debug(f"Suppressed in recon_tools.py: {_exc}")

    # If ALL canary users (including obviously fake ones) are "valid" → PATCHED
    if canary_total > 0 and canary_valid == canary_total:
        print(f"  [!] ALL {canary_total} canary users returned valid (including fake names)")
        print(f"  [!] Server is PATCHED — aborting full enumeration (saves ~2 min)")
        output = f"[SSH USER ENUMERATION — {target}:{port}]\n"
        output += f"CVE-2018-15473 (OpenSSH ≤ 7.7)\n"
        output += f"Canary test: {canary_valid}/{canary_total} returned valid (including fake usernames)\n"
        output += f"\n[!] WARNING: Server is PATCHED against CVE-2018-15473 — ALL users return valid.\n"
        output += f"[!] Results are UNRELIABLE. Skipped full enumeration.\n"
        output += f"[!] Falling back to default priority users for bruteforce.\n"
        output += f"\nAI: ssh_user_enum results are UNRELIABLE. Use default users for bruteforce.\n"
        return output

    # If canary test shows SOME invalid → server MAY be vulnerable
    # ── PHASE 2: FULL SCAN ────────────────────────────────────────
    # Remove canary users already tested, test remaining
    all_users = list(dict.fromkeys(default_users + extended_users))
    remaining = [u for u in all_users if u not in canary_users]

    valid_users = [u for u in canary_users if u not in ["support", "aaa_fake_user_m7k"]
                   and _check_user is not None]  # placeholder — re-check below
    # Actually rebuild from canary results
    valid_users = []
    invalid_count = 0
    error_count = 0

    # Re-count canary results (we already printed them)
    # Just test the remaining users
    print(f"  [*] Phase 2: Server may be vulnerable — testing {len(remaining)} more usernames...")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_check_user, u): u for u in remaining}
        for future in as_completed(futures):
            username = futures[future]
            try:
                if future.result():
                    valid_users.append(username)
                    print(f"      [+] VALID USER: {username}")
                else:
                    invalid_count += 1
            except Exception as e:
                error_count += 1

    total_tested = len(valid_users) + invalid_count + canary_total
    output = f"[SSH USER ENUMERATION — {target}:{port}]\n"
    output += f"CVE-2018-15473 (OpenSSH ≤ 7.7)\n"
    output += f"Tested: {total_tested} usernames\n"
    output += f"Valid: {len(valid_users)} | Invalid: {invalid_count} | Errors: {error_count}\n"

    # Double-check false positive (if >70% valid despite canary passing)
    if total_tested > 0 and len(valid_users) / total_tested > 0.70:
        output += f"\n[!] WARNING: {len(valid_users)}/{total_tested} ({100*len(valid_users)//total_tested}%) users returned valid.\n"
        output += f"[!] Server is likely PATCHED against CVE-2018-15473 — results UNRELIABLE.\n"
        output += f"[!] Falling back to default priority users for bruteforce.\n"
        output += f"\nAI: ssh_user_enum results are UNRELIABLE. Use default users for bruteforce.\n"
        valid_users.clear()
    elif valid_users:
        output += f"\nCONFIRMED VALID USERS:\n"
        for u in valid_users:
            output += f"  ✓ {u}\n"
        output += f"\nAI: Use these users for targeted bruteforce with [TOOL: bruteforce ssh {target}]\n"
    else:
        output += f"\nNo valid users confirmed (server may be patched or not vulnerable).\n"
        output += f"AI: Proceed with default user list for bruteforce.\n"

    return output


# ─────────────────────────────────────────────
# BRUTEFORCE (v3.7 — LEAN 2-TIER, NO TIMEOUT CAP)
# ─────────────────────────────────────────────
