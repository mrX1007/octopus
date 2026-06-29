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

from core.tools.base import (
    run_tool, is_tool_available, get_tool_config, _fmt_elapsed,
    C_GREY, C_RESET, C_CYAN, C_GREEN, C_YELLOW, C_RED, C_BLUE, C_MAGENTA,
)
from core.tools.registry import tool

# Config helpers
try:
    from config import CFG, find_wordlist, find_all_wordlists
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""
    def find_all_wordlists(cat): return []

# Scrapling availability
try:
    from scrapling import StealthyFetcher as _StealthyFetcher
    _SCRAPLING_OK = True
except ImportError:
    _StealthyFetcher = None
    _SCRAPLING_OK = False


def _ensure_url(target: str, scheme: str = "http") -> str:
    target = (target or "").strip().rstrip("/")
    if target.startswith(("http://", "https://")):
        return target
    return f"{scheme}://{target}"


def _url_candidates(target: str) -> list:
    target = (target or "").strip().rstrip("/")
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"http://{target}", f"https://{target}"]


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """Parse host[:port] without treating URL paths as part of the host."""
    raw = (target or "").strip()
    raw = raw.replace("http://", "").replace("https://", "")
    raw = raw.split("/", 1)[0]
    host = raw
    port = default_port
    if raw.count(":") == 1:
        maybe_host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = int(maybe_port)
    return host.strip(), int(port)


def _coerce_port(port, default_port: int) -> int:
    try:
        return int(port)
    except (TypeError, ValueError):
        return int(default_port)


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
    print(f"  [*] nikto -h {scan_target}  (this may take a while...)")
    return run_tool(["nikto", "-h", scan_target] + flags, timeout=tc.get("timeout", 300))


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


@tool(name="scrapling_crawl", aliases=["crawl"], category="recon", description="Deep crawl a website using scrapling for link discovery and content extraction.", requires=["python:scrapling"])
def run_scrapling_crawl(url: str, max_pages: int = 10) -> str:
    """
    Deep crawl a website using scrapling for link discovery and content extraction.
    """
    if not url.startswith("http"):
        url = f"http://{url}"

    print(f"  [*] Scrapling Crawl (max {max_pages} pages): {url}")

    try:
        from scrapling import StealthyFetcher
        fetcher = StealthyFetcher()

        visited = set()
        to_visit = [url]
        results = []
        base_domain = url.split("//")[-1].split("/")[0]

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                page = fetcher.fetch(current_url)
                if page.status == 200:
                    title_el = page.css_first("title")
                    title = title_el.text() if title_el else "No title"
                    results.append(f"  [{page.status}] {current_url} — {title[:60]}")

                    # Discover new links on same domain
                    for a in page.css("a[href]"):
                        href = a.attributes.get("href", "")
                        if href.startswith("/"):
                            href = f"{url.rstrip('/')}{href}"
                        if base_domain in href and href not in visited:
                            to_visit.append(href)
            except Exception as e:
                results.append(f"  [ERR] {current_url}")
                continue

        output = f"[SCRAPLING CRAWL — {url}]\n"
        output += f"Pages crawled: {len(visited)}\n"
        output += "\n".join(results) + "\n"
        return output

    except ImportError:
        return "[!] scrapling not installed. Install with: pip install scrapling"
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

    import time

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
