#!/usr/bin/env python3
"""
"""

import re
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from ddgs import DDGS   # pip install duckduckgo-search

# ─────────────────────────────────────────────
# HTTP SESSION SETUP (Resilience)
# ─────────────────────────────────────────────

def get_resilient_session() -> requests.Session:
    """
    Returns a requests Session with robust retry logic
    for transient network errors or rate limits.
    """
    session = requests.Session()
    retries = Retry(
        total=2,           # Was 5 — too many retries cause hangs
        backoff_factor=0.5, # Was 1 — faster recovery
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"})
    return session

session = get_resilient_session()


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """
    Search DuckDuckGo with HARD TIMEOUT.
    v3.2: Wrapped in threading timeout to prevent hanging.
    """
    import threading

    print(f"  [*] Searching: {query}")
    result_container = [None]

    def _do_search():
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            if not results:
                result_container[0] = "[!] No search results found."
                return
            output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
            output += "─" * 50 + "\n"
            for i, r in enumerate(results, 1):
                output += f"\n[{i}] {r['title']}\n"
                output += f"    URL     : {r['href']}\n"
                output += f"    Snippet : {r['body']}\n"
            result_container[0] = output
        except Exception as e:
            result_container[0] = f"[!] Search failed: {e}"

    t = threading.Thread(target=_do_search, daemon=True)
    t.start()
    t.join(timeout=15)  # HARD 15s timeout

    if result_container[0] is None:
        return f"[!] Search timed out after 15s for: {query}"
    return result_container[0]


# ─────────────────────────────────────────────
# CVE SPECIFIC SEARCH (ENHANCED v3.0)
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    """
    Search for a specific CVE.
    v3.2: FAST — DDG + NVD only. Removed MITRE (too slow/blocks).
    Total max time: ~20s.
    """
    print(f"  [*] Looking up {cve_id}...")

    # DDG search (15s timeout built-in)
    ddg_results = web_search(f"{cve_id} vulnerability exploit", max_results=3)

    # NVD API lookup for CVSS score (8s timeout)
    nvd_data = _fetch_nvd_cvss(cve_id)

    output = ddg_results
    if nvd_data:
        output += f"\n\n[NVD CVSS DATA: {cve_id}]\n{nvd_data}"

    print(f"  [✓] {cve_id} lookup complete")
    return output


def _fetch_nvd_cvss(cve_id: str) -> str:
    """
    Fetch CVSS score from NVD API v2.0 for a CVE.
    Returns formatted string with score and severity, or empty string.
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        resp = session.get(url, timeout=8)  # Strict 8s timeout
        if resp.status_code != 200:
            return ""

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return ""

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")[:300]
                break

        # Try CVSS v3.1 first, then v3.0, then v2.0
        metrics = cve_data.get("metrics", {})
        cvss_info = ""

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(version, [])
            if metric_list:
                m = metric_list[0]
                cvss_data = m.get("cvssData", {})
                score = cvss_data.get("baseScore", "?")
                severity = cvss_data.get("baseSeverity", m.get("baseSeverity", "?"))
                vector = cvss_data.get("vectorString", "?")
                exploitability = m.get("exploitabilityScore", "?")
                impact = m.get("impactScore", "?")
                cvss_info = (
                    f"  CVSS Score: {score} ({severity})\n"
                    f"  Vector: {vector}\n"
                    f"  Exploitability: {exploitability}\n"
                    f"  Impact: {impact}\n"
                )
                break

        output = ""
        if cvss_info:
            output += cvss_info
        if desc:
            output += f"  Description: {desc}\n"

        # Published/modified dates
        published = cve_data.get("published", "")
        if published:
            output += f"  Published: {published[:10]}\n"

        return output

    except Exception as e:
        return f"  [!] NVD lookup failed: {e}"


def search_exploit(service: str, version: str) -> str:
    """
    Search for known exploits for a service + version combo.
    e.g. search_exploit("apache", "2.4.49")
    """
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    return web_search(query, max_results=5)


def search_fix(vuln_name: str) -> str:
    """
    Search for mitigation/fix for a vulnerability.
    """
    query = f"how to fix {vuln_name} security mitigation patch"
    return web_search(query, max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCHER (v3.0 — scrapling-enhanced)
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 3000, use_scrapling: bool = False) -> str:
    """
    Fetch a URL and return extracted plain text.
    v3.0: Can use scrapling for JS-heavy pages.
    Strips all HTML tags. Truncated to max_chars for LLM context.
    """
    # Try scrapling first if requested
    if use_scrapling:
        scrapling_result = _fetch_with_scrapling(url, max_chars)
        if scrapling_result:
            return scrapling_result

    # Standard requests fallback
    try:
        resp = session.get(url, timeout=10)  # Was 15s, reduced to prevent blocking
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # remove nav/footer/script noise
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        # collapse blank lines
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)

        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

        return clean

    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


def _fetch_with_scrapling(url: str, max_chars: int = 3000) -> str:
    """
    Fetch a page using scrapling's StealthyFetcher.
    Returns cleaned text or None if scrapling is unavailable.
    """
    try:
        from scrapling import StealthyFetcher
        fetcher = StealthyFetcher()
        page = fetcher.fetch(url)

        if page.status == 200:
            body = page.css_first("body")
            text = body.text(separator="\n", strip=True) if body else page.text()

            # Clean up
            lines = [l for l in text.splitlines() if l.strip()]
            clean = "\n".join(lines)

            if len(clean) > max_chars:
                clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

            return clean
        else:
            return None
    except ImportError:
        return None
    except Exception as e:
        return None


# ─────────────────────────────────────────────
# TOOL DISPATCH HANDLER
# ─────────────────────────────────────────────

import subprocess
import shutil

def search_searchsploit(query: str) -> str:
    """
    Searches Exploit-DB locally using the searchsploit binary (common on Athena OS/Parrot).
    """
    print(f"  [*] SearchSploit lookup: {query}")
    if not shutil.which("searchsploit"):
        return "[!] searchsploit is not installed or not in PATH. DO NOT use [SEARCHSPLOIT] again. Use [SEARCH: exploit poc] instead to find exploits online."

    try:
        # -t = search in title
        result = subprocess.run(
            ["searchsploit", "-t", query],
            capture_output=True,
            text=True,
            timeout=30
        )
        out = result.stdout.strip()
        if not out or "No Results" in out:
            return f"[!] No searchsploit results for {query}. Try broadening the search or use [SEARCH: ...]."
        
        # limit output size so we don't blow up context
        lines = out.splitlines()
        if len(lines) > 20:
            out = "\n".join(lines[:20]) + "\n... [TRUNCATED]"
            
        return f"[SEARCHSPLOIT RESULTS]\n{out}"
    except Exception as e:
        return f"[!] searchsploit failed: {e}. Use [SEARCH: ...] instead."

def handle_search_dispatch(query: str) -> str:
    """
    v7.0: Smarter routing. Detects 'service + version' and checks searchsploit first.
    Also handles CVEs and specific PoC requests.
    """
    query = query.strip()

    # 1. CVE pattern — CVE-YYYY-NNNNN
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        # v7.0: searchsploit for CVEs is often faster/better than web search
        cve_id = cve_match.group()
        import subprocess, shutil
        if shutil.which("searchsploit"):
            try:
                res = subprocess.run(["searchsploit", "--cve", cve_id], capture_output=True, text=True, timeout=10)
                if "No Results" not in res.stdout and len(res.stdout) > 50:
                    return f"[SEARCHSPLOIT LOCAL CVE MATCH]\n{res.stdout}\n\n[CVE DB INFO]\n{search_cve(cve_id)}"
            except Exception as _exc:
                logging.debug(f"Suppressed in search.py: {_exc}")
        return search_cve(cve_id)

    # 2. Explicit searchsploit request
    if "searchsploit" in query.lower():
        return search_searchsploit(query.replace("searchsploit","",1).strip())

    # 3. Detect "Service + Version" strings (e.g. "vsftpd 2.3.4" or "OpenSSH 7.2")
    # If the query looks like a service version, hit searchsploit BEFORE web search
    version_pattern = re.compile(r'^[a-zA-Z0-9\-\_]+\s+\d+\.\d+')
    if version_pattern.search(query):
        import subprocess, shutil
        if shutil.which("searchsploit"):
            try:
                res = subprocess.run(["searchsploit", query], capture_output=True, text=True, timeout=10)
                if "No Results" not in res.stdout and len(res.stdout) > 50:
                    return f"[SEARCHSPLOIT LOCAL MATCH for '{query}']\n{res.stdout}"
            except Exception as _exc:
                logging.debug(f"Suppressed in search.py: {_exc}")

    # 4. Exploit / PoC keywords — target github and recent years
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        # v7.0: Bias towards recent GitHub PoCs
        from datetime import datetime
        year = datetime.now().year
        enhanced_query = f"{query} exploit OR poc site:github.com ({year} OR {year-1} OR {year-2})"
        return web_search(enhanced_query, max_results=5)

    # 5. Fix/patch keywords
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)

    # 6. Default general web search
    return web_search(query, max_results=5)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    print("[4] Fetch with scrapling")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(web_search(q))

    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(search_cve(cve))

    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))

    elif choice == "4":
        url = input("URL: ").strip()
        print(fetch_page(url, use_scrapling=True))
