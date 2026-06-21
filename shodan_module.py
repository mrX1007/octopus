#!/usr/bin/env python3

import os
import sys
import json
import time
from datetime import datetime

try:
    import shodan
except ImportError:
    shodan = None

try:
    from config import CFG, get_secret
except ImportError:
    CFG = {}
    def get_secret(k, d=""): return os.environ.get(k, d)

try:
    import mysql.connector
except ImportError:
    mysql = None

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_BLUE   = "\033[94m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"

# ═══════════════════════════════════════════════
# SHODAN RECON CLASS
# ═══════════════════════════════════════════════

class ShodanRecon:
    """Full Shodan API wrapper with DB storage and pipeline integration."""

    def __init__(self, api_key: str = None):
        """Initialize Shodan client.
        Key priority: argument → .env SHODAN_API_KEY → config.yaml → error."""
        self.api_key = api_key or get_secret("SHODAN_API_KEY", "")
        self.api = None
        self.cfg = CFG.get("shodan", {})
        self.max_results = self.cfg.get("max_results", 100)
        self.timeout = self.cfg.get("timeout", 30)
        self.results_dir = self.cfg.get("results_dir", "/tmp/octopus_shodan")
        self._last_results = []
        self._db_conn = None

        if not self.api_key:
            print(f"  {C_YELLOW}[!] No Shodan API key. Set SHODAN_API_KEY in .env{C_RESET}")
            return

        if shodan is None:
            print(f"  {C_RED}[!] shodan library not installed: pip install shodan{C_RESET}")
            return

        try:
            self.api = shodan.Shodan(self.api_key)
            info = self.api.info()
            print(f"  {C_GREEN}[✓] Shodan API connected — credits: {info.get('query_credits', '?')}, "
                  f"scan credits: {info.get('scan_credits', '?')}{C_RESET}")
        except Exception as e:
            print(f"  {C_RED}[!] Shodan API error: {e}{C_RESET}")
            self.api = None

    def _ensure_dir(self):
        """Create results directory if needed."""
        os.makedirs(self.results_dir, exist_ok=True)

    def _get_db(self):
        """Get/create MariaDB connection. Returns None if unavailable."""
        if self._db_conn and self._db_conn.is_connected():
            return self._db_conn
        try:
            db_cfg = CFG.get("db", {})
            self._db_conn = mysql.connector.connect(
                host=db_cfg.get("host", "localhost"),
                user=db_cfg.get("user", "octopus"),
                password=db_cfg.get("password", "123"),
                database=db_cfg.get("database", "octopus"),
                connect_timeout=5,
            )
            self._ensure_table()
            return self._db_conn
        except Exception as e:
            return None

    def _ensure_table(self):
        """Create shodan_results table if not exists."""
        if not self._db_conn:
            return
        try:
            cur = self._db_conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS shodan_results (
                    id          INT AUTO_INCREMENT PRIMARY KEY,
                    ip          VARCHAR(45) NOT NULL,
                    port        INT,
                    transport   VARCHAR(10),
                    service     VARCHAR(100),
                    version     VARCHAR(200),
                    banner      TEXT,
                    vulns       TEXT,
                    os_name     VARCHAR(100),
                    country     VARCHAR(10),
                    org         VARCHAR(200),
                    hostnames   TEXT,
                    query       VARCHAR(500),
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                    raw_json    LONGTEXT,
                    INDEX idx_ip (ip),
                    INDEX idx_port (port),
                    INDEX idx_query (query(100))
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            self._db_conn.commit()
            cur.close()
        except Exception as e:
            print(f"  {C_GREY}[~] DB table creation: {e}{C_RESET}")

    # ─── CORE API METHODS ──────────────────────

    def search(self, query: str, max_results: int = None) -> dict:
        """Run Shodan search query.
        Examples: 'port:22 country:RU', 'apache 2.4.49', 'vuln:CVE-2021-44228'
        Returns: {'total': N, 'matches': [...], 'query': str}"""
        if not self.api:
            return {"error": "Shodan API not initialized", "total": 0, "matches": []}

        max_res = max_results or self.max_results
        print(f"\n  {C_CYAN}[*] Shodan search: {C_BOLD}{query}{C_RESET}")

        try:
            results = self.api.search(query, limit=max_res)
            total = results.get("total", 0)
            matches = results.get("matches", [])

            print(f"  {C_GREEN}[+] Found {total} total results, retrieved {len(matches)}{C_RESET}")

            structured = {
                "query": query,
                "total": total,
                "retrieved": len(matches),
                "timestamp": datetime.now().isoformat(),
                "matches": [],
            }

            for m in matches:
                entry = {
                    "ip": m.get("ip_str", ""),
                    "port": m.get("port", 0),
                    "transport": m.get("transport", "tcp"),
                    "service": m.get("product", m.get("_shodan", {}).get("module", "")),
                    "version": m.get("version", ""),
                    "banner": (m.get("data", "")[:500]),
                    "vulns": list(m.get("vulns", {}).keys()) if m.get("vulns") else [],
                    "os": m.get("os", ""),
                    "country": m.get("location", {}).get("country_code", ""),
                    "org": m.get("org", ""),
                    "hostnames": m.get("hostnames", []),
                    "timestamp": m.get("timestamp", ""),
                }
                structured["matches"].append(entry)

            self._last_results = structured["matches"]

            # Save to DB + JSON
            self.save_to_db(structured)
            self._save_json(structured, f"search_{query[:30].replace(' ','_')}")

            return structured

        except shodan.APIError as e:
            err = f"Shodan API error: {e}"
            print(f"  {C_RED}[!] {err}{C_RESET}")
            return {"error": err, "total": 0, "matches": []}
        except Exception as e:
            err = f"Shodan search failed: {e}"
            print(f"  {C_RED}[!] {err}{C_RESET}")
            return {"error": err, "total": 0, "matches": []}

    def host_info(self, ip: str) -> dict:
        """Get full host information from Shodan.
        Returns ports, services, vulns, banners, OS, location."""
        if not self.api:
            return {"error": "Shodan API not initialized"}

        print(f"\n  {C_CYAN}[*] Shodan host lookup: {C_BOLD}{ip}{C_RESET}")

        try:
            host = self.api.host(ip)

            info = {
                "ip": host.get("ip_str", ip),
                "os": host.get("os", "Unknown"),
                "org": host.get("org", "Unknown"),
                "isp": host.get("isp", ""),
                "country": host.get("country_name", ""),
                "city": host.get("city", ""),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "vulns": list(host.get("vulns", [])),
                "last_update": host.get("last_update", ""),
                "ports": host.get("ports", []),
                "services": [],
            }

            for svc in host.get("data", []):
                info["services"].append({
                    "port": svc.get("port", 0),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": (svc.get("data", "")[:300]),
                    "vulns": list(svc.get("vulns", {}).keys()) if svc.get("vulns") else [],
                    "cpe": svc.get("cpe", []),
                })

            print(f"  {C_GREEN}[+] {ip}: {len(info['ports'])} ports, "
                  f"{len(info['vulns'])} vulns, OS: {info['os']}{C_RESET}")

            self._save_json(info, f"host_{ip.replace('.','_')}")
            return info

        except shodan.APIError as e:
            err = f"Shodan host error: {e}"
            print(f"  {C_RED}[!] {err}{C_RESET}")
            return {"error": err}
        except Exception as e:
            return {"error": str(e)}

    def search_exploits(self, query: str) -> list:
        """Search Shodan Exploits database.
        Returns list of exploit entries."""
        if not self.api:
            return []

        print(f"\n  {C_CYAN}[*] Shodan exploit search: {query}{C_RESET}")

        try:
            results = self.api.exploits.search(query, limit=20)
            exploits = []
            for e in results.get("matches", []):
                exploits.append({
                    "description": e.get("description", "")[:200],
                    "source": e.get("source", ""),
                    "id": e.get("_id", ""),
                    "cve": e.get("cve", []),
                    "type": e.get("type", ""),
                    "platform": e.get("platform", ""),
                })

            print(f"  {C_GREEN}[+] Found {len(exploits)} exploits{C_RESET}")
            return exploits

        except Exception as e:
            print(f"  {C_RED}[!] Exploit search failed: {e}{C_RESET}")
            return []

    # ─── STORAGE ───────────────────────────────

    def save_to_db(self, results: dict):
        """Save search results to MariaDB shodan_results table."""
        conn = self._get_db()
        if not conn:
            return

        query_str = results.get("query", "")
        matches = results.get("matches", [])
        if not matches:
            return

        try:
            cur = conn.cursor()
            sql = """INSERT INTO shodan_results
                     (ip, port, transport, service, version, banner, vulns,
                      os_name, country, org, hostnames, query, raw_json)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

            rows = []
            for m in matches:
                rows.append((
                    m.get("ip", ""),
                    m.get("port", 0),
                    m.get("transport", "tcp"),
                    m.get("service", ""),
                    m.get("version", ""),
                    m.get("banner", "")[:2000],
                    json.dumps(m.get("vulns", [])),
                    m.get("os", ""),
                    m.get("country", ""),
                    m.get("org", ""),
                    json.dumps(m.get("hostnames", [])),
                    query_str,
                    json.dumps(m),
                ))

            cur.executemany(sql, rows)
            conn.commit()
            cur.close()
            print(f"  {C_GREEN}[+] Saved {len(rows)} results to DB{C_RESET}")

        except Exception as e:
            print(f"  {C_GREY}[~] DB save failed (JSON backup used): {e}{C_RESET}")

    def _save_json(self, data: dict, prefix: str = "results"):
        """Save results to JSON file as backup."""
        self._ensure_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Clean prefix for filename
        clean_prefix = "".join(c if c.isalnum() or c in "_-" else "_" for c in prefix)
        filepath = os.path.join(self.results_dir, f"{clean_prefix}_{ts}.json")
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            print(f"  {C_GREY}[~] JSON backup: {filepath}{C_RESET}")
            return filepath
        except Exception as e:
            print(f"  {C_GREY}[~] JSON save failed: {e}{C_RESET}")
            return ""

    # ─── PIPELINE & FORMATTING ─────────────────

    def format_for_pipeline(self, results: dict = None) -> list:
        """Convert Shodan results to OCTOPUS target list.
        Returns: [{ip, ports: [int], services: [{port, name, version}], vulns: [str]}]"""
        matches = (results or {}).get("matches", self._last_results)
        if not matches:
            return []

        # Group by IP
        by_ip = {}
        for m in matches:
            ip = m.get("ip", "")
            if not ip:
                continue
            if ip not in by_ip:
                by_ip[ip] = {
                    "ip": ip,
                    "ports": [],
                    "services": [],
                    "vulns": set(),
                    "os": m.get("os", ""),
                    "org": m.get("org", ""),
                    "country": m.get("country", ""),
                }
            port = m.get("port", 0)
            if port and port not in by_ip[ip]["ports"]:
                by_ip[ip]["ports"].append(port)
            by_ip[ip]["services"].append({
                "port": port,
                "name": m.get("service", ""),
                "version": m.get("version", ""),
            })
            for v in m.get("vulns", []):
                by_ip[ip]["vulns"].add(v)

        targets = []
        for ip, data in by_ip.items():
            data["vulns"] = sorted(data["vulns"])
            data["ports"].sort()
            targets.append(data)

        return targets

    def format_for_llm(self, results: dict = None) -> str:
        """Format results for AI analysis context."""
        targets = self.format_for_pipeline(results)
        if not targets:
            return "[Shodan] No results found.\n"

        lines = [f"[SHODAN RESULTS — {len(targets)} unique hosts]\n"]
        for i, t in enumerate(targets[:20], 1):  # Cap at 20 for context window
            ports_str = ", ".join(str(p) for p in t["ports"][:15])
            svcs = "; ".join(f"{s['port']}/{s['name']} {s['version']}" for s in t["services"][:10])
            vulns_str = ", ".join(t["vulns"][:10]) if t["vulns"] else "none known"
            lines.append(
                f"  {i}. {t['ip']} ({t['org']}, {t['country']})\n"
                f"     Ports: {ports_str}\n"
                f"     Services: {svcs}\n"
                f"     Vulns: {vulns_str}\n"
            )

        total = results.get("total", len(targets)) if results else len(targets)
        if total > 20:
            lines.append(f"\n  ... and {total - 20} more hosts.\n")

        lines.append(f"\nAI: Analyze targets above. High-vuln hosts are priority for killchain.\n")
        return "\n".join(lines)

    def auto_pipeline(self, query: str) -> str:
        """Full auto pipeline: search → save → format → return for killchain.
        This is the main entry point for automated workflows."""
        print(f"\n  {C_MAGENTA}{'═' * 60}{C_RESET}")
        print(f"  {C_MAGENTA}[SHODAN AUTO-PIPELINE] Query: {query}{C_RESET}")
        print(f"  {C_MAGENTA}{'═' * 60}{C_RESET}")

        # 1. Search
        results = self.search(query)
        if results.get("error") or not results.get("matches"):
            return f"[Shodan] Search failed or no results for: {query}\n"

        # 2. Format for pipeline
        targets = self.format_for_pipeline(results)

        # 3. Generate AI-friendly report
        output = self.format_for_llm(results)

        # 4. Summary
        vuln_hosts = sum(1 for t in targets if t.get("vulns"))
        output += f"\n[PIPELINE SUMMARY]\n"
        output += f"  Total hosts: {len(targets)}\n"
        output += f"  Hosts with known CVEs: {vuln_hosts}\n"
        output += f"  Results saved to DB + {self.results_dir}\n"

        if self.cfg.get("auto_pipeline", True) and targets:
            output += f"\nAI: {vuln_hosts} hosts have known vulnerabilities. "
            output += "Run killchain on priority targets:\n"
            for t in sorted(targets, key=lambda x: len(x.get("vulns", [])), reverse=True)[:5]:
                if t.get("vulns"):
                    output += f"  [TOOL: nmap -Pn -sT -sV -sC {t['ip']}]\n"

        return output


# ═══════════════════════════════════════════════
# STANDALONE FUNCTIONS (called from tools.py)
# ═══════════════════════════════════════════════

def run_shodan_search(query: str) -> str:
    """[TOOL: shodan search QUERY] handler."""
    sr = ShodanRecon()
    if not sr.api:
        return "[!] Shodan API not available. Set SHODAN_API_KEY in .env\n"

    if sr.cfg.get("auto_pipeline", True):
        return sr.auto_pipeline(query)
    else:
        results = sr.search(query)
        return sr.format_for_llm(results)


def run_shodan_host(ip: str) -> str:
    """[TOOL: shodan host IP] handler."""
    sr = ShodanRecon()
    if not sr.api:
        return "[!] Shodan API not available. Set SHODAN_API_KEY in .env\n"

    info = sr.host_info(ip)
    if info.get("error"):
        return f"[!] {info['error']}\n"

    output = f"[SHODAN HOST: {ip}]\n{'═' * 60}\n"
    output += f"  OS:        {info.get('os', 'Unknown')}\n"
    output += f"  Org:       {info.get('org', 'Unknown')}\n"
    output += f"  ISP:       {info.get('isp', '')}\n"
    output += f"  Location:  {info.get('city', '')}, {info.get('country', '')}\n"
    output += f"  Hostnames: {', '.join(info.get('hostnames', []))}\n"
    output += f"  Ports:     {', '.join(str(p) for p in info.get('ports', []))}\n"

    if info.get("vulns"):
        output += f"\n  {C_RED}CVEs ({len(info['vulns'])}):{C_RESET}\n"
        for cve in info["vulns"][:25]:
            output += f"    • {cve}\n"

    output += f"\n  Services:\n"
    for svc in info.get("services", []):
        vuln_tag = f" {C_RED}[VULN: {', '.join(svc['vulns'][:3])}]{C_RESET}" if svc.get("vulns") else ""
        output += f"    {svc['port']}/{svc['transport']} — {svc['product']} {svc['version']}{vuln_tag}\n"
        if svc.get("banner"):
            output += f"      Banner: {svc['banner'][:120]}\n"

    output += f"\nAI: Use nmap for deep scan, then killchain_vuln_assess for exploitation.\n"
    return output


def run_shodan_vulns(ip: str) -> str:
    """[TOOL: shodan vulns IP] handler — focused CVE report."""
    sr = ShodanRecon()
    if not sr.api:
        return "[!] Shodan API not available. Set SHODAN_API_KEY in .env\n"

    info = sr.host_info(ip)
    if info.get("error"):
        return f"[!] {info['error']}\n"

    vulns = info.get("vulns", [])
    if not vulns:
        return f"[Shodan] No known CVEs for {ip}\n"

    output = f"[SHODAN CVE REPORT: {ip}]\n{'═' * 60}\n"
    output += f"  Total CVEs: {len(vulns)}\n\n"
    for cve in vulns:
        output += f"  • {cve}\n"

    # Cross-reference with services
    output += f"\n  Vulnerable Services:\n"
    for svc in info.get("services", []):
        if svc.get("vulns"):
            output += f"    {svc['port']}/{svc['transport']} {svc['product']} {svc['version']}: "
            output += f"{', '.join(svc['vulns'])}\n"

    output += f"\nAI: Cross-check CVEs with searchsploit.\n"
    for cve in vulns[:5]:
        output += f"  [SEARCHSPLOIT: {cve}]\n"

    return output


def run_shodan_interactive(target: str = "") -> str:
    """Interactive Shodan interface for terminal menu."""
    print(f"\n  {C_MAGENTA}{'=' * 60}{C_RESET}")
    print(f"  {C_MAGENTA}    OCTOPUS -- Shodan OSINT Module v8.1{C_RESET}")
    print(f"  {C_MAGENTA}{'=' * 60}{C_RESET}")

    sr = ShodanRecon()
    if not sr.api:
        return "[!] Shodan API not configured. Add SHODAN_API_KEY to .env\n"

    if target:
        return run_shodan_smart(target)

    # Interactive mode
    print(f"\n  {C_CYAN}Options:{C_RESET}")
    print(f"    1. Search (dork/query)")
    print(f"    2. Host lookup (IP)")
    print(f"    3. Vulnerability scan (IP)")
    print(f"    4. Exploit search")
    print(f"    5. Auto-pipeline (search -> killchain)")
    print(f"    6. Range/subnet scan (CIDR)")

    try:
        choice = input(f"\n  {C_CYAN}Choice [1-6]: {C_RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        return ""

    if choice == "1":
        q = input(f"  {C_CYAN}Shodan query: {C_RESET}").strip()
        if q:
            return run_shodan_search(q)
    elif choice == "2":
        ip = input(f"  {C_CYAN}Target IP: {C_RESET}").strip()
        if ip:
            return run_shodan_host(ip)
    elif choice == "3":
        ip = input(f"  {C_CYAN}Target IP: {C_RESET}").strip()
        if ip:
            return run_shodan_vulns(ip)
    elif choice == "4":
        q = input(f"  {C_CYAN}Exploit query: {C_RESET}").strip()
        if q:
            exploits = sr.search_exploits(q)
            output = f"[SHODAN EXPLOITS: {q}]\n"
            for ex in exploits:
                output += f"  - [{ex['source']}] {ex['description']}\n"
                if ex.get("cve"):
                    output += f"    CVEs: {', '.join(ex['cve'])}\n"
            return output
    elif choice == "5":
        q = input(f"  {C_CYAN}Pipeline query: {C_RESET}").strip()
        if q:
            return sr.auto_pipeline(q)
    elif choice == "6":
        cidr = input(f"  {C_CYAN}CIDR range (e.g. 83.166.241.0/24): {C_RESET}").strip()
        if cidr:
            return run_shodan_range(cidr)

    return "[!] Cancelled\n"


# ═══════════════════════════════════════════════
# v8.1: RANGE / SUBNET SCANNING
# ═══════════════════════════════════════════════

def run_shodan_range(cidr: str) -> str:
    """[TOOL: shodan range 83.166.241.0/24] — scan entire subnet.
    Uses Shodan 'net:CIDR' search filter."""
    sr = ShodanRecon()
    if not sr.api:
        return "[!] Shodan API not available. Set SHODAN_API_KEY in .env\n"

    # Normalize: accept both '83.166.241.0/24' and 'net:83.166.241.0/24'
    cidr = cidr.strip()
    if cidr.startswith("net:"):
        query = cidr
    else:
        query = f"net:{cidr}"

    print(f"\n  {C_MAGENTA}[SHODAN RANGE SCAN] {cidr}{C_RESET}")

    results = sr.search(query, max_results=200)
    if results.get("error") or not results.get("matches"):
        return f"[Shodan] No hosts found in range {cidr}\n"

    output = sr.format_for_llm(results)
    targets = sr.format_for_pipeline(results)

    # Range summary
    output += f"\n[RANGE SUMMARY: {cidr}]\n"
    output += f"  Total hosts found: {len(targets)}\n"

    # Group by port for quick overview
    port_counts = {}
    for t in targets:
        for p in t.get("ports", []):
            port_counts[p] = port_counts.get(p, 0) + 1
    if port_counts:
        output += f"  Port distribution:\n"
        for port, count in sorted(port_counts.items(), key=lambda x: -x[1])[:15]:
            output += f"    {port}: {count} hosts\n"

    vuln_hosts = [t for t in targets if t.get("vulns")]
    if vuln_hosts:
        output += f"\n  [!] {len(vuln_hosts)} hosts with known CVEs:\n"
        for t in vuln_hosts[:10]:
            output += f"    {t['ip']}: {', '.join(t['vulns'][:5])}\n"

    output += f"\nAI: Range {cidr} scanned. Focus on vuln hosts for killchain.\n"
    return output


def run_shodan_smart(target: str) -> str:
    """v8.1: Auto-detect input type and route to correct handler.
    - 1.2.3.4        → host lookup
    - 1.2.3.0/24     → range scan
    - net:1.2.3.0/24 → range scan
    - port:22 text   → search query
    - anything else  → search query
    """
    import re as _re
    target = target.strip()

    # CIDR notation: 1.2.3.0/24
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', target):
        return run_shodan_range(target)

    # net: prefix
    if target.lower().startswith("net:"):
        return run_shodan_range(target)

    # Single IP
    if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return run_shodan_host(target)

    # Everything else = search query
    return run_shodan_search(target)


# ═══════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{C_RED}    OCTOPUS — Shodan Module Test{C_RESET}\n")
    sr = ShodanRecon()
    if sr.api:
        print(f"  {C_GREEN}[✓] API connected{C_RESET}")
        # Quick test: host info
        if len(sys.argv) > 1:
            target = sys.argv[1]
            import re
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                print(run_shodan_host(target))
            else:
                print(run_shodan_search(target))
        else:
            print(f"  Usage: python3 shodan_module.py <IP or query>")
    else:
        print(f"  {C_RED}[✗] API not available{C_RESET}")
