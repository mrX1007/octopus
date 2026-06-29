#!/usr/bin/env python3
"""Regression tests for AI evidence parsing."""


def test_ssh_session_output_seeds_credentials_service_and_privesc():
    from core.ai.evidence import OutputParser

    output = """
[*] SSH Post-Exploitation Analysis: support@83.166.241.164:22
[+] SSH connected as support@83.166.241.164
Known: support:qweqwe123

[+] Hostname
$ hostname; hostname -f 2>/dev/null || true
web01

[+] OS release
$ cat /etc/os-release 2>/dev/null | head -20
PRETTY_NAME="CentOS Linux 7 (Core)"

[+] Kernel
$ uname -r
3.10.0-1160.el7.x86_64

[+] SUID binaries
$ find / -perm -4000 -type f 2>/dev/null | head -80
/usr/bin/passwd
/usr/bin/sudo
"""

    facts = OutputParser().parse_tool_output("ssh_session", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("credential", "support:qweqwe123 (cached)") in pairs
    assert ("credential", "ssh_login_success:support@83.166.241.164") in pairs
    assert ("port_open", "22/tcp (ssh)") in pairs
    assert ("service_status", "ssh_authenticated") in pairs
    assert ("hostname", "web01") in pairs
    assert ("os_version", "CentOS Linux 7 (Core)") in pairs
    assert ("kernel_version", "3.10.0-1160.el7.x86_64") in pairs
    assert ("privesc_vector", "suid_binaries_present") in pairs


def test_ssh_controlled_inventory_output_becomes_post_access_facts():
    from core.ai.evidence import OutputParser

    output = """
[*] SSH Controlled Inventory: support@83.166.241.164:22
[+] SSH connected as support@83.166.241.164:22
[+] Controlled command allowlist: id, whoami, hostname, uname, ip addr, ss/netstat, sudo -n -l

[+] Identity
$ id
uid=1000(support) gid=1000(support)

[+] Hostname
$ hostname
web01

[+] Kernel
$ uname -a
Linux web01 5.15.0-91-generic x86_64 GNU/Linux

[+] Network addresses
$ ip -o addr show 2>/dev/null || ip addr show 2>/dev/null
2: eth0    inet 10.10.0.5/24 brd 10.10.0.255 scope global eth0

[+] Listening services
$ ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*

[+] Sudo rights
$ sudo -n -l 2>/dev/null || true
User support may run the following commands on web01:
    (ALL) NOPASSWD: /usr/bin/systemctl

[+] Runtime stack markers
$ command -v nginx apache2 httpd php php-fpm python3 node npm go java docker podman psql mysql redis-server mongod 2>/dev/null || true
/usr/sbin/nginx
/usr/bin/node
/usr/bin/docker
/usr/bin/psql

[+] Container runtime
$ docker ps --format '{{.Names}} {{.Image}} {{.Ports}}' 2>/dev/null | head -60
web nginx:latest 0.0.0.0:8080->80/tcp

[+] Web roots
$ find /var/www /srv /opt /home -maxdepth 3 -type d
/var/www/app/public
/srv/api/current

[+] App manifests
$ find /var/www /srv /opt /home -maxdepth 5 -type f
/var/www/app/package.json
/srv/api/requirements.txt

[+] Config candidates
$ find /var/www /srv /opt /home -maxdepth 5 -type f -printf '%p %s bytes\\n'
/var/www/app/.env 123 bytes
/srv/api/settings.py 456 bytes

[+] Scheduled tasks
$ find /etc/cron* /var/spool/cron -maxdepth 2 -type f
/etc/cron.d/app

[+] SSH inventory completed
"""

    facts = OutputParser().parse_tool_output("ssh_inventory 83.166.241.164", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("credential", "ssh_login_success:support@83.166.241.164") in pairs
    assert ("post_exploit_stage", "post_access_inventory_completed") in pairs
    assert ("service_status", "ssh_inventory_completed") in pairs
    assert ("hostname", "web01") in pairs
    assert ("kernel_version", "Linux web01 5.15.0-91-generic x86_64 GNU/Linux") in pairs
    assert ("internal_host", "10.10.0.5") in pairs
    assert ("internal_subnet", "10.10.0.5/24") in pairs
    assert ("local_listening_port", "22") in pairs
    assert ("app_stack", "nginx") in pairs
    assert ("app_stack", "nodejs") in pairs
    assert ("app_stack", "docker") in pairs
    assert ("app_stack", "postgresql") in pairs
    assert ("web_root", "/var/www/app/public") in pairs
    assert ("web_root", "/srv/api/current") in pairs
    assert ("app_manifest", "/var/www/app/package.json") in pairs
    assert ("app_manifest", "/srv/api/requirements.txt") in pairs
    assert ("config_candidate", "/var/www/app/.env") in pairs
    assert ("config_candidate", "/srv/api/settings.py") in pairs
    assert ("container_runtime", "containers_observed_or_runtime_present") in pairs
    assert ("scheduled_task_surface", "cron_or_systemd_timers_present") in pairs
    assert ("privesc_vector", "sudo_rights_present") in pairs


def test_privesc_output_confirms_root_pwnkit_and_post_exploit_state():
    from core.ai.evidence import OutputParser

    output = """
[KILL CHAIN] Stage 3: Privilege Escalation — support@83.166.241.164
Current: uid=1000(support) gid=1000(support)
[*] Deploying CVE-2021-4034 PwnKit exploit...
[→] SUID binaries... ← EXPLOITABLE SUID!
    /usr/bin/pkexec
[+] ROOT via pre-compiled PwnKit!
PwnKit binary output: uid=0(root) gid=0(root)
[+] Extracted /etc/shadow (762 bytes)
root:$6$hash
[+] SSH key injected for root — VERIFIED
[+] ✓ ROOT ACCESS CONFIRMED
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("exploit_success", "CVE-2021-4034 PwnKit root access") in pairs
    assert ("vulnerability", "CVE-2021-4034") in pairs
    assert ("system_access", "uid=0") in pairs
    assert ("system_access", "root_access_confirmed") in pairs
    assert ("credential", "ssh_login_success:support@83.166.241.164") in pairs
    assert ("port_open", "22/tcp (ssh)") in pairs
    assert ("privesc_vector", "suid_pkexec") in pairs
    assert ("credential_material", "shadow_file_extracted") in pairs
    assert ("data_exfiltration", "shadow_file_extracted") not in pairs
    assert ("persistence", "ssh_key_injected") in pairs
    assert ("credential", "ssh_key_available:root@83.166.241.164") in pairs


def test_cpanel_sniper_output_becomes_app_access_not_ssh_root():
    from core.ai.evidence import OutputParser

    output = """
║  CVE-2026-41940 — cPanel/WHM Auth Bypass         ║
  Target:   https://67.215.12.67:2087
  Status:   VULNERABLE
  Token:    /cpsess3282187461
  Session:  :nllWuSD9KpP7C1kL
  Version:  11.120.0.11
  API URL:  https://67.215.12.67:2087/cpsess3282187461/json-api/version

  TARGET IS VULNERABLE — authenticated session obtained
  Cookie:      whostmgrsession=:nllWuSD9KpP7C1kL
"""

    facts = OutputParser().parse_tool_output("cpanel_exploit 67.215.12.67", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "2087/tcp (cpanel) [cPanel/WHM]") in pairs
    assert ("web_surface", "cpanel_whm:2087") in pairs
    assert ("credential", "whm_session:nllWuSD9KpP7C1kL") in pairs
    assert ("application_access", "cpanel_whm_authenticated") in pairs
    assert ("system_access", "root_access_confirmed") not in pairs


def test_exfil_stage_output_marks_exfiltration_completed():
    from core.ai.evidence import OutputParser

    output = """
[KILL CHAIN — DATA EXFILTRATION — root@83.166.241.164:22]
============================================================
[+] EXFIL: /etc/passwd -> /loot/passwd (1200 bytes)
Files exfiltrated: 1
Exfil directory: /Users/admin/OCTOPUS/loot/83_166_241_164
Total data: 1,200 bytes
[+] Target report saved: /Users/admin/OCTOPUS/loot/83_166_241_164/report.txt
"""

    facts = OutputParser().parse_tool_output("killchain_exfil 83.166.241.164", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("data_exfiltration", "files_exfiltrated:1") in pairs
    assert ("data_exfiltration", "loot_collected") in pairs
    assert ("post_exploit_stage", "data_exfiltration_completed") in pairs
    assert ("loot_artifact", "exfil_directory_created") in pairs
    assert ("loot_artifact", "target_report_saved") in pairs


def test_shardbrowser_surface_output_becomes_web_facts():
    from core.ai.evidence import OutputParser

    output = """
[ShardX Direct Browse - https://example.test]
URL: https://example.test
Content size: 4123 bytes
Page title: Example Admin Portal
Forms: 1
  form_action: /login
Input fields: 2
  input: text:username
  input: password:password
  link: /admin
"""

    facts = OutputParser().parse_tool_output("browser_surface_analysis", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("browser_rendered", "https://example.test") in pairs
    assert ("web_title", "Example Admin Portal") in pairs
    assert ("web_surface", "rendered_bytes:4123") in pairs
    assert ("web_surface", "forms:1") in pairs
    assert ("web_surface", "login_form_detected") in pairs
    assert ("web_input", "password:password") in pairs
    assert ("web_link", "/admin") in pairs


def test_ffuf_and_http_headers_become_web_surface_facts():
    from core.ai.evidence import OutputParser

    ffuf_output = """
_reports                [Status: 301, Size: 162, Words: 5, Lines: 8]
admin                   [Status: 403, Size: 312, Words: 12, Lines: 10]
"""
    headers_output = """
[Headers: http://10.0.0.5:3000]
HTTP/1.1 302 Found
Server: nginx/1.24.0
Location: /login
X-Powered-By: Express
"""

    parser = OutputParser()
    facts = parser.parse_tool_output("ffuf http://10.0.0.5:3000", ffuf_output)
    facts += parser.parse_tool_output("curl_headers http://10.0.0.5:3000", headers_output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("web_path", "/_reports:301") in pairs
    assert ("web_path", "/admin:403") in pairs
    assert ("web_server", "nginx/1.24.0") in pairs
    assert ("web_redirect", "/login") in pairs
    assert ("web_powered_by", "Express") in pairs


def test_internal_network_recon_output_becomes_pivot_facts():
    from core.ai.evidence import OutputParser

    output = """
[NETWORK DISCOVERY]
[SUMMARY]
  Subnets: 10.10.0.5/24, 172.16.4.10/24
  Hosts:   3 unique IPs discovered
    -> 10.10.0.1
    -> 10.10.0.23
Internal hosts discovered: 2
"""

    facts = OutputParser().parse_tool_output("network_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("internal_subnet", "10.10.0.5/24") in pairs
    assert ("internal_subnet", "172.16.4.10/24") in pairs
    assert ("internal_host", "10.10.0.1") in pairs
    assert ("internal_host", "10.10.0.23") in pairs
    assert ("internal_network", "hosts_discovered:2") in pairs


def test_failed_killchain_banner_does_not_create_root_login_fact():
    from core.ai.evidence import OutputParser

    output = """
[KILL CHAIN] Stage 3: Privilege Escalation — root@83.166.241.164
[!] SSH connection failed: Auth failed: root:None@83.166.241.164
"""

    facts = OutputParser().parse_tool_output("killchain_privesc 83.166.241.164", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("credential", "ssh_login_success:root@83.166.241.164") not in pairs
    assert ("service_status", "ssh_authenticated") not in pairs
    assert ("service_status", "ssh_auth_failed:root@83.166.241.164") in pairs


def test_session_id_parser_ignores_tool_menu_numbers():
    from core.ai.evidence import OutputParser

    output = """
[+] Session created -- SL# 33
  [18] ssh_session
  [19] vuln assess
[KILL CHAIN] Stage 3: Privilege Escalation — support@83.166.241.164
PwnKit binary output: uid=0(root) gid=0(root)
[+] ✓ ROOT ACCESS CONFIRMED
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("credential", "ssh_login_success:support@83.166.241.164") in pairs
    assert {fact["session_id"] for fact in facts} == {"33"}


def test_patched_ssh_user_enum_does_not_become_vulnerability():
    from core.ai.evidence import OutputParser

    output = """
[*] SSH User Enumeration (CVE-2018-15473): 83.166.241.164:22
[*] Phase 1: Testing 4 canary users for false-positive detection...
[+] VALID USER: admin
[+] VALID USER: root
[+] VALID USER: aaa_fake_user_m7k
[!] ALL 4 canary users returned valid (including fake names)
[!] Server is PATCHED — aborting full enumeration
CVE-2018-15473 — ALL users return valid.
"""

    facts = OutputParser().parse_tool_output("ssh_user_enum 83.166.241.164", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("potential_vulnerability", "CVE-2018-15473") not in pairs
    assert not any(ftype == "exploit_attempted" and "CVE-2018-15473" in value for ftype, value in pairs)
    assert ("service_status", "ssh_user_enum_unreliable_or_patched") in pairs


def test_exploit_selection_output_becomes_candidate_facts():
    from core.ai.evidence import OutputParser

    output = """
[EXPLOIT SELECTION - 10.0.0.5]
Services analyzed: 1
[EXPLOIT CANDIDATE 1] http:80 Apache httpd 2.4.49 -> exploit/multi/http/apache_normalize_path_rce (version_map; matched 'apache 2.4.49')
  Payload recommendation: generic/shell_reverse_tcp
  MSF check: msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
  MSF run gated: msf_run 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
"""

    facts = OutputParser().parse_tool_output("exploit_select 10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert (
        "exploit_candidate",
        "exploit/multi/http/apache_normalize_path_rce on http:80 [Apache httpd 2.4.49]",
    ) in pairs
    assert ("msf_module", "exploit/multi/http/apache_normalize_path_rce") in pairs
    assert ("payload_recommendation", "generic/shell_reverse_tcp") in pairs
    assert (
        "verification_command",
        "msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80",
    ) in pairs


def test_msf_check_output_becomes_verification_fact():
    from core.ai.evidence import OutputParser

    output = """
[*] Running check method for exploit/multi/http/apache_normalize_path_rce
[+] The target appears to be vulnerable.
"""

    facts = OutputParser().parse_tool_output(
        "msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("vulnerability", "msf_check_positive:exploit/multi/http/apache_normalize_path_rce") in pairs
    assert ("msf_module", "exploit/multi/http/apache_normalize_path_rce") in pairs


def test_manual_recon_nmap_table_becomes_ports_and_versions():
    from core.ai.evidence import OutputParser

    output = """
[ NMAP OUTPUT ]
21/tcp   open  ftp        Pure-FTPd
80/tcp   open  http       Golang net/http server
2087/tcp open  ssl/http   cPanel WHM
3000/tcp filtered http
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
Service Info: Host: test-app.example
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "21/tcp (ftp) [Pure-FTPd]") in pairs
    assert ("port_open", "2087/tcp (ssl/http) [cPanel WHM]") in pairs
    assert ("port_filtered", "3000/tcp (http)") in pairs
    assert ("service_version", "postgresql:5432:PostgreSQL DB 9.6.0 or later") in pairs
    assert ("hostname", "test-app.example") in pairs


def test_protocol_action_outputs_become_service_facts():
    from core.ai.evidence import OutputParser

    ftp_output = """
[FTP Anonymous Check - 10.0.0.5:21]
Banner: 220 Pure-FTPd
Anonymous login: allowed
Entries (2):
  pub
  backups
"""
    smtp_output = """
[SMTP Probe - 10.0.0.5:587]
Banner: 220 b'mail.example ESMTP Postfix'
EHLO code: 250
STARTTLS: supported
AUTH mechanisms: PLAIN LOGIN
Open relay test: not_performed
"""
    db_output = """
[DB Inventory - postgresql 10.0.0.5:5432]
Using credential: postgres@10.0.0.5
DB inventory completed: postgresql
Version: PostgreSQL 15.4 on x86_64-pc-linux-gnu
Current user: postgres
Databases (2):
  postgres
  appdb
"""

    parser = OutputParser()
    facts = parser.parse_tool_output("ftp_anonymous_check 10.0.0.5 21", ftp_output)
    facts += parser.parse_tool_output("smtp_probe 10.0.0.5 587", smtp_output)
    facts += parser.parse_tool_output("db_inventory 10.0.0.5 5432 postgresql", db_output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("vulnerability", "ftp_anonymous_login_allowed:10.0.0.5:21") in pairs
    assert ("service_status", "ftp_anonymous_allowed:21") in pairs
    assert ("credential", "ftp_anonymous:anonymous@10.0.0.5:21") in pairs
    assert ("service_status", "smtp_probe_completed:587") in pairs
    assert ("service_status", "smtp_starttls_supported:587") in pairs
    assert ("service_status", "smtp_auth_mechanisms:587:PLAIN,LOGIN") in pairs
    assert ("service_status", "db_inventory_completed:postgresql:5432") in pairs
    assert ("service_version", "postgresql:5432:PostgreSQL 15.4 on x86_64-pc-linux-gnu") in pairs
    assert ("database_inventory", "current_user:postgresql:postgres") in pairs
    assert ("database_inventory", "databases:postgresql:2") in pairs


def test_exploit_selection_active_msf_run_is_gated_fact():
    from core.ai.evidence import OutputParser

    output = """
[EXPLOIT CANDIDATE 1] http:80 Apache httpd 2.4.49 -> exploit/multi/http/apache_normalize_path_rce (version_map; matched 'apache 2.4.49')
  Payload recommendation: generic/shell_reverse_tcp
  MSF check: msf_check 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
  MSF run gated: msf_run 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80
"""

    facts = OutputParser().parse_tool_output("exploit_select 10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert (
        "active_command",
        "msf_run 10.0.0.5 exploit/multi/http/apache_normalize_path_rce RHOSTS=10.0.0.5 RPORT=80",
    ) in pairs


def test_web_tool_outputs_become_pipeline_facts():
    from core.ai.evidence import OutputParser

    output = """
[+] WordPress version 6.2 identified
[!] Title: Plugin Vulnerability
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1
[+] parameter 'id' appears to be injectable
Apache Tomcat JMX Proxy is accessible without authentication - vulnerable
"""

    facts = OutputParser().parse_tool_output("wpscan sqlmap jmx2rce_scan", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_version", "WordPress 6.2") in pairs
    assert ("potential_vulnerability", "wordpress_wpscan_findings") in pairs
    assert ("vulnerability", "sql_injection:id") in pairs
    assert ("vulnerability", "tomcat_jmx_proxy_exposed") in pairs


def test_plugin_json_and_payload_artifacts_become_facts():
    from core.ai.evidence import OutputParser

    plugin_output = """
{
  "plugin": "cpanel_auth_bypass",
  "success": true,
  "data": {"status": "vulnerable"},
  "artifacts": ["/tmp/report.json"],
  "credentials": [],
  "sessions": [{"type": "cpanel", "session": "cpsess123"}],
  "error": ""
}

--- plugin output ---
scan completed
"""
    artifact_output = """
[+] Python implant generated: /Users/admin/Downloads/Octopus2/data/generated/implant_python.py
Size: 1234 bytes
C2: http://127.0.0.1:8443
"""

    facts = OutputParser().parse_tool_output("plugin cpanel_auth_bypass 10.0.0.5 scan", plugin_output)
    facts += OutputParser().parse_tool_output("build_python_implant", artifact_output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("plugin_result", "cpanel_auth_bypass:success") in pairs
    assert ("plugin_artifact", "/tmp/report.json") in pairs
    assert ("credential", "cpanel_session:cpsess123") in pairs
    assert ("vulnerability", "cpanel_auth_bypass_confirmed") in pairs
    assert (
        "payload_artifact",
        "python_implant:/Users/admin/Downloads/Octopus2/data/generated/implant_python.py",
    ) in pairs
    assert ("c2_profile", "http://127.0.0.1:8443") in pairs


def test_mixed_plugin_json_keeps_structured_facts_when_regex_matches_cve():
    from core.ai.evidence import OutputParser

    output = """
{
  "plugin": "cpanel_auth_bypass",
  "success": true,
  "data": {"status": "vulnerable", "cve": "CVE-2026-41940"},
  "artifacts": ["/tmp/cpanel.json"],
  "sessions": [{"type": "cpanel", "session": "cpsess456"}],
  "error": ""
}

--- plugin output ---
CVE-2026-41940 detected during scan
"""

    facts = OutputParser().parse_tool_output("plugin cpanel_auth_bypass 10.0.0.5 scan", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("potential_vulnerability", "CVE-2026-41940") in pairs
    assert ("plugin_result", "cpanel_auth_bypass:success") in pairs
    assert ("plugin_artifact", "/tmp/cpanel.json") in pairs
    assert ("credential", "cpanel_session:cpsess456") in pairs
    assert ("vulnerability", "cpanel_auth_bypass_confirmed") in pairs


def test_legacy_killchain_stage_outputs_become_stage_status_facts():
    from core.ai.evidence import OutputParser

    vuln_output = """
[KILL CHAIN -- VULNERABILITY ASSESSMENT -- 10.0.0.5]
Total exploitable findings: 2
"""
    exploit_output = """
[KILL CHAIN -- EXPLOITATION -- 10.0.0.5]
Exploits attempted: 3 | Succeeded: 1
"""
    blocked_output = "[!] Data exfiltration requires valid SSH credentials for 10.0.0.5."

    parser = OutputParser()
    facts = parser.parse_tool_output("killchain_vuln_assess 10.0.0.5", vuln_output)
    facts += parser.parse_tool_output("killchain_exploit 10.0.0.5", exploit_output)
    facts += parser.parse_tool_output("killchain_exfil 10.0.0.5", blocked_output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("stage_status", "vulnerability_assessment:findings:2") in pairs
    assert ("potential_vulnerability", "killchain_findings:2") in pairs
    assert ("stage_status", "exploitation:attempted:3:succeeded:1") in pairs
    assert ("exploit_success", "killchain_auto_exploit_success") in pairs
    assert ("stage_status", "data_exfiltration:blocked_missing_credentials") in pairs


def test_internal_network_parser_filters_public_and_boundary_hosts():
    from core.ai.evidence import OutputParser

    output = """
[NETWORK DISCOVERY]
[SUMMARY]
  Subnets: 83.166.241.164/20, 10.10.0.5/24, 169.254.0.0/16
    -> 83.166.241.164
    -> 10.10.0.0
    -> 10.10.0.23
    -> 10.10.0.255
    -> 169.254.169.254
Internal hosts discovered: 5
"""

    facts = OutputParser().parse_tool_output("network_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("internal_subnet", "83.166.241.164/20") not in pairs
    assert ("internal_subnet", "10.10.0.5/24") in pairs
    assert ("internal_subnet", "169.254.0.0/16") in pairs
    assert ("internal_host", "83.166.241.164") not in pairs
    assert ("internal_host", "10.10.0.0") not in pairs
    assert ("internal_host", "10.10.0.23") in pairs
    assert ("internal_host", "10.10.0.255") not in pairs
    assert ("internal_host", "169.254.169.254") in pairs


def test_active_directory_outputs_become_domain_facts():
    from core.ai.evidence import OutputParser

    output = """
[AD ENUMERATION — 10.10.10.5]
[AD USERS]
  (via ldap3 — 12 users)
  administrator  (adminCount=1 | displayName=Admin)
[AD GROUPS]
  (via ldap3 — 4 groups)
  Domain Admins  (member=CN=Administrator)
[AD COMPUTERS]
  (via ldap3 — 7 computers)
Domain Name: CORP.LOCAL
AI: AD enumeration complete.
"""

    facts = OutputParser().parse_tool_output("ad_enum 10.10.10.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("ad_enumeration", "completed") in pairs
    assert ("ad_users", "count:12") in pairs
    assert ("ad_groups", "count:4") in pairs
    assert ("ad_computers", "count:7") in pairs
    assert ("ad_domain", "CORP.LOCAL") in pairs
    assert ("ad_high_value_object", "privileged_group_or_admincount_present") in pairs


def test_kerberos_and_dcsync_outputs_become_credential_material_facts():
    from core.ai.evidence import OutputParser

    output = """
[AS-REP ROAST — 10.10.10.5]
[+] 2 AS-REP hash(es) extracted -> /loot/asrep_hashes.txt
$krb5asrep$23$user@CORP.LOCAL:abcd
[KERBEROAST — 10.10.10.5]
[+] 3 Kerberoast hash(es) extracted -> /loot/kerberoast_hashes.txt
$krb5tgs$23$*svc/http
[DCSYNC — 10.10.10.5]
[+] DCSync successful — 42 hash(es) extracted
"""

    facts = OutputParser().parse_tool_output("kerberos_assessment", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("kerberos_hashes", "asrep_count:2") in pairs
    assert ("credential_material", "asrep_hash_file:/loot/asrep_hashes.txt") in pairs
    assert ("kerberos_hashes", "kerberoast_count:3") in pairs
    assert ("credential_material", "kerberoast_hash_file:/loot/kerberoast_hashes.txt") in pairs
    assert ("domain_hash_dump", "count:42") in pairs


def test_hash_cracking_output_marks_credentials_without_leaking_password_fact():
    from core.ai.evidence import OutputParser

    output = """
[HASH CRACKER -- LOCAL GPU CRACKING]
[Phase 1: Hash Analysis]
  Crackable hashes: 2
[CRACKING RESULTS]
  Total hashes:   2
  Cracked:        1
  CRACKED CREDENTIALS:
    + root:toor
AI: 1/2 hashes cracked. Use cracked credentials for SSH login.
"""

    facts = OutputParser().parse_tool_output("crack_hashes 10.10.10.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("hash_material", "crackable:2") in pairs
    assert ("hash_cracking", "cracked:1/2") in pairs
    assert ("credential", "cracked_credentials:1") in pairs
    assert ("credential", "cracked_password_for:root") in pairs
    assert ("credential", "root:toor") not in pairs


def test_low_value_failed_structured_facts_are_sanitized():
    from core.ai.evidence import OutputParser

    output = """
{
  "facts": [
    {"type": "target_host", "value": "83.166.241.164", "confidence": 90},
    {"type": "connection_status", "value": "Failed", "confidence": 90},
    {"type": "scan_status", "value": "skipped", "confidence": 90},
    {"type": "port_open", "value": "22/tcp", "confidence": 90}
  ]
}
"""

    facts = OutputParser().parse_tool_output("killchain_persist", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("target_host", "83.166.241.164") not in pairs
    assert ("connection_status", "Failed") not in pairs
    assert ("scan_status", "skipped") not in pairs
    assert ("port_open", "22/tcp") in pairs
