#!/usr/bin/env python3
"""Regression tests for AI evidence parsing."""


def test_ssh_session_output_seeds_credentials_service_and_privesc():
    from core.ai.evidence import OutputParser

    output = """
[*] SSH Post-Exploitation Analysis: support@83.166.241.164:22
[+] SSH connected as support@83.166.241.164
Known: support:fixture-password-123

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

    assert ("credential", "support:fixture-password-123 (cached)") in pairs
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

[+] Software versions
$ (nginx -v 2>&1 || true); (apache2 -v 2>&1 || true); (php -v 2>/dev/null | head -1 || true); (python3 --version 2>&1 || true); (node --version 2>&1 || true); (psql --version 2>&1 || true)
nginx version: nginx/1.14.0
Server version: Apache/2.4.29 (Ubuntu)
PHP 7.2.24-0ubuntu0.18.04.17 (cli)
Python 3.8.10
v16.20.2
psql (PostgreSQL) 14.11

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
    assert ("service_version", "nginx:local:nginx/1.14.0") in pairs
    assert ("service_version", "apache:local:Apache/2.4.29 (Ubuntu)") in pairs
    assert ("service_version", "php:local:PHP 7.2.24-0ubuntu0.18.04.17 (cli)") in pairs
    assert ("service_version", "python:local:Python 3.8.10") in pairs
    assert ("service_version", "nodejs:local:v16.20.2") in pairs
    assert ("service_version", "postgresql:local:psql (PostgreSQL) 14.11") in pairs
    assert ("web_root", "/var/www/app/public") in pairs
    assert ("web_root", "/srv/api/current") in pairs
    assert ("app_manifest", "/var/www/app/package.json") in pairs
    assert ("app_manifest", "/srv/api/requirements.txt") in pairs
    assert ("config_candidate", "/var/www/app/.env") in pairs
    assert ("config_candidate", "/srv/api/settings.py") in pairs
    assert ("container_runtime", "containers_observed_or_runtime_present") in pairs
    assert ("scheduled_task_surface", "cron_or_systemd_timers_present") in pairs
    assert ("privesc_vector", "sudo_rights_present") in pairs


def test_ssh_inventory_sudo_rights_at_uid_zero_are_post_access_context_not_privesc():
    from core.ai.evidence import OutputParser

    output = """
[*] SSH Controlled Inventory: root@10.0.0.5:22
[+] SSH connected as root@10.0.0.5:22

[+] Identity
$ id
uid=0(root) gid=0(root)

[+] Sudo rights
$ sudo -n -l 2>/dev/null || true
User root may run the following commands on web01:
    (ALL) NOPASSWD: ALL

[+] SSH inventory completed
"""

    facts = OutputParser().parse_tool_output("ssh_inventory 10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("privilege_context", "already_root") in pairs
    assert ("post_access_note", "sudo_rights_present") in pairs
    assert ("privesc_vector", "sudo_rights_present") not in pairs


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


def test_exfil_stage_output_indexes_loot_manifest_artifacts():
    from core.ai.evidence import OutputParser

    output = """
[KILL CHAIN — DATA EXFILTRATION — root@10.0.0.5:22]
[+] EXFIL: /var/www/app/.env -> /loot/env_var_www_app_.env (123 bytes)
[+] EXFIL: /root/.ssh/authorized_keys -> /loot/root_authorized_keys (2048 bytes)
    ← CREDENTIALS in file
Files exfiltrated: 2
Exfil directory: /loot/10_0_0_5
Total data: 2,171 bytes
"""

    facts = OutputParser().parse_tool_output("killchain_exfil 10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("loot_artifact", "file:/var/www/app/.env") in pairs
    assert ("loot_artifact", "local_copy:/loot/env_var_www_app_.env") in pairs
    assert ("config_candidate", "/var/www/app/.env") in pairs
    assert ("credential_material", "ssh_material:/root/.ssh/authorized_keys") in pairs
    assert ("credential_material", "sensitive_material_observed_in_loot") in pairs
    assert ("loot_artifact", "total_bytes:2171") in pairs


def test_manual_recon_web_ports_detected_becomes_open_port_fact():
    from core.ai.evidence import OutputParser

    output = """
[+] Recon complete.
  [*] Web ports detected ['80'] — running extended web tools...
  [*] Scrapling: http://10.0.0.5
Title: Welcome to nginx!
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "80/tcp (http)") in pairs
    assert ("web_title", "Welcome to nginx!") in pairs


def test_timestamped_nmap_output_becomes_ports_and_versions():
    from core.ai.evidence import OutputParser

    output = """
[144s] 22/tcp    open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.6
[144s] 80/tcp    open  http        nginx 1.14.0 (Ubuntu)
[144s] 443/tcp   open  ssl/http    nginx 1.14.0 (Ubuntu)
[144s] 5432/tcp  open  postgresql  PostgreSQL DB 14.1 - 14.6
[144s] 3000/tcp  filtered ppp
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("port_open", "22/tcp (ssh) [OpenSSH 7.6p1 Ubuntu 4ubuntu0.6]") in pairs
    assert ("service_version", "ssh:22:OpenSSH 7.6p1 Ubuntu 4ubuntu0.6") in pairs
    assert ("port_open", "80/tcp (http) [nginx 1.14.0 (Ubuntu)]") in pairs
    assert ("port_open", "5432/tcp (postgresql) [PostgreSQL DB 14.1 - 14.6]") in pairs
    assert ("port_filtered", "3000/tcp (ppp)") in pairs


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


def test_failed_browser_surface_does_not_mark_rendered():
    from core.ai.evidence import OutputParser

    output = """
[Browser Surface Fallback - http://77.105.177.122]
URL: http://77.105.177.122
ShardBrowser status: [!] ShardBrowser not ready: missing engine
Fallback: scrapling/requests

[!] Requests fallback failed: HTTPConnectionPool(host='77.105.177.122', port=80)
[!] All scrapling/requests attempts failed for http://77.105.177.122.
"""

    facts = OutputParser().parse_tool_output("browser_surface_analysis", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("browser_rendered", "http://77.105.177.122") not in pairs
    assert ("service_status", "web_fetch_failed:http://77.105.177.122") in pairs


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


def test_web_endpoint_parser_normalizes_url_tool_output():
    import json

    from core.ai.evidence import OutputParser

    output = """
[REQUESTS+BS4 RESULT - https://10.0.0.5:43117/login?next=admin]
Status: 200
Title: Login
"""

    facts = OutputParser().parse_tool_output("scrapling https://10.0.0.5:43117/login?next=admin", output)
    endpoints = [json.loads(fact["value"]) for fact in facts if fact["type"] == "web_endpoint"]

    assert {
        "url": "https://10.0.0.5:43117/login?next=admin",
        "scheme": "https",
        "host": "10.0.0.5",
        "port": "43117",
        "path": "/login",
        "service": "",
        "status": "",
        "title": "",
    } in endpoints


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
    assert ("vulnerability_endpoint", "msf_check_positive:exploit/multi/http/apache_normalize_path_rce:80") in pairs


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


def test_auxiliary_login_candidate_does_not_emit_active_command():
    from core.ai.evidence import OutputParser

    output = """
[EXPLOIT CANDIDATE 1] ssh:22 OpenSSH 7.4 -> auxiliary/scanner/ssh/ssh_login (version_map; matched 'openssh 7.4')
  Payload recommendation: none/check-only
  MSF check: msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RHOSTS=10.0.0.5 RPORT=22
  MSF run gated: msf_run 10.0.0.5 auxiliary/scanner/ssh/ssh_login RHOSTS=10.0.0.5 RPORT=22
"""

    facts = OutputParser().parse_tool_output("exploit_select 10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert (
        "verification_command",
        "msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RHOSTS=10.0.0.5 RPORT=22",
    ) in pairs
    assert not any(ftype == "active_command" for ftype, _value in pairs)


def test_msf_login_success_timeout_is_login_status_not_vulnerability():
    from core.ai.evidence import OutputParser

    output = """
[*] MSF Module: auxiliary/scanner/ssh/ssh_login
[MSF 13s] [+] 10.0.0.5:22     - Success: 'support:qweqwe123' ''
[MSF 23s] [-] 10.0.0.5:22     - Failed to setup the session - Net::SSH::Exception Unknown platform: unknown
[TIMEOUT] MSF killed after 60s
"""

    facts = OutputParser().parse_tool_output(
        "msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RHOSTS=10.0.0.5 RPORT=22",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_status", "msf_login_check_success:auxiliary/scanner/ssh/ssh_login:22") in pairs
    assert ("credential", "ssh_login_success:support@10.0.0.5") in pairs
    assert ("service_status", "ssh_authenticated") in pairs
    assert ("port_open", "22/tcp (ssh)") in pairs
    assert not any(ftype == "password" or value == "qweqwe123" for ftype, value in pairs)
    assert not any(ftype == "vulnerability" and "ssh_login" in value for ftype, value in pairs)


def test_nmap_filtered_output_does_not_fall_back_to_llm_ports():
    from core.ai.evidence import OutputParser

    parser = OutputParser()

    def fail_llm(*_args, **_kwargs):
        raise AssertionError("nmap output should be owned by deterministic parsers")

    parser.llm_extractor.parse = fail_llm
    facts = parser.parse_tool_output(
        "nmap -Pn -sV 10.0.0.5",
        "Nmap scan report for 10.0.0.5\nNot shown: 999 filtered tcp ports (no-response)\n",
    )

    assert not any(fact["type"] == "port_open" for fact in facts)


def test_msf_runtime_stack_trace_becomes_error_status_not_vulnerability():
    from core.ai.evidence import OutputParser

    output = """
[*] MSF Module: exploit/linux/redis/redis_replication_cmd_exec
[MSF 0s]    12 /usr/lib/ruby/3.4.0/rubygems/errors.rb
[MSF 0s]    49 /usr/lib/ruby/3.4.0/bundler/errors.rb
[MSF 0s]   123 /opt/metasploit/vendor/bundle/ruby/3.4.0/gems/psych-5.2.6/lib/psych/syntax_error.rb
"""

    facts = OutputParser().parse_tool_output(
        "msf_check 10.0.0.5 exploit/linux/redis/redis_replication_cmd_exec RHOSTS=10.0.0.5 RPORT=49161",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_status", "msf_check_error:exploit/linux/redis/redis_replication_cmd_exec") in pairs
    assert not any(ftype == "vulnerability" for ftype, _value in pairs)


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

    facts = OutputParser().parse_tool_output("wpscan sqlmap jmx2rce_scan http://10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_version", "WordPress 6.2") in pairs
    assert ("potential_vulnerability", "wordpress_wpscan_findings") in pairs
    assert ("vulnerability", "sql_injection:id") in pairs
    assert ("vulnerability", "tomcat_jmx_proxy_exposed") in pairs
    assert ("vulnerability_endpoint", "tomcat_jmx_proxy_exposed:http://10.0.0.5") in pairs


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


def test_active_directory_review_outputs_become_structured_security_facts():
    from core.ai.evidence import OutputParser

    output = """
[AD SECURITY REVIEW]
Domain Name: CORP.LOCAL
BloodHound data collected -> /loot/corp/bloodhound
Shortest paths to Domain Admins: 3
Local Admin Paths: 4
High Value Targets: 6
User: CORP\\svc-web
Minimum password length: 8
Password history length: 24
Lockout threshold: 0
Unconstrained delegation: WEB01$
Resource-Based Constrained Delegation: APP01 -> WEB01
ESC1: vulnerable template UserAuth allows enrollee supplies subject
GPO issue: local admins configured through legacy policy
GenericAll -> CORP\\Helpdesk
WriteDacl on CORP\\Domain Admins
"""

    facts = OutputParser().parse_tool_output("ad_security_review 10.10.10.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("ad_domain", "CORP.LOCAL") in pairs
    assert ("ad_graph_data", "/loot/corp/bloodhound") in pairs
    assert ("ad_attack_path", "domain_admin_paths:3") in pairs
    assert ("ad_local_admin_path", "count:4") in pairs
    assert ("ad_high_value_object", "count:6") in pairs
    assert ("ad_object", "CORP\\svc-web") in pairs
    assert ("ad_password_policy", "min_length:8") in pairs
    assert ("ad_password_policy", "lockout_threshold:0") in pairs
    assert ("ad_gpo_issue", "weak_password_min_length:8") in pairs
    assert ("ad_gpo_issue", "account_lockout_disabled") in pairs
    assert ("ad_delegation", "WEB01$") in pairs
    assert ("ad_delegation", "unconstrained_delegation_present") in pairs
    assert any(ftype == "ad_adcs_issue" and value.startswith("ESC1:") for ftype, value in pairs)
    assert ("ad_gpo_issue", "local admins configured through legacy policy") in pairs
    assert ("ad_acl_issue", "GenericAll:CORP\\Helpdesk") in pairs
    assert any(ftype == "ad_acl_issue" and value.startswith("WriteDacl:") for ftype, value in pairs)


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
    + root:fixture-password-123
AI: 1/2 hashes cracked. Use cracked credentials for SSH login.
"""

    facts = OutputParser().parse_tool_output("crack_hashes 10.10.10.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("hash_material", "crackable:2") in pairs
    assert ("hash_cracking", "cracked:1/2") in pairs
    assert ("credential", "cracked_credentials:1") in pairs
    assert ("credential", "cracked_password_for:root") in pairs
    assert ("credential", "root:fixture-password-123") not in pairs


def test_negative_evidence_from_timeouts_and_unconfirmed_checks():
    from core.ai.evidence import OutputParser

    output = """
[TIMEOUT] nuclei killed after 300s
[WARNING] no usable links found (with GET parameters)
[!] Shodan host error: No information available for that IP.
[GRAPHQL CHECK - http://10.0.0.5/graphql]
No response from endpoint
"""

    facts = OutputParser().parse_tool_output(
        "nuclei_safe sqlmap shodan graphql_check http://10.0.0.5",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_status", "tool_timeout:nuclei_safe") in pairs
    assert ("service_status", "sqlmap_no_get_parameters_found") in pairs
    assert ("service_status", "external_intel_no_host_information:shodan") in pairs
    assert ("service_status", "graphql_introspection_not_confirmed") in pairs


def test_manual_recon_timeout_preserves_actual_tool_names():
    from core.ai.evidence import OutputParser

    output = """
[TIMEOUT] nuclei killed after 300s
[TIMEOUT] nikto killed after 300s
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_status", "tool_timeout:nuclei") in pairs
    assert ("service_status", "tool_timeout:nikto") in pairs
    assert ("service_status", "tool_timeout:manual_recon") not in pairs


def test_nikto_and_nuclei_statuses_create_typed_check_results():
    import json

    from core.ai.evidence import OutputParser

    output = """
[NIKTO - http://10.0.0.5]
[PARTIAL OUTPUT - nikto - 5 lines captured before timeout]
+ Referrer-Policy header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
[TIMEOUT] nikto killed after 300s
[NIKTO - http://10.0.0.5:8080]
No issues found
[NIKTO COMPLETE - http://10.0.0.5:8080]
[NUCLEI SAFE - http://10.0.0.5]
No nuclei findings detected.
[NUCLEI COMPLETE - http://10.0.0.5]
"""

    facts = OutputParser().parse_tool_output("manual_recon", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}
    checks = [
        json.loads(fact["value"])
        for fact in facts
        if fact["type"] == "check_result"
    ]

    assert ("service_status", "tool_timeout:nikto") in pairs
    assert ("service_status", "nikto_scan_completed:http://10.0.0.5:8080") in pairs
    assert ("service_status", "nuclei_scan_completed:http://10.0.0.5") in pairs
    assert {
        "tool": "nikto",
        "kind": "web_vulnerability",
        "status": "timeout",
        "scope": {"type": "endpoint", "value": "http://10.0.0.5"},
    }.items() <= checks[0].items()
    assert any(
        check["tool"] == "nikto"
        and check["status"] == "completed"
        and check["scope"] == {"type": "endpoint", "value": "http://10.0.0.5:8080"}
        for check in checks
    )
    assert any(
        check["tool"] == "nuclei_safe"
        and check["status"] == "completed"
        and check["scope"] == {"type": "endpoint", "value": "http://10.0.0.5"}
        for check in checks
    )


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


def test_web_endpoint_parser_rejects_trailing_json_context_garbage():
    from core.ai.evidence import OutputParser

    context = 'web_endpoint -> {"url": "https://83.166.242.55:9003/"}'

    facts = OutputParser().parse_tool_output("exploit_select 83.166.242.55 " + context, "")
    endpoints = [fact["value"] for fact in facts if fact["type"] == "web_endpoint"]

    assert endpoints == []


def test_browser_surface_partial_fallback_is_rendered_not_fetch_failed():
    from core.ai.evidence import OutputParser

    output = """
URL: https://67.215.12.67:2087
  [!] Requests fallback failed: HTTPConnectionPool(host='67.215.12.67', port=42084)
Page title: WHM Login
Forms: 3
  link: ?locale=en
"""

    facts = OutputParser().parse_tool_output("browser_surface_analysis https://67.215.12.67:2087", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("browser_rendered", "https://67.215.12.67:2087") in pairs
    assert ("service_status", "web_fetch_failed:https://67.215.12.67:2087") not in pairs
    assert any(ftype == "web_endpoint" and "https://67.215.12.67:2087/" in value for ftype, value in pairs)


def test_network_recon_pivot_output_marks_network_recon_completed():
    from core.ai.evidence import OutputParser

    output = """
[PIVOT] Discovering internal networks...
Subnets: 172.17.0.0/16, 192.168.48.0/20
  -> 172.17.0.2
  -> 172.17.0.3
"""

    facts = OutputParser().parse_tool_output("network_recon 83.166.242.55", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("internal_subnet", "172.17.0.0/16") in pairs
    assert ("internal_host", "172.17.0.2") in pairs
    assert ("service_status", "network_recon_completed") in pairs


def test_internal_service_probe_output_becomes_structured_facts():
    from core.ai.evidence import OutputParser

    output = """
[INTERNAL SERVICE PROBE]
Host limit: 20
Ports: 22 80 443 5432
OPEN 172.24.108.2:22/tcp
OPEN 172.24.108.2:5432/tcp
Internal services discovered: 2
"""

    facts = OutputParser().parse_tool_output("internal_service_probe 83.166.241.164", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("internal_service", "172.24.108.2:22/tcp (ssh)") in pairs
    assert ("internal_service", "172.24.108.2:5432/tcp (postgresql)") in pairs
    assert ("service_status", "internal_service_probe_completed:2") in pairs


def test_msf_login_skip_becomes_status_fact():
    from core.ai.evidence import OutputParser

    output = "[!] MSF login check skipped: auxiliary/scanner/ssh/ssh_login requires explicit credentials; Short check not run."
    facts = OutputParser().parse_tool_output(
        "msf_check 10.0.0.5 auxiliary/scanner/ssh/ssh_login RPORT=22",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("service_status", "msf_login_check_skipped:auxiliary/scanner/ssh/ssh_login") in pairs


def test_asm_and_nuclei_outputs_become_normalized_facts():
    from core.ai.evidence import OutputParser

    output = """
[ASM HTTPX - example.com]
https://app.example.com [200] [Admin Panel] [nginx,React]
203.0.113.10:8443
[NUCLEI SAFE - https://app.example.com]
{"template-id":"exposed-panel","info":{"name":"Panel","severity":"medium"},"matched-at":"https://app.example.com/admin"}
"""

    facts = OutputParser().parse_tool_output("httpx_probe example.com nuclei_safe https://app.example.com", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("asset_domain", "app.example.com") in pairs
    assert ("asset_ip", "203.0.113.10") in pairs
    assert ("asset_service", "203.0.113.10:8443/tcp") in pairs
    assert ("asset_url", "https://app.example.com") in pairs
    assert any(ftype == "technology" and "React" in value for ftype, value in pairs)
    assert any(ftype == "nuclei_finding" and "medium:exposed-panel" in value for ftype, value in pairs)


def test_api_secret_code_and_cloud_outputs_become_normalized_facts():
    from core.ai.evidence import OutputParser

    output = """
[OPENAPI IMPORT - openapi.json]
GET /users auth=unknown_or_none
POST /admin auth=required
[GRAPHQL CHECK - https://api.example.com/graphql]
{"data":{"__schema":{"queryType":{"name":"Query"}}}}
[GITLEAKS SCAN - .]
{"RuleID":"generic-api-key","File":"app/.env","Verified":false}
[SEMGREP SCAN - .]
{"results":[{"check_id":"python.lang.security.audit","path":"app.py","extra":{"severity":"WARNING"}}]}
[TRIVY SCAN - .]
{"Results":[{"Target":"requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","Severity":"HIGH"}],"Secrets":[{"RuleID":"aws-access-key"}]}]}
[PROWLER SCAN - aws]
{"Status":"FAIL","Severity":"high","CheckID":"s3_bucket_public_access","ResourceId":"bucket-1"}
"""

    facts = OutputParser().parse_tool_output(
        "openapi_import openapi.json graphql_check https://api.example.com/graphql gitleaks_scan . semgrep_scan . trivy_scan . prowler_scan aws",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("api_endpoint", "GET:/users:auth=unknown_or_none") in pairs
    assert ("api_security_note", "auth_unknown_or_none:GET:/users") in pairs
    assert ("api_security_note", "graphql_introspection_enabled") in pairs
    assert any(ftype == "secret_finding" and "generic-api-key:app/.env" in value for ftype, value in pairs)
    assert any(ftype == "secret_finding" and "aws-access-key:requirements.txt" in value for ftype, value in pairs)
    assert any(ftype == "code_finding" and "python.lang.security.audit:app.py" in value for ftype, value in pairs)
    assert any(ftype == "code_finding" and "CVE-2024-0001:requirements.txt" in value for ftype, value in pairs)
    assert any(ftype == "cloud_finding" and "s3_bucket_public_access:bucket-1" in value for ftype, value in pairs)


def test_web_security_headers_cors_jwt_js_and_proxy_import_facts():
    from core.ai.evidence import OutputParser

    output = """
[SECURITY HEADERS - https://app.example.com]
HTTP/2 200
Server: nginx
Set-Cookie: sid=abc123; Path=/
Content-Security-Policy: default-src * 'unsafe-inline'
[CORS CHECK - https://app.example.com]
Origin: https://octopus.invalid
Access-Control-Allow-Origin: https://octopus.invalid
Access-Control-Allow-Credentials: true
[JWT ANALYZE]
alg: none
typ: JWT
kid: ../../etc/passwd
claims: sub, role, exp
[JS ROUTE EXTRACT - https://app.example.com/app.js]
Routes: 3
/api/users/{id}
/graphql
/admin/settings
[BURP IMPORT - burp.xml]
URL https://app.example.com/admin
ISSUE Cross-origin resource sharing arbitrary origin trusted
[ZAP IMPORT - zap.json]
URL https://app.example.com/account?id=123
ALERT Medium Cookie No HttpOnly Flag
"""

    facts = OutputParser().parse_tool_output(
        "security_headers_check https://app.example.com cors_check https://app.example.com jwt_analyze token js_route_extract https://app.example.com/app.js burp_import burp.xml zap_import zap.json",
        output,
    )
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("web_security_note", "missing_hsts") in pairs
    assert ("web_security_note", "weak_csp_policy") in pairs
    assert ("web_security_note", "cookie_missing_httponly:sid") in pairs
    assert ("web_security_note", "cors_reflective_or_wildcard_origin") in pairs
    assert ("web_security_note", "cors_credentials_allowed") in pairs
    assert not any(
        ftype == "web_endpoint" and "octopus.invalid" in value
        for ftype, value in pairs
    )
    assert ("jwt_metadata", "alg:none") in pairs
    assert ("web_security_note", "jwt_review_required_alg:none") in pairs
    assert ("js_route", "/api/users/{id}") in pairs
    assert ("api_endpoint", "UNKNOWN:/graphql:source=js") in pairs
    assert any(ftype == "api_security_note" and value.startswith("idor_candidate:UNKNOWN:/api/users") for ftype, value in pairs)
    assert ("asset_url", "https://app.example.com/admin") in pairs
    assert any(ftype == "proxy_finding" and "Cookie No HttpOnly" in value for ftype, value in pairs)


def test_cors_check_without_allowed_origin_does_not_fall_back_to_llm():
    from core.ai.evidence import OutputParser

    parser = OutputParser()

    def fail_llm(*_args, **_kwargs):
        raise AssertionError("family-owned CORS output must not use LLM fallback")

    parser.llm_extractor.parse = fail_llm
    output = """
[CORS CHECK - http://10.0.0.5]
Origin: https://octopus.invalid
HTTP/1.1 405 Method Not Allowed
Server: nginx
Allow: GET, HEAD
"""

    facts = parser.parse_tool_output("cors_check http://10.0.0.5", output)
    pairs = {(fact["type"], fact["value"]) for fact in facts}

    assert ("origin", "https://octopus.invalid") not in pairs
    assert not any(fact["type"] == "web_endpoint" and "octopus.invalid" in fact["value"] for fact in facts)
