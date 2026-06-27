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


def test_privesc_output_confirms_root_pwnkit_and_post_exploit_state():
    from core.ai.evidence import OutputParser

    output = """
[KILL CHAIN] Stage 3: Privilege Escalation — support@83.166.241.164
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
    assert ("data_exfiltration", "shadow_file_extracted") in pairs
    assert ("persistence", "ssh_key_injected") in pairs


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
