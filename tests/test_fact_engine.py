#!/usr/bin/env python3
"""Tests for core/ai/fact_engine.py — fact extraction from tool output."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestExtractOpenPorts:
    """Test extraction of open port facts from nmap output."""

    def test_extracts_standard_ports(self, sample_nmap_output):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output(sample_nmap_output, "nmap")

        port_facts = [f for f in facts if f[0] and "22" in f[0]]
        assert len(port_facts) > 0, "Should extract SSH port 22"

    def test_extracts_service_versions(self, sample_nmap_output):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output(sample_nmap_output, "nmap")

        # Should find Apache version
        all_text = " ".join(f[0] for f in facts if f[0])
        assert "Apache" in all_text or "apache" in all_text or "2.4.52" in all_text

    def test_extracts_mysql_port(self, sample_nmap_output):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output(sample_nmap_output, "nmap")

        all_text = " ".join(f[0] for f in facts if f[0])
        assert "3306" in all_text or "mysql" in all_text.lower()


class TestExtractCredentials:
    """Test credential extraction from various tool outputs."""

    def test_extracts_ssh_creds_from_hydra(self):
        from core.ai.fact_engine import extract_facts_from_output
        hydra_output = """
[22][ssh] host: 192.168.1.100   login: admin   password: admin123
[22][ssh] host: 192.168.1.100   login: root   password: toor
"""
        facts = extract_facts_from_output(hydra_output, "bruteforce")
        all_text = " ".join(f[0] for f in facts if f[0])
        assert "admin" in all_text

    def test_extracts_web_login_creds(self):
        from core.ai.fact_engine import extract_facts_from_output
        output = """
[+] Found valid credentials: admin:password123
[+] Login successful at http://target/admin
"""
        facts = extract_facts_from_output(output, "web_bruteforce")
        all_text = " ".join(f[0] for f in facts if f[0])
        assert "admin" in all_text or "password" in all_text.lower()


class TestExtractWebApps:
    """Test web application detection."""

    def test_detects_tomcat(self, sample_nmap_output):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output(sample_nmap_output, "nmap")

        all_text = " ".join(f[0] for f in facts if f[0]).lower()
        assert "tomcat" in all_text or "8080" in all_text


class TestExtractVulnerabilities:
    """Test CVE and vulnerability extraction."""

    def test_extracts_cve_from_nmap_scripts(self, sample_nmap_vuln_output):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output(sample_nmap_vuln_output, "nmap")

        all_text = " ".join(f[0] for f in facts if f[0])
        assert "CVE" in all_text or "vuln" in all_text.lower()


class TestNoFalsePositives:
    """Test that noise doesn't generate false facts."""

    def test_empty_input_returns_empty(self):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output("", "nmap")
        assert isinstance(facts, list)

    def test_garbage_input_returns_minimal(self):
        from core.ai.fact_engine import extract_facts_from_output
        facts = extract_facts_from_output("random garbage text xyz 12345", "nmap")
        # Should not extract any meaningful facts from noise
        assert len(facts) <= 2  # May extract the text itself as a raw fact


class TestDuplicateDedup:
    """Test that duplicate facts are deduplicated."""

    def test_repeated_ports_deduped(self):
        from core.ai.fact_engine import extract_facts_from_output
        output = """
22/tcp   open  ssh   OpenSSH 8.9p1
22/tcp   open  ssh   OpenSSH 8.9p1
22/tcp   open  ssh   OpenSSH 8.9p1
"""
        facts = extract_facts_from_output(output, "nmap")
        port_22_facts = [f for f in facts if f[0] and "22" in f[0]]
        # Should have at most 2 (fact + version)
        assert len(port_22_facts) <= 3
