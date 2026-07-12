#!/usr/bin/env python3
"""
Pytest fixtures and helpers for OCTOPUS test suite.
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── Sample Data Fixtures ───────────────────────────────

@pytest.fixture
def sample_nmap_output():
    """Realistic nmap scan output for testing fact extraction."""
    return """
Starting Nmap 7.94 ( https://nmap.org ) at 2026-06-15 10:00 UTC
Nmap scan report for 192.168.1.100
Host is up (0.0023s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http    Apache httpd 2.4.52 ((Ubuntu))
3306/tcp open  mysql       MySQL 8.0.35-0ubuntu0.22.04.1
8080/tcp open  http-proxy  Apache Tomcat 9.0.58

Service detection performed. 5 services scanned.
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""


@pytest.fixture
def sample_nmap_vuln_output():
    """Nmap output with vulnerability indicators."""
    return """
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache/2.4.49
| http-vuln-cve2021-41773:
|   VULNERABLE:
|   Path Traversal in Apache HTTP Server 2.4.49
|     State: VULNERABLE
|     IDs:  CVE:CVE-2021-41773
|     Risk factor: High
"""


@pytest.fixture
def sample_facts():
    """List of fact dicts as produced by FactStore."""
    return [
        {"type": "open_port", "value": "22/tcp ssh OpenSSH 8.9p1", "confidence": 95, "source": "nmap"},
        {"type": "open_port", "value": "80/tcp http Apache 2.4.52", "confidence": 95, "source": "nmap"},
        {"type": "open_port", "value": "3306/tcp mysql MySQL 8.0.35", "confidence": 95, "source": "nmap"},
        {"type": "web_app", "value": "Apache Tomcat 9.0.58 on 8080", "confidence": 80, "source": "nmap"},
        {"type": "vulnerability", "value": "CVE-2021-41773 Path Traversal", "confidence": 70, "source": "nmap_scripts"},
        {"type": "credential", "value": "admin:admin123", "confidence": 50, "source": "bruteforce"},
    ]


@pytest.fixture
def sample_session_data():
    """Mock session data as returned by db.get_session()."""
    return {
        "history": (1, "192.168.1.100", "2026-06-15 10:00:00", "complete"),
        "vulns": [
            (1, 1, "CVE-2021-41773", "HIGH", "80", "http",
             "Path Traversal in Apache 2.4.49", "CONFIRMED", "nmap",
             "HTTP 200 with /etc/passwd", "curl --path-as-is ...", 8.1),
            (2, 1, "Weak SSH Config", "MEDIUM", "22", "ssh",
             "SSH allows password authentication", "UNCONFIRMED", "nmap",
             "password auth advertised", "ssh -o PreferredAuthentications=password", None),
        ],
        "fixes": [
            (1, 1, 1, "Upgrade Apache to >= 2.4.51", "ai"),
            (2, 1, 2, "Disable password auth in sshd_config", "ai"),
        ],
        "exploits": [
            (1, 1, "CVE-2021-41773", "curl", "../../etc/passwd", "Success", "Root file read achieved"),
        ],
        "summary": (1, 1, "raw scan data...", "AI analysis text...", "HIGH", "2026-06-15 10:30:00"),
    }


@pytest.fixture
def mock_db_connection():
    """Mock MySQL connection for DB tests."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    cursor.fetchone.return_value = (1,)
    cursor.fetchall.return_value = []
    cursor.lastrowid = 1
    return conn, cursor


@pytest.fixture
def tmp_config(tmp_path):
    """Create a temporary config.yaml for testing."""
    config_content = """
db:
  host: localhost
  user: test_user
  password: test_pass
  database: test_db

ollama:
  url: http://localhost:11434/api/generate
  model: test-model

paths:
  wordlists: /tmp/wordlists
  reports: /tmp/reports
"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(config_content)
    return str(config_file)
