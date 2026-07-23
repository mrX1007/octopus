"""Isolated nightly smoke for one representative native scanner."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.external_tools, pytest.mark.integration, pytest.mark.platform]


def test_nmap_can_probe_loopback_without_a_shell() -> None:
    executable = shutil.which("nmap")
    if executable is None:
        if os.environ.get("OCTOPUS_REQUIRE_EXTERNAL_TOOLS") == "1":
            pytest.fail("nightly external-tools environment did not provision nmap")
        pytest.skip("nmap is not installed")

    completed = subprocess.run(
        [executable, "-sn", "-n", "127.0.0.1"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert "127.0.0.1" in completed.stdout
