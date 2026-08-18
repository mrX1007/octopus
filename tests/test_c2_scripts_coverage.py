"""Unit tests for C2 offline scripts."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

import pytest

import scripts.bootstrap_c2_admin as bootstrap_script
import scripts.install_c2_service_identity as install_script
from scripts.quality.generate_c2_v2_golden_vectors import generate_vectors


@pytest.mark.unit
def test_generate_c2_v2_golden_vectors():
    vectors = generate_vectors()
    assert "client_public_key_hex" in vectors
    assert "daemon_public_key_hex" in vectors
    assert "fixture_checksum_sha256" in vectors


@pytest.mark.unit
def test_install_c2_service_identity(tmp_path: Path):
    priv_file = tmp_path / "priv" / "server.key"
    pub_file = tmp_path / "pub" / "server.pub"

    # 1. First installation
    rc = install_script.install_service_identity(priv_path=priv_file, pub_path=pub_file)
    assert rc == 0
    assert priv_file.exists()
    assert pub_file.exists()

    # 2. Already exists
    rc_idempotent = install_script.install_service_identity(priv_path=priv_file, pub_path=pub_file)
    assert rc_idempotent == 0

    # 3. Main entry point
    with patch.object(install_script, "install_service_identity", return_value=0):
        assert install_script.main() == 0


@pytest.mark.unit
def test_bootstrap_c2_admin_script(tmp_path: Path):
    db_file = tmp_path / "bootstrap.db"
    key_file = tmp_path / "bootstrap.key"

    argv = [
        "--db-path",
        str(db_file),
        "--client-uid",
        "1000",
        "--client-gid",
        "1000",
        "--name",
        "test-bootstrap-admin",
        "--key-path",
        str(key_file),
    ]

    with patch("os.geteuid", return_value=0), patch("os.chown"), patch("os.fchown"):
        rc = bootstrap_script.main(argv)
        assert rc == 0
        assert key_file.exists()

    # Test failure path
    failing_argv = [
        "--db-path",
        "/invalid_directory_path_1234/test.db",
        "--client-uid",
        "1000",
        "--client-gid",
        "1000",
    ]
    err_stream = io.StringIO()
    with patch("sys.stderr", err_stream):
        rc_fail = bootstrap_script.main(failing_argv)
        assert rc_fail == 1
