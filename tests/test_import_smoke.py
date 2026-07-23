"""Import boundaries must not depend on a writable current directory."""

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("profile", ["runtime", "c2"])
def test_imports_from_read_only_working_directory(tmp_path: Path, profile: str) -> None:
    read_only = tmp_path / "read-only-cwd"
    read_only.mkdir()
    read_only.chmod(0o555)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Point C2 persistence inside the read-only directory. A pure import must
    # neither try to create this path nor touch the operator's workspace data.
    env["OCTOPUS_DATA_DIR"] = str(read_only / "forbidden-runtime-data")
    env["OCTOPUS_C2_KEY_PASSPHRASE"] = "import-smoke-only-passphrase"

    try:
        completed = subprocess.run(
            [
                os.fspath(Path(os.sys.executable)),
                os.fspath(ROOT / "scripts" / "quality" / "import_smoke.py"),
                "--profile",
                profile,
            ],
            cwd=read_only,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        read_only.chmod(0o755)

    assert completed.returncode == 0, completed.stderr
    assert not tuple(read_only.iterdir())
