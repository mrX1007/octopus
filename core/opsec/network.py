#!/usr/bin/env python3

import os
from typing import Any, Optional

from core.transport.base import GoTLSTransport, PythonTransport, Transport
from core.transport.profiles import get_profile


class OpsecClient:
    """
    High-level OPSEC HTTP client.

    Usage:
        client = OpsecClient(profile="updater", browser="chrome")
        resp = client.request("GET", "https://example.com")
    """

    def __init__(self, profile: str = "updater", browser: str = "chrome",
                 use_go_tls: bool = True):
        """
        Args:
            profile: Traffic profile name (updater, browser, scraper, stealth)
            browser: JA3 fingerprint to mimic (chrome, firefox, safari, edge)
            use_go_tls: If True, use Go uTLS binary. If False, use Python requests.
        """
        policy = get_profile(profile)

        if use_go_tls:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            go_bin = os.path.join(base_dir, "ja3_client")

            if not os.path.exists(go_bin):
                self._compile_go_client(base_dir, go_bin)

            self._transport: Transport = GoTLSTransport(
                go_binary=go_bin, browser=browser, policy=policy
            )
        else:
            self._transport: Transport = PythonTransport(policy=policy)

    def _compile_go_client(self, base_dir: str, go_bin: str):
        """Compile the Go JA3 client if it doesn't exist."""
        import subprocess
        print("[*] Compiling Go JA3 client...")
        src = os.path.join(base_dir, "ja3_client.go")
        try:
            subprocess.run(["go", "build", "-o", go_bin, src], check=True, cwd=base_dir)
        except Exception as e:
            print(f"[!] Failed to compile JA3 client: {e}")

    def request(self, method: str, url: str,
                headers: Optional[dict[str, str]] = None,
                body: str = "",
                **kwargs) -> dict[str, Any]:
        """
        Make an HTTP request with traffic shaping and JA3 spoofing.
        Traffic policy (jitter, retries, pacing) is applied automatically.
        """
        body_bytes = body.encode('utf-8') if body else None
        return self._transport.request(method, url, headers, body_bytes)

    @property
    def transport(self) -> Transport:
        """Access the underlying transport for advanced usage."""
        return self._transport


if __name__ == "__main__":
    client = OpsecClient(profile="browser", browser="firefox", use_go_tls=False)
    print("[*] Testing OpsecClient with Python transport...")
    resp = client.request("GET", "https://httpbin.org/get")
    if resp.get("error"):
        print(f"Error: {resp['error']}")
    else:
        print(f"Status: {resp['status_code']}")
        print(f"Body: {resp['body'][:200]}")
