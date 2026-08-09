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

    def __init__(
        self,
        profile: str = "updater",
        browser: str = "chrome",
        use_go_tls: bool = False,
        go_binary: Optional[str] = None,
    ):
        """
        Args:
            profile: Traffic profile name (updater, browser, scraper, stealth)
            browser: JA3 fingerprint to mimic (chrome, firefox, safari, edge)
            use_go_tls: If True, explicitly opt into the deployment-managed,
                prebuilt Go uTLS binary. The portable default uses Python
                requests. Runtime compilation is intentionally forbidden.
            go_binary: Exact deployed uTLS binary path. When omitted, opt-in
                mode reads ``OCTOPUS_GO_TLS_BINARY`` and otherwise fails closed.
        """
        policy = get_profile(profile)

        if use_go_tls:
            go_bin = go_binary if go_binary is not None else os.environ.get("OCTOPUS_GO_TLS_BINARY")
            if not go_bin or not go_bin.strip():
                raise RuntimeError("Go TLS opt-in requires go_binary or OCTOPUS_GO_TLS_BINARY")
            self._transport: Transport = GoTLSTransport(go_binary=go_bin, browser=browser, policy=policy)
        else:
            self._transport: Transport = PythonTransport(policy=policy)

    def request(
        self, method: str, url: str, headers: Optional[dict[str, str]] = None, body: str = "", **kwargs
    ) -> dict[str, Any]:
        """
        Make an HTTP request with traffic shaping and JA3 spoofing.
        Traffic policy (jitter, retries, pacing) is applied automatically.
        """
        body_bytes = body.encode("utf-8") if body else None
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
