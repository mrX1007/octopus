"""
Unified Transport Abstraction Layer.

Every network operation in the framework goes through Transport.
This consolidates the fragmented OPSEC into a single layer:
  - Traffic policy (jitter, pacing, bandwidth)
  - Profile-based cadence (updater, browser, scraper)
  - Forensic minimization (artifact tracking, temp file cleanup)

The Transport is NOT the TLS layer — it wraps HTTP clients
and applies behavioral shaping on top.
"""

import json
import os
import random
import tempfile
import time
from abc import ABC, abstractmethod
from typing import Any, Optional


class TrafficPolicy:
    """
    Defines the behavioral envelope for network operations.
    Applied automatically by the Transport layer.
    """

    def __init__(self, profile_name: str = "default",
                 min_jitter: float = 0.1, max_jitter: float = 2.0,
                 burst_size: int = 3, burst_cooldown: float = 5.0,
                 chunk_size: int = 16384,
                 retry_base: float = 1.0, retry_max: float = 30.0,
                 retry_jitter: float = 0.5,
                 max_retries: int = 3):
        self.profile_name = profile_name
        self.min_jitter = min_jitter
        self.max_jitter = max_jitter
        self.burst_size = burst_size
        self.burst_cooldown = burst_cooldown
        self.chunk_size = chunk_size
        self.retry_base = retry_base
        self.retry_max = retry_max
        self.retry_jitter = retry_jitter
        self.max_retries = max_retries

        # State
        self._request_count = 0
        self._last_burst_time = 0.0

    def pre_request_delay(self) -> float:
        """Calculate the delay before making a request based on policy."""
        self._request_count += 1

        # Burst logic: allow N requests quickly, then cooldown
        if self._request_count % self.burst_size == 0:
            now = time.time()
            elapsed = now - self._last_burst_time
            if elapsed < self.burst_cooldown:
                delay = self.burst_cooldown - elapsed
                delay += random.uniform(0, self.retry_jitter)
                self._last_burst_time = now + delay
                return delay
            self._last_burst_time = now

        # Normal jitter
        return random.uniform(self.min_jitter, self.max_jitter)

    def retry_delay(self, attempt: int) -> float:
        """Exponential backoff with jitter for retries."""
        delay = min(self.retry_base * (2 ** attempt), self.retry_max)
        delay += random.uniform(-self.retry_jitter, self.retry_jitter)
        return max(0.1, delay)

    def chunk_data(self, data: bytes) -> list[bytes]:
        """Split data into profile-appropriate chunks."""
        if len(data) <= self.chunk_size:
            return [data]
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunks.append(data[i:i + self.chunk_size])
        return chunks


class Transport(ABC):
    """
    Abstract base for all network transports.

    Concrete implementations wrap specific HTTP clients
    (requests, subprocess Go client, etc.) but all share
    the same traffic policy and behavioral interface.
    """

    def __init__(self, policy: Optional[TrafficPolicy] = None):
        self.policy = policy or TrafficPolicy()
        self._temp_files: list[str] = []

    @abstractmethod
    def _do_request(self, method: str, url: str,
                    headers: Optional[dict[str, str]] = None,
                    body: Optional[bytes] = None,
                    timeout: float = 30.0) -> dict[str, Any]:
        """
        Perform the actual HTTP request.
        Returns: {"status_code": int, "headers": dict, "body": str, "error": str}
        """
        pass

    def request(self, method: str, url: str,
                headers: Optional[dict[str, str]] = None,
                body: Optional[bytes] = None,
                timeout: float = 30.0) -> dict[str, Any]:
        """
        Make an HTTP request with traffic policy applied.
        Handles jitter, retries, and temp file cleanup.
        """
        # Pre-request delay
        delay = self.policy.pre_request_delay()
        if delay > 0:
            time.sleep(delay)

        last_error = None
        for attempt in range(self.policy.max_retries + 1):
            try:
                result = self._do_request(method, url, headers, body, timeout)
                if "error" not in result or not result["error"]:
                    return result
                last_error = result.get("error", "Unknown error")
            except Exception as e:
                last_error = str(e)

            if attempt < self.policy.max_retries:
                retry_delay = self.policy.retry_delay(attempt)
                time.sleep(retry_delay)

        return {"error": last_error, "status_code": 0, "headers": {}, "body": ""}

    def cleanup(self):
        """Remove any temporary files created during transport operations."""
        for f in self._temp_files:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except OSError:
                pass
        self._temp_files.clear()

    def _create_temp_file(self, content: str) -> str:
        """Create a temp file and track it for cleanup."""
        fd, path = tempfile.mkstemp(prefix="mt_", suffix=".tmp")
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        self._temp_files.append(path)
        return path


class PythonTransport(Transport):
    """Transport implementation using Python requests library."""

    def _do_request(self, method: str, url: str,
                    headers: Optional[dict[str, str]] = None,
                    body: Optional[bytes] = None,
                    timeout: float = 30.0) -> dict[str, Any]:
        try:
            import requests
        except ImportError:
            return {"error": "requests library not installed", "status_code": 0,
                    "headers": {}, "body": ""}

        try:
            resp = requests.request(
                method=method, url=url,
                headers=headers or {},
                data=body,
                timeout=timeout,
                verify=True
            )
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
            }
        except requests.Timeout:
            return {"error": "Request timed out", "status_code": 0,
                    "headers": {}, "body": ""}
        except Exception as e:
            return {"error": str(e), "status_code": 0, "headers": {}, "body": ""}


class GoTLSTransport(Transport):
    """
    Transport implementation using the Go uTLS binary for JA3 spoofing.
    Wraps core/opsec/ja3_client.go as a subprocess.
    """

    def __init__(self, go_binary: Optional[str] = None, browser: str = "chrome",
                 policy: Optional[TrafficPolicy] = None):
        super().__init__(policy)
        self.browser = browser

        if go_binary:
            self.go_binary = go_binary
        else:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.go_binary = os.path.join(base, "opsec", "ja3_client")

    def _do_request(self, method: str, url: str,
                    headers: Optional[dict[str, str]] = None,
                    body: Optional[bytes] = None,
                    timeout: float = 30.0) -> dict[str, Any]:
        import subprocess

        req_data = {
            "method": method.upper(),
            "url": url,
            "headers": headers or {},
            "body": body.decode('utf-8') if body else "",
            "browser": self.browser,
        }

        req_file = self._create_temp_file(json.dumps(req_data))

        try:
            result = subprocess.run(
                [self.go_binary, "-in", req_file],
                capture_output=True, text=True, timeout=timeout
            )

            if result.returncode != 0:
                return {"error": f"Go client failed: {result.stderr}",
                        "status_code": 0, "headers": {}, "body": ""}

            return json.loads(result.stdout)

        except subprocess.TimeoutExpired:
            return {"error": "Request timed out", "status_code": 0,
                    "headers": {}, "body": ""}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON from Go client",
                    "status_code": 0, "headers": {}, "body": ""}
        except FileNotFoundError:
            return {"error": f"Go binary not found: {self.go_binary}",
                    "status_code": 0, "headers": {}, "body": ""}
        finally:
            self.cleanup()
