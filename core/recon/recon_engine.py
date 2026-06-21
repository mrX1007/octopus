#!/usr/bin/env python3
"""
Asynchronous Reconnaissance Engine

Features:
- Pure asyncio lightweight task queue (no Celery/Redis)
- Adaptive scanning (e.g., fuzzing only triggers if HTTP detected)
- Heuristic banner grabbing and TLS fingerprinting
- Distributed worker pattern (in-memory)
"""

import os
import logging
import ssl
import json
import time
import asyncio
import socket
from datetime import datetime
from typing import Dict, Any, List

C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_RESET  = "\033[0m"


class ReconTask:
    def __init__(self, target: str, task_type: str, priority: int = 1, meta: Dict = None):
        self.target = target
        self.task_type = task_type
        self.priority = priority
        self.meta = meta or {}

    def __lt__(self, other):
        return self.priority < other.priority


class ReconEngine:
    def __init__(self, concurrency: int = 10):
        self.concurrency = concurrency
        self.queue = asyncio.PriorityQueue()
        self.results: Dict[str, Dict[str, Any]] = {}
        self.state: Dict[str, Dict[str, Any]] = {}
        self.completed_tasks = 0

    async def _worker(self, worker_id: int):
        while True:
            try:
                task: ReconTask = await self.queue.get()
                await self._process_task(task, worker_id)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"  {C_RED}[!] Worker {worker_id} error on {task.task_type}: {e}{C_RESET}")
            finally:
                self.queue.task_done()
                self.completed_tasks += 1

    async def _process_task(self, task: ReconTask, worker_id: int):
        # Initialize state for new targets
        if task.target not in self.results:
            self.results[task.target] = {}
            self.state[task.target] = {"open_ports": [], "services": {}}

        # Dispatch
        if task.task_type == "nmap_fast":
            await self._run_nmap_fast(task.target)
        elif task.task_type == "banner_grab":
            await self._grab_banner(task.target, task.meta["port"])
        elif task.task_type == "tls_fingerprint":
            await self._tls_fingerprint(task.target, task.meta["port"])
        elif task.task_type == "http_probe":
            await self._http_probe(task.target, task.meta["port"], task.meta.get("is_tls", False))
        elif task.task_type == "enum4linux":
            await self._run_enum4linux(task.target)
        else:
            print(f"  {C_YELLOW}[!] Unknown task type: {task.task_type}{C_RESET}")

    # =========================================================================
    # TASK HANDLERS
    # =========================================================================

    async def _run_nmap_fast(self, target: str):
        """Asynchronous NMAP scan. Parses open ports and queues adaptive tasks."""
        print(f"  {C_CYAN}[*] Running fast async NMAP on {target}...{C_RESET}")
        cmd = ["nmap", "-T4", "-F", "--open", "-n", target]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode('utf-8', errors='ignore')
        
        self.results[target]["nmap"] = out
        
        # Adaptive Scanning: Parse ports and queue specific tasks
        ports = []
        for line in out.splitlines():
            if "/tcp" in line and "open" in line:
                try:
                    port = int(line.split("/")[0])
                    ports.append(port)
                    self.state[target]["open_ports"].append(port)
                except ValueError:
                    continue
        
        # Queue follow-up adaptive tasks
        for port in ports:
            # High priority (0) for banners so we get them fast
            await self.queue.put(ReconTask(target, "banner_grab", priority=0, meta={"port": port}))
            
            if port in [443, 8443, 10443]:
                await self.queue.put(ReconTask(target, "tls_fingerprint", priority=0, meta={"port": port}))
                await self.queue.put(ReconTask(target, "http_probe", priority=1, meta={"port": port, "is_tls": True}))
            elif port in [80, 8080, 8000]:
                await self.queue.put(ReconTask(target, "http_probe", priority=1, meta={"port": port, "is_tls": False}))
            elif port in [139, 445]:
                await self.queue.put(ReconTask(target, "enum4linux", priority=2))

    async def _grab_banner(self, target: str, port: int):
        """Pure python async banner grabbing with heuristic protocol detection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=3.0
            )
            # Send an HTTP request and some generic bytes to trigger a response
            writer.write(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n\x00\x00")
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            
            banner = data.decode('utf-8', errors='ignore').strip()
            if banner:
                svc = self._heuristic_service_detect(port, banner)
                self.state[target]["services"][port] = svc
                
                # Format for output
                if "banners" not in self.results[target]:
                    self.results[target]["banners"] = ""
                self.results[target]["banners"] += f"[Port {port} | {svc}] {banner[:100]}...\n"
                
        except Exception as e:
            pass # Silent fail on timeouts

    def _heuristic_service_detect(self, port: int, banner: str) -> str:
        banner = banner.lower()
        if "ssh-" in banner: return "ssh"
        if "http/" in banner or "html" in banner: return "http"
        if "ftp" in banner or "220" in banner[:4]: return "ftp"
        if "mysql" in banner: return "mysql"
        return "unknown"

    async def _tls_fingerprint(self, target: str, port: int):
        """Async TLS fingerprinting without relying on sslscan executable."""
        try:
            # We use a blocking call to get_server_certificate wrapped in to_thread
            cert_pem = await asyncio.to_thread(
                ssl.get_server_certificate, (target, port), timeout=5
            )
            if "tls" not in self.results[target]:
                self.results[target]["tls"] = ""
            self.results[target]["tls"] += f"[Port {port} TLS Cert Extracted]\n{cert_pem[:200]}...\n"
        except Exception as e:
            pass

    async def _http_probe(self, target: str, port: int, is_tls: bool):
        """Custom HTTP prober (async) capturing Server headers and titles."""
        proto = "https" if is_tls else "http"
        url = f"{proto}://{target}:{port}/"
        try:
            # Minimal pure-python async HTTP GET using asyncio streams
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=is_tls if is_tls else None), 
                timeout=5.0
            )
            req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            writer.close()
            await writer.wait_closed()
            
            resp = data.decode('utf-8', errors='ignore')
            
            # Simple title extraction
            title = "None"
            if "<title>" in resp.lower():
                import re
                match = re.search(r'<title>(.*?)</title>', resp, re.IGNORECASE | re.DOTALL)
                if match: title = match.group(1).strip()
            
            server = "Unknown"
            for line in resp.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break

            if "http_enum" not in self.results[target]:
                self.results[target]["http_enum"] = ""
            self.results[target]["http_enum"] += f"URL: {url} | Server: {server} | Title: {title}\n"
            
        except Exception as _exc:
            logging.debug(f"Suppressed in recon_engine.py: {_exc}")

    async def _run_enum4linux(self, target: str):
        print(f"  {C_CYAN}[*] Running async enum4linux on {target}...{C_RESET}")
        cmd = ["enum4linux", "-a", target]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            self.results[target]["enum4linux"] = stdout.decode('utf-8', errors='ignore')
        except asyncio.TimeoutError:
            proc.kill()
            self.results[target]["enum4linux"] = "[!] enum4linux timed out."
        except Exception as e:
            self.results[target]["enum4linux"] = f"[!] enum4linux error: {e}"

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    async def run_scan(self, targets: List[str]) -> Dict[str, Dict[str, str]]:
        """Run the async recon engine against a list of targets."""
        print(f"\n{C_CYAN}[*] Initializing Async Recon Engine v9.0 for {len(targets)} target(s){C_RESET}")
        start_time = time.time()
        
        # Seed initial tasks (priority 10 so they run first but yield to adaptive tasks)
        for target in targets:
            await self.queue.put(ReconTask(target, "nmap_fast", priority=10))
            
        # Start workers
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.concurrency)]
        
        # Wait for all tasks (initial + adaptive) to complete
        await self.queue.join()
        
        # Shutdown workers
        for w in workers:
            w.cancel()
            
        elapsed = time.time() - start_time
        print(f"{C_GREEN}[+] Async Recon Engine finished. Processed {self.completed_tasks} tasks in {elapsed:.2f}s.{C_RESET}")
        
        # Combine results into the format expected by LLM
        final_output = {}
        for target, data in self.results.items():
            combined = ""
            for tool_name, output in data.items():
                if output.strip():
                    combined += f"[{tool_name.upper()}]\n{output.strip()}\n\n"
            final_output[target] = combined
            
        return final_output

# Helper to run from synchronous code
def run_async_recon(targets: List[str], concurrency: int = 10) -> Dict[str, str]:
    engine = ReconEngine(concurrency=concurrency)
    return asyncio.run(engine.run_scan(targets))

if __name__ == "__main__":
    # Test script
    import sys
    targets_to_scan = sys.argv[1:] if len(sys.argv) > 1 else ["127.0.0.1"]
    res = run_async_recon(targets_to_scan, concurrency=20)
    for t, out in res.items():
        print(f"\n{'='*50}\nRESULTS FOR {t}\n{'='*50}\n")
        print(out)
