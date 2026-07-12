#!/usr/bin/env python3
"""
Local hash extraction & cracking: hashcat (CUDA/GPU primary) + john (CPU fallback).
Optimized for: Intel i9-14900 / RTX 4080 / 64GB RAM.

Usage:
    from hash_cracker import HashCracker
    hc = HashCracker()
    result = hc.smart_crack(shadow_content)
    for user, pwd in hc.get_cracked_pairs():
        register_credential("ssh", host, user, pwd)
"""

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time

try:
    from config import CFG, find_wordlist
except ImportError:
    CFG = {}
    def find_wordlist(cat): return ""

# ANSI Colors
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"
C_GREY   = "\033[90m"
C_MAGENTA = "\033[95m"
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"

# Hash type mapping: shadow prefix -> (hashcat mode, name)
HASH_TYPES = {
    "$1$":   (500,   "MD5crypt"),
    "$2a$":  (3200,  "bcrypt"),
    "$2b$":  (3200,  "bcrypt"),
    "$2y$":  (3200,  "bcrypt"),
    "$5$":   (7400,  "SHA-256crypt"),
    "$6$":   (1800,  "SHA-512crypt"),
    "$y$":   (29000, "yescrypt"),
    "$gy$":  (29000, "yescrypt"),
    "$sha1$": (12000, "PBKDF2-SHA1"),
}

# Common Athena OS wordlist paths.
WORDLIST_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/wordlists/seclists/Passwords/darkc0de.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/john/password.lst",
    os.path.expanduser("~/.octopus/wordlists/rockyou.txt"),
]

# Hashcat rule paths
RULE_PATHS = [
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
    "/usr/share/hashcat/rules/dive.rule",
    "/usr/share/hashcat/rules/rockyou-30000.rule",
]


class HashCracker:
    """Local hash cracking engine -- GPU-accelerated with hashcat, CPU fallback with john."""

    def __init__(self):
        self.hashcat = shutil.which("hashcat")
        self.john = shutil.which("john")
        self.has_gpu = False
        self.cracked = {}  # {hash_str: password}
        self.cracked_users = {}  # {username: password}
        self.cfg = CFG.get("hash_cracker", {})
        self.workload = self.cfg.get("workload", 3)
        self.timeout = self.cfg.get("timeout", 600)
        self._workdir = tempfile.mkdtemp(prefix="octopus_crack_")

        if self.hashcat:
            try:
                r = subprocess.run(
                    [self.hashcat, "--backend-info"],
                    capture_output=True, text=True, timeout=10
                )
                if "CUDA" in r.stdout or "OpenCL" in r.stdout or "HIP" in r.stdout:
                    self.has_gpu = True
            except Exception as _exc:
                logging.debug(f"Suppressed in hash_cracker.py: {_exc}")

        if self.hashcat:
            gpu_tag = f"{C_GREEN}GPU (CUDA){C_RESET}" if self.has_gpu else f"{C_YELLOW}CPU only{C_RESET}"
            print(f"  {C_GREEN}[+] hashcat: {self.hashcat} [{gpu_tag}]{C_RESET}")
        elif self.john:
            print(f"  {C_YELLOW}[~] hashcat not found, using john: {self.john}{C_RESET}")
        else:
            print(f"  {C_RED}[!] No cracking tool found. Install hashcat or john.{C_RESET}")

    def _find_wordlist(self, prefer_small=False):
        wl = find_wordlist("passwords")
        if wl and os.path.isfile(wl):
            if prefer_small:
                for path in WORDLIST_PATHS:
                    if os.path.isfile(path) and "10k" in path:
                        return path
            return wl
        for path in WORDLIST_PATHS:
            if os.path.isfile(path):
                if prefer_small and os.path.getsize(path) > 10_000_000:
                    continue
                return path
        minimal = os.path.join(self._workdir, "mini_wordlist.txt")
        with open(minimal, "w") as f:
            f.write("\n".join([
                "password", "123456", "12345678", "qwerty", "abc123",
                "monkey", "1234567", "letmein", "trustno1", "dragon",
                "baseball", "iloveyou", "master", "sunshine", "ashley",
                "root", "toor", "admin", "test", "guest", "changeme",
                "r00t", "p@ssw0rd", "P@ssw0rd", "P@ssword1", "m3tatr0n",
            ]))
        return minimal

    def _find_rules(self):
        for path in RULE_PATHS:
            if os.path.isfile(path):
                return path
        return ""

    # --- HASH PARSING ---

    def extract_hashes_from_shadow(self, shadow_content):
        entries = []
        for line in shadow_content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            user = parts[0]
            hash_field = parts[1]
            if hash_field in ("*", "!", "!!", "", "x", "NP", "LK"):
                continue
            if hash_field.startswith("!"):
                continue
            info = self.identify_hash_type(hash_field)
            if info.get("hashcat_mode"):
                entries.append({
                    "user": user,
                    "hash": hash_field,
                    "full_line": line,
                    "algorithm": info["algorithm"],
                    "hashcat_mode": info["hashcat_mode"],
                })
        return entries

    def identify_hash_type(self, hash_str):
        for prefix, (mode, name) in HASH_TYPES.items():
            if hash_str.startswith(prefix):
                return {
                    "algorithm": name,
                    "hashcat_mode": mode,
                    "prefix": prefix,
                    "description": f"{name} (hashcat mode {mode})",
                }
        return {"algorithm": "unknown", "hashcat_mode": None, "description": "Unknown hash type"}

    # --- CRACKING ENGINES ---

    def crack_with_hashcat(self, hash_file, wordlist, hash_type=None,
                           rules=None, timeout=None, extra_args=None):
        if not self.hashcat:
            return {"error": "hashcat not found", "cracked": {}}
        timeout = timeout or self.timeout
        potfile = os.path.join(self._workdir, "hashcat.potfile")
        outfile = os.path.join(self._workdir, "cracked.txt")
        cmd = [
            self.hashcat,
            "-m", str(hash_type or 1800),
            "-a", "0",
            "-w", str(self.workload),
            "--potfile-path", potfile,
            "-o", outfile,
            "--outfile-format=3",
            hash_file,
            wordlist,
        ]
        if self.has_gpu:
            cmd.extend(["-D", "1,2", "--force"])
        if rules and os.path.isfile(rules):
            cmd.extend(["-r", rules])
        if extra_args:
            cmd.extend(extra_args)

        print(f"    {C_CYAN}[*] hashcat: mode={hash_type}, wl={os.path.basename(wordlist)}"
              f"{', rules=' + os.path.basename(rules) if rules else ''}{C_RESET}")

        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"    {C_YELLOW}[!] hashcat timeout ({timeout}s){C_RESET}")
        except Exception as e:
            return {"error": str(e), "cracked": {}}
        elapsed = time.time() - start

        cracked = {}
        if os.path.isfile(outfile):
            try:
                with open(outfile) as f:
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            h, p = line.split(":", 1)
                            cracked[h] = p
            except Exception as _exc:
                logging.debug(f"Suppressed in hash_cracker.py: {_exc}")

        self.cracked.update(cracked)
        return {"cracked": cracked, "cracked_count": len(cracked), "elapsed": round(elapsed, 1)}

    def crack_with_john(self, hash_file, wordlist, timeout=None):
        if not self.john:
            return {"error": "john not found", "cracked": {}}
        timeout = timeout or self.timeout
        cmd = [self.john, "--wordlist=" + wordlist, hash_file]
        print(f"    {C_CYAN}[*] john: wl={os.path.basename(wordlist)}{C_RESET}")
        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"    {C_YELLOW}[!] john timeout ({timeout}s){C_RESET}")
        except Exception as e:
            return {"error": str(e), "cracked": {}}
        elapsed = time.time() - start

        cracked = {}
        try:
            show = subprocess.run([self.john, "--show", hash_file],
                                  capture_output=True, text=True, timeout=15)
            for line in show.stdout.strip().splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] not in ("*", "!", ""):
                        cracked[parts[0]] = parts[1]
        except Exception as _exc:
            logging.debug(f"Suppressed in hash_cracker.py: {_exc}")
        self.cracked.update(cracked)
        return {"cracked": cracked, "cracked_count": len(cracked), "elapsed": round(elapsed, 1)}

    # --- SMART CRACK PIPELINE ---

    def smart_crack(self, shadow_content):
        output = f"\n{'=' * 60}\n[HASH CRACKER -- LOCAL GPU CRACKING]\n{'=' * 60}\n"
        entries = self.extract_hashes_from_shadow(shadow_content)
        if not entries:
            output += "[!] No crackable hashes found in shadow data.\n"
            return output

        output += f"\n[Phase 1: Hash Analysis]\n  Crackable hashes: {len(entries)}\n"

        by_type = {}
        for e in entries:
            mode = e["hashcat_mode"]
            if mode not in by_type:
                by_type[mode] = {"algorithm": e["algorithm"], "entries": []}
            by_type[mode]["entries"].append(e)

        for mode, data in by_type.items():
            users = ", ".join(e["user"] for e in data["entries"][:5])
            more = f" +{len(data['entries'])-5}" if len(data["entries"]) > 5 else ""
            output += f"  {data['algorithm']} (mode {mode}): {len(data['entries'])} hashes -- {users}{more}\n"

        print(f"  {C_CYAN}[*] {len(entries)} crackable hashes found{C_RESET}")

        if not self.hashcat and not self.john:
            output += "\n[!] No cracking tool available.\n  Extracted hashes:\n"
            for e in entries:
                output += f"    {e['user']}:{e['hash']}\n"
            return output

        total_start = time.time()

        for mode, data in by_type.items():
            hash_file = os.path.join(self._workdir, f"hashes_m{mode}.txt")
            if self.hashcat:
                with open(hash_file, "w") as f:
                    for e in data["entries"]:
                        f.write(e["hash"] + "\n")
            else:
                with open(hash_file, "w") as f:
                    for e in data["entries"]:
                        f.write(f"{e['user']}:{e['hash']}:::::::\n")

            # Phase 2: Quick dictionary
            output += f"\n[Phase 2: Quick Dictionary -- {data['algorithm']}]\n"
            print(f"  {C_CYAN}[*] Phase 2: Quick attack ({data['algorithm']})...{C_RESET}")
            small_wl = self._find_wordlist(prefer_small=True)
            if small_wl:
                if self.hashcat:
                    r = self.crack_with_hashcat(hash_file, small_wl, mode, timeout=30)
                else:
                    r = self.crack_with_john(hash_file, small_wl, timeout=30)
                output += f"  Cracked: {r.get('cracked_count', 0)} in {r.get('elapsed', '?')}s\n"
                self._map_cracked_to_users(data["entries"])

            # Phase 3: Rockyou + rules
            remaining = [e for e in data["entries"] if e["user"] not in self.cracked_users]
            if remaining:
                output += f"\n[Phase 3: Rockyou + Rules -- {data['algorithm']}]\n"
                print(f"  {C_CYAN}[*] Phase 3: Rockyou + rules ({data['algorithm']})...{C_RESET}")
                main_wl = self._find_wordlist(prefer_small=False)
                rules = self._find_rules()
                if main_wl:
                    if self.hashcat:
                        r = self.crack_with_hashcat(hash_file, main_wl, mode, rules=rules, timeout=120)
                    else:
                        r = self.crack_with_john(hash_file, main_wl, timeout=120)
                    output += f"  Cracked: {r.get('cracked_count', 0)} in {r.get('elapsed', '?')}s\n"
                    self._map_cracked_to_users(data["entries"])

            # Phase 4: Mask attack
            remaining = [e for e in data["entries"] if e["user"] not in self.cracked_users]
            if remaining and self.hashcat:
                output += f"\n[Phase 4: Mask Attack -- {data['algorithm']}]\n"
                print(f"  {C_CYAN}[*] Phase 4: Mask attack ({data['algorithm']})...{C_RESET}")
                masks = [
                    "?d?d?d?d?d?d", "?d?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d",
                    "?u?l?l?l?l?d?d", "?u?l?l?l?l?l?d?d", "?l?l?l?l?l?l?d?d",
                ]
                potfile = os.path.join(self._workdir, "hashcat.potfile")
                for mask in masks:
                    try:
                        mask_cmd = [
                            self.hashcat, "-m", str(mode), "-a", "3",
                            "-w", str(self.workload), "--potfile-path", potfile,
                            "-o", os.path.join(self._workdir, "cracked.txt"),
                            "--outfile-format=3",
                        ]
                        if self.has_gpu:
                            mask_cmd.extend(["-D", "1,2", "--force"])
                        mask_cmd.extend([hash_file, mask])
                        subprocess.run(mask_cmd, capture_output=True, text=True, timeout=60)
                    except Exception as _exc:
                        logging.debug(f"Suppressed in hash_cracker.py: {_exc}")
                # Re-read cracked
                outfile = os.path.join(self._workdir, "cracked.txt")
                if os.path.isfile(outfile):
                    try:
                        with open(outfile) as f:
                            for line in f:
                                line = line.strip()
                                if ":" in line:
                                    h, p = line.split(":", 1)
                                    self.cracked[h] = p
                    except Exception as _exc:
                        logging.debug(f"Suppressed in hash_cracker.py: {_exc}")
                self._map_cracked_to_users(data["entries"])
                output += "  Mask phase complete\n"

        total_elapsed = time.time() - total_start
        self._map_cracked_to_users(entries)

        output += f"\n{'=' * 60}\n[CRACKING RESULTS]\n{'=' * 60}\n"
        output += f"  Total hashes:   {len(entries)}\n"
        output += f"  Cracked:        {len(self.cracked_users)}\n"
        output += f"  Time elapsed:   {total_elapsed:.1f}s\n"
        output += f"  Engine:         {'hashcat (GPU)' if self.hashcat else 'john (CPU)'}\n\n"

        if self.cracked_users:
            output += "  CRACKED CREDENTIALS:\n"
            for user, pwd in self.cracked_users.items():
                output += f"    + {user}:{pwd}\n"
                print(f"  {C_GREEN}[+] CRACKED: {user}:{pwd}{C_RESET}")
        else:
            output += "  No passwords cracked.\n"

        remaining = [e for e in entries if e["user"] not in self.cracked_users]
        if remaining:
            output += f"\n  Remaining ({len(remaining)}):\n"
            for e in remaining:
                output += f"    - {e['user']} ({e['algorithm']})\n"

        output += f"\nAI: {len(self.cracked_users)}/{len(entries)} hashes cracked. "
        output += "Use cracked credentials for SSH login.\n"
        return output

    def _map_cracked_to_users(self, entries):
        for e in entries:
            if e["hash"] in self.cracked:
                self.cracked_users[e["user"]] = self.cracked[e["hash"]]

    def get_cracked_pairs(self):
        return list(self.cracked_users.items())

    def format_results(self):
        if not self.cracked_users:
            return "[Hash Cracker] No passwords cracked.\n"
        output = "[CRACKED CREDENTIALS]\n"
        for user, pwd in self.cracked_users.items():
            output += f"  + {user}:{pwd}\n"
        return output

    def cleanup(self):
        try:
            import shutil as _shutil
            _shutil.rmtree(self._workdir, ignore_errors=True)
        except Exception as _exc:
            logging.debug(f"Suppressed in hash_cracker.py: {_exc}")


# ---- STANDALONE FUNCTIONS ----

def run_crack_hashes(shadow_file_or_content):
    hc = HashCracker()
    if os.path.isfile(shadow_file_or_content):
        with open(shadow_file_or_content) as f:
            content = f.read()
    elif "$" in shadow_file_or_content and ":" in shadow_file_or_content:
        content = shadow_file_or_content
    else:
        return f"[!] Not a valid shadow file or content: {shadow_file_or_content[:100]}\n"
    result = hc.smart_crack(content)
    hc.cleanup()
    return result


def run_crack_single(hash_str):
    hc = HashCracker()
    info = hc.identify_hash_type(hash_str)
    if not info.get("hashcat_mode"):
        return f"[!] Unknown hash type: {hash_str[:60]}\n"
    shadow_line = f"unknown:{hash_str}:19000:0:99999:7:::"
    result = hc.smart_crack(shadow_line)
    hc.cleanup()
    return result


if __name__ == "__main__":
    print(f"\n{C_RED}    OCTOPUS -- Hash Cracker Test{C_RESET}\n")
    hc = HashCracker()
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isfile(target):
            print(run_crack_hashes(target))
        else:
            info = hc.identify_hash_type(target)
            print(f"  Hash type: {info}")
    else:
        print("  Usage:")
        print("    python3 hash_cracker.py /path/to/shadow")
        print("    python3 hash_cracker.py '$6$salt$hash...'")
        print(f"\n  hashcat: {'Y ' + str(hc.hashcat) if hc.hashcat else 'N'}")
        print(f"  john:    {'Y ' + str(hc.john) if hc.john else 'N'}")
        print(f"  GPU:     {'Y CUDA' if hc.has_gpu else 'N'}")
