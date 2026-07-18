#!/usr/bin/env python3


import copy
import os
from typing import Optional

import yaml

# Load .env before constructing defaults.
try:
    from dotenv import load_dotenv
    # Search for .env in: 1) script dir  2) cwd  3) home dir
    _SCRIPT_DIR_ENV = os.path.dirname(os.path.abspath(__file__))
    for _env_path in [
        os.path.join(_SCRIPT_DIR_ENV, ".env"),
        os.path.join(os.getcwd(), ".env"),
        os.path.expanduser("~/.octopus/.env"),
    ]:
        if os.path.isfile(_env_path):
            load_dotenv(_env_path)
            break
    else:
        load_dotenv()  # Try default locations
except ImportError:
    pass  # python-dotenv not installed — env vars still work via os.environ

# Config locations are ordered from highest to lowest priority.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATHS = [
    os.environ.get("OCTOPUS_CONFIG", ""),
    os.path.join(_SCRIPT_DIR, "config.yaml"),
    os.path.expanduser("~/.octopus/config.yaml"),
    "/etc/octopus/config.yaml",
]


def _find_config() -> str:
    for path in _CONFIG_PATHS:
        if path and os.path.isfile(path):
            return path
    return ""


DEFAULTS = {
    "db": {
        "host": "localhost",
        "user": "octopus",
        "password": "123",
        "database": "octopus",
    },
    "ollama": {
        "url": os.environ.get("OCTOPUS_OLLAMA_URL", "http://localhost:11434/api/generate"),
        "model": os.environ.get("OCTOPUS_OLLAMA_MODEL", "octopus-qwen"),
        "max_tokens": 4096,
        "json_max_tokens": 1536,
        "temperature": 0.4,
        "json_temperature": 0.15,
        "top_p": 0.9,
        "timeout": 1200,
        "retries": 3,
        "context_window": 6,
        "max_tool_loops": 25,
        "summarize_threshold": 8000,
        "concurrent_tools": 8,
        "num_gpu": 999,
        "num_threads": 16,
        "num_ctx": 16384,
        "num_batch": 512,
        "repeat_penalty": 1.15,
    },
    "shodan": {
        "api_key": os.environ.get("SHODAN_API_KEY", ""),
        "max_results": 100,
        "timeout": 30,
        "auto_scan": False,
        "save_results": True,
        "results_dir": "/tmp/octopus_shodan",
        "auto_pipeline": True,
    },
    "hash_cracker": {
        "preferred": "hashcat",   # hashcat (GPU) or john (CPU)
        "gpu_device": 0,          # CUDA device ID
        "workload": 3,            # hashcat -w (1=low, 2=med, 3=high, 4=insane)
        "timeout": 600,           # max seconds per cracking phase
        "max_wordlist_size": 50_000_000,  # max lines from wordlist
    },
    "killchain": {
        "enabled": True,
        "stages": {
            "vuln_assess": True,
            "exploitation": True,
            "privesc": True,
            "persistence": True,
            "lateral_movement": True,
            "data_exfil": True,
            "cleanup": True,
        },
        "exfil_dir": "/tmp",
    },
    "bruteforce": {
        "adaptive_threads": True,
        "ssh_thread_levels": [4, 2, 1],
        "max_retries": 3,
        "backoff_seconds": [30, 60, 120],
        "ssh_wait_W": 15,
        "ssh_wait_w": 15,
        "cooldown_between_tiers": 10,
    },
    "strategy": {
        "prefer_stealth": True,
        "max_bruteforce_time": 600,
        "auto_killchain": True,
        "auto_post_access_inventory": True,
        "auto_ssh_inventory": True,
        "auto_internal_recon": True,
        "auto_payload_generation": False,
        "auto_persistence": False,
        "auto_data_exfil": False,
        "auto_cleanup": False,
        "allow_active_msf": False,
        "active_authorized": False,
        "authorized_targets": [],
        "max_active_msf_runs_per_scan": 1,
        "allow_arbitrary_ssh_exec": False,
        "fact_action_max_depth": 0,
        "fact_action_max_commands": 0,
        "fact_action_batch_commands": 0,
        "verification_followup_commands": 0,
        "searchsploit_followup_queries": 0,
        "web_surface_endpoint_limit": 0,
        "web_surface_followup_commands": 0,
        "web_path_followup_commands": 0,
        "web_link_followup_commands": 0,
        "web_link_url_limit": 0,
        "exploit_select_context_facts": 0,
        "parallel_tools": 8,
        "max_director_loops": 10,
        "mission": {
            "task_retry_budget": 2,
            "retryable_error_classes": [
                "timeout",
                "rate_limit",
                "transient_network",
                "provider_unavailable",
                "tool_unavailable",
            ],
            "max_state_replans": 3,
        },
        "task_scoring": {
            "schema_version": "1.0",
            "weights": {
                "information_gain": 3.0,
                "coverage_value": 2.5,
                "verification_value": 2.0,
                "path_value": 2.0,
                "cost": 1.0,
                "repeat": 3.0,
                "risk": 1.5,
                "uncertainty": 1.5,
            },
        },
    },
    "reporting": {
        "auto_export": False,
        "include_raw_output": False,
        "cvss_scoring": True,
    },
    "paths": {
        "reports": "~/OCTOPUS/reports",
        "logs": "~/OCTOPUS/logs",
        "checkpoints": "/tmp",
        "secrets": "data/secrets.db",
    },
    "wordlists": {
        "passwords": [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/john/password.lst",
            os.path.expanduser("~/.octopus/wordlists/rockyou.txt"),
        ],
        "usernames": [
            "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        ],
        "web_dirs": [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ],
        "dns": [],
        "snmp": [],
        "ftp_passwords": [],
        "ssh_passwords": [],
        "http_default_creds": [],
        "sqli": [],
        "xss": [],
        "lfi": [],
    },
    "scrapling": {
        "enabled": True,
        "timeout": 30,
        "max_crawl_pages": 10,
        "use_stealth": True,
    },
    "default_users": [
        "root", "admin", "administrator", "support", "user",
        "test", "guest", "operator", "ftp", "www",
    ],
    "tools": {
        "nmap":         {"default_flags": ["-sV", "-sC", "-T4", "--open", "-Pn", "-sT"], "timeout": 180},
        "hydra":        {"threads": 4, "timeout": 300},
        "ffuf":         {"threads": 50, "timeout": 120, "match_codes": "200,204,301,302,307,401,403"},
        "nikto":        {"timeout": 300},
        "sqlmap":       {"level": 1, "risk": 1, "timeout": 180},
        "wpscan":       {"timeout": 180},
        "enum4linux":   {"timeout": 150},
        "sslscan":      {"timeout": 120},
        "smbclient":    {"timeout": 45},
        "curl":         {"timeout": 20},
        "dig":          {"timeout": 15},
        "whois":        {"timeout": 30},
        "whatweb":      {"timeout": 90},
        "searchsploit": {"timeout": 30, "max_results": 20},
        "msfconsole":   {"timeout": 300},
    },
}


def _matches_default_type(value, default) -> bool:
    """Return whether a configured value is compatible with a known default."""
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        if not isinstance(value, list):
            return False
        if default:
            exemplar = default[0]
            return all(_matches_default_type(item, exemplar) for item in value)
        return True
    if isinstance(default, dict):
        return isinstance(value, dict)
    return isinstance(value, type(default))


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge a mapping into a detached copy, retaining valid known-key types."""
    if not isinstance(base, dict) or not isinstance(override, dict):
        raise TypeError("configuration base and override must be mappings")
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in base and isinstance(base[key], dict):
            if isinstance(value, dict):
                result[key] = _deep_merge(base[key], value)
        elif key in base:
            if _matches_default_type(value, base[key]):
                result[key] = copy.deepcopy(value)
        else:
            # Unknown extension keys have no schema, but must still be detached.
            result[key] = copy.deepcopy(value)
    return result


def load_config() -> dict:
    """Load config.yaml and merge with defaults. Returns final config dict."""
    config_path = _find_config()

    if config_path:
        try:
            with open(config_path) as f:
                user_config = yaml.safe_load(f)
            if user_config is None:
                user_config = {}
            if not isinstance(user_config, dict):
                raise TypeError("the top-level YAML value must be a mapping")
            cfg = _deep_merge(DEFAULTS, user_config)
        except Exception as e:
            print(f"\033[93m[!] Failed to load {config_path}: {e}. Using defaults.\033[0m")
            cfg = copy.deepcopy(DEFAULTS)
    else:
        print("\033[93m[!] No config.yaml found. Using built-in defaults.\033[0m")
        cfg = copy.deepcopy(DEFAULTS)

    if isinstance(cfg.get("paths"), dict):
        for key, val in cfg["paths"].items():
            if isinstance(val, str):
                cfg["paths"][key] = os.path.expanduser(val)

    # Environment values take precedence over YAML.
    cfg["db"]["host"]     = os.environ.get("OCTOPUS_DB_HOST", cfg["db"]["host"])
    cfg["db"]["user"]     = os.environ.get("OCTOPUS_DB_USER", cfg["db"]["user"])
    cfg["db"]["password"] = os.environ.get("OCTOPUS_DB_PASS", cfg["db"]["password"])
    cfg["db"]["database"] = os.environ.get("OCTOPUS_DB_NAME", cfg["db"]["database"])

    if os.environ.get("OCTOPUS_OLLAMA_URL"):
        cfg["ollama"]["url"] = os.environ["OCTOPUS_OLLAMA_URL"]
    if os.environ.get("OCTOPUS_OLLAMA_MODEL"):
        cfg["ollama"]["model"] = os.environ["OCTOPUS_OLLAMA_MODEL"]
    if os.environ.get("OCTOBENCH_OLLAMA_CONTEXT_LENGTH"):
        cfg["ollama"]["num_ctx"] = int(
            os.environ["OCTOBENCH_OLLAMA_CONTEXT_LENGTH"]
        )

    return cfg


def find_wordlist(category: str, cfg: Optional[dict] = None) -> str:
    """
    Find the first existing wordlist file from a category.
    Categories: 'passwords', 'usernames', 'web_dirs', 'dns', 'snmp',
                'ftp_passwords', 'ssh_passwords', 'http_default_creds',
                'sqli', 'xss', 'lfi'
    Returns path string or empty string if none found.
    """
    if cfg is None:
        cfg = CFG
    if not isinstance(cfg, dict):
        return ""
    wordlists = cfg.get("wordlists", {})
    if not isinstance(wordlists, dict):
        return ""
    paths = wordlists.get(category, [])
    if not isinstance(paths, (list, tuple)):
        return ""
    for p in paths:
        if not isinstance(p, str):
            continue
        expanded = os.path.expanduser(p)
        if os.path.isfile(expanded):
            return expanded
    return ""


def find_all_wordlists(category: str, cfg: Optional[dict] = None) -> list:
    """
    Find ALL existing wordlist files from a category.
    Returns list of existing paths.
    """
    if cfg is None:
        cfg = CFG
    if not isinstance(cfg, dict):
        return []
    wordlists = cfg.get("wordlists", {})
    if not isinstance(wordlists, dict):
        return []
    paths = wordlists.get(category, [])
    if not isinstance(paths, (list, tuple)):
        return []
    found = []
    for p in paths:
        if not isinstance(p, str):
            continue
        expanded = os.path.expanduser(p)
        if os.path.isfile(expanded):
            found.append(expanded)
    return found


def get_tool_config(tool_name: str, cfg: Optional[dict] = None) -> dict:
    """Get tool-specific config dict. Returns empty dict if not configured."""
    if cfg is None:
        cfg = CFG
    if not isinstance(cfg, dict):
        return {}
    tools = cfg.get("tools", {})
    if not isinstance(tools, dict):
        return {}
    value = tools.get(tool_name, {})
    return value if isinstance(value, dict) else {}


def get_secret(key: str, default: str = "") -> str:
    """
    Get a secret value with priority: .env/os.environ → config.yaml → default.
    Useful for API keys, passwords, tokens that should NOT be in yaml.
    Usage: get_secret("SHODAN_API_KEY")
    """
    env_val = os.environ.get(key, "")
    if env_val:
        return env_val
    _SECRET_MAP = {
        "SHODAN_API_KEY": ("shodan", "api_key"),
        "OCTOPUS_DB_PASS": ("db", "password"),
        "OCTOPUS_C2_PSK": ("c2", "psk"),
    }
    if key in _SECRET_MAP:
        section, subkey = _SECRET_MAP[key]
        section_cfg = CFG.get(section, {})
        val = section_cfg.get(subkey, "") if isinstance(section_cfg, dict) else ""
        if val:
            return val
    return default


CFG = load_config()


if __name__ == "__main__":
    print("\033[91m    OCTOPUS — Config Loader\033[0m")
    print(f"\033[90m    Config file: {_find_config() or 'NONE (using defaults)'}\033[0m\n")

    print(f"  DB:          {CFG['db']['host']} / {CFG['db']['database']}")
    print(f"  Ollama:      {CFG['ollama']['model']} @ {CFG['ollama']['url']}")
    print(f"  Reports:     {CFG['paths']['reports']}")
    print(f"  Logs:        {CFG['paths']['logs']}")
    print(f"  Checkpoints: {CFG['paths']['checkpoints']}")

    print("\n  \033[96m[ WORDLIST AVAILABILITY ]\033[0m")
    for cat in CFG["wordlists"]:
        total = len(CFG["wordlists"][cat])
        found = len(find_all_wordlists(cat))
        first = find_wordlist(cat)
        status = f"\033[92m{found}/{total}\033[0m" if found > 0 else f"\033[91m0/{total}\033[0m"
        first_short = os.path.basename(first) if first else "—"
        print(f"    {cat:<22} {status:<20} primary: {first_short}")

    print("\n  \033[96m[ TOOL TIMEOUTS ]\033[0m")
    for tool, tcfg in CFG.get("tools", {}).items():
        timeout = tcfg.get("timeout", "?")
        print(f"    {tool:<18} {timeout}s")
