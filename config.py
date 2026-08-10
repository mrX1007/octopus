#!/usr/bin/env python3


import copy
import math
import os
from collections.abc import Mapping
from typing import Any, Optional

import yaml  # type: ignore[import-untyped]

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

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_USER_CONFIG_PATH = "~/.octopus/config.yaml"
_SYSTEM_CONFIG_PATH = "/etc/octopus/config.yaml"
_BUNDLED_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "config.yaml")


class ConfigValidationError(ValueError):
    """Raised when an explicit configuration source violates the contract."""


def _find_config() -> str:
    """Resolve config with explicit > user > system > bundled precedence."""

    explicit = os.environ.get("OCTOPUS_CONFIG", "").strip()
    if explicit:
        explicit = os.path.abspath(os.path.expanduser(explicit))
        if not os.path.isfile(explicit):
            raise ConfigValidationError(f"OCTOPUS_CONFIG does not reference a readable file: {explicit}")
        return explicit

    for candidate in (
        _USER_CONFIG_PATH,
        _SYSTEM_CONFIG_PATH,
        _BUNDLED_CONFIG_PATH,
    ):
        path = os.path.abspath(os.path.expanduser(candidate))
        if os.path.isfile(path):
            return path
    return ""


KILLCHAIN_STAGE_KEYS: tuple[str, ...] = (
    "vuln_assess",
    "exploitation",
    "privesc",
    "persistence",
    "lateral_movement",
    "data_exfil",
    "cleanup",
)


DEFAULTS: dict[str, Any] = {
    "db": {
        "host": "localhost",
        "user": "octopus",
        "password": "",
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
        "top_k": 10,
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
        "json_format": True,
        "json_think": False,
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
        "preferred": "hashcat",  # hashcat (GPU) or john (CPU)
        "gpu_device": 0,  # CUDA device ID
        "workload": 3,  # hashcat -w (1=low, 2=med, 3=high, 4=insane)
        "timeout": 600,  # max seconds per cracking phase
        "max_wordlist_size": 50_000_000,  # max lines from wordlist
    },
    "killchain": {
        "enabled": True,
        "stages": dict.fromkeys(KILLCHAIN_STAGE_KEYS, True),
        "quick_privesc_after_root": True,
        "credential_harvest_timeout": 25,
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
        "task_inputs": {
            # Explicit operator-owned local/cloud scopes for autonomous tasks.
            # Artifact facts are accepted only beneath these filesystem roots.
            "filesystem_scopes": [],
            "session_profiles": [],
            "jwt_artifacts": [],
            "burp_exports": [],
            "zap_exports": [],
            "openapi_specs": [],
            "cloud_providers": [],
            # Per-plugin values validated against discovered input_schema.
            # Credential/path/artifact references remain opaque at this layer.
            "plugin_actions": {},
        },
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
        "plan_enrichment_limit": 8,
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
        "memory": "~/OCTOPUS/memory",
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
        "root",
        "admin",
        "administrator",
        "support",
        "user",
        "test",
        "guest",
        "operator",
        "ftp",
        "www",
    ],
    "tools": {
        "nmap": {
            "default_flags": ["-sV", "-sC", "-T4", "--open", "-Pn", "-sT"],
            "timeout": 300,
            "aggressive_flags": ["-A", "-T4", "-p-", "-Pn", "-sT"],
        },
        "hydra": {"threads": 16, "timeout": 600, "flags": ["-V"]},
        "ffuf": {
            "threads": 50,
            "timeout": 120,
            "match_codes": "200,204,301,302,307,401,403",
            "flags": ["-c"],
            "maxtime": 60,
            "request_timeout": 5,
        },
        "nikto": {"timeout": 300, "flags": ["-nointeractive"]},
        "sqlmap": {"level": 1, "risk": 1, "timeout": 180, "flags": ["--batch", "--crawl=1"]},
        "wpscan": {"timeout": 180, "flags": ["--no-update", "--random-user-agent"]},
        "enum4linux": {"timeout": 150, "flags": ["-a"]},
        "sslscan": {"timeout": 120, "flags": ["--no-colour"]},
        "smbclient": {"timeout": 45, "flags": ["-N"]},
        "curl": {"timeout": 20, "flags": ["-sI", "--max-time", "10", "--location"]},
        "dig": {"timeout": 15, "record_types": ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]},
        "whois": {"timeout": 30},
        "whatweb": {"timeout": 90, "aggression": 3},
        "searchsploit": {"timeout": 30, "max_results": 20},
        "msfconsole": {"timeout": 300},
        "gobuster": {"threads": 50, "timeout": 180, "flags": []},
        "dirb": {"timeout": 180, "flags": []},
        "nuclei": {
            "timeout": 1200,
            "request_timeout": 20,
            "retries": 2,
            "severity": "info,low,medium,high,critical",
            "exclude_tags": "dos,fuzz,bruteforce,intrusive,destructive",
        },
    },
}


_EMPTY_LIST_ITEM_TYPES: dict[tuple[str, ...], type] = {
    ("strategy", "authorized_targets"): str,
    ("strategy", "task_inputs", "filesystem_scopes"): str,
    ("strategy", "task_inputs", "session_profiles"): str,
    ("strategy", "task_inputs", "jwt_artifacts"): str,
    ("strategy", "task_inputs", "burp_exports"): str,
    ("strategy", "task_inputs", "zap_exports"): str,
    ("strategy", "task_inputs", "openapi_specs"): str,
    ("strategy", "task_inputs", "cloud_providers"): str,
    ("wordlists", "dns"): str,
    ("wordlists", "snmp"): str,
    ("wordlists", "ftp_passwords"): str,
    ("wordlists", "ssh_passwords"): str,
    ("wordlists", "http_default_creds"): str,
    ("wordlists", "sqli"): str,
    ("wordlists", "xss"): str,
    ("wordlists", "lfi"): str,
    ("tools", "gobuster", "flags"): str,
    ("tools", "dirb", "flags"): str,
}

_NUMERIC_RANGES: dict[tuple[str, ...], tuple[Optional[float], Optional[float]]] = {
    ("ollama", "max_tokens"): (1, None),
    ("ollama", "json_max_tokens"): (1, None),
    ("ollama", "temperature"): (0, 2),
    ("ollama", "json_temperature"): (0, 2),
    ("ollama", "top_p"): (0, 1),
    ("ollama", "top_k"): (1, None),
    ("ollama", "timeout"): (1, None),
    ("ollama", "retries"): (0, None),
    ("ollama", "context_window"): (1, None),
    ("ollama", "max_tool_loops"): (1, None),
    ("ollama", "summarize_threshold"): (512, None),
    ("ollama", "concurrent_tools"): (1, 256),
    ("ollama", "num_threads"): (1, None),
    ("ollama", "num_ctx"): (1, None),
    ("ollama", "num_batch"): (1, None),
    ("ollama", "repeat_penalty"): (0.01, None),
    ("shodan", "max_results"): (1, None),
    ("shodan", "timeout"): (1, None),
    ("hash_cracker", "gpu_device"): (0, None),
    ("hash_cracker", "workload"): (1, 4),
    ("hash_cracker", "timeout"): (1, None),
    ("hash_cracker", "max_wordlist_size"): (1, None),
    ("killchain", "credential_harvest_timeout"): (1, 3600),
    ("bruteforce", "max_retries"): (0, None),
    ("bruteforce", "ssh_wait_W"): (0, None),
    ("bruteforce", "ssh_wait_w"): (0, None),
    ("bruteforce", "cooldown_between_tiers"): (0, None),
    ("strategy", "max_bruteforce_time"): (0, None),
    ("strategy", "max_active_msf_runs_per_scan"): (0, None),
    ("strategy", "fact_action_max_depth"): (0, None),
    ("strategy", "fact_action_max_commands"): (0, None),
    ("strategy", "fact_action_batch_commands"): (0, None),
    ("strategy", "verification_followup_commands"): (0, None),
    ("strategy", "searchsploit_followup_queries"): (0, None),
    ("strategy", "web_surface_endpoint_limit"): (0, None),
    ("strategy", "web_surface_followup_commands"): (0, None),
    ("strategy", "web_path_followup_commands"): (0, None),
    ("strategy", "web_link_followup_commands"): (0, None),
    ("strategy", "web_link_url_limit"): (0, None),
    ("strategy", "exploit_select_context_facts"): (0, None),
    ("strategy", "parallel_tools"): (1, 256),
    ("strategy", "max_director_loops"): (1, None),
    ("strategy", "plan_enrichment_limit"): (0, None),
    ("strategy", "mission", "task_retry_budget"): (0, None),
    ("strategy", "mission", "max_state_replans"): (0, None),
    ("scrapling", "timeout"): (1, None),
    ("scrapling", "max_crawl_pages"): (1, None),
}

for _tool_name, _tool_defaults in DEFAULTS["tools"].items():
    _NUMERIC_RANGES[("tools", _tool_name, "timeout")] = (0, None)
    if "threads" in _tool_defaults:
        _NUMERIC_RANGES[("tools", _tool_name, "threads")] = (1, 256)
    if "request_timeout" in _tool_defaults:
        _NUMERIC_RANGES[("tools", _tool_name, "request_timeout")] = (1, None)
    if "retries" in _tool_defaults:
        _NUMERIC_RANGES[("tools", _tool_name, "retries")] = (0, None)

_NUMERIC_RANGES.update(
    {
        ("tools", "ffuf", "maxtime"): (0, None),
        ("tools", "sqlmap", "level"): (1, 5),
        ("tools", "sqlmap", "risk"): (1, 3),
        ("tools", "whatweb", "aggression"): (1, 4),
        ("tools", "searchsploit", "max_results"): (1, None),
    }
)

_NUMERIC_LIST_RANGES: dict[tuple[str, ...], tuple[Optional[float], Optional[float]]] = {
    ("bruteforce", "ssh_thread_levels"): (1, 256),
    ("bruteforce", "backoff_seconds"): (0, None),
}


def _path_label(path: tuple[str, ...]) -> str:
    return ".".join(path) or "<root>"


def _expected_type_name(default) -> str:
    if isinstance(default, bool):
        return "boolean"
    if isinstance(default, int):
        return "integer"
    if isinstance(default, float):
        return "number"
    if isinstance(default, str):
        return "string"
    if isinstance(default, list):
        return "list"
    if isinstance(default, dict):
        return "mapping"
    return type(default).__name__


def _matches_default_type(
    value,
    default,
    path: tuple[str, ...] = (),
) -> bool:
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
            return all(_matches_default_type(item, exemplar, path) for item in value)
        item_type = _EMPTY_LIST_ITEM_TYPES.get(path)
        return not value if item_type is None else all(isinstance(item, item_type) for item in value)
    if isinstance(default, dict):
        return isinstance(value, dict)
    return isinstance(value, type(default))


def _validate_value(path: tuple[str, ...], value) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ConfigValidationError(f"{_path_label(path)} must be finite; got {value!r}")

    bounds = _NUMERIC_RANGES.get(path)
    if bounds is not None:
        minimum, maximum = bounds
        if minimum is not None and value < minimum:
            raise ConfigValidationError(f"{_path_label(path)} must be >= {minimum:g}; got {value!r}")
        if maximum is not None and value > maximum:
            raise ConfigValidationError(f"{_path_label(path)} must be <= {maximum:g}; got {value!r}")

    list_bounds = _NUMERIC_LIST_RANGES.get(path)
    if list_bounds is not None:
        minimum, maximum = list_bounds
        for index, item in enumerate(value):
            if minimum is not None and item < minimum:
                raise ConfigValidationError(f"{_path_label(path)}[{index}] must be >= {minimum:g}; got {item!r}")
            if maximum is not None and item > maximum:
                raise ConfigValidationError(f"{_path_label(path)}[{index}] must be <= {maximum:g}; got {item!r}")

    if path == ("strategy", "task_inputs", "cloud_providers"):
        supported = {"aws", "azure", "gcp", "kubernetes", "m365"}
        for index, item in enumerate(value):
            if item.strip().casefold() not in supported:
                raise ConfigValidationError(
                    f"{_path_label(path)}[{index}] must be a supported cloud provider; got {item!r}"
                )


def _strict_json_config_value(value: Any, path: tuple[str, ...]) -> Any:
    """Validate and detach a plugin input value without interpreting it."""

    if value is None or isinstance(value, (str, bool, int)):
        if value is None:
            raise ConfigValidationError(f"{_path_label(path)} must not be null")
        return copy.deepcopy(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ConfigValidationError(f"{_path_label(path)} must be finite; got {value!r}")
        return value
    if isinstance(value, list):
        return [_strict_json_config_value(item, (*path, str(index))) for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ConfigValidationError(f"{_path_label(path)} keys must be non-empty strings")
            result[key] = _strict_json_config_value(item, (*path, key))
        return result
    raise ConfigValidationError(
        f"{_path_label(path)} must contain only JSON-compatible values; got {type(value).__name__}"
    )


def _validate_plugin_action_inputs(value: Any, path: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigValidationError(f"{_path_label(path)} must be a mapping; got {type(value).__name__}")
    result = {}
    for plugin_name, parameters in value.items():
        if not isinstance(plugin_name, str) or not plugin_name.strip():
            raise ConfigValidationError(f"{_path_label(path)} plugin names must be non-empty strings")
        plugin_path = (*path, plugin_name)
        if not isinstance(parameters, Mapping):
            raise ConfigValidationError(
                f"{_path_label(plugin_path)} must be a mapping; got {type(parameters).__name__}"
            )
        result[plugin_name] = _strict_json_config_value(parameters, plugin_path)
    return result


def _deep_merge(
    base: Mapping[Any, Any],
    override: Mapping[Any, Any],
    *,
    _path: tuple[str, ...] = (),
) -> dict[Any, Any]:
    """Strictly merge a validated mapping into a detached defaults copy."""
    if not isinstance(base, Mapping) or not isinstance(override, Mapping):
        raise ConfigValidationError(f"{_path_label(_path)} must be a mapping")
    result = copy.deepcopy(dict(base))
    for key, value in override.items():
        path = (*_path, str(key))
        if key not in base:
            if _path == ("killchain", "stages"):
                allowed = ", ".join(KILLCHAIN_STAGE_KEYS)
                raise ConfigValidationError(f"unknown killchain stage {_path_label(path)!r}; allowed stages: {allowed}")
            raise ConfigValidationError(f"unknown configuration key {_path_label(path)!r}")

        default = base[key]
        if path == ("strategy", "task_inputs", "plugin_actions"):
            result[key] = _validate_plugin_action_inputs(value, path)
            continue
        if isinstance(default, dict):
            if not isinstance(value, Mapping):
                raise ConfigValidationError(f"{_path_label(path)} must be a mapping; got {type(value).__name__}")
            result[key] = _deep_merge(default, value, _path=path)
            continue

        if not _matches_default_type(value, default, path):
            raise ConfigValidationError(
                f"{_path_label(path)} must be {_expected_type_name(default)}; got {type(value).__name__}"
            )
        _validate_value(path, value)
        result[key] = copy.deepcopy(value)
    return result


def _env_int(name: str, path: tuple[str, ...]) -> Optional[int]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigValidationError(f"environment variable {name} must be an integer; got {raw!r}") from exc
    _validate_value(path, value)
    return value


def load_config() -> dict:
    """Load and strictly validate the highest-precedence config source."""
    config_path = _find_config()

    if config_path:
        try:
            with open(config_path, encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            if user_config is None:
                user_config = {}
            if not isinstance(user_config, Mapping):
                raise ConfigValidationError("the top-level YAML value must be a mapping")
            cfg = _deep_merge(DEFAULTS, user_config)
        except ConfigValidationError as exc:
            raise ConfigValidationError(f"invalid configuration in {config_path}: {exc}") from exc
        except Exception as exc:
            raise ConfigValidationError(f"failed to read configuration {config_path}: {exc}") from exc
    else:
        print("\033[93m[!] No config.yaml found. Using built-in defaults.\033[0m")
        cfg = copy.deepcopy(DEFAULTS)

    if isinstance(cfg.get("paths"), dict):
        for key, val in cfg["paths"].items():
            if isinstance(val, str):
                cfg["paths"][key] = os.path.expanduser(val)

    # Environment values take precedence over YAML.
    cfg["db"]["host"] = os.environ.get("OCTOPUS_DB_HOST", cfg["db"]["host"])
    cfg["db"]["user"] = os.environ.get("OCTOPUS_DB_USER", cfg["db"]["user"])
    cfg["db"]["password"] = os.environ.get("OCTOPUS_DB_PASS", cfg["db"]["password"])
    cfg["db"]["database"] = os.environ.get("OCTOPUS_DB_NAME", cfg["db"]["database"])

    if os.environ.get("OCTOPUS_OLLAMA_URL"):
        cfg["ollama"]["url"] = os.environ["OCTOPUS_OLLAMA_URL"]
    if os.environ.get("OCTOPUS_OLLAMA_MODEL"):
        cfg["ollama"]["model"] = os.environ["OCTOPUS_OLLAMA_MODEL"]
    env_num_ctx = _env_int(
        "OCTOBENCH_OLLAMA_CONTEXT_LENGTH",
        ("ollama", "num_ctx"),
    )
    if env_num_ctx is not None:
        cfg["ollama"]["num_ctx"] = env_num_ctx

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
