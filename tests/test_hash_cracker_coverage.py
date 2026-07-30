"""Process-free branch coverage for the local hash-cracker wrapper."""

from __future__ import annotations

import builtins
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import hash_cracker

pytestmark = [pytest.mark.unit, pytest.mark.security]


class Clock:
    def __init__(self, *values: float) -> None:
        self.values = list(values)
        self.current = self.values[0] if self.values else 0.0

    def __call__(self) -> float:
        if self.values:
            self.current = self.values.pop(0)
        return self.current


def bare_cracker(tmp_path, *, hashcat=None, john=None, gpu=False):
    cracker = object.__new__(hash_cracker.HashCracker)
    cracker.hashcat = hashcat
    cracker.john = john
    cracker.has_gpu = gpu
    cracker.cracked = {}
    cracker.cracked_users = {}
    cracker.cfg = {}
    cracker.workload = 3
    cracker.timeout = 600
    cracker._workdir = str(tmp_path)
    return cracker


@pytest.mark.parametrize(
    ("backend", "gpu", "needle"),
    [
        ("CUDA backend", True, "GPU (CUDA)"),
        ("OpenCL backend", True, "GPU (CUDA)"),
        ("HIP backend", True, "GPU (CUDA)"),
        ("CPU backend", False, "CPU only"),
    ],
)
def test_init_detects_each_backend(monkeypatch, tmp_path, capsys, backend, gpu, needle) -> None:
    monkeypatch.setattr(hash_cracker.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(
        hash_cracker.shutil,
        "which",
        lambda name: f"/bin/{name}",
    )
    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=backend),
    )
    cracker = hash_cracker.HashCracker()
    assert cracker.has_gpu is gpu
    assert needle in capsys.readouterr().out


def test_init_backend_error_john_only_and_no_tools(monkeypatch, tmp_path, capsys, caplog) -> None:
    monkeypatch.setattr(hash_cracker.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(hash_cracker.shutil, "which", lambda name: f"/bin/{name}")
    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("backend failed")),
    )
    with caplog.at_level("DEBUG"):
        assert hash_cracker.HashCracker().has_gpu is False
    assert "backend failed" in caplog.text

    monkeypatch.setattr(
        hash_cracker.shutil,
        "which",
        lambda name: "/bin/john" if name == "john" else None,
    )
    assert hash_cracker.HashCracker().john == "/bin/john"
    assert "using john" in capsys.readouterr().out

    monkeypatch.setattr(hash_cracker.shutil, "which", lambda _name: None)
    cracker = hash_cracker.HashCracker()
    assert cracker.hashcat is None and cracker.john is None
    assert "No cracking tool" in capsys.readouterr().out


def test_wordlist_precedence_filtering_fallback_and_rules(monkeypatch, tmp_path) -> None:
    cracker = bare_cracker(tmp_path)
    configured = str(tmp_path / "configured.txt")
    ten_k = str(tmp_path / "10k-common.txt")
    large = str(tmp_path / "large.txt")
    small = str(tmp_path / "small.txt")
    paths = ["/missing", large, small, ten_k]
    monkeypatch.setattr(hash_cracker, "WORDLIST_PATHS", paths)
    monkeypatch.setattr(hash_cracker, "find_wordlist", lambda _category: configured)
    monkeypatch.setattr(
        hash_cracker.os.path,
        "isfile",
        lambda path: path in {configured, ten_k, large, small},
    )
    monkeypatch.setattr(hash_cracker.os.path, "getsize", lambda path: 20_000_000 if path == large else 10)
    assert cracker._find_wordlist() == configured
    assert cracker._find_wordlist(prefer_small=True) == ten_k

    monkeypatch.setattr(hash_cracker, "WORDLIST_PATHS", [small])
    assert cracker._find_wordlist(prefer_small=True) == configured

    monkeypatch.setattr(hash_cracker, "find_wordlist", lambda _category: "")
    monkeypatch.setattr(hash_cracker, "WORDLIST_PATHS", ["/missing", large, small])
    assert cracker._find_wordlist(prefer_small=True) == small
    assert cracker._find_wordlist(prefer_small=False) == large

    monkeypatch.setattr(hash_cracker.os.path, "isfile", lambda _path: False)
    generated = cracker._find_wordlist()
    assert generated.endswith("mini_wordlist.txt")
    assert "p@ssw0rd" in Path(generated).read_text(encoding="utf-8")

    rule = "/rules/best.rule"
    monkeypatch.setattr(hash_cracker, "RULE_PATHS", ["/missing", rule])
    monkeypatch.setattr(hash_cracker.os.path, "isfile", lambda path: path == rule)
    assert cracker._find_rules() == rule
    monkeypatch.setattr(hash_cracker.os.path, "isfile", lambda _path: False)
    assert cracker._find_rules() == ""


def test_shadow_extraction_and_hash_identification_cover_all_filters(tmp_path) -> None:
    cracker = bare_cracker(tmp_path)
    content = """

    # comment
    malformed
    star:*
    locked:!$6$salt$locked
    unknown:plainhash
    alice:$6$salt$hash:1:2
    bob:$2b$salt$hash:1:2
    """
    entries = cracker.extract_hashes_from_shadow(content)
    assert [(entry["user"], entry["hashcat_mode"]) for entry in entries] == [
        ("alice", 1800),
        ("bob", 3200),
    ]
    for locked in ("!", "!!", "", "x", "NP", "LK"):
        assert cracker.extract_hashes_from_shadow(f"user:{locked}:rest") == []
    assert cracker.identify_hash_type("$1$salt$hash")["algorithm"] == "MD5crypt"
    assert cracker.identify_hash_type("unknown")["hashcat_mode"] is None


def test_hashcat_missing_success_timeout_error_and_output_read_failure(
    monkeypatch,
    tmp_path,
    capsys,
    caplog,
) -> None:
    cracker = bare_cracker(tmp_path)
    assert "hashcat not found" in cracker.crack_with_hashcat("hashes", "words")["error"]

    cracker.hashcat = "/bin/hashcat"
    cracker.has_gpu = True
    wordlist = tmp_path / "words.txt"
    rules = tmp_path / "rules.rule"
    wordlist.write_text("password\n", encoding="utf-8")
    rules.write_text(":\n", encoding="utf-8")
    outfile = tmp_path / "cracked.txt"
    outfile.write_text("hash:password\ninvalid\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda cmd, **kwargs: calls.append((cmd, kwargs)) or SimpleNamespace(stdout=""),
    )
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.26))
    result = cracker.crack_with_hashcat(
        "hashes",
        str(wordlist),
        500,
        rules=str(rules),
        timeout=9,
        extra_args=["--quiet"],
    )
    assert result == {"cracked": {"hash": "password"}, "cracked_count": 1, "elapsed": 1.3}
    assert "-D" in calls[0][0] and "-r" in calls[0][0] and "--quiet" in calls[0][0]
    assert "rules=" in capsys.readouterr().out

    outfile.unlink()
    cracker.has_gpu = False
    monkeypatch.setattr(hash_cracker.time, "time", Clock(4.0, 4.0))
    result = cracker.crack_with_hashcat("hashes", str(wordlist), rules="/missing", extra_args=[])
    assert result["cracked"] == {}
    assert "-D" not in calls[-1][0] and "-r" not in calls[-1][0]

    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("hashcat", 3)),
    )
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    assert cracker.crack_with_hashcat("hashes", str(wordlist), timeout=3)["elapsed"] == 1.0
    assert "timeout" in capsys.readouterr().out

    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("launch failed")),
    )
    assert cracker.crack_with_hashcat("hashes", str(wordlist))["error"] == "launch failed"

    outfile.write_text("hash:password\n", encoding="utf-8")
    monkeypatch.setattr(hash_cracker.subprocess, "run", lambda *_args, **_kwargs: None)
    original_open = builtins.open

    def broken_output(path, *args, **kwargs):
        if str(path) == str(outfile):
            raise OSError("cannot read output")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", broken_output)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    with caplog.at_level("DEBUG"):
        assert cracker.crack_with_hashcat("hashes", str(wordlist))["cracked_count"] == 0
    assert "cannot read output" in caplog.text


def test_john_missing_success_timeouts_and_show_failure(monkeypatch, tmp_path, capsys, caplog) -> None:
    cracker = bare_cracker(tmp_path)
    assert "john not found" in cracker.crack_with_john("hashes", "words")["error"]
    cracker.john = "/bin/john"
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if "--show" in cmd:
            return SimpleNamespace(stdout="no delimiter\n#comment:value\nlocked:*:rest\nalice:secret:rest\n")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(hash_cracker.subprocess, "run", run)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.25))
    result = cracker.crack_with_john("hashes", "words", timeout=7)
    assert result == {"cracked": {"alice": "secret"}, "cracked_count": 1, "elapsed": 1.2}

    sequence = [subprocess.TimeoutExpired("john", 2), SimpleNamespace(stdout="")]

    def timeout_then_show(*_args, **_kwargs):
        effect = sequence.pop(0)
        if isinstance(effect, BaseException):
            raise effect
        return effect

    monkeypatch.setattr(hash_cracker.subprocess, "run", timeout_then_show)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    assert cracker.crack_with_john("hashes", "words", timeout=2)["cracked_count"] == 0
    assert "timeout" in capsys.readouterr().out

    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("launch failed")),
    )
    assert cracker.crack_with_john("hashes", "words")["error"] == "launch failed"

    sequence = [SimpleNamespace(stdout=""), RuntimeError("show failed")]

    def failed_show(*_args, **_kwargs):
        effect = sequence.pop(0)
        if isinstance(effect, BaseException):
            raise effect
        return effect

    monkeypatch.setattr(hash_cracker.subprocess, "run", failed_show)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    with caplog.at_level("DEBUG"):
        assert cracker.crack_with_john("hashes", "words")["cracked"] == {}
    assert "show failed" in caplog.text


def shadow_entries(count=1, *, mode=1800):
    return [
        {
            "user": f"user{index}",
            "hash": f"$6$salt$hash{index}",
            "full_line": "line",
            "algorithm": "SHA-512crypt",
            "hashcat_mode": mode,
        }
        for index in range(count)
    ]


def test_smart_crack_no_hashes_and_no_engine(monkeypatch, tmp_path) -> None:
    cracker = bare_cracker(tmp_path)
    assert "No crackable hashes" in cracker.smart_crack("root:!:")
    entries = shadow_entries(2)
    monkeypatch.setattr(cracker, "extract_hashes_from_shadow", lambda _content: entries)
    output = cracker.smart_crack("ignored")
    assert "No cracking tool available" in output
    assert "user0:$6$" in output


def test_smart_hashcat_all_phases_gpu_mask_and_partial_results(
    monkeypatch,
    tmp_path,
    capsys,
    caplog,
) -> None:
    cracker = bare_cracker(tmp_path, hashcat="/bin/hashcat", gpu=True)
    entries = shadow_entries(6) + shadow_entries(1, mode=500)
    entries[-1] = dict(entries[-1], user="md5", hash="$1$salt$md5", algorithm="MD5crypt")
    monkeypatch.setattr(cracker, "extract_hashes_from_shadow", lambda _content: entries)
    wordlists = iter(("small", "main", "small", "main"))
    monkeypatch.setattr(cracker, "_find_wordlist", lambda **_kwargs: next(wordlists))
    monkeypatch.setattr(cracker, "_find_rules", lambda: "rules")
    monkeypatch.setattr(
        cracker,
        "crack_with_hashcat",
        lambda *_args, **_kwargs: {"cracked_count": 0},
    )
    outfile = tmp_path / "cracked.txt"
    outfile.write_text(f"{entries[0]['hash']}:password\ninvalid\n", encoding="utf-8")
    mask_calls = []

    def mask_run(command, **kwargs):
        mask_calls.append((command, kwargs))
        if len(mask_calls) == 1:
            raise RuntimeError("one mask failed")
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(hash_cracker.subprocess, "run", mask_run)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 3.5))
    with caplog.at_level("DEBUG"):
        output = cracker.smart_crack("ignored")
    assert "+1" in output
    assert "Mask phase complete" in output
    assert "CRACKED CREDENTIALS" in output
    assert "Remaining" in output
    assert "hashcat (GPU)" in output
    assert "one mask failed" in caplog.text
    assert "CRACKED" in capsys.readouterr().out
    assert all("-D" in command for command, _kwargs in mask_calls)


def test_smart_hashcat_skips_completed_or_missing_dictionary_phases(monkeypatch, tmp_path) -> None:
    cracker = bare_cracker(tmp_path, hashcat="/bin/hashcat", gpu=False)
    entries = shadow_entries(1)
    monkeypatch.setattr(cracker, "extract_hashes_from_shadow", lambda _content: entries)

    def quick_crack(*_args, **_kwargs):
        cracker.cracked[entries[0]["hash"]] = "password"
        return {"cracked_count": 1, "elapsed": 0}

    monkeypatch.setattr(cracker, "crack_with_hashcat", quick_crack)
    monkeypatch.setattr(cracker, "_find_wordlist", lambda **_kwargs: "small")
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 1.1))
    output = cracker.smart_crack("ignored")
    assert "Remaining" not in output
    assert "user0:password" in output

    empty = bare_cracker(tmp_path, hashcat="/bin/hashcat", gpu=False)
    monkeypatch.setattr(empty, "extract_hashes_from_shadow", lambda _content: entries)
    monkeypatch.setattr(empty, "_find_wordlist", lambda **_kwargs: "")
    monkeypatch.setattr(empty, "_find_rules", lambda: "")
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 1.0))
    output = empty.smart_crack("ignored")
    assert "No passwords cracked" in output


def test_smart_john_writes_shadow_format_and_uses_cpu_engine(monkeypatch, tmp_path) -> None:
    cracker = bare_cracker(tmp_path, john="/bin/john")
    entries = shadow_entries(1)
    monkeypatch.setattr(cracker, "extract_hashes_from_shadow", lambda _content: entries)
    wordlists = iter(("small", "main"))
    monkeypatch.setattr(cracker, "_find_wordlist", lambda **_kwargs: next(wordlists))
    monkeypatch.setattr(cracker, "_find_rules", lambda: "")
    calls = []

    def john(*args, **kwargs):
        calls.append((args, kwargs))
        return {"cracked_count": 0}

    monkeypatch.setattr(cracker, "crack_with_john", john)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    output = cracker.smart_crack("ignored")
    written = (tmp_path / "hashes_m1800.txt").read_text(encoding="utf-8")
    assert "user0:$6$salt$hash0:::::::" in written
    assert "john (CPU)" in output
    assert len(calls) == 2


def test_mask_output_read_failure_and_cpu_mask_command(monkeypatch, tmp_path, caplog) -> None:
    cracker = bare_cracker(tmp_path, hashcat="/bin/hashcat", gpu=False)
    entries = shadow_entries(1)
    monkeypatch.setattr(cracker, "extract_hashes_from_shadow", lambda _content: entries)
    monkeypatch.setattr(cracker, "_find_wordlist", lambda **_kwargs: "")
    monkeypatch.setattr(cracker, "_find_rules", lambda: "")
    monkeypatch.setattr(hash_cracker.subprocess, "run", lambda *_args, **_kwargs: None)
    outfile = tmp_path / "cracked.txt"
    outfile.write_text("hash:password\n", encoding="utf-8")
    original_open = builtins.open

    def broken_output(path, *args, **kwargs):
        if str(path) == str(outfile) and "r" in (args[0] if args else kwargs.get("mode", "r")):
            raise OSError("mask output unreadable")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", broken_output)
    monkeypatch.setattr(hash_cracker.time, "time", Clock(1.0, 2.0))
    with caplog.at_level("DEBUG"):
        output = cracker.smart_crack("ignored")
    assert "Mask phase complete" in output
    assert "mask output unreadable" in caplog.text


def test_mapping_format_pairs_and_cleanup(monkeypatch, tmp_path, caplog) -> None:
    cracker = bare_cracker(tmp_path)
    entries = shadow_entries(2)
    cracker.cracked = {entries[0]["hash"]: "password"}
    cracker._map_cracked_to_users(entries)
    assert cracker.get_cracked_pairs() == [("user0", "password")]
    assert "user0:password" in cracker.format_results()
    cracker.cracked_users.clear()
    assert "No passwords cracked" in cracker.format_results()

    removals = []
    monkeypatch.setattr(hash_cracker.shutil, "rmtree", lambda *args, **kwargs: removals.append((args, kwargs)))
    cracker.cleanup()
    assert removals[0][1] == {"ignore_errors": True}
    monkeypatch.setattr(
        hash_cracker.shutil,
        "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )
    with caplog.at_level("DEBUG"):
        cracker.cleanup()
    assert "cleanup failed" in caplog.text


class FacadeCracker:
    instances = ()

    def __init__(self) -> None:
        self.cleaned = False
        type(self).instances.append(self)

    def smart_crack(self, content):
        return f"smart:{content}"

    def cleanup(self) -> None:
        self.cleaned = True

    def identify_hash_type(self, value):
        return {"hashcat_mode": 1800 if value.startswith("$6$") else None}


def test_standalone_facades_file_content_invalid_and_single(monkeypatch, tmp_path) -> None:
    FacadeCracker.instances = []
    monkeypatch.setattr(hash_cracker, "HashCracker", FacadeCracker)
    shadow = tmp_path / "shadow"
    shadow.write_text("alice:$6$salt$hash", encoding="utf-8")
    assert hash_cracker.run_crack_hashes(str(shadow)) == "smart:alice:$6$salt$hash"
    assert FacadeCracker.instances[-1].cleaned is True
    assert hash_cracker.run_crack_hashes("alice:$6$salt$hash") == "smart:alice:$6$salt$hash"
    assert "Not a valid shadow" in hash_cracker.run_crack_hashes("invalid")
    assert "Unknown hash type" in hash_cracker.run_crack_single("plain")
    assert "smart:unknown:$6$salt$hash" in hash_cracker.run_crack_single("$6$salt$hash")
    assert FacadeCracker.instances[-1].cleaned is True


def test_config_import_fallback_executes_original_module(monkeypatch) -> None:
    source = Path(hash_cracker.__file__).read_text(encoding="utf-8")
    original_import = builtins.__import__

    def without_config(name, *args, **kwargs):
        if name == "config":
            raise ImportError("config absent")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_config)
    namespace = {"__name__": "hash_cracker_without_config", "__file__": hash_cracker.__file__}
    exec(compile(source, hash_cracker.__file__, "exec"), namespace)
    assert namespace["CFG"] == {}
    assert namespace["find_wordlist"]("passwords") == ""


@pytest.mark.parametrize(
    ("argv", "tools", "backend", "needle"),
    [
        (["hash_cracker.py"], {}, "", "Usage:"),
        (
            ["hash_cracker.py"],
            {"hashcat": "/bin/hashcat", "john": "/bin/john"},
            "CUDA",
            "Y CUDA",
        ),
        (["hash_cracker.py", "$6$salt$hash"], {}, "", "Hash type:"),
    ],
)
def test_main_entrypoint_usage_and_hash_modes(monkeypatch, tmp_path, capsys, argv, tools, backend, needle) -> None:
    source = Path(hash_cracker.__file__).read_text(encoding="utf-8")
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(hash_cracker.tempfile, "mkdtemp", lambda **_kwargs: str(tmp_path))
    monkeypatch.setattr(hash_cracker.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setattr(
        hash_cracker.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=backend),
    )
    exec(
        compile(source, hash_cracker.__file__, "exec"),
        {"__name__": "__main__", "__file__": hash_cracker.__file__},
    )
    assert needle in capsys.readouterr().out


def test_main_entrypoint_file_mode(monkeypatch, tmp_path, capsys) -> None:
    shadow = tmp_path / "shadow"
    shadow.write_text("alice:$6$salt$hash", encoding="utf-8")
    source = Path(hash_cracker.__file__).read_text(encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["hash_cracker.py", str(shadow)])
    monkeypatch.setattr(hash_cracker.shutil, "which", lambda _name: None)
    workdirs = iter((str(tmp_path / "one"), str(tmp_path / "two")))
    for path in (tmp_path / "one", tmp_path / "two"):
        path.mkdir()
    monkeypatch.setattr(hash_cracker.tempfile, "mkdtemp", lambda **_kwargs: next(workdirs))
    exec(
        compile(source, hash_cracker.__file__, "exec"),
        {"__name__": "__main__", "__file__": hash_cracker.__file__},
    )
    assert "No cracking tool available" in capsys.readouterr().out
