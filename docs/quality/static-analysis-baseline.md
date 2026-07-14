# OCTOPUS static-analysis baseline

Baseline date: 2026-07-14

Git revision before the first quality slice: `a865746`

The checkout contained the two previously recorded dirty vendor submodules.
They are excluded from first-party analysis together with `venv/` and `data/`.
All counts below were collected before changing the configured gates. No
finding was hidden with a new `noqa`, `type: ignore`, per-file ignore, or broad
tool exclusion.

## Ruff

The old report of 407 Pyflakes findings is no longer reproducible on this
revision:

```bash
venv/bin/python -m ruff check . --select F --statistics
```

```text
All checks passed
```

The bounded expanded inventory command was:

```bash
venv/bin/python -m ruff check . \
  --select E,F,I,B,UP,SIM,C4,PIE,RUF --statistics
```

It reported 609 findings:

| Rule | Count | Disposition in the first slice |
|---|---:|---|
| `E501` | 595 | tracked formatting backlog; not silently auto-rewritten |
| `PIE790` | 9 | safe autofix: redundant `pass` after a docstring |
| `I001` | 2 | safe autofix: import ordering |
| `PIE810` | 2 | reviewed equivalent `startswith(tuple)` rewrite |
| `UP022` | 1 | reviewed equivalent `capture_output=True` rewrite |

After the 14 non-line-length fixes, the same inventory contains only the 595
`E501` findings. Their distribution is:

| Domain | Count |
|---|---:|
| `core/ai` | 372 |
| `core/tools` | 110 |
| `core/killchain` | 51 |
| tests | 31 |
| root modules | 24 |
| `core/exploits` | 3 |
| `core/c2` | 2 |
| payloads | 1 |
| `core/recon` | 1 |

The largest files are `core/ai/evidence.py` (237),
`core/tools/post_tools.py` (54), `core/tools/recon_tools.py` (43),
`core/ai/pipeline.py` (28), and `tests/test_pipeline_quality.py` (22).

The configured ratchet now selects `E4`, `E7`, `E9`, `F`, `I`, `B`, `UP`,
`SIM`, `C4`, `PIE`, and `RUF`. The existing `E501` ignore remains visible
while the measured line-length backlog is fixed by domain. No new ignore was
added. When the 595 lines reach zero, select the full `E` family and remove
the `E501` ignore in the same change.

## mypy

The previous configured gate checked only three files and was green. A plain
full-tree invocation was not valid before this slice:

```bash
venv/bin/python -m mypy . --no-error-summary
```

It stopped with a duplicate module named `base` for
`core/plugins/base.py` and `core/transport/base.py`. These directories are
namespace packages without `__init__.py`; `explicit_package_bases = true`
resolves their module identity without adding runtime packages merely for the
type checker.

The deterministic full inventory command was:

```bash
venv/bin/python -m mypy . --explicit-package-bases --no-incremental
```

```text
Found 195 errors in 43 files (checked 149 source files)
```

Error-code distribution:

| Code | Count |
|---|---:|
| `index` | 31 |
| `import-untyped` | 29 |
| `misc` | 27 |
| `union-attr` | 25 |
| `var-annotated` | 16 |
| `arg-type` | 15 |
| `assignment` | 12 |
| `unused-ignore` | 11 |
| `attr-defined` | 10 |
| `return-value` | 9 |
| `no-redef` | 7 |
| `operator` | 1 |
| `dict-item` | 1 |
| `call-arg` | 1 |

Domain distribution:

| Domain | Count |
|---|---:|
| `core/killchain` | 58 |
| `core/tools` | 48 |
| root modules | 42 |
| `core/knowledge` | 24 |
| tests | 5 |
| `core/exploits` | 5 |
| `core/recon` | 4 |
| `core/observability` | 2 |
| `core/c2` | 2 |
| `core/ai` | 2 |
| payloads | 1 |
| `core/transport` | 1 |
| `core/opsec` | 1 |

The highest-count files are `core/knowledge/graph.py` (23),
`core/tools/exploit_tools.py` (20), `core/tools/post_tools.py` (14),
`octopus.py` (12), `evasion.py` (12), and
`core/tools/recon_tools.py` (10). Of the 149 checked files, 106 had no mypy
error in this no-incremental inventory. This does not imply strict typing:
mypy still reports that some untyped function bodies are not checked.

The first no-suppression ratchet covers 13 verified-clean sources:

- all files in `core/execution/` and `core/plugins/`;
- `core/secrets.py` and `core/credentials.py`;
- `core/ai/runtime.py` and `core/ai/command_scheduler.py`;
- `core/tools/targeting.py`.

The configured command is:

```bash
venv/bin/python -m mypy
```

Each later slice must fix a bounded domain and add it to `files` in the same
change. The intended order is: missing third-party stub packages and trivial
annotations; C2/AI/observability/recon; result and registry contracts; graph
types; tools; killchain; root orchestration. Existing `type: ignore` comments
are removed only after the corresponding types are made sound, never replaced
with broader suppression.
