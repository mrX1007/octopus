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
`core/ai/pipeline.py` (28), and the historical
`tests/test_pipeline_quality.py` (22), which Wave 6 later split and removed.

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

## Wave 6 ratchet verification (2026-07-15)

The configured first-party ratchet now covers 38 source files/directories,
including actions, benchmarks, execution, plugins, facts/assessments, mission
state, canonical graph identity/projection, report schema, decision trace,
runtime, credentials and secrets.

```text
venv/bin/ruff check .
All checks passed!

venv/bin/python -m mypy
Success: no issues found in 38 source files

PYTHONPYCACHEPREFIX=/private/tmp/octopus-wave6-pyc \
  venv/bin/python -m compileall -q core modules tests octopus.py msf.py tools.py
exit 0
```

Mypy still notes that two untyped bodies in `core/plugins/events.py` are not
checked; these are informational notes, not errors or new suppressions.

## Mission/assessment ratchet verification (2026-07-16)

The configured ratchet now covers 50 source files/directories. The added set
includes capability and exploit assessment, all extracted pipeline mixins, the
scan lifecycle, and the dynamic-composition typing seam. No module-level
suppression or per-file ignore was added.

```text
venv/bin/python -m ruff check .
All checks passed!

venv/bin/python -m mypy
Success: no issues found in 50 source files
```

The two existing informational notes for untyped plugin event bodies remain;
they are not type-check failures.

## Competitor benchmark ratchet verification (2026-07-16)

Adding the system-manifest, bounded command-runner, matrix/publication, and CLI
package increased the configured mypy gate from 50 to 55 source files:

```text
venv/bin/python -m ruff check .
All checks passed!

venv/bin/python -m mypy
Success: no issues found in 55 source files
```

No new suppression or per-file ignore was introduced.

## Current mypy boundary audit (2026-07-23)

The configured command remains green over 90 source files out of 227 current
first-party Python sources discovered by the coverage gate. This revision adds
14 directly checked modules covering the split mission-store implementation,
evaluated-fact snapshot, follow-up extraction, thin application/version seams,
CLI history/parser/presentation modules, and the shared C2 protocol constants:

```text
venv/bin/python -m mypy --no-incremental
Success: no issues found in 90 source files
```

This is still an incremental ratchet, not whole-tree type coverage. The
configuration uses `follow_imports = "skip"`; replacing it with `normal`
over the expanded scope reports 164 errors in 36 files. That
inventory includes both missing third-party stubs and first-party type errors,
so changing the mode without resolving the inventory would make the required
static-analysis job red. The next safe migration must remove this global skip
while fixing or explicitly owning each newly followed module; it must not hide
the inventory behind a broader ignore.
