# CLI composition and lifecycle

The command-line interface has one explicit composition boundary:

- `core.cli.main.create_parser()` defines argument parsing without constructing
  runtime services;
- `core.cli.main.create_app()` composes an `OctopusCLIApplication` without
  starting it;
- `OctopusCLIApplication.run()` owns signal registration, logging/history
  setup, supervisor start/stop, preflight, C2 startup, plugin discovery, and the
  interactive menu;
- `core.cli.application` contains the existing interactive workflows and
  compatibility adapters, but performs no application startup at import;
- `core.cli.presentation` and `core.cli.history` own the shared UI and readline
  helpers. `core.cli` is a re-export-only facade;
- `octopus.py` is the executable and deprecated import facade. It forwards the
  historical helper surface while preserving module-local monkeypatch state.

## Import contract

Importing `octopus`, `core.cli`, `core.cli.main`, or
`core.cli.application` does not register signal handlers, start threads or
subprocesses, make network requests, open a database, or start C2. MariaDB and
export functions are resolved lazily at the first workflow call. Readline exit
hooks are registered only by `setup_readline()`, which is invoked from the
interactive lifecycle.

The operational ordering remains:

```text
main(argv)
  -> trace command OR supervisor command OR interactive application
  -> logging + readline
  -> supervisor start
  -> preflight
  -> C2 daemon startup
  -> plugin/module discovery
  -> interactive menu
  -> supervisor stop + prior SIGINT handler restoration
```

`trace`, `status`, `stop`, `health`, `pid`, `--help`, and `--version` do not
enter the interactive lifecycle. The first five legacy commands retain their
existing workflow/supervisor implementations.

## Compatibility and remaining debt

Existing imports such as `octopus._adapt_state_to_result` and tests/plugins that
monkeypatch `octopus.AIPipeline`, DB functions, or workflow helpers remain
supported through the documented deprecation window. New code should import
`core.cli.main`, `core.cli`, or `core.cli.application` directly.

The workflow module intentionally remains large and retains legacy scan/session
globals. This phase isolates process startup and import safety; it does not
change scan behavior, move C2 implementation, or add operational capability.
