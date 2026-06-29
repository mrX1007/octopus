# OCTOPUS

Autonomous Strategic AI Pentest Engine

OCTOPUS is a local, AI-assisted security assessment framework for authorized
lab, internal audit, red-team and research workflows. It combines classic
reconnaissance tools, an evidence-first fact pipeline, local LLM planning,
credential/state memory, plugin loading, reporting, OSINT, post-access
inventory and optional C2 infrastructure into one operator console.

The project is built around one core idea: tool output should not stay as raw
logs. OCTOPUS parses output into structured facts, stores those facts, resolves
the current target state, and uses that state to choose the next useful action.

## Legal And Scope Notice

Use OCTOPUS only on systems you own or where you have explicit written
authorization to test. The framework contains dual-use and offensive security
capabilities. Operators are responsible for defining scope, preserving logs,
and complying with law, contracts and rules of engagement.

By default, the project separates normal automatic checks from gated actions.
Examples of gated or scope-sensitive actions include active Metasploit runs,
arbitrary SSH command execution and C2 deployment. Keep these controls unless
you are operating inside a controlled, authorized environment.

## What It Is Used For

OCTOPUS is intended for:

- External service discovery and fingerprinting.
- Web surface mapping and vulnerability assessment.
- Evidence-driven vulnerability verification.
- Credential tracking across scans.
- Post-access host inventory after confirmed authentication.
- Internal network reconnaissance from an authorized foothold.
- Active Directory and Kerberos assessment in lab or authorized enterprise
  environments.
- Shodan-based OSINT and target enrichment.
- Report generation and historical scan review.
- Plugin-based extension of exploit, persistence, evasion and assessment
  modules.
- Local LLM-assisted planning and analysis with Ollama.

It is not a replacement for operator judgment. The AI pipeline is designed to
reduce repetitive work, correlate facts and avoid losing context between tools.

## High-Level Architecture

```text
operator
  |
  v
octopus.py CLI
  |
  +--> interactive tools / manual recon
  +--> Shodan discovery
  +--> C2 management thin client
  +--> history / resume / report export
  |
  v
AI Pipeline
  |
  +--> DirectorLLM decides the next goal
  +--> MissionPlanner builds task plans
  +--> DiscoveryAgent runs recon tasks
  +--> AnalysisAgent forms hypotheses from facts
  +--> VerificationAgent validates claims
  |
  v
Tool Registry and Plugin Manager
  |
  +--> nmap, ffuf, whatweb, nikto, sqlmap, wpscan, etc.
  +--> Metasploit check/run wrappers
  +--> SSH, AD, Kerberos, pivot and post-access tools
  +--> class-based modules under modules/
  |
  v
Evidence / RAG / Memory Layer
  |
  +--> OutputParser extracts facts from raw output
  +--> FactStore stores scan facts in SQLite
  +--> CredentialStore syncs credentials across cache, MariaDB and graph
  +--> KnowledgeGraph stores typed relationships
  +--> VectorMemory stores optional ChromaDB semantic memory
  +--> ContextBuilder builds the compact context sent to the LLM
```

## Main Components

### CLI Entrypoint

File: `octopus.py`

The main console provides:

- New Scan
- View History
- Resume Unfinished Scan
- C2 Server Management
- preflight checks
- graceful Ctrl+C handling and interrupted-session status
- tab completion and command history
- automatic C2 daemon startup when available
- plugin/module discovery at startup

### AI Pipeline

Core files:

- `core/ai/pipeline.py`
- `core/ai/director.py`
- `core/ai/planner.py`
- `core/ai/task_agents.py`
- `core/ai/context_builder.py`
- `core/ai/state_resolver.py`
- `core/ai/evidence.py`
- `core/ai/tool_registry.py`

The pipeline loop works as follows:

1. Parse manual or tool output into facts.
2. Seed known credentials from the credential store.
3. Build target context from facts.
4. Ask the Director for the next high-level goal.
5. Ask the Planner for tasks.
6. Normalize and optimize tasks using deterministic guardrails.
7. Run tools through the registry.
8. Parse new output into facts.
9. Run deterministic fact-driven follow-up actions.
10. Repeat until the Director concludes, budgets are hit, or no new facts are
    being produced.

### Fact-Driven Actions

The current pipeline can automatically trigger additional deterministic probes
when concrete facts appear. Examples:

- known cached SSH credential -> `ssh_session` verification path
- confirmed SSH auth -> controlled `ssh_inventory`
- cPanel or WHM surface -> cPanel assessment plugin
- discovered interesting web path -> `curl_headers` and `scrapling`
- FTP service -> `ftp_anonymous_check`
- SMTP service -> `smtp_probe`
- PostgreSQL/MySQL service with known creds -> read-only `db_inventory`
- positive `msf_check` inside authorized scope -> eligible `msf_run`

This is the main mechanism that makes modules work together instead of acting
as isolated menu items.

### RAG And Memory

OCTOPUS has more than one memory layer. The important distinction:

- Evidence-first RAG is the primary live pipeline.
- Vector memory is optional semantic recall.

Primary evidence-first RAG:

- `OutputParser` converts raw tool output into structured facts.
- `FactStore` stores facts and hypotheses per scan and host.
- `StateResolver` converts facts into stage state:
  - recon complete
  - credentials found
  - root access confirmed
  - post-access inventory complete
  - persistence established
  - internal recon complete
  - exfiltration complete
  - cleanup complete
- `ContextBuilder` retrieves relevant facts and builds compact context for the
  Director and Planner.
- `EvidenceVerifier` checks whether a claim is supported by facts.
- `CredentialStore` retrieves known credentials so scans can reuse confirmed
  access instead of rediscovering it.
- `KnowledgeGraph` stores typed relationships between assets, services,
  credentials, sessions and vulnerabilities.

Optional vector memory:

- File: `memory.py`
- Backend: ChromaDB.
- Path: `paths.memory` in `config.yaml`, default `~/OCTOPUS/memory`.
- Stores session findings with categories such as credentials, root access and
  active session.
- Uses semantic deduplication before storing similar findings.

In practice, the fact pipeline is what drives decisions. ChromaDB memory is a
supporting long-context recall layer.

### Tool Registry

Core files:

- `core/tools/registry.py`
- `core/tools/runner.py`
- `core/tools/recon_tools.py`
- `core/tools/exploit_tools.py`
- `core/tools/post_tools.py`
- `core/ai/tool_registry.py`

OCTOPUS tools are registered with the `@tool(...)` decorator. The AI registry
maps high-level tasks such as `service_discovery`, `web_vulnerability_testing`
or `post_access_inventory` to actual tool commands.

Current registry coverage is expected to be complete. At the time of this
README, the project reports:

```text
registry coverage: 61/61
unknown: []
```

Execution profiles:

- `auto`: normal pipeline-capable command.
- `followup`: runs only when emitted by facts or verification results.
- `manual_gated`: callable, but not automatically started by normal planning.
- `legacy_wrapper`: older wrapper kept for compatibility.
- `alias_wrapper`: alias around an existing implementation.

### Plugin System

Core files:

- `core/plugins/base.py`
- `core/plugins/loader.py`
- `core/plugins/events.py`

Module directory:

- `modules/`

Current class-based modules include:

- `modules/exploits/cpanel_auth_bypass.py`
- `modules/evasion/payload_keying.py`
- `modules/persistence/systemd.py`

Plugins inherit from `OctopusPlugin` and return `PluginResult` / `CheckResult`
objects. The loader discovers modules, validates required fields and normalizes
legacy return values into a common result contract.

### Knowledge Graph

Core files:

- `core/knowledge/graph.py`
- `core/knowledge/models.py`
- `core/knowledge/enricher.py`

The graph is SQLite-backed and stores typed nodes:

- assets
- identities
- credentials
- services
- sessions
- vulnerabilities
- campaigns

It also stores typed edges, for example:

- asset runs service
- identity has credential
- credential can access asset
- session leads to asset
- vulnerability affects service

Default path:

```text
data/knowledge.db
```

### Credential Store

File: `core/credentials.py`

The credential store is a single access layer over:

- in-memory session cache
- MariaDB `credentials` table
- KnowledgeGraph credential nodes and edges
- legacy `_KNOWN_CREDS` cache in `core/tools/exploit_tools.py`

This is why later stages can reuse credentials found earlier in the scan or in
previous sessions.

### C2 Framework

Core files:

- `core/c2/daemon.py`
- `core/c2/builder.py`
- `core/c2/crypto_engine.py`
- `core/c2/db_backend.py`
- `core/c2/event_store.py`
- `core/c2/operators.py`
- `core/c2/implant.go`
- `core/c2/implants/python_implant.py`
- `core/c2/implants/powershell_stager.py`
- `core/c2/channels/dns.py`

The C2 daemon uses FastAPI and Uvicorn, stores state in `data/c2.db`, exposes
agent-facing HTTP endpoints and a local Unix socket control plane at:

```text
/tmp/octopus.sock
```

The operator console can:

- list active agents
- queue tasks
- view task results
- build implants
- manage operators

Use C2 features only in an authorized lab or explicitly scoped engagement.

### ShardBrowser / ShardX Integration

File: `core/osint/shardbrowser.py`

Vendor directory:

```text
vendor/shardbrowser/
```

ShardBrowser is used for browser-rendered web surface analysis and OSINT. The
integration supports:

- profile management
- random browser fingerprints
- CDP sessions
- optional proxy binding
- multi-session workflows
- browser-rendered page extraction

Registry tools:

- `browser_surface_analysis`
- `shardbrowser_osint`

### Reporting

File: `export.py`

OCTOPUS can export PDF reports with:

- target metadata
- executive summary
- vulnerability matrix
- CVSS approximation by severity
- remediation/fix sections
- exploit attempt summary
- AI analysis summary

Default report path:

```text
~/OCTOPUS/reports
```

## Technology Stack

Language and runtime:

- Python 3.9+
- Go for C2 implant building
- optional PowerShell stager generation

Local AI:

- Ollama
- model configured in `config.yaml`
- default model name: `octopus-qwen`
- Modelfile optimized for a Qwen 9B class model with 16K context

Storage:

- MariaDB/MySQL for scan history, reports, credentials and tool results
- SQLite for FactStore, KnowledgeGraph, C2 DB and local event stores
- ChromaDB for optional vector memory

Web and networking:

- requests / httpx / urllib3
- BeautifulSoup / lxml
- Scrapling
- FastAPI / Uvicorn
- Paramiko

OSINT:

- Shodan
- DuckDuckGo search wrapper
- ShardBrowser / ShardX vendor SDK

Reporting:

- ReportLab
- Pillow
- Pygments
- Rich

External security tools:

- nmap
- rustscan
- curl
- whois
- dig
- sslscan
- ffuf
- enum4linux
- smbclient
- wpscan
- sqlmap
- nikto
- searchsploit
- msfconsole
- hashcat
- john
- Go toolchain
- garble
- optional impacket / ldap3 for AD modules

## Repository Layout

```text
.
├── octopus.py                 # main CLI
├── config.yaml                # primary configuration
├── config.py                  # config loader and env overrides
├── db.py                      # MariaDB schema and DB API
├── tools.py                   # backward-compatible tool exports
├── memory.py                  # optional ChromaDB vector memory
├── search.py                  # web/CVE/search helpers
├── shodan_module.py           # Shodan discovery and persistence
├── msf.py                     # Metasploit wrapper
├── export.py                  # PDF reporting
├── core/
│   ├── ai/                    # Director, Planner, agents, facts, parser
│   ├── c2/                    # C2 daemon, crypto, builders, implants
│   ├── cli/                   # shared CLI helpers
│   ├── exploits/              # exploit selection/mapping
│   ├── killchain/             # privesc, persistence, lateral, exfil, AD
│   ├── knowledge/             # SQLite knowledge graph
│   ├── observability/         # audit and metrics
│   ├── opsec/                 # artifact and transport helpers
│   ├── osint/                 # ShardBrowser integration
│   ├── plugins/               # plugin SDK and loader
│   ├── recon/                 # async recon engine
│   ├── tools/                 # registered tool implementations
│   └── transport/             # traffic policies and transports
├── modules/
│   ├── evasion/
│   ├── exploits/
│   ├── persistence/
│   └── post/
├── payloads/
├── vendor/
│   ├── cpanel_sniper/
│   └── shardbrowser/
├── data/
└── tests/
```

## Installation

### 1. System Packages

Install the external tools you plan to use. On macOS, many can be installed
with Homebrew. On Linux, use the package manager for your distribution.

Common baseline:

```bash
brew install nmap whois curl go
```

Recommended security tools, depending on your environment:

```bash
brew install ffuf nikto sqlmap hashcat john
```

Metasploit, enum4linux, smbclient, wpscan, sslscan, rustscan, searchsploit,
impacket and garble may require separate installation depending on the OS.

### 2. Python Environment

```bash
cd /Users/admin/Downloads/Octopus2
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional development test dependencies:

```bash
pip install pytest pytest-mock pytest-cov
```

Optional AD/Kerberos support:

```bash
pip install impacket ldap3
```

### 3. MariaDB / MySQL

Create the database and user expected by the default config:

```sql
CREATE DATABASE octopus CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'octopus'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON octopus.* TO 'octopus'@'localhost';
FLUSH PRIVILEGES;
```

Adjust `config.yaml` or environment variables if you use different values.

Supported DB environment overrides:

```bash
export OCTOPUS_DB_HOST=localhost
export OCTOPUS_DB_USER=octopus
export OCTOPUS_DB_PASS=123
export OCTOPUS_DB_NAME=octopus
```

The schema is auto-created and migrated on startup.

### 4. Ollama Model

Start Ollama:

```bash
ollama serve
```

Create the configured model from the project Modelfile:

```bash
ollama create octopus-qwen -f Modelfile
```

The default `Modelfile` uses:

```text
FROM huihui_ai/qwen3.5-abliterated:9b
num_ctx 16384
num_predict 4096
num_batch 512
```

You can change the model in `config.yaml`:

```yaml
ollama:
  model: "octopus-qwen"
  url: "http://localhost:11434/api/generate"
```

Or override via environment:

```bash
export OCTOPUS_OLLAMA_MODEL=octopus-qwen
export OCTOPUS_OLLAMA_URL=http://localhost:11434/api/generate
```

### 5. Secrets

Secrets should be loaded from environment variables or `.env`, not committed
into the repository.

Common values:

```bash
export SHODAN_API_KEY=...
export OCTOPUS_API_KEY=...
export OCTOPUS_C2_PSK=...
```

## Configuration

Primary config file:

```text
config.yaml
```

Important sections:

- `db`: MariaDB connection.
- `ollama`: local model endpoint, model name, context and generation params.
- `scrapling`: page fetch and crawl behavior.
- `shodan`: API result limits and persistence settings.
- `hash_cracker`: hashcat/john preferences.
- `killchain`: stage enablement and output paths.
- `strategy`: automation and gating policy.
- `reporting`: PDF/report behavior.
- `bruteforce`: adaptive throttling settings.
- `paths`: reports, logs, checkpoints and vector memory.
- `wordlists`: password, username and web content lists.
- `tools`: per-tool flags and timeouts.

Recommended default posture:

```yaml
strategy:
  allow_active_msf: false
  active_authorized: false
  authorized_targets: []
  max_active_msf_runs_per_scan: 1
  auto_ssh_inventory: true
  allow_arbitrary_ssh_exec: false
```

For an authorized lab target, active Metasploit execution can be scoped:

```yaml
strategy:
  allow_active_msf: true
  active_authorized: true
  authorized_targets:
    - "10.10.10.0/24"
  max_active_msf_runs_per_scan: 1
```

## Running OCTOPUS

Start the interactive console:

```bash
python3 octopus.py
```

Supervisor commands:

```bash
python3 octopus.py status
python3 octopus.py health
python3 octopus.py pid
python3 octopus.py stop
```

Main menu:

```text
[1] New Scan
[2] View History
[3] Resume Unfinished Scan
[4] C2 Server Management
[5] Exit
```

New Scan modes:

```text
[1] Direct IP / Domain
[2] Shodan Discovery
```

The direct scan path:

1. Creates a DB session.
2. Runs selected recon tools.
3. Sends raw output to the AI pipeline.
4. Parses facts.
5. Runs deterministic follow-up actions.
6. Saves final findings and summary.

## Registered Tools

### Recon

- `nmap`: smart staged Nmap scanning.
- `whois`: WHOIS lookup.
- `whatweb`: web technology fingerprinting.
- `curl_headers`: HTTP(S) header collection.
- `dig`: DNS records.
- `sslscan`: TLS/SSL assessment.
- `ffuf`: web content discovery.
- `enum4linux`: SMB/Windows enumeration.
- `smbclient`: anonymous SMB share listing.
- `wpscan`: WordPress assessment.
- `sqlmap`: basic SQL injection crawl/detection.
- `nikto`: web server checks.
- `scrapling`: stealth/page extraction with requests fallback.
- `scrapling_crawl`: bounded crawl for links and page titles.
- `ssh_user_enum`: OpenSSH CVE-2018-15473 username enumeration logic with
  false-positive detection.
- `ftp_anonymous_check`: anonymous FTP check and limited listing.
- `smtp_probe`: SMTP banner/EHLO/STARTTLS/AUTH capability probe.
- `browser_surface_analysis`: ShardBrowser-rendered page analysis.
- `shardbrowser_osint`: isolated browser OSINT.
- `shodan`: Shodan search/host/vulnerability lookups.
- `waf_detect`: WAF/firewall detection.
- `searchsploit`: exploit-db search.

### Exploit Selection And Verification

- `exploit_select`: maps service banners to exploit and Metasploit candidates.
- `msf_check`: follow-up Metasploit verification.
- `msf_run`: gated active Metasploit execution.
- `jmx2rce_scan`: Tomcat JMX Proxy exposure check.
- `jmx2rce_rce`: gated RCE action.
- `jmx2rce_read`: gated file read action.
- `jmx2rce_cleanup`: gated cleanup action.
- `bruteforce`: adaptive service brute-force wrapper.
- `stealth_brute`: alias wrapper for bruteforce.
- `web_login_brute`: web login brute-force helper.

### Post-Access And Killchain

- `ssh_session`: gated SSH session verification/analysis.
- `ssh_inventory`: controlled post-access inventory.
- `ssh_exec`: gated arbitrary SSH command execution.
- `db_inventory`: read-only PostgreSQL/MySQL inventory using known credentials.
- `killchain_vuln_assess`: legacy vulnerability assessment wrapper.
- `killchain_exploit`: legacy auto-exploit wrapper.
- `killchain_privesc`: privilege escalation stage.
- `killchain_persist`: persistence stage.
- `killchain_lateral`: lateral movement stage.
- `killchain_exfil`: data exfiltration stage.
- `killchain_cleanup`: cleanup stage.
- `killchain_full`: legacy full-chain wrapper.
- `network_recon`: internal network discovery through SSH.
- `socks_proxy`: SSH SOCKS proxy setup.
- `port_forward`: SSH local forward setup.

### Active Directory / Kerberos

- `ad_enum`: Active Directory enumeration.
- `asrep_roast`: AS-REP roasting.
- `kerberoast`: Kerberoasting.
- `dcsync`: DCSync with domain credentials.
- `pass_the_hash`: pass-the-hash authentication.
- `psexec`: PsExec remote execution.
- `wmiexec`: WMIExec remote execution.

### Payload / C2

- `build_go_implant`: build Go implant.
- `build_python_implant`: generate Python implant.
- `build_ps_stager`: generate PowerShell stager.
- `deploy_c2_beacon`: manual-gated C2 beacon deployment.

### Plugins

- `plugin`: run class-based OCTOPUS plugins or list discovered plugins.
- `cpanel_exploit`: cPanel/WHM assessment wrapper.

## Automation And Gating Model

Normal automatic flow includes discovery, parsing, verification, safe follow-up
checks and controlled post-access inventory.

Follow-up examples:

- `exploit_select` can emit `msf_check`.
- A positive `msf_check` can promote a matching `msf_run` only when active MSF
  is enabled and the target is inside `authorized_targets`.
- Confirmed SSH auth can trigger `ssh_inventory`.
- `ffuf` paths can trigger `curl_headers` and `scrapling`.
- DB ports trigger `db_inventory` only when service credentials are already
  known.

Manual or gated examples:

- arbitrary `ssh_exec`
- active `msf_run`
- C2 deployment
- JMX RCE/read/cleanup actions

This model keeps registry coverage honest without making every capability run
blindly.

## Output And Storage

MariaDB tables:

- `history`
- `vulnerabilities`
- `fixes`
- `exploits_attempted`
- `summary`
- `tool_results`
- `credentials`
- `shodan_results`

SQLite/local files:

- `data/facts.db`: AI FactStore
- `data/knowledge.db`: KnowledgeGraph
- `data/c2.db`: C2 daemon state
- `data/keys/`: C2 keys
- `~/OCTOPUS/logs`: log files
- `~/OCTOPUS/reports`: PDF reports
- `/tmp/octopus_checkpoint_<id>.json`: interrupted scan checkpoints
- `/tmp/octopus.sock`: C2 daemon IPC socket
- `/tmp/octopus.pid` and `/tmp/octopus.lock`: supervisor files

## Testing And Validation

Compile all Python files:

```bash
env PYTHONPYCACHEPREFIX=/private/tmp/octopus_pycache \
  python3 -m compileall -q core modules tests octopus.py tools.py
```

Run pytest if installed:

```bash
python3 -m pytest
```

Run focused regression files:

```bash
python3 -m pytest tests/test_pipeline_quality.py tests/test_evidence_parser.py tests/test_result_adapter.py
```

Check registry coverage:

```bash
python3 -c 'import tools
from core.ai.tool_registry import ToolRegistry
from core.tools.registry import list_tools
r = ToolRegistry()
report = r.get_coverage_report([t.name for t in list_tools()])
print(report["covered"], "/", report["registered"])
print(report["unknown"])'
```

Expected healthy result:

```text
61 / 61
[]
```

## Troubleshooting

### Ollama is not running

Start Ollama:

```bash
ollama serve
```

Then create or pull the configured model:

```bash
ollama create octopus-qwen -f Modelfile
```

### Model not found

Check config:

```yaml
ollama:
  model: "octopus-qwen"
```

Check installed models:

```bash
ollama list
```

### Database connection fails

Verify MariaDB is running and the configured user can connect:

```bash
mysql -u octopus -p octopus
```

Or override with environment variables:

```bash
export OCTOPUS_DB_HOST=localhost
export OCTOPUS_DB_USER=octopus
export OCTOPUS_DB_PASS=123
export OCTOPUS_DB_NAME=octopus
```

### Tools are skipped

OCTOPUS checks tool availability through the registry. Install missing system
tools or Python modules, then restart the console.

Common examples:

```bash
brew install nmap ffuf nikto sqlmap hashcat john
pip install scrapling shodan paramiko
```

### Shodan is disabled

Install the library and set an API key:

```bash
pip install shodan
export SHODAN_API_KEY=...
```

### ShardBrowser is unavailable

Install Python dependencies:

```bash
pip install "httpx[socks]" patchright
```

ShardX engine assets are managed by the vendor SDK under
`vendor/shardbrowser/sdks/python/`.

### pytest is missing

Install development dependencies:

```bash
pip install pytest pytest-mock pytest-cov
```

## Development Notes

When adding a new tool:

1. Add a function with `@tool(...)`.
2. Return machine-parseable output.
3. Add parser logic in `core/ai/evidence.py` when the output creates facts.
4. Add task mapping or execution profile in `core/ai/tool_registry.py`.
5. Add regression tests.
6. Check registry coverage.

When adding a plugin:

1. Put the module under `modules/`.
2. Inherit from `OctopusPlugin`.
3. Implement `check()` and/or `run()`.
4. Return `CheckResult` / `PluginResult`.
5. Keep facts, credentials, sessions and artifacts structured.
6. Verify `PluginManager("modules/").list_plugins()` shows the plugin.

## Current Project Status

The project is an active local R&D codebase. It contains production-like
components, experimental modules and legacy compatibility wrappers. Some
capabilities require external tools, API keys, drivers, wordlists or a lab
environment before they become available.

The intended quality bar is:

- no dead registered tools
- no unparsed useful outputs
- no false stage progression without facts
- no credential loss between modules
- no automatic active exploitation outside configured scope
- deterministic fallback behavior when the LLM fails
- clear final outcome summaries

## License / Responsibility

No warranty is provided. Use only in authorized environments. The operator is
responsible for target scope, approvals, data handling and compliance.
