# OCTOPUS - Autonomous Penetration Testing Framework

OCTOPUS is an advanced, autonomous penetration testing framework driven by AI. It orchestrates a suite of offensive security tools, manages state and intelligence gathered during scans, and uses Large Language Models (LLMs) to plan and execute complex attack chains, from initial reconnaissance to privilege escalation and data exfiltration.

## Features

- **Autonomous Agent Pipeline**: Utilizes a Director, Mission Planner, and specialized agents (Discovery, Analysis, Verification) to autonomously navigate the kill chain.
- **LLM Integration**: Leverages local LLMs (via Ollama) for decision making, hypothesis generation, and fact extraction from unstructured tool outputs.
- **Robust State Management**: Maintains a comprehensive "Fact Store" (SQLite/MariaDB) to track discovered assets, services, vulnerabilities, and credentials, preventing redundant actions.
- **Tool Orchestration**: Seamlessly integrates with industry-standard tools like Nmap, Nikto, Enum4linux, Hydra, SearchSploit, and custom exploit modules.
- **Kill Chain Automation**: Capable of automating lateral movement, persistence establishment, and stealth cleanup.
- **Evidence Verification**: Cross-references findings to validate vulnerabilities before reporting them as confirmed, reducing false positives.

## Prerequisites

- Python 3.8+
- MariaDB / MySQL
- Ollama (with a configured model, e.g., `octopus-qwen` or `llama3`)
- Standard pentesting tools in your `$PATH`:
  - `nmap`
  - `nikto`
  - `enum4linux`
  - `hydra`
  - `searchsploit`
  - etc.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mrX1007/octopus.git
   cd octopus
   ```

2. **Install Python dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Database Setup:**
   Ensure MariaDB is running and create the necessary database and user. The default configuration expects:
   - Database: `octopus`
   - User: `octopus`
   - Password: `123`
   *(Update `config.yaml` if your setup differs).*

   The schema will be automatically initialized on the first run.

4. **Ollama Setup:**
   Ensure Ollama is running and you have the required model pulled:
   ```bash
   ollama pull qwen
   # Or whichever model you configure in config.yaml
   ```

5. **Configuration:**
   Review `config.yaml` and `.env.example` to set up API keys (e.g., Shodan) and adjust LLM parameters.

## Usage

Start the interactive console:

```bash
python3 octopus.py
```

### Main Menu Options:
- **New Scan**: Start a new autonomous scan against a specific IP or Domain.
- **Shodan Discovery**: Use Shodan to discover targets.
- **Resume Scan**: Continue a previously interrupted or incomplete scan.
- **View History**: Review past scan sessions and their findings.

### Scan Modes:
During a scan, you can choose which tools to run manually, or let the AI take over entirely by selecting the `AI ANALYSIS` option (or running the pipeline directly).

## Architecture

OCTOPUS is built around a robust AI pipeline (`core/ai/pipeline.py`):
1. **Director**: Reads the current context and decides the next high-level goal (e.g., `vulnerability_assessment`, `credential_harvesting`).
2. **Planner**: Decomposes the goal into specific tasks for the agents.
3. **Task Agents**:
   - **Discovery Agent**: Runs tools to gather raw data.
   - **Analysis Agent**: Uses the LLM to form hypotheses based on collected facts.
   - **Verification Agent**: Runs targeted tests to confirm hypotheses.
4. **Evidence Engine & Fact Store**: Parses tool outputs (via Regex and LLMs) into structured facts and stores them persistently, forming the context for the next cycle.

## Disclaimer

**OCTOPUS is designed for authorized penetration testing and educational purposes ONLY.** Do not use this tool against systems you do not own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this software.

---

## Project Status & Background

### Development Chronology
Active development of this project initiated in **May 2026**. The original architectural inspiration stemmed from the [METATRON](https://github.com/sooryathejas/METATRON) framework. However, initial evaluation demonstrated that the reference implementation possessed functional limitations and lacked the depth required for advanced operational scenarios. Consequently, this repository represents an extended, independent R&D pipeline focused on refining autonomous agent loops, command-and-control (C2) resilience, and dynamic evasion mechanics.

### Maintenance & Release Policy
* **Development Continuity:** This project remains an active internal research vector. It is **not** abandoned.
* **Public Release Commitment:** There is no commitment, implicit or explicit, to maintain continuous public releases, upstream syncs, or stable open-source distributions. Future iterations, core modules, and tactical components may be restricted to private repositories or internal infrastructure without prior notice.

---