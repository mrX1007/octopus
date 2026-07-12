#!/usr/bin/env python3
"""
Plugin SDK with lifecycle, versioning, capabilities, and events.

Every OCTOPUS module (exploit, recon, post-exploit, evasion, OSINT)
inherits from OctopusPlugin and gets:
  - Typed classification (PluginType, KillChainStage)
  - Dependency declaration (other plugins, system tools, pip packages)
  - Capability model (network, file_write, shell_exec)
  - Lifecycle hooks (setup → check → run → cleanup)
  - Cross-plugin event handling
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Optional


class PluginType(Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST = "post"
    EVASION = "evasion"
    OSINT = "osint"
    PERSISTENCE = "persistence"
    LATERAL = "lateral"
    AUXILIARY = "auxiliary"


class KillChainStage(Enum):
    RECON = 1
    VULN_ASSESS = 2
    EXPLOITATION = 3
    INITIAL_ACCESS = 4
    PRIVESC = 5
    PERSISTENCE = 6
    LATERAL = 7
    EXFIL = 8
    CLEANUP = 9


@dataclass
class CheckResult:
    """Result of a vulnerability check (non-destructive probe)."""
    vulnerable: bool = False
    confidence: float = 0.0        # 0.0 to 1.0
    details: str = ""
    version: str = ""
    evidence: str = ""


@dataclass
class PluginResult:
    """Result of a full plugin execution."""
    success: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    output: str = ""
    artifacts: list[str] = field(default_factory=list)  # file paths produced
    credentials: list[dict[str, str]] = field(default_factory=list)
    sessions: list[dict[str, str]] = field(default_factory=list)
    error: str = ""


@dataclass
class PluginContext:
    """Runtime context passed to plugins during setup."""
    target: str = ""
    campaign: str = ""
    work_dir: str = "/tmp/octopus"
    knowledge_graph: Any = None    # KnowledgeGraph instance
    event_bus: Any = None          # EventBus instance
    credentials: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)


class OctopusPlugin:
    """
    Base class for all OCTOPUS modules.

    Subclasses MUST set:
      - name: str
      - version: str (semver)
      - description: str
      - plugin_type: PluginType

    Subclasses SHOULD override:
      - run(**kwargs) -> PluginResult
      - check(target, **kwargs) -> CheckResult  (for exploits)

    Subclasses MAY override:
      - setup(context) -> bool
      - cleanup()
      - on_credential_found(cred)
      - on_session_opened(session)
    """

    name: str = "base_plugin"
    version: str = "0.0.0"
    author: str = ""
    description: str = "Base plugin"

    plugin_type: PluginType = PluginType.AUXILIARY
    kill_chain_stage: KillChainStage = KillChainStage.RECON

    depends_on: ClassVar[list[str]] = []       # other plugin names
    requires: ClassVar[list[str]] = []         # system tools (nmap, hydra, etc.)
    python_deps: ClassVar[list[str]] = []      # pip packages

    capabilities: ClassVar[set[str]] = set()   # "network", "file_write", "shell_exec", "root"

    _context: Optional[PluginContext] = None

    def setup(self, context: PluginContext) -> bool:
        """
        Initialize the plugin with runtime context.
        Called before run(). Return False to abort execution.
        """
        self._context = context
        return True

    def check(self, target: str, **kwargs) -> CheckResult:
        """
        Non-destructive vulnerability check.
        For exploit plugins: probe whether the target is vulnerable.
        Returns CheckResult with confidence score.
        """
        return CheckResult(vulnerable=False, details="check() not implemented")

    def run(self, **kwargs) -> PluginResult:
        """
        Main execution entry point.
        Override this in your plugin.
        """
        raise NotImplementedError(f"Plugin '{self.name}' must implement run()")

    def cleanup(self) -> None:
        """
        Cleanup after execution.
        Remove temp files, close connections, etc.
        """
        pass

    def on_credential_found(self, credential: dict[str, str]):
        """Called when ANY plugin discovers credentials."""
        pass

    def on_session_opened(self, session: dict[str, str]):
        """Called when ANY plugin opens a new session (SSH, HTTP, etc.)."""
        pass

    def on_vulnerability_confirmed(self, vuln: dict[str, str]):
        """Called when ANY plugin confirms a vulnerability."""
        pass

    @property
    def context(self) -> PluginContext:
        if self._context is None:
            return PluginContext()
        return self._context

    def emit_event(self, event_type: str, data: dict[str, Any]):
        """Emit an event to the cross-plugin event bus."""
        if self._context and self._context.event_bus:
            self._context.event_bus.emit(event_type, data, source=self.name)

    def log(self, msg: str, level: str = "info"):
        """Log a message with plugin prefix."""
        prefix = f"[{self.name}]"
        if level == "error":
            print(f"  \033[91m{prefix} {msg}\033[0m")
        elif level == "warn":
            print(f"  \033[93m{prefix} {msg}\033[0m")
        elif level == "success":
            print(f"  \033[92m{prefix} {msg}\033[0m")
        else:
            print(f"  \033[96m{prefix} {msg}\033[0m")

    def __repr__(self):
        return f"<Plugin {self.name} v{self.version} ({self.plugin_type.value})>"
