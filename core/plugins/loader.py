#!/usr/bin/env python3
"""
Plugin Manager with validation, lifecycle management, and event dispatching.

Discovers, validates, and executes plugins from the modules/ directory.
Supports sandboxed execution with timeouts, dependency resolution,
and cross-plugin event propagation.
"""

import os
import sys
import shutil
import importlib.util
import inspect
import logging
import concurrent.futures
from typing import Dict, Type, List, Optional, Any

from core.plugins.base import (
    OctopusPlugin, PluginType, KillChainStage,
    PluginContext, PluginResult, CheckResult
)
from core.plugins.events import PluginEventBus


class PluginManager:
    """
    Central plugin management.

    Usage:
        pm = PluginManager("modules/")
        pm.discover()
        result = pm.execute("cpanel_auth_bypass", target="10.0.0.1")
    """

    def __init__(self, modules_dir: str = "modules/",
                 event_bus: PluginEventBus = None):
        self.modules_dir = modules_dir
        self.plugins: Dict[str, Type[OctopusPlugin]] = {}
        self.event_bus = event_bus or PluginEventBus()
        self._instances: Dict[str, OctopusPlugin] = {}
        self.discover()

    def discover(self, dirs: List[str] = None):
        """Scan directories for plugins. Defaults to self.modules_dir."""
        search_dirs = dirs or [self.modules_dir]
        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            for root, _, files in os.walk(search_dir):
                for fname in files:
                    if fname.endswith(".py") and not fname.startswith("__"):
                        self._load_module(os.path.join(root, fname))

    def _load_module(self, path: str):
        """Load a single plugin module from a file path."""
        module_name = os.path.splitext(os.path.basename(path))[0]
        spec = importlib.util.spec_from_file_location(module_name, path)
        if not spec or not spec.loader:
            return

        module = importlib.util.module_from_spec(spec)
        try:
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, OctopusPlugin) and
                        obj is not OctopusPlugin and
                        hasattr(obj, 'name') and obj.name != "base_plugin"):
                    self.plugins[obj.name] = obj
                    logging.debug(f"Plugin discovered: {obj.name} v{obj.version} ({path})")
        except Exception as e:
            logging.warning(f"Failed to load plugin from {path}: {e}")

    def get_plugin(self, name: str) -> Optional[Type[OctopusPlugin]]:
        """Get a plugin class by name."""
        return self.plugins.get(name)

    def get_instance(self, name: str) -> Optional[OctopusPlugin]:
        """Get or create a plugin instance by name."""
        if name not in self._instances:
            plugin_class = self.get_plugin(name)
            if not plugin_class:
                return None
            self._instances[name] = plugin_class()
        return self._instances[name]

    def validate(self, plugin_name: str) -> List[str]:
        """
        Validate a plugin's dependencies and requirements.
        Returns list of error messages (empty = valid).
        """
        errors = []
        plugin_class = self.get_plugin(plugin_name)
        if not plugin_class:
            return [f"Plugin '{plugin_name}' not found"]

        instance = plugin_class()

        # Check system tool requirements
        for tool in instance.requires:
            if not shutil.which(tool):
                errors.append(f"Required system tool not found: {tool}")

        # Check plugin dependencies
        for dep in instance.depends_on:
            if dep not in self.plugins:
                errors.append(f"Required plugin not found: {dep}")

        # Check Python dependencies
        for pkg in instance.python_deps:
            try:
                __import__(pkg.split("[")[0])  # handle extras like "requests[socks]"
            except ImportError:
                errors.append(f"Required Python package not installed: {pkg}")

        return errors

    def execute(self, plugin_name: str, context: PluginContext = None,
                timeout: int = 120, **kwargs) -> PluginResult:
        """
        Execute a plugin with sandboxing and lifecycle management.

        1. Validate dependencies
        2. Call setup(context)
        3. Call run(**kwargs) with timeout
        4. Call cleanup()
        5. Propagate events
        """
        plugin_class = self.get_plugin(plugin_name)
        if not plugin_class:
            return PluginResult(success=False, error=f"Plugin '{plugin_name}' not found")

        # Validate
        errors = self.validate(plugin_name)
        if errors:
            return PluginResult(success=False,
                                error=f"Validation failed: {'; '.join(errors)}")

        instance = plugin_class()

        # Setup context
        ctx = context or PluginContext()
        ctx.event_bus = self.event_bus
        if not instance.setup(ctx):
            return PluginResult(success=False, error="Plugin setup() returned False")

        # Execute with timeout in a thread
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(instance.run, **kwargs)
                result = future.result(timeout=timeout)

                # Propagate credential events
                if result.credentials:
                    for cred in result.credentials:
                        self.event_bus.emit("credential.found", cred, source=plugin_name)
                        self._dispatch_to_plugins("on_credential_found", cred)

                # Propagate session events
                if result.sessions:
                    for sess in result.sessions:
                        self.event_bus.emit("session.opened", sess, source=plugin_name)
                        self._dispatch_to_plugins("on_session_opened", sess)

                return result

        except concurrent.futures.TimeoutError:
            return PluginResult(success=False,
                                error=f"Plugin '{plugin_name}' timed out after {timeout}s")
        except Exception as e:
            return PluginResult(success=False,
                                error=f"Plugin '{plugin_name}' crashed: {str(e)}")
        finally:
            try:
                instance.cleanup()
            except Exception as e:
                logging.warning(f"Plugin {plugin_name} cleanup error: {e}")

    def check(self, plugin_name: str, target: str, **kwargs) -> CheckResult:
        """Run a non-destructive vulnerability check."""
        instance = self.get_instance(plugin_name)
        if not instance:
            return CheckResult(vulnerable=False, details=f"Plugin '{plugin_name}' not found")
        try:
            return instance.check(target, **kwargs)
        except Exception as e:
            return CheckResult(vulnerable=False, details=f"Check failed: {e}")

    def _dispatch_to_plugins(self, method_name: str, data: Any):
        """Call a method on all loaded plugin instances."""
        for name, cls in self.plugins.items():
            instance = self.get_instance(name)
            if instance and hasattr(instance, method_name):
                try:
                    getattr(instance, method_name)(data)
                except Exception as e:
                    pass  # Never crash on event dispatch

    def resolve_dependencies(self, target_plugins: List[str]) -> List[str]:
        """Resolve dependency graph and return ordered execution list."""
        ordered = []
        visited = set()
        visiting = set()

        def dfs(plugin_name):
            if plugin_name in visiting:
                raise ValueError(f"Circular dependency: {plugin_name}")
            if plugin_name in visited:
                return

            plugin_class = self.get_plugin(plugin_name)
            if not plugin_class:
                raise ValueError(f"Required plugin not found: {plugin_name}")

            visiting.add(plugin_name)
            instance = plugin_class()
            for dep in instance.depends_on:
                dfs(dep)

            visiting.remove(plugin_name)
            visited.add(plugin_name)
            ordered.append(plugin_name)

        for p in target_plugins:
            dfs(p)
        return ordered

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[str]:
        """Get all plugin names of a specific type."""
        result = []
        for name, cls in self.plugins.items():
            if hasattr(cls, 'plugin_type') and cls.plugin_type == plugin_type:
                result.append(name)
        return result

    def get_plugins_for_stage(self, stage: KillChainStage) -> List[str]:
        """Get all plugin names for a specific kill chain stage."""
        result = []
        for name, cls in self.plugins.items():
            if hasattr(cls, 'kill_chain_stage') and cls.kill_chain_stage == stage:
                result.append(name)
        return result

    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all discovered plugins with their metadata."""
        plugins_info = []
        for name, cls in self.plugins.items():
            instance = cls()
            plugins_info.append({
                "name": name,
                "version": getattr(instance, 'version', '0.0.0'),
                "type": getattr(instance, 'plugin_type', PluginType.AUXILIARY).value,
                "stage": getattr(instance, 'kill_chain_stage', KillChainStage.RECON).value,
                "description": getattr(instance, 'description', ''),
                "author": getattr(instance, 'author', ''),
                "requires": getattr(instance, 'requires', []),
                "depends_on": getattr(instance, 'depends_on', []),
            })
        return plugins_info
