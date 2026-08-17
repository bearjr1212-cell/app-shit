"""
Dynamic Plugin Loading System
─────────────────────────────
Provides plugin discovery, registration, and lifecycle management
for attack modules. Allows loading plugins dynamically from
configurable directories without requiring static imports.

Usage:
    from posframework.plugin_loader import PluginLoader, AttackPlugin

    loader = PluginLoader()
    loader.discover()  # auto-discover from default plugins directory
    loader.list_plugins()  # show all registered plugins
    plugin = loader.get_plugin("deauth")
    plugin.setup(config)
    plugin.execute(context)
    plugin.teardown()
"""

import os
import sys
import importlib
import importlib.util
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any

log = logging.getLogger("posframework.plugin_loader")


class AttackPlugin(ABC):
    """
    Abstract base class for all attack plugins.

    All plugins must implement the five core lifecycle methods:
      - name(): return a unique identifier for the plugin
      - description(): return a human-readable description
      - category(): return the plugin category (recon, deauth, mitm, dos, printer, etc.)
      - setup(config): initialize the plugin with configuration
      - execute(context): run the plugin's attack logic
      - teardown(): clean up resources
    """

    @abstractmethod
    def name(self) -> str:
        """Return the unique name/identifier of this plugin."""
        ...

    @abstractmethod
    def description(self) -> str:
        """Return a human-readable description of this plugin."""
        ...

    @abstractmethod
    def category(self) -> str:
        """
        Return the plugin category. Standard categories:
          recon, deauth, mitm, dos, printer, karma, rogue_ap, krack, clone
        """
        ...

    @abstractmethod
    def setup(self, config: Dict[str, Any]) -> bool:
        """
        Initialize the plugin with the given configuration.

        Args:
            config: Dictionary of configuration parameters
                    (interface names, targets, options, etc.)

        Returns:
            True if setup succeeded, False otherwise.
        """
        ...

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Any:
        """
        Execute the plugin's primary attack/recon logic.

        Args:
            context: Runtime context with target info, database handle,
                     signal data, etc.

        Returns:
            Plugin-specific result (could be status dict, captured data, etc.)
        """
        ...

    @abstractmethod
    def teardown(self) -> None:
        """Clean up all resources held by this plugin."""
        ...

    @property
    def enabled(self) -> bool:
        """Whether this plugin is currently enabled."""
        return getattr(self, "_enabled", True)

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"<Plugin '{self.name()}' [{self.category()}] ({status})>"


class PluginLoader:
    """
    Dynamic plugin discovery and registration system.

    Discovers plugins from one or more directories, loads them via importlib,
    and organizes them by category for the orchestrator to use.

    Usage:
        loader = PluginLoader()
        loader.discover()  # scans default plugins dir
        loader.discover("/path/to/custom/plugins")  # scan additional dir

        # Get plugins
        all_plugins = loader.list_plugins()
        deauth_plugins = loader.get_plugins_by_category("deauth")
        plugin = loader.get_plugin("deauth")
    """

    # Standard plugin categories matching existing module groups
    CATEGORIES = [
        "recon", "deauth", "mitm", "dos", "printer",
        "karma", "rogue_ap", "krack", "clone", "disruption",
        "credential", "handshake", "isolation",
    ]

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        """
        Initialize the PluginLoader.

        Args:
            plugin_dirs: Optional list of directories to scan for plugins.
                        Defaults to posframework/plugins/ if not specified.
        """
        self._plugins: Dict[str, AttackPlugin] = {}
        self._categories: Dict[str, List[str]] = {cat: [] for cat in self.CATEGORIES}
        self._disabled: set = set()
        self._plugin_dirs: List[Path] = []

        # Default plugins directory is posframework/plugins/
        default_dir = Path(__file__).parent / "plugins"
        self._plugin_dirs.append(default_dir)

        if plugin_dirs:
            for d in plugin_dirs:
                p = Path(d)
                if p.is_dir():
                    self._plugin_dirs.append(p)
                else:
                    log.warning(f"Plugin directory not found: {d}")

    def discover(self, directory: Optional[str] = None) -> int:
        """
        Discover and load plugins from the configured directories
        or a specific directory.

        Args:
            directory: Optional specific directory to scan.
                      If None, scans all configured plugin_dirs.

        Returns:
            Number of plugins successfully loaded.
        """
        dirs_to_scan = [Path(directory)] if directory else self._plugin_dirs
        loaded = 0

        for plugin_dir in dirs_to_scan:
            if not plugin_dir.is_dir():
                log.debug(f"Plugin directory does not exist: {plugin_dir}")
                continue

            for filepath in sorted(plugin_dir.glob("*.py")):
                if filepath.name.startswith("_"):
                    continue  # skip __init__.py and private modules

                try:
                    count = self._load_plugin_file(filepath)
                    loaded += count
                except Exception as e:
                    log.warning(f"Failed to load plugin from {filepath.name}: {e}")

        log.info(f"Plugin discovery complete: {loaded} plugins loaded from {len(dirs_to_scan)} directories")
        return loaded

    def _load_plugin_file(self, filepath: Path) -> int:
        """
        Load a single plugin file and register any AttackPlugin subclasses found.

        Args:
            filepath: Path to the .py file to load.

        Returns:
            Number of plugin classes registered from this file.
        """
        module_name = f"posframework.plugins.{filepath.stem}"

        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None or spec.loader is None:
            return 0

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            log.warning(f"Error executing plugin module {filepath.name}: {e}")
            del sys.modules[module_name]
            return 0

        # Find all AttackPlugin subclasses in the module
        count = 0
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type)
                    and issubclass(attr, AttackPlugin)
                    and attr is not AttackPlugin):
                try:
                    instance = attr()
                    self.register(instance)
                    count += 1
                except Exception as e:
                    log.warning(f"Failed to instantiate plugin {attr_name}: {e}")

        return count

    def register(self, plugin: AttackPlugin) -> None:
        """
        Register a plugin instance.

        Args:
            plugin: An instance of an AttackPlugin subclass.

        Raises:
            TypeError: If plugin is not an AttackPlugin instance.
            ValueError: If a plugin with the same name is already registered.
        """
        if not isinstance(plugin, AttackPlugin):
            raise TypeError(f"Expected AttackPlugin instance, got {type(plugin)}")

        plugin_name = plugin.name()

        if plugin_name in self._plugins:
            log.warning(f"Plugin '{plugin_name}' already registered, skipping duplicate")
            return

        self._plugins[plugin_name] = plugin

        # Register by category
        category = plugin.category()
        if category not in self._categories:
            self._categories[category] = []
        self._categories[category].append(plugin_name)

        # Apply disabled state if previously disabled
        if plugin_name in self._disabled:
            plugin.enabled = False

        log.debug(f"Registered plugin: {plugin}")

    def unregister(self, name: str) -> bool:
        """
        Remove a plugin from the registry.

        Args:
            name: The plugin name to remove.

        Returns:
            True if removed, False if not found.
        """
        if name not in self._plugins:
            return False

        plugin = self._plugins[name]
        category = plugin.category()

        del self._plugins[name]
        if category in self._categories and name in self._categories[category]:
            self._categories[category].remove(name)

        return True

    def get_plugin(self, name: str) -> Optional[AttackPlugin]:
        """
        Get a plugin by name.

        Args:
            name: The unique plugin name.

        Returns:
            The plugin instance, or None if not found.
        """
        return self._plugins.get(name)

    def get_plugins_by_category(self, category: str) -> List[AttackPlugin]:
        """
        Get all plugins in a category.

        Args:
            category: The category to filter by.

        Returns:
            List of plugin instances in the given category.
        """
        names = self._categories.get(category, [])
        return [self._plugins[n] for n in names if n in self._plugins]

    def list_plugins(self) -> List[AttackPlugin]:
        """
        Return all registered plugins.

        Returns:
            List of all registered plugin instances.
        """
        return list(self._plugins.values())

    def list_plugin_names(self) -> List[str]:
        """
        Return names of all registered plugins.

        Returns:
            List of plugin name strings.
        """
        return list(self._plugins.keys())

    def list_categories(self) -> Dict[str, int]:
        """
        Return categories with their plugin counts.

        Returns:
            Dict mapping category name to number of plugins.
        """
        return {cat: len(names) for cat, names in self._categories.items() if names}

    def enable_plugin(self, name: str) -> bool:
        """
        Enable a plugin by name.

        Args:
            name: The plugin name to enable.

        Returns:
            True if found and enabled, False if not found.
        """
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = True
            self._disabled.discard(name)
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        """
        Disable a plugin by name.

        Args:
            name: The plugin name to disable.

        Returns:
            True if found and disabled, False if not found.
        """
        plugin = self._plugins.get(name)
        if plugin:
            plugin.enabled = False
            self._disabled.add(name)
            return True
        return False

    def get_enabled_plugins(self) -> List[AttackPlugin]:
        """Return only enabled plugins."""
        return [p for p in self._plugins.values() if p.enabled]

    def get_disabled_plugins(self) -> List[AttackPlugin]:
        """Return only disabled plugins."""
        return [p for p in self._plugins.values() if not p.enabled]

    def print_plugin_table(self) -> str:
        """
        Generate a formatted table of all registered plugins.

        Returns:
            Formatted string table suitable for terminal output.
        """
        if not self._plugins:
            return "No plugins loaded."

        lines = []
        lines.append(f"{'Name':<20} {'Category':<12} {'Status':<10} {'Description'}")
        lines.append("-" * 70)

        for plugin in sorted(self._plugins.values(), key=lambda p: (p.category(), p.name())):
            status = "enabled" if plugin.enabled else "disabled"
            desc = plugin.description()[:35]
            lines.append(f"{plugin.name():<20} {plugin.category():<12} {status:<10} {desc}")

        return "\n".join(lines)
