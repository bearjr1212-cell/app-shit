"""
POSFramework Attack Plugins
────────────────────────────
This package contains dynamically loadable attack plugins that wrap
the existing engine classes via the AttackPlugin interface.

Plugins in this directory are auto-discovered by the PluginLoader.
Each plugin file should contain one or more classes that inherit from
posframework.plugin_loader.AttackPlugin.

Available plugins:
    deauth_plugin  - Deauthentication attack (wraps DeauthEngine)
    dos_plugin     - WiFi DoS attacks (wraps WiFiDoSEngine)
    mitm_plugin    - Man-in-the-middle attack (wraps MITMEngine)
"""
