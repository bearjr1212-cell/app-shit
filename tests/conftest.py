"""
Shared fixtures for the POSFramework test suite.
"""

import os
import sys
import tempfile
import sqlite3
import pytest

# Ensure posframework package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temporary database path for tests."""
    return str(tmp_path / "test.db")


@pytest.fixture
def db_instance(tmp_db):
    """Provide an initialized POSDatabase instance with a temp DB."""
    from posframework.database import POSDatabase
    db = POSDatabase(db_path=tmp_db)
    yield db
    db.close()


@pytest.fixture
def tmp_config_file(tmp_path):
    """Create a temporary YAML config file."""
    config_content = """
general:
  interface: wlan0test
  ap_interface: wlan1test
  channels: "5ghz"

recon:
  timeout: 60
  channel_hop_interval: 0.5
  status_interval: 15

attack:
  deauth_burst_count: 3
  deauth_burst_interval: 0.2
  beacon_interval: 0.05
  rssi_limit: -70
  enable_karma: false
  enable_dos: true
  dos_mode: beacon_exhaust

rogue_ap:
  captive_portal_port: 8080
  captive_portal_ssl_port: 8443

plugins:
  enabled: []
  plugins_dir: null

profiles:
  custom:
    recon.channel_hop_interval: 2.0
    attack.deauth_burst_count: 1
"""
    config_file = tmp_path / "posframework.yaml"
    config_file.write_text(config_content)
    return str(config_file)


@pytest.fixture
def sample_plugin_dir(tmp_path):
    """Create a temp directory with a sample plugin."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()

    plugin_code = '''
from posframework.plugin_system import BasePlugin, PluginMetadata, PluginType


class SamplePlugin(BasePlugin):
    @staticmethod
    def metadata():
        return PluginMetadata(
            name="sample-plugin",
            version="1.0.0",
            description="A sample test plugin",
            plugin_type=PluginType.SCANNER,
        )

    async def on_start(self):
        pass

    def on_tick(self, ctx):
        pass


class AnotherPlugin(BasePlugin):
    @staticmethod
    def metadata():
        return PluginMetadata(
            name="another-plugin",
            version="1.0.0",
            description="Another test plugin",
            plugin_type=PluginType.ATTACK,
        )

    async def on_start(self):
        pass

    def on_tick(self, ctx):
        pass
'''
    (plugin_dir / "test_plugins.py").write_text(plugin_code)

    # Also create an invalid plugin to test error handling
    (plugin_dir / "broken_plugin.py").write_text("raise ImportError('intentional')\n")

    # Create a file that should be skipped
    (plugin_dir / "__init__.py").write_text("")
    (plugin_dir / "_private.py").write_text("# should be skipped")

    return str(plugin_dir)
