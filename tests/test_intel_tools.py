"""
Unit tests for Intelligence & Analysis tool wrappers.
────────────────────────────────────────────────────────
Tests p0f, kismet, airgraph-ng, and horst wrappers with mocked subprocess
calls (no actual tools required).
"""

import json
import os
import sys
import tempfile
import time
from unittest.mock import patch, MagicMock, mock_open

try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False
    # Create a minimal pytest.raises replacement for import-time checks
    class _PytestShim:
        class _RaisesCtx:
            def __init__(self, exc):
                self.exc = exc
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, tb):
                if exc_type is None:
                    raise AssertionError(f"Expected {self.exc.__name__}")
                if issubclass(exc_type, self.exc):
                    return True
                return False
        @staticmethod
        def raises(exc):
            return _PytestShim._RaisesCtx(exc)
    pytest = _PytestShim()

# Ensure posframework is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── P0F Tests ────────────────────────────────────────────────────────────────

class TestP0F:
    """Tests for the P0F wrapper class."""

    @patch("posframework.tools.p0f.is_available", return_value=True)
    def test_p0f_instantiation(self, mock_avail):
        """P0F class can be instantiated when tool is available."""
        from posframework.tools.p0f import P0F
        p0f = P0F("wlan0mon")
        assert p0f.interface == "wlan0mon"
        assert p0f.running is False

    @patch("posframework.tools.p0f.is_available", return_value=False)
    def test_p0f_not_installed(self, mock_avail):
        """P0F raises FileNotFoundError when tool is missing."""
        from posframework.tools.p0f import P0F
        with pytest.raises(FileNotFoundError):
            P0F("wlan0mon")

    @patch("posframework.tools.p0f.is_available", return_value=True)
    @patch("posframework.tools.p0f.which", return_value="/usr/bin/p0f")
    @patch("subprocess.Popen")
    def test_p0f_start(self, mock_popen, mock_which, mock_avail):
        """P0F.start() launches p0f as a background process."""
        from posframework.tools.p0f import P0F
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Process is running
        mock_popen.return_value = mock_proc

        p0f = P0F("eth0")
        result = p0f.start()

        assert result is True
        assert p0f.running is True
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "/usr/bin/p0f"
        assert "-i" in cmd
        assert "eth0" in cmd

    @patch("posframework.tools.p0f.is_available", return_value=True)
    def test_p0f_parse_output(self, mock_avail):
        """P0F correctly parses p0f output log format."""
        from posframework.tools.p0f import P0F, P0FResult

        p0f_output = """.-[ 192.168.1.100/54321 -> 10.0.0.1/80 (syn) ]-
| client   = 192.168.1.100/54321
| os       = Linux 3.11 and newer
| dist     = 2
| link     = Ethernet or modem
| uptime   = 36 hrs
| raw_sig  = 4:64+2:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
`----

.-[ 192.168.1.101/12345 -> 10.0.0.1/443 (syn) ]-
| client   = 192.168.1.101/12345
| os       = Windows 7 or 8
| dist     = 1
| link     = Ethernet or modem
| raw_sig  = 8192:128+0:0:1460:8:mss,nop,ws,nop,nop,sok:df,id+:0
`----
"""
        p0f = P0F("eth0")

        # Write fake output to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".p0f.log", delete=False) as f:
            f.write(p0f_output)
            p0f._output_file = f.name

        try:
            results = p0f.get_results()
            assert len(results) == 2

            # Check first result
            linux_host = None
            windows_host = None
            for r in results:
                if r.ip == "192.168.1.100":
                    linux_host = r
                elif r.ip == "192.168.1.101":
                    windows_host = r

            assert linux_host is not None
            assert linux_host.os == "Linux"
            assert "3.11" in linux_host.os_flavor
            assert linux_host.distance == 2
            assert linux_host.link_type == "Ethernet or modem"
            assert linux_host.uptime == "36 hrs"

            assert windows_host is not None
            assert windows_host.os == "Windows"
            assert windows_host.distance == 1
        finally:
            os.unlink(p0f._output_file)

    @patch("posframework.tools.p0f.is_available", return_value=True)
    def test_p0f_get_results_live(self, mock_avail):
        """P0F.get_results_live() returns dicts suitable for vector loading."""
        from posframework.tools.p0f import P0F, P0FResult

        p0f = P0F("eth0")
        p0f._results = {
            "192.168.1.1": P0FResult(
                ip="192.168.1.1", os="Linux", os_flavor="5.x",
                distance=1, link_type="Ethernet"
            )
        }

        live = p0f.get_results_live()
        assert len(live) == 1
        assert live[0]["ip"] == "192.168.1.1"
        assert live[0]["os"] == "Linux"
        assert live[0]["distance"] == 1

    @patch("posframework.tools.p0f.is_available", return_value=True)
    @patch("posframework.tools.p0f.which", return_value="/usr/bin/p0f")
    @patch("subprocess.Popen")
    def test_p0f_stop(self, mock_popen, mock_which, mock_avail):
        """P0F.stop() terminates the background process."""
        from posframework.tools.p0f import P0F
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        p0f = P0F("eth0")
        p0f.start()
        p0f.stop()

        mock_proc.send_signal.assert_called()
        assert p0f._proc is None


# ─── Kismet Tests ─────────────────────────────────────────────────────────────

class TestKismetClient:
    """Tests for the KismetClient wrapper class."""

    @patch("posframework.tools.kismet.is_available", return_value=True)
    def test_kismet_instantiation(self, mock_avail):
        """KismetClient can be instantiated when kismet is available."""
        from posframework.tools.kismet import KismetClient
        kc = KismetClient("wlan0mon")
        assert kc.interface == "wlan0mon"
        assert kc.running is False
        assert kc.port == 2501

    @patch("posframework.tools.kismet.is_available", return_value=False)
    def test_kismet_not_installed(self, mock_avail):
        """KismetClient raises FileNotFoundError when kismet is missing."""
        from posframework.tools.kismet import KismetClient
        with pytest.raises(FileNotFoundError):
            KismetClient("wlan0mon")

    @patch("posframework.tools.kismet.is_available", return_value=True)
    @patch("posframework.tools.kismet.which", return_value="/usr/bin/kismet")
    @patch("subprocess.Popen")
    def test_kismet_start_server(self, mock_popen, mock_which, mock_avail):
        """KismetClient.start_server() launches kismet as a background process."""
        from posframework.tools.kismet import KismetClient
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        kc = KismetClient("wlan0mon")
        result = kc.start_server()

        assert result is True
        assert kc.running is True
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "/usr/bin/kismet"
        assert "-c" in cmd
        assert "wlan0mon" in cmd

    @patch("posframework.tools.kismet.is_available", return_value=True)
    def test_kismet_parse_devices(self, mock_avail):
        """KismetClient correctly parses ekjson device data."""
        from posframework.tools.kismet import KismetClient, KismetDevice

        # Simulated ekjson output (one JSON object per line)
        ekjson_data = (
            '{"kismet.device.base.macaddr":"AA:BB:CC:DD:EE:FF",'
            '"kismet.device.base.type":"Wi-Fi AP",'
            '"kismet.device.base.name":"MyNetwork",'
            '"dot11.device":{"dot11.device.last_beaconed_ssid":"TestNet"},'
            '"kismet.device.base.channel":"6",'
            '"kismet.device.base.frequency":2437,'
            '"kismet.device.base.signal":{"kismet.common.signal.last_signal":-45},'
            '"kismet.device.base.manuf":"Intel",'
            '"kismet.device.base.crypt":"WPA2",'
            '"kismet.device.base.packets.total":1234}\n'
            '{"kismet.device.base.macaddr":"11:22:33:44:55:66",'
            '"kismet.device.base.type":"Wi-Fi Client",'
            '"kismet.device.base.name":"ClientDevice",'
            '"kismet.device.base.channel":"6",'
            '"kismet.device.base.signal":{"kismet.common.signal.last_signal":-65},'
            '"kismet.device.base.packets.total":567}\n'
        )

        kc = KismetClient("wlan0mon")
        kc._parse_devices(ekjson_data)

        assert len(kc._devices) == 2
        assert "AA:BB:CC:DD:EE:FF" in kc._devices
        assert "11:22:33:44:55:66" in kc._devices

        ap = kc._devices["AA:BB:CC:DD:EE:FF"]
        assert ap.ssid == "TestNet"
        assert ap.device_type == "Wi-Fi AP"
        assert ap.signal_dbm == -45
        assert ap.manufacturer == "Intel"
        assert ap.encryption == "WPA2"
        assert ap.packets == 1234

    @patch("posframework.tools.kismet.is_available", return_value=True)
    def test_kismet_get_ssids(self, mock_avail):
        """KismetClient.get_ssids() returns AP SSIDs from cache."""
        from posframework.tools.kismet import KismetClient, KismetDevice

        kc = KismetClient("wlan0mon")
        kc._devices = {
            "AA:BB:CC:DD:EE:FF": KismetDevice(
                mac="AA:BB:CC:DD:EE:FF", device_type="Wi-Fi AP",
                ssid="TestNet", channel=6, signal_dbm=-45, encryption="WPA2"
            ),
            "11:22:33:44:55:66": KismetDevice(
                mac="11:22:33:44:55:66", device_type="Wi-Fi Client",
                ssid="", channel=6, signal_dbm=-65
            ),
        }

        ssids = kc.get_ssids()
        assert len(ssids) == 1
        assert ssids[0]["ssid"] == "TestNet"
        assert ssids[0]["bssid"] == "AA:BB:CC:DD:EE:FF"

    @patch("posframework.tools.kismet.is_available", return_value=True)
    def test_kismet_get_devices_live(self, mock_avail):
        """KismetClient.get_devices_live() returns dicts for vector loading."""
        from posframework.tools.kismet import KismetClient, KismetDevice

        kc = KismetClient("wlan0mon")
        kc._devices = {
            "AA:BB:CC:DD:EE:FF": KismetDevice(
                mac="AA:BB:CC:DD:EE:FF", device_type="Wi-Fi AP",
                ssid="LiveNet", channel=11, signal_dbm=-40
            ),
        }

        live = kc.get_devices_live()
        assert len(live) == 1
        assert live[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert live[0]["ssid"] == "LiveNet"
        assert live[0]["channel"] == 11


# ─── Airgraph-NG Tests ────────────────────────────────────────────────────────

class TestAirgraphNG:
    """Tests for the AirgraphNG wrapper class."""

    @patch("posframework.tools.airgraph.is_available", return_value=True)
    def test_airgraph_instantiation(self, mock_avail):
        """AirgraphNG can be instantiated when tool is available."""
        from posframework.tools.airgraph import AirgraphNG
        ag = AirgraphNG()
        assert ag is not None

    @patch("posframework.tools.airgraph.is_available", return_value=False)
    def test_airgraph_not_installed(self, mock_avail):
        """AirgraphNG raises FileNotFoundError when tool is missing."""
        from posframework.tools.airgraph import AirgraphNG
        with pytest.raises(FileNotFoundError):
            AirgraphNG()

    @patch("posframework.tools.airgraph.is_available", return_value=True)
    @patch("posframework.tools.airgraph.run_tool")
    def test_airgraph_generate_capr(self, mock_run, mock_avail):
        """AirgraphNG generates CAPR graph with correct command args."""
        from posframework.tools.airgraph import AirgraphNG

        mock_run.return_value = MagicMock(
            returncode=0, stdout="Generated 5 nodes and 8 edges\n", stderr=""
        )

        ag = AirgraphNG()

        # Create a fake CSV file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("BSSID, First time seen, Last time seen\n")
            csv_file = f.name

        try:
            result = ag.generate_graph(
                csv_file=csv_file,
                output_file="/tmp/test_graph.png",
                graph_type="CAPR"
            )

            assert result.success is True
            assert result.graph_type == "CAPR"
            mock_run.assert_called_once()
            args = mock_run.call_args[0][1]
            assert "-i" in args
            assert csv_file in args
            assert "-o" in args
            assert "/tmp/test_graph.png" in args
            assert "-g" in args
            assert "CAPR" in args
        finally:
            os.unlink(csv_file)

    @patch("posframework.tools.airgraph.is_available", return_value=True)
    @patch("posframework.tools.airgraph.run_tool")
    def test_airgraph_generate_cpg(self, mock_run, mock_avail):
        """AirgraphNG generates CPG graph correctly."""
        from posframework.tools.airgraph import AirgraphNG

        mock_run.return_value = MagicMock(
            returncode=0, stdout="3 nodes, 2 edges\n", stderr=""
        )

        ag = AirgraphNG()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("BSSID, First time seen\n")
            csv_file = f.name

        try:
            result = ag.generate_cpg(csv_file, "/tmp/probes.png")
            assert result.success is True
            assert result.graph_type == "CPG"
        finally:
            os.unlink(csv_file)

    @patch("posframework.tools.airgraph.is_available", return_value=True)
    def test_airgraph_invalid_graph_type(self, mock_avail):
        """AirgraphNG rejects invalid graph types."""
        from posframework.tools.airgraph import AirgraphNG
        ag = AirgraphNG()
        result = ag.generate_graph("/tmp/fake.csv", "/tmp/out.png", "INVALID")
        assert result.success is False
        assert "Invalid graph type" in result.error

    @patch("posframework.tools.airgraph.is_available", return_value=True)
    def test_airgraph_missing_csv(self, mock_avail):
        """AirgraphNG returns error when CSV file does not exist."""
        from posframework.tools.airgraph import AirgraphNG
        ag = AirgraphNG()
        result = ag.generate_graph("/nonexistent/file.csv", "/tmp/out.png")
        assert result.success is False
        assert "not found" in result.error


# ─── Horst Tests ──────────────────────────────────────────────────────────────

class TestHorst:
    """Tests for the Horst wrapper class."""

    @patch("posframework.tools.horst.is_available", return_value=True)
    def test_horst_instantiation(self, mock_avail):
        """Horst can be instantiated when tool is available."""
        from posframework.tools.horst import Horst
        h = Horst("wlan0mon")
        assert h.interface == "wlan0mon"
        assert h.running is False

    @patch("posframework.tools.horst.is_available", return_value=False)
    def test_horst_not_installed(self, mock_avail):
        """Horst raises FileNotFoundError when tool is missing."""
        from posframework.tools.horst import Horst
        with pytest.raises(FileNotFoundError):
            Horst("wlan0mon")

    @patch("posframework.tools.horst.is_available", return_value=True)
    @patch("posframework.tools.horst.which", return_value="/usr/bin/horst")
    @patch("subprocess.Popen")
    def test_horst_start(self, mock_popen, mock_which, mock_avail):
        """Horst.start() launches horst as a background process."""
        from posframework.tools.horst import Horst
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stderr = MagicMock()
        mock_popen.return_value = mock_proc

        h = Horst("wlan0mon")
        result = h.start()

        assert result is True
        assert h.running is True
        cmd = mock_popen.call_args[0][0]
        assert cmd[0] == "/usr/bin/horst"
        assert "-i" in cmd
        assert "wlan0mon" in cmd

    @patch("posframework.tools.horst.is_available", return_value=True)
    def test_horst_parse_output(self, mock_avail):
        """Horst correctly parses scan output for nodes and stats."""
        from posframework.tools.horst import Horst

        # Simulated horst output
        horst_output = """1700000001 -45 -95 AA:BB:CC:DD:EE:FF BEACON 6
1700000002 -55 -95 11:22:33:44:55:66 PROBE_REQ 6
1700000003 -40 -90 AA:BB:CC:DD:EE:FF DATA 6
1700000004 -65 -95 22:33:44:55:66:77 ACK 11
1700000005 -50 -93 AA:BB:CC:DD:EE:FF MGMT 6
"""

        h = Horst("wlan0mon")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".horst.log", delete=False) as f:
            f.write(horst_output)
            h._output_file = f.name

        try:
            nodes = h.get_nodes()
            assert len(nodes) == 3

            # Check AP node
            ap = None
            for n in nodes:
                if n.mac == "AA:BB:CC:DD:EE:FF":
                    ap = n
                    break

            assert ap is not None
            assert ap.mode == "AP"  # Detected from BEACON
            assert ap.packet_count == 3
            assert ap.channel == 6

            # Check client node
            client = None
            for n in nodes:
                if n.mac == "11:22:33:44:55:66":
                    client = n
                    break

            assert client is not None
            assert client.mode == "STA"  # Detected from PROBE_REQ

            # Check stats
            stats = h.get_stats()
            assert stats.total_packets == 5
            assert stats.mgmt_packets == 3  # BEACON + PROBE_REQ + MGMT
            assert stats.ctrl_packets == 1  # ACK
            assert stats.data_packets == 1  # DATA
        finally:
            os.unlink(h._output_file)

    @patch("posframework.tools.horst.is_available", return_value=True)
    def test_horst_get_nodes_live(self, mock_avail):
        """Horst.get_nodes_live() returns dicts for vector loading."""
        from posframework.tools.horst import Horst, HorstNode

        h = Horst("wlan0mon")
        h._nodes = {
            "AA:BB:CC:DD:EE:FF": HorstNode(
                mac="AA:BB:CC:DD:EE:FF", signal=-45, noise=-95,
                snr=50, packet_count=100, channel=6, mode="AP"
            ),
        }

        live = h.get_nodes_live()
        assert len(live) == 1
        assert live[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert live[0]["signal"] == -45
        assert live[0]["mode"] == "AP"

    @patch("posframework.tools.horst.is_available", return_value=True)
    @patch("posframework.tools.horst.which", return_value="/usr/bin/horst")
    @patch("subprocess.Popen")
    def test_horst_stop(self, mock_popen, mock_which, mock_avail):
        """Horst.stop() terminates the background process."""
        from posframework.tools.horst import Horst
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stderr = MagicMock()
        mock_popen.return_value = mock_proc

        h = Horst("wlan0mon")
        h.start()
        h.stop()

        mock_proc.send_signal.assert_called()
        assert h._proc is None


# ─── TOOL_REGISTRY Integration Test ──────────────────────────────────────────

class TestToolRegistry:
    """Tests verifying intel tools are registered in TOOL_REGISTRY."""

    def test_p0f_in_registry(self):
        """p0f is registered in TOOL_REGISTRY."""
        from posframework.tools import TOOL_REGISTRY
        assert "p0f" in TOOL_REGISTRY
        assert TOOL_REGISTRY["p0f"]["category"] == "fingerprint"
        assert TOOL_REGISTRY["p0f"]["binary"] == "p0f"

    def test_kismet_in_registry(self):
        """kismet is registered in TOOL_REGISTRY."""
        from posframework.tools import TOOL_REGISTRY
        assert "kismet" in TOOL_REGISTRY
        assert TOOL_REGISTRY["kismet"]["category"] == "intel"
        assert TOOL_REGISTRY["kismet"]["binary"] == "kismet"

    def test_airgraph_in_registry(self):
        """airgraph-ng is registered in TOOL_REGISTRY."""
        from posframework.tools import TOOL_REGISTRY
        assert "airgraph-ng" in TOOL_REGISTRY
        assert TOOL_REGISTRY["airgraph-ng"]["category"] == "visualization"
        assert TOOL_REGISTRY["airgraph-ng"]["binary"] == "airgraph-ng"

    def test_horst_in_registry(self):
        """horst is registered in TOOL_REGISTRY."""
        from posframework.tools import TOOL_REGISTRY
        assert "horst" in TOOL_REGISTRY
        assert TOOL_REGISTRY["horst"]["category"] == "scanning"
        assert TOOL_REGISTRY["horst"]["binary"] == "horst"


# ─── Manual test runner (for environments without pytest) ─────────────────────

def _run_manual_tests():
    """Run tests manually using assertions (for sandboxes without pytest)."""
    import traceback

    tests_passed = 0
    tests_failed = 0
    failures = []

    # Collect test classes and methods
    test_classes = [TestP0F, TestKismetClient, TestAirgraphNG, TestHorst, TestToolRegistry]

    for cls in test_classes:
        instance = cls()
        for method_name in dir(instance):
            if not method_name.startswith("test_"):
                continue
            method = getattr(instance, method_name)
            test_name = f"{cls.__name__}.{method_name}"
            try:
                method()
                tests_passed += 1
                print(f"  PASS: {test_name}")
            except Exception as e:
                tests_failed += 1
                failures.append((test_name, str(e)))
                print(f"  FAIL: {test_name} - {e}")
                traceback.print_exc()

    print(f"\nResults: {tests_passed} passed, {tests_failed} failed")
    if failures:
        print("\nFailures:")
        for name, err in failures:
            print(f"  - {name}: {err}")
    return tests_failed == 0


if __name__ == "__main__":
    success = _run_manual_tests()
    sys.exit(0 if success else 1)
