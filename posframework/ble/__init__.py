"""
BLE (Bluetooth Low Energy) Attack Module
-----------------------------------------

Real-world BLE scanning, beacon spoofing, GATT exploitation,
and HID injection using the bleak library.

Capabilities:
- BLE device discovery with iBeacon/Eddystone parsing
- Beacon spoofing (iBeacon, Eddystone-URL) via hcitool
- GATT service enumeration and characteristic read/write
- HID keyboard injection over Bluetooth (BadUSB-style)

Requirements:
- bleak (async BLE library): pip install bleak
- bluez (Linux Bluetooth stack): apt install bluez
- Root/sudo for hcitool advertising commands
"""

from __future__ import annotations

from .scanner import BLEScanner, BLEDevice, BeaconType, ScanConfig
from .beacon_spoofer import BeaconSpoofer, BeaconConfig
from .gatt_explorer import GATTExplorer, GATTService, GATTCharacteristic, DeviceProfile
from .hid_injector import HIDInjector, HIDConfig, HIDType, KEYCODES

__all__ = [
    "BLEScanner",
    "BLEDevice",
    "BeaconType",
    "ScanConfig",
    "BeaconSpoofer",
    "BeaconConfig",
    "GATTExplorer",
    "GATTService",
    "GATTCharacteristic",
    "DeviceProfile",
    "HIDInjector",
    "HIDConfig",
    "HIDType",
    "KEYCODES",
]
