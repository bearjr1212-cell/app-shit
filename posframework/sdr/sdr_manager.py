"""
SDR Device Manager - RTL-SDR, RTL-SDR Blog V4, and HackRF support.

Manages Software-Defined Radio hardware for RF spectrum analysis,
signal capture, and (with HackRF) transmission.

Supported devices:
- RTL-SDR (R820T/R820T2): 24-1766 MHz, RX only, up to 3.2 MSPS
- RTL-SDR Blog V4 (R828D): 500 kHz-1766 MHz, HF direct sampling, bias tee
- HackRF One: 1-6000 MHz, TX/RX, up to 20 MSPS
- YARD Stick One: 300-928 MHz sub-GHz
- LimeSDR: 100 kHz-3.8 GHz, TX/RX

Requirements: pip install pyrtlsdr
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Graceful pyrtlsdr import
try:
    from rtlsdr import RtlSdr
    _HAS_RTLSDR = True
except ImportError:
    _HAS_RTLSDR = False
    RtlSdr = None  # type: ignore[assignment, misc]


class SDRType(str, Enum):
    """Supported SDR device types."""
    RTL_SDR = "rtl_sdr"
    RTL_SDR_V4 = "rtl_sdr_v4"
    HACKRF = "hackrf"
    YARD_STICK = "yardstick"
    LIMESDR = "limesdr"
    UNKNOWN = "unknown"


@dataclass
class SDRDevice:
    """Discovered SDR device with capabilities."""
    device_type: SDRType
    device_index: int = 0
    serial: str = ""
    name: str = ""

    # Frequency range
    min_freq_hz: int = 24_000_000
    max_freq_hz: int = 1_766_000_000

    # Capabilities
    can_transmit: bool = False
    max_sample_rate: int = 3_200_000
    has_hf_mode: bool = False
    has_bias_tee: bool = False

    # Current state
    is_open: bool = False
    current_freq_hz: int = 0
    current_sample_rate: int = 0
    current_gain: float = 0.0
    direct_sampling: int = 0  # 0=off, 1=I-ADC, 2=Q-ADC

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_type": self.device_type.value,
            "device_index": self.device_index,
            "serial": self.serial,
            "name": self.name,
            "min_freq_mhz": self.min_freq_hz / 1_000_000,
            "max_freq_mhz": self.max_freq_hz / 1_000_000,
            "can_transmit": self.can_transmit,
            "has_hf_mode": self.has_hf_mode,
            "has_bias_tee": self.has_bias_tee,
            "is_open": self.is_open,
            "current_freq_mhz": self.current_freq_hz / 1_000_000,
            "direct_sampling": self.direct_sampling,
        }


@dataclass
class SDRConfig:
    """SDR operating configuration."""
    center_freq_hz: int = 433_920_000  # 433.92 MHz ISM band
    sample_rate: int = 2_048_000       # 2.048 MSPS
    gain: float = 40.0                 # dB (use 'auto' via 0 for AGC)
    ppm_correction: int = 0            # Frequency error correction
    bandwidth_hz: int = 0              # 0 = auto (matches sample_rate)

    # Scan parameters
    scan_start_hz: int = 430_000_000
    scan_end_hz: int = 440_000_000
    scan_step_hz: int = 100_000


class SDRManager:
    """
    SDR device manager with full RTL-SDR and HackRF support.

    Handles device discovery, initialization, frequency tuning,
    gain control, and IQ sample capture.

    Usage:
        manager = SDRManager()
        await manager.start()

        devices = await manager.discover_devices()
        if devices:
            await manager.open_device(0)
            await manager.set_frequency(433_920_000)
            samples = await manager.capture_samples(num_samples=262144)
            await manager.close_device()

        await manager.stop()
    """

    def __init__(self, config: SDRConfig | None = None):
        self.config = config or SDRConfig()
        self._running = False
        self._devices: list[SDRDevice] = []
        self._active_device: SDRDevice | None = None
        self._sdr: Any = None  # RtlSdr instance
        self._stats = {
            "devices_found": 0,
            "samples_captured": 0,
            "signals_detected": 0,
        }

    async def start(self) -> bool:
        """Initialize manager and discover devices."""
        try:
            await self.discover_devices()
            self._running = True
            logger.info("SDRManager started, found %d devices", len(self._devices))
            return True
        except Exception as e:
            logger.error("SDRManager start failed: %s", e)
            return False

    async def stop(self) -> None:
        """Stop manager and release all devices."""
        if self._active_device:
            await self.close_device()
        self._running = False
        logger.info("SDRManager stopped")

    async def discover_devices(self) -> list[SDRDevice]:
        """
        Discover all connected SDR devices.

        Probes for RTL-SDR via pyrtlsdr and HackRF via hackrf_info CLI.
        """
        self._devices = []

        # Discover RTL-SDR devices
        if _HAS_RTLSDR:
            try:
                device_count = RtlSdr.get_device_count()
                for i in range(device_count):
                    serial = RtlSdr.get_device_serial(i)
                    name = RtlSdr.get_device_name(i)

                    # Detect RTL-SDR Blog V4 (R828D tuner)
                    is_v4 = any(v4_id in name for v4_id in ("R828D", "V4", "Blog V4"))

                    device = SDRDevice(
                        device_type=SDRType.RTL_SDR_V4 if is_v4 else SDRType.RTL_SDR,
                        device_index=i,
                        serial=serial,
                        name=name,
                        min_freq_hz=500_000 if is_v4 else 24_000_000,
                        max_freq_hz=1_766_000_000,
                        can_transmit=False,
                        max_sample_rate=3_200_000,
                        has_hf_mode=is_v4,
                        has_bias_tee=is_v4,
                    )
                    self._devices.append(device)
            except Exception as e:
                logger.debug("RTL-SDR discovery error: %s", e)
        else:
            logger.debug("pyrtlsdr not installed - RTL-SDR discovery skipped")

        # Discover HackRF devices via CLI
        try:
            result = subprocess.run(
                ["hackrf_info"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "Serial number" in result.stdout:
                device = SDRDevice(
                    device_type=SDRType.HACKRF,
                    device_index=len(self._devices),
                    serial="hackrf",
                    name="HackRF One",
                    min_freq_hz=1_000_000,
                    max_freq_hz=6_000_000_000,
                    can_transmit=True,
                    max_sample_rate=20_000_000,
                )
                self._devices.append(device)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        self._stats["devices_found"] = len(self._devices)
        return self._devices

    async def open_device(self, device_index: int = 0) -> bool:
        """
        Open an SDR device for use.

        Initializes the device with the configured sample rate, frequency, and gain.
        """
        if device_index >= len(self._devices):
            logger.error("Device index %d not found (have %d)", device_index, len(self._devices))
            return False

        device = self._devices[device_index]

        if device.device_type in (SDRType.RTL_SDR, SDRType.RTL_SDR_V4):
            if not _HAS_RTLSDR:
                raise RuntimeError(
                    "pyrtlsdr library required - install with: pip install pyrtlsdr"
                )
            try:
                self._sdr = RtlSdr(device.device_index)
                self._sdr.sample_rate = self.config.sample_rate
                self._sdr.center_freq = self.config.center_freq_hz
                self._sdr.gain = self.config.gain
                if self.config.ppm_correction:
                    self._sdr.freq_correction = self.config.ppm_correction
            except Exception as e:
                logger.error("Failed to open RTL-SDR device %d: %s", device_index, e)
                return False
        else:
            logger.warning(
                "SDR type %s not directly supported via pyrtlsdr (only RTL-SDR)",
                device.device_type.value,
            )
            return False

        device.is_open = True
        device.current_freq_hz = self.config.center_freq_hz
        device.current_sample_rate = self.config.sample_rate
        device.current_gain = self.config.gain
        self._active_device = device

        logger.info("Opened SDR device: %s (index=%d)", device.name, device_index)
        return True

    async def close_device(self) -> None:
        """Close the active SDR device."""
        if self._sdr:
            try:
                self._sdr.close()
            except Exception:
                pass
            self._sdr = None

        if self._active_device:
            self._active_device.is_open = False
            self._active_device = None

    async def set_frequency(self, freq_hz: int) -> bool:
        """Set center frequency in Hz."""
        if not self._sdr or not self._active_device:
            return False
        try:
            self._sdr.center_freq = freq_hz
            self._active_device.current_freq_hz = freq_hz
            return True
        except Exception as e:
            logger.error("Set frequency failed: %s", e)
            return False

    async def set_gain(self, gain_db: float) -> bool:
        """Set gain in dB. Use 0 for automatic gain control."""
        if not self._sdr or not self._active_device:
            return False
        try:
            self._sdr.gain = gain_db
            self._active_device.current_gain = gain_db
            return True
        except Exception as e:
            logger.error("Set gain failed: %s", e)
            return False

    async def set_sample_rate(self, rate: int) -> bool:
        """Set sample rate in samples per second."""
        if not self._sdr or not self._active_device:
            return False
        try:
            self._sdr.sample_rate = rate
            self._active_device.current_sample_rate = rate
            return True
        except Exception as e:
            logger.error("Set sample rate failed: %s", e)
            return False

    async def set_direct_sampling(self, mode: int) -> bool:
        """
        Set direct sampling mode for HF reception (RTL-SDR V4).

        Args:
            mode: 0=off, 1=I-ADC input, 2=Q-ADC input
                  For V4 HF (500 kHz - 28 MHz): use mode=2
        """
        if not self._sdr or not self._active_device:
            return False

        if not self._active_device.has_hf_mode and mode > 0:
            logger.warning("Device does not support HF direct sampling")
            return False

        try:
            self._sdr.set_direct_sampling(mode)
            self._active_device.direct_sampling = mode
            logger.info("Direct sampling mode: %d", mode)
            return True
        except Exception as e:
            logger.error("Set direct sampling failed: %s", e)
            return False

    async def set_bias_tee(self, enabled: bool) -> bool:
        """
        Enable/disable bias tee (RTL-SDR V4).

        Provides 4.5V DC on antenna input for powered antennas/LNAs.
        """
        if not self._sdr or not self._active_device:
            return False
        if not self._active_device.has_bias_tee:
            logger.warning("Device does not have bias tee")
            return False
        try:
            self._sdr.set_bias_tee(enabled)
            logger.info("Bias tee: %s", "enabled" if enabled else "disabled")
            return True
        except Exception as e:
            logger.error("Bias tee control failed: %s", e)
            return False

    async def capture_samples(self, num_samples: int = 262144) -> list[complex]:
        """
        Capture IQ samples from the active device.

        Args:
            num_samples: Number of complex IQ samples to capture

        Returns:
            List of complex IQ samples (I + jQ)
        """
        if not self._sdr:
            raise RuntimeError("No SDR device open - call open_device() first")

        try:
            samples = self._sdr.read_samples(num_samples)
            self._stats["samples_captured"] += num_samples
            return list(samples)
        except Exception as e:
            logger.error("Sample capture failed: %s", e)
            return []

    def get_devices(self) -> list[SDRDevice]:
        """Get list of discovered devices."""
        return self._devices

    def get_active_device(self) -> SDRDevice | None:
        """Get the currently active device."""
        return self._active_device

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_sdr_devices": len(self._devices),
            "posframework_sdr_samples_captured": self._stats["samples_captured"],
            "posframework_sdr_signals_detected": self._stats["signals_detected"],
        }
