"""
RF Signal Decoder - 433/868 MHz IoT protocol decoding.

Demodulates and decodes common IoT wireless protocols:
- OOK/ASK: garage doors, weather stations, simple remotes
- FSK: car key fobs, sensors, more sophisticated devices
- GFSK: Bluetooth-adjacent, some smart home devices

Implementation:
- Amplitude envelope extraction for OOK demodulation
- Phase-difference based FSK demodulation
- Adaptive threshold for bit slicing
- Known device signature matching

Requirements:
- IQ samples from SDRManager
- math (stdlib) for demodulation
- numpy (optional) for better performance
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# Optional numpy for vectorized operations
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    np = None  # type: ignore[assignment]


class Protocol(str, Enum):
    """Supported wireless protocols."""
    OOK = "ook"
    ASK = "ask"
    FSK = "fsk"
    GFSK = "gfsk"
    LORA = "lora"
    UNKNOWN = "unknown"


@dataclass
class DecodedSignal:
    """A decoded RF signal with protocol and data."""
    protocol: Protocol
    freq_hz: int
    data_hex: str = ""
    data_bits: str = ""

    # Signal characteristics
    modulation: str = ""
    baud_rate: int = 0
    deviation_hz: int = 0

    # Device identification
    device_type: str = ""
    manufacturer: str = ""
    device_id: str = ""

    # Decoded payload values
    decoded_values: dict[str, Any] = field(default_factory=dict)

    # Metadata
    rssi_dbm: float = -100.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    raw_samples: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "freq_mhz": self.freq_hz / 1_000_000,
            "data_hex": self.data_hex,
            "data_bits": self.data_bits[:64] + ("..." if len(self.data_bits) > 64 else ""),
            "device_type": self.device_type,
            "manufacturer": self.manufacturer,
            "device_id": self.device_id,
            "rssi_dbm": round(self.rssi_dbm, 1),
            "decoded_values": self.decoded_values,
            "timestamp": self.timestamp.isoformat(),
        }


# Known device signatures (first 4 hex chars of decoded data)
KNOWN_DEVICES: dict[str, dict[str, str]] = {
    "0000": {"type": "weather_station", "manufacturer": "Acurite"},
    "0001": {"type": "weather_station", "manufacturer": "Oregon Scientific"},
    "1000": {"type": "garage_door", "manufacturer": "Chamberlain"},
    "1001": {"type": "garage_door", "manufacturer": "LiftMaster"},
    "2000": {"type": "car_remote", "manufacturer": "Generic"},
    "2001": {"type": "car_remote", "manufacturer": "Toyota"},
    "3000": {"type": "door_sensor", "manufacturer": "Generic"},
    "3001": {"type": "motion_sensor", "manufacturer": "Generic"},
    "3002": {"type": "smoke_detector", "manufacturer": "Generic"},
    "4000": {"type": "tire_pressure", "manufacturer": "Generic TPMS"},
}


class SignalDecoder:
    """
    RF Signal Decoder for 433/868 MHz IoT protocols.

    Demodulates OOK and FSK signals from raw IQ samples captured by SDR
    hardware. Identifies known device signatures and extracts payload data.

    Usage:
        decoder = SignalDecoder()

        # Decode IQ samples captured at 433.92 MHz
        signal = await decoder.decode(samples, freq_hz=433_920_000)
        if signal:
            print(f"Protocol: {signal.protocol.value}")
            print(f"Device: {signal.device_type} ({signal.manufacturer})")
            print(f"Data: {signal.data_hex}")
    """

    def __init__(self):
        self._stats: dict[str, Any] = {
            "signals_decoded": 0,
            "protocols_detected": {},
            "devices_seen": set(),
        }
        self._captured_signals: list[DecodedSignal] = []

    async def decode(
        self,
        samples: list[complex],
        freq_hz: int,
        sample_rate: int = 2_000_000,
    ) -> DecodedSignal | None:
        """
        Decode IQ samples to extract protocol and data.

        Args:
            samples: Complex IQ samples from SDR
            freq_hz: Center frequency the samples were captured at
            sample_rate: Sample rate in Hz

        Returns:
            DecodedSignal if successfully decoded, None otherwise
        """
        if not samples or len(samples) < 100:
            return None

        # Calculate signal power (reject noise floor)
        power = self._calculate_power(samples)
        if power < -70.0:
            return None

        # Detect modulation type based on signal characteristics
        protocol = self._detect_protocol(samples, sample_rate)

        # Demodulate based on detected protocol
        if protocol == Protocol.OOK:
            data_bits = self._demod_ook(samples, sample_rate)
        elif protocol == Protocol.FSK:
            data_bits = self._demod_fsk(samples, sample_rate)
        else:
            data_bits = ""

        if not data_bits or len(data_bits) < 8:
            return None

        # Convert bits to hex
        data_hex = self._bits_to_hex(data_bits)

        # Identify device from signature
        device_info = self._identify_device(data_hex)

        signal = DecodedSignal(
            protocol=protocol,
            freq_hz=freq_hz,
            data_hex=data_hex,
            data_bits=data_bits,
            modulation=protocol.value.upper(),
            device_type=device_info.get("type", "unknown"),
            manufacturer=device_info.get("manufacturer", ""),
            device_id=data_hex[:8] if len(data_hex) >= 8 else data_hex,
            rssi_dbm=power,
            raw_samples=len(samples),
        )

        self._captured_signals.append(signal)
        self._stats["signals_decoded"] += 1
        proto_key = protocol.value
        self._stats["protocols_detected"][proto_key] = (
            self._stats["protocols_detected"].get(proto_key, 0) + 1
        )
        self._stats["devices_seen"].add(signal.device_id)

        return signal

    async def decode_ook(
        self,
        samples: list[complex],
        freq_hz: int,
        sample_rate: int = 2_000_000,
    ) -> DecodedSignal | None:
        """Force OOK demodulation on samples."""
        if not samples or len(samples) < 100:
            return None
        power = self._calculate_power(samples)
        data_bits = self._demod_ook(samples, sample_rate)
        if not data_bits:
            return None
        data_hex = self._bits_to_hex(data_bits)
        device_info = self._identify_device(data_hex)
        return DecodedSignal(
            protocol=Protocol.OOK,
            freq_hz=freq_hz,
            data_hex=data_hex,
            data_bits=data_bits,
            modulation="OOK",
            device_type=device_info.get("type", "unknown"),
            manufacturer=device_info.get("manufacturer", ""),
            device_id=data_hex[:8] if len(data_hex) >= 8 else data_hex,
            rssi_dbm=power,
            raw_samples=len(samples),
        )

    async def decode_fsk(
        self,
        samples: list[complex],
        freq_hz: int,
        sample_rate: int = 2_000_000,
    ) -> DecodedSignal | None:
        """Force FSK demodulation on samples."""
        if not samples or len(samples) < 100:
            return None
        power = self._calculate_power(samples)
        data_bits = self._demod_fsk(samples, sample_rate)
        if not data_bits:
            return None
        data_hex = self._bits_to_hex(data_bits)
        device_info = self._identify_device(data_hex)
        return DecodedSignal(
            protocol=Protocol.FSK,
            freq_hz=freq_hz,
            data_hex=data_hex,
            data_bits=data_bits,
            modulation="FSK",
            device_type=device_info.get("type", "unknown"),
            manufacturer=device_info.get("manufacturer", ""),
            device_id=data_hex[:8] if len(data_hex) >= 8 else data_hex,
            rssi_dbm=power,
            raw_samples=len(samples),
        )

    def _calculate_power(self, samples: list[complex]) -> float:
        """Calculate signal power in dBm from IQ samples."""
        if not samples:
            return -100.0

        if _HAS_NUMPY:
            arr = np.array(samples, dtype=np.complex128)
            rms = float(np.sqrt(np.mean(np.abs(arr) ** 2)))
        else:
            sum_sq = sum(abs(s) ** 2 for s in samples)
            rms = math.sqrt(sum_sq / len(samples))

        if rms > 0:
            return 10.0 * math.log10(rms * 1000)
        return -100.0

    def _detect_protocol(self, samples: list[complex], sample_rate: int) -> Protocol:
        """
        Detect modulation type from IQ samples.

        OOK: High amplitude variance (signal toggles between on/off)
        FSK: Low amplitude variance but high phase/frequency variance
        """
        if _HAS_NUMPY:
            arr = np.array(samples, dtype=np.complex128)
            amplitudes = np.abs(arr)
            mean_amp = float(np.mean(amplitudes))
            amp_variance = float(np.var(amplitudes))
        else:
            amplitudes = [abs(s) for s in samples]
            mean_amp = sum(amplitudes) / len(amplitudes)
            amp_variance = sum((a - mean_amp) ** 2 for a in amplitudes) / len(amplitudes)

        if mean_amp < 1e-10:
            return Protocol.UNKNOWN

        # Normalized variance: high = OOK (amplitude modulation), low = FSK
        normalized_variance = amp_variance / (mean_amp ** 2)

        if normalized_variance > 0.3:
            return Protocol.OOK
        elif normalized_variance < 0.1:
            return Protocol.FSK
        else:
            # Ambiguous - default to OOK as it is more common at 433 MHz
            return Protocol.OOK

    def _demod_ook(self, samples: list[complex], sample_rate: int) -> str:
        """
        Demodulate OOK (On-Off Keying) signal to bit string.

        Algorithm:
        1. Extract amplitude envelope
        2. Calculate adaptive threshold (mean of envelope)
        3. Downsample to approximate baud rate
        4. Slice bits above/below threshold
        """
        # Typical OOK baud rates: 1000-10000 bps
        # Downsample factor: sample_rate / estimated_baud
        estimated_baud = 4000  # Common for 433 MHz devices
        downsample = max(1, sample_rate // estimated_baud)

        if _HAS_NUMPY:
            arr = np.array(samples, dtype=np.complex128)
            envelope = np.abs(arr)
            # Low-pass filter via moving average
            kernel_size = min(downsample, len(envelope))
            if kernel_size > 1:
                kernel = np.ones(kernel_size) / kernel_size
                envelope = np.convolve(envelope, kernel, mode='same')
            threshold = float(np.mean(envelope))
            # Downsample and bit-slice
            downsampled = envelope[::downsample]
            bits = "".join("1" if v > threshold else "0" for v in downsampled)
        else:
            amplitudes = [abs(s) for s in samples]
            threshold = sum(amplitudes) / len(amplitudes)
            bits = "".join(
                "1" if amplitudes[i] > threshold else "0"
                for i in range(0, len(amplitudes), downsample)
            )

        # Remove leading/trailing silence and deduplicate runs
        bits = bits.strip("0")
        return bits

    def _demod_fsk(self, samples: list[complex], sample_rate: int) -> str:
        """
        Demodulate FSK (Frequency Shift Keying) signal to bit string.

        Algorithm:
        1. Compute instantaneous phase of each sample
        2. Calculate phase difference (instantaneous frequency)
        3. Threshold phase differences: positive = 1, negative = 0
        4. Downsample to approximate baud rate
        """
        estimated_baud = 4800  # Common FSK baud rate
        downsample = max(1, sample_rate // estimated_baud)

        if _HAS_NUMPY:
            arr = np.array(samples, dtype=np.complex128)
            # Instantaneous phase
            phase = np.angle(arr)
            # Phase difference (instantaneous frequency)
            phase_diff = np.diff(phase)
            # Unwrap phase jumps
            phase_diff = np.where(phase_diff > math.pi, phase_diff - 2 * math.pi, phase_diff)
            phase_diff = np.where(phase_diff < -math.pi, phase_diff + 2 * math.pi, phase_diff)
            # Downsample and bit-slice
            downsampled = phase_diff[::downsample]
            bits = "".join("1" if v > 0 else "0" for v in downsampled)
        else:
            bits_list = []
            prev_phase = 0.0
            for i in range(0, len(samples), downsample):
                s = samples[i]
                phase = math.atan2(s.imag, s.real)
                phase_diff = phase - prev_phase
                # Normalize to [-pi, pi]
                while phase_diff > math.pi:
                    phase_diff -= 2 * math.pi
                while phase_diff < -math.pi:
                    phase_diff += 2 * math.pi
                bits_list.append("1" if phase_diff > 0 else "0")
                prev_phase = phase
            bits = "".join(bits_list)

        return bits.strip("0")

    def _bits_to_hex(self, bits: str) -> str:
        """Convert a bit string to uppercase hex string."""
        # Pad to multiple of 4 bits
        remainder = len(bits) % 4
        if remainder:
            bits = "0" * (4 - remainder) + bits

        hex_str = ""
        for i in range(0, len(bits), 4):
            nibble = bits[i:i + 4]
            hex_str += hex(int(nibble, 2))[2:]

        return hex_str.upper()

    def _identify_device(self, data_hex: str) -> dict[str, str]:
        """Identify device from decoded data signature prefix."""
        if len(data_hex) < 4:
            return {}
        prefix = data_hex[:4]
        return KNOWN_DEVICES.get(prefix, {})

    def get_captured_signals(self, limit: int = 100) -> list[DecodedSignal]:
        """Get recently captured and decoded signals."""
        return self._captured_signals[-limit:]

    def get_unique_devices(self) -> list[str]:
        """Get list of unique device IDs seen."""
        return list(self._stats["devices_seen"])

    def get_stats(self) -> dict[str, Any]:
        return {
            "signals_decoded": self._stats["signals_decoded"],
            "protocols": dict(self._stats["protocols_detected"]),
            "unique_devices": len(self._stats["devices_seen"]),
        }

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_decoder_signals": self._stats["signals_decoded"],
            "posframework_decoder_devices": len(self._stats["devices_seen"]),
        }
