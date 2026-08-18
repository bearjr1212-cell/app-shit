"""
RF Spectrum Analyzer - Frequency scanning and signal peak detection.

Performs real FFT-based spectrum analysis using captured IQ samples.
Scans across frequency ranges and identifies active signals.

Features:
- FFT-based power spectral density calculation
- Configurable frequency sweep with dwell time
- Signal peak detection with configurable threshold
- Frequency monitoring over time
- numpy FFT for accurate spectral analysis (fallback to pure Python)

Requirements:
- SDRManager with an open device
- numpy (optional, for FFT): pip install numpy
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

UTC = timezone.utc
from typing import Any

logger = logging.getLogger(__name__)

# Optional numpy for FFT (falls back to basic power calculation)
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    np = None  # type: ignore[assignment]


@dataclass
class SignalPeak:
    """Detected signal peak in the spectrum."""
    freq_hz: int
    power_dbm: float
    bandwidth_hz: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def freq_mhz(self) -> float:
        return self.freq_hz / 1_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "freq_mhz": self.freq_mhz,
            "power_dbm": round(self.power_dbm, 2),
            "bandwidth_khz": self.bandwidth_hz / 1000,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class SpectrumData:
    """Complete spectrum scan result."""
    start_freq_hz: int
    end_freq_hz: int
    step_hz: int
    power_levels: list[float] = field(default_factory=list)
    peaks: list[SignalPeak] = field(default_factory=list)
    scan_time_seconds: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def freq_points(self) -> list[int]:
        """Get list of frequency points in the scan."""
        return list(range(self.start_freq_hz, self.end_freq_hz + 1, self.step_hz))

    @property
    def num_points(self) -> int:
        return len(self.power_levels)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_freq_mhz": self.start_freq_hz / 1_000_000,
            "end_freq_mhz": self.end_freq_hz / 1_000_000,
            "step_khz": self.step_hz / 1000,
            "num_points": self.num_points,
            "peaks_count": len(self.peaks),
            "scan_time_seconds": round(self.scan_time_seconds, 3),
            "peaks": [p.to_dict() for p in self.peaks],
        }


class SpectrumAnalyzer:
    """
    RF Spectrum Analyzer using SDR hardware.

    Performs FFT-based power spectral density analysis across frequency
    ranges to identify active signals and their characteristics.

    Usage:
        from posframework.sdr import SDRManager, SpectrumAnalyzer

        sdr = SDRManager()
        await sdr.start()
        await sdr.open_device(0)

        analyzer = SpectrumAnalyzer(sdr)
        result = await analyzer.scan(
            start_hz=430_000_000,
            end_hz=440_000_000,
            step_hz=100_000,
        )

        for peak in result.peaks:
            print(f"{peak.freq_mhz:.3f} MHz: {peak.power_dbm:.1f} dBm")
    """

    def __init__(self, sdr_manager: Any):
        self.sdr = sdr_manager
        self._stats = {
            "scans_completed": 0,
            "peaks_found": 0,
            "total_scan_time": 0.0,
        }

    async def scan(
        self,
        start_hz: int,
        end_hz: int,
        step_hz: int = 100_000,
        dwell_time: float = 0.05,
        fft_size: int = 1024,
        threshold_dbm: float = -60.0,
    ) -> SpectrumData:
        """
        Scan a frequency range and detect signal peaks.

        Args:
            start_hz: Start frequency in Hz
            end_hz: End frequency in Hz
            step_hz: Frequency step size in Hz
            dwell_time: Time at each frequency step (seconds)
            fft_size: FFT size for spectral analysis
            threshold_dbm: Minimum power level to register as a peak

        Returns:
            SpectrumData with power levels and detected peaks
        """
        start_time = datetime.now(UTC)
        power_levels: list[float] = []
        peaks: list[SignalPeak] = []

        freq = start_hz
        while freq <= end_hz:
            # Tune SDR to this frequency
            await self.sdr.set_frequency(freq)
            await asyncio.sleep(dwell_time)

            # Capture IQ samples
            samples = await self.sdr.capture_samples(num_samples=fft_size)

            # Calculate power at this frequency
            if samples:
                power = self._calculate_power_fft(samples)
            else:
                power = -100.0

            power_levels.append(power)

            # Detect peaks above threshold
            if power > threshold_dbm:
                peaks.append(SignalPeak(
                    freq_hz=freq,
                    power_dbm=power,
                ))

            freq += step_hz

        scan_time = (datetime.now(UTC) - start_time).total_seconds()

        result = SpectrumData(
            start_freq_hz=start_hz,
            end_freq_hz=end_hz,
            step_hz=step_hz,
            power_levels=power_levels,
            peaks=peaks,
            scan_time_seconds=scan_time,
        )

        self._stats["scans_completed"] += 1
        self._stats["peaks_found"] += len(peaks)
        self._stats["total_scan_time"] += scan_time

        return result

    async def find_strongest(
        self,
        start_hz: int,
        end_hz: int,
        step_hz: int = 50_000,
    ) -> SignalPeak | None:
        """Find the strongest signal in a frequency range."""
        result = await self.scan(start_hz, end_hz, step_hz, threshold_dbm=-100.0)
        if not result.peaks:
            return None
        return max(result.peaks, key=lambda p: p.power_dbm)

    async def monitor_frequency(
        self,
        freq_hz: int,
        duration_seconds: float = 10.0,
        sample_interval: float = 0.1,
        fft_size: int = 1024,
    ) -> list[float]:
        """
        Monitor a single frequency over time.

        Returns list of power readings (dBm) at the sample interval.
        """
        power_readings: list[float] = []

        await self.sdr.set_frequency(freq_hz)

        elapsed = 0.0
        while elapsed < duration_seconds:
            samples = await self.sdr.capture_samples(num_samples=fft_size)
            power = self._calculate_power_fft(samples) if samples else -100.0
            power_readings.append(power)
            await asyncio.sleep(sample_interval)
            elapsed += sample_interval

        return power_readings

    async def get_peak_frequencies(
        self,
        start_hz: int,
        end_hz: int,
        step_hz: int = 50_000,
        top_n: int = 10,
    ) -> list[SignalPeak]:
        """
        Get the N strongest signals in a frequency range.

        Returns peaks sorted by power (strongest first).
        """
        result = await self.scan(start_hz, end_hz, step_hz, threshold_dbm=-100.0)
        sorted_peaks = sorted(result.peaks, key=lambda p: p.power_dbm, reverse=True)
        return sorted_peaks[:top_n]

    def _calculate_power_fft(self, samples: list[complex]) -> float:
        """
        Calculate signal power using FFT-based power spectral density.

        Uses numpy FFT if available for accuracy, otherwise falls back
        to simple RMS power calculation.
        """
        if not samples:
            return -100.0

        if _HAS_NUMPY:
            # Real FFT-based PSD calculation
            arr = np.array(samples, dtype=np.complex128)

            # Apply Hanning window to reduce spectral leakage
            window = np.hanning(len(arr))
            windowed = arr * window

            # Compute FFT and power spectral density
            fft_result = np.fft.fft(windowed)
            psd = np.abs(fft_result) ** 2 / len(arr)

            # Mean power across all bins
            mean_power = np.mean(psd)

            if mean_power > 0:
                return float(10.0 * np.log10(mean_power + 1e-12))
            return -100.0

        else:
            # Fallback: simple RMS power (no FFT)
            sum_sq = sum(abs(s) ** 2 for s in samples)
            rms = math.sqrt(sum_sq / len(samples))
            if rms > 0:
                return 10.0 * math.log10(rms * 1000)
            return -100.0

    def get_stats(self) -> dict[str, Any]:
        """Get analyzer statistics."""
        return self._stats.copy()

    def get_metrics(self) -> dict[str, Any]:
        """Prometheus-compatible metrics."""
        return {
            "posframework_spectrum_scans": self._stats["scans_completed"],
            "posframework_spectrum_peaks": self._stats["peaks_found"],
            "posframework_spectrum_scan_time": self._stats["total_scan_time"],
        }
