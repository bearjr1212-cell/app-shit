"""
SDR (Software-Defined Radio) Module
------------------------------------

Real-world SDR device management, spectrum analysis, and signal decoding
for RTL-SDR, RTL-SDR Blog V4, and HackRF devices.

Capabilities:
- Device discovery and initialization (RTL-SDR, HackRF)
- Frequency tuning, gain control, sample rate configuration
- RTL-SDR V4: HF direct sampling, bias tee support
- FFT-based spectrum analysis with peak detection
- OOK/FSK signal decoding for 433/868 MHz IoT devices
- IQ sample capture and streaming

Requirements:
- pyrtlsdr: pip install pyrtlsdr
- numpy (optional, for FFT): pip install numpy
- RTL-SDR hardware with USB connection
"""

from __future__ import annotations

from .sdr_manager import SDRManager, SDRDevice, SDRConfig, SDRType
from .spectrum_analyzer import SpectrumAnalyzer, SpectrumData, SignalPeak
from .signal_decoder import SignalDecoder, DecodedSignal, Protocol

__all__ = [
    "SDRManager",
    "SDRDevice",
    "SDRConfig",
    "SDRType",
    "SpectrumAnalyzer",
    "SpectrumData",
    "SignalPeak",
    "SignalDecoder",
    "DecodedSignal",
    "Protocol",
]
