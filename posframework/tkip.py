"""
posframework.tkip - Temporal Key Integrity Protocol (TKIP) implementation

Complete TKIP module implementing IEEE 802.11-2020 Section 12.5.2:
- Michael MIC algorithm (per-MSDU integrity check)
- TKIP key mixing (Phase 1 + Phase 2 for per-packet WEP key)
- TKIP Sequence Counter (TSC) / IV generation
- TKIP encapsulation and decapsulation
- MIC failure detection and countermeasures handling

TKIP uses:
  - Michael MIC for data integrity (weak but fast)
  - Per-packet key mixing to derive unique RC4 keys
  - Extended IV to avoid WEP's IV reuse weakness
  - TSC replay protection

Key hierarchy within PTK for TKIP:
  PTK[0:16]   = KCK (Key Confirmation Key) - EAPOL MIC
  PTK[16:32]  = KEK (Key Encryption Key) - EAPOL key data encryption
  PTK[32:48]  = TK (Temporal Key) - TKIP encryption
  PTK[48:56]  = TX MIC Key (AP -> STA or STA -> AP depending on role)
  PTK[56:64]  = RX MIC Key

Note: TKIP is deprecated (IEEE 802.11-2012) but still found in legacy
POS environments that haven't migrated to CCMP/WPA2-only configurations.

Integration:
  - handshake.py: Uses TKIPEngine for frame decryption when PTK derivation
    indicates TKIP cipher suite (key_length=32 in EAPOL).
  - krack.py: Uses TKIPEngine to demonstrate Michael MIC key recovery via
    KRACK nonce reuse on TKIP-protected frames.
  - tshark_decrypt.py: Uses TKIPEngine as fallback decryption when CCMP
    is not negotiated.
  - orchestrator.py: References TKIP cipher suite when identifying legacy
    targets vulnerable to MIC-based attacks.
  - recon.py: Identifies TKIP cipher from handshake key descriptor version
    (v1 = HMAC-MD5/RC4 = TKIP).
"""

import struct
import time
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, List

from posframework.config import log

# Try native acceleration
try:
    from posframework.native.tkip_mic import (
        michael_mic_compute, michael_mic_verify,
        phase1_key_mixing, phase2_key_mixing, build_iv,
    )
    _HAS_NATIVE = True
except ImportError:
    _HAS_NATIVE = False

# --- Constants ---

TKIP_TK_LEN = 16           # Temporal Key length
TKIP_MIC_KEY_LEN = 8       # Michael MIC key length
TKIP_MIC_LEN = 8           # Michael MIC output length
TKIP_IV_LEN = 8            # IV + Extended IV
TKIP_ICV_LEN = 4           # WEP ICV (CRC-32)
TKIP_RC4_KEY_LEN = 16      # Per-packet RC4 key

# MIC countermeasures timing (IEEE 802.11-2020 12.5.2.5)
MIC_FAILURE_TIMEOUT = 60.0  # seconds - window for 2 MIC failures
MIC_COUNTERMEASURES_PERIOD = 60.0  # seconds - deauth/block period


class TKIPRole(Enum):
    """Role in TKIP communication (affects MIC key selection)."""
    AUTHENTICATOR = "authenticator"  # AP side
    SUPPLICANT = "supplicant"        # Station side


class MICCountermeasureState(Enum):
    """State of MIC countermeasures FSM."""
    NORMAL = "normal"
    SINGLE_FAILURE = "single_failure"
    COUNTERMEASURES_ACTIVE = "countermeasures_active"


@dataclass
class TKIPKey:
    """Complete TKIP key material derived from PTK."""
    tk: bytes           # 16-byte Temporal Key (for encryption)
    tx_mic_key: bytes   # 8-byte TX Michael MIC key
    rx_mic_key: bytes   # 8-byte RX Michael MIC key

    @classmethod
    def from_ptk(cls, ptk: bytes, role: TKIPRole = TKIPRole.SUPPLICANT) -> "TKIPKey":
        """
        Extract TKIP keys from PTK.

        For TKIP, PTK is 512 bits (64 bytes):
          [0:16]  KCK
          [16:32] KEK
          [32:48] TK (Temporal Key)
          [48:56] AP TX MIC Key (= STA RX MIC Key)
          [56:64] STA TX MIC Key (= AP RX MIC Key)

        Args:
            ptk: 64-byte Pairwise Transient Key
            role: AUTHENTICATOR (AP) or SUPPLICANT (STA)

        Returns:
            TKIPKey with correctly assigned TX/RX MIC keys.
        """
        if len(ptk) < 64:
            raise ValueError("PTK must be at least 64 bytes for TKIP")

        tk = ptk[32:48]

        if role == TKIPRole.AUTHENTICATOR:
            # AP: TX key = bytes 48-56, RX key = bytes 56-64
            tx_mic_key = ptk[48:56]
            rx_mic_key = ptk[56:64]
        else:
            # STA: TX key = bytes 56-64, RX key = bytes 48-56
            tx_mic_key = ptk[56:64]
            rx_mic_key = ptk[48:56]

        return cls(tk=tk, tx_mic_key=tx_mic_key, rx_mic_key=rx_mic_key)


@dataclass
class MICCountermeasures:
    """
    TKIP MIC failure countermeasures state machine.

    Per IEEE 802.11-2020 12.5.2.5:
    - First MIC failure: log and start timer
    - Second MIC failure within 60s: invoke countermeasures
    - Countermeasures: deauth all STAs, disable TKIP for 60s
    """
    state: MICCountermeasureState = MICCountermeasureState.NORMAL
    first_failure_time: float = 0.0
    countermeasures_start: float = 0.0
    failure_count: int = 0
    total_failures: int = 0

    def report_mic_failure(self) -> bool:
        """
        Report a MIC failure event.

        Returns:
            True if countermeasures should be invoked.
        """
        now = time.time()
        self.total_failures += 1

        if self.state == MICCountermeasureState.COUNTERMEASURES_ACTIVE:
            # Already in countermeasures
            if now - self.countermeasures_start > MIC_COUNTERMEASURES_PERIOD:
                # Countermeasures period expired, restart
                self.state = MICCountermeasureState.SINGLE_FAILURE
                self.first_failure_time = now
                self.failure_count = 1
                return False
            return True

        if self.state == MICCountermeasureState.NORMAL:
            self.state = MICCountermeasureState.SINGLE_FAILURE
            self.first_failure_time = now
            self.failure_count = 1
            log.warning("TKIP: first MIC failure detected, starting timer")
            return False

        # SINGLE_FAILURE state - check if within timeout window
        if now - self.first_failure_time <= MIC_FAILURE_TIMEOUT:
            # Second failure within window -> countermeasures!
            self.state = MICCountermeasureState.COUNTERMEASURES_ACTIVE
            self.countermeasures_start = now
            self.failure_count += 1
            log.critical(
                "TKIP: second MIC failure within 60s! "
                "COUNTERMEASURES INVOKED - disabling TKIP associations"
            )
            return True
        else:
            # Outside window, reset
            self.first_failure_time = now
            self.failure_count = 1
            return False

    @property
    def is_blocked(self) -> bool:
        """Check if TKIP is currently blocked by countermeasures."""
        if self.state != MICCountermeasureState.COUNTERMEASURES_ACTIVE:
            return False
        now = time.time()
        if now - self.countermeasures_start > MIC_COUNTERMEASURES_PERIOD:
            self.state = MICCountermeasureState.NORMAL
            self.failure_count = 0
            return False
        return True


class TKIPEngine:
    """
    TKIP encryption/decryption engine.

    Manages per-session TKIP state including:
    - Key material (TK + MIC keys)
    - TSC (TX and RX sequence counters)
    - Phase 1 key cache
    - MIC countermeasures
    """

    def __init__(self, key: TKIPKey, ta: bytes, ra: bytes,
                 role: TKIPRole = TKIPRole.SUPPLICANT):
        """
        Initialize TKIP engine.

        Args:
            key: TKIP key material
            ta: 6-byte Transmitter Address (own MAC)
            ra: 6-byte Receiver Address (peer MAC)
            role: AUTHENTICATOR or SUPPLICANT
        """
        if len(ta) != 6 or len(ra) != 6:
            raise ValueError("MAC addresses must be 6 bytes")

        self.key = key
        self.ta = ta
        self.ra = ra
        self.role = role

        # Sequence counters
        self.tx_tsc: int = 0       # TX TKIP Sequence Counter (48-bit)
        self.rx_tsc: int = -1      # Last valid RX TSC (-1 = none received)

        # Phase 1 key cache (valid while upper 32 bits of TSC unchanged)
        self._p1k_cache: Optional[bytes] = None
        self._p1k_tsc_hi: int = -1

        # MIC countermeasures
        self.countermeasures = MICCountermeasures()

    def compute_mic(self, da: bytes, sa: bytes, data: bytes,
                    priority: int = 0) -> bytes:
        """
        Compute Michael MIC for transmission.

        Args:
            da: 6-byte destination address
            sa: 6-byte source address
            data: MSDU payload
            priority: QoS TID (0 for non-QoS)

        Returns:
            8-byte Michael MIC.
        """
        if _HAS_NATIVE:
            return michael_mic_compute(self.key.tx_mic_key, da, sa,
                                       priority, data)
        return self._py_michael_mic(self.key.tx_mic_key, da, sa, priority, data)

    def verify_mic(self, da: bytes, sa: bytes, data: bytes,
                   mic: bytes, priority: int = 0) -> bool:
        """
        Verify Michael MIC on received data.

        Also handles MIC failure countermeasures.

        Args:
            da: 6-byte destination address
            sa: 6-byte source address
            data: MSDU payload (without MIC)
            mic: 8-byte received MIC
            priority: QoS TID

        Returns:
            True if MIC is valid, False if failed.
        """
        if _HAS_NATIVE:
            valid = michael_mic_verify(self.key.rx_mic_key, da, sa,
                                       priority, data, mic)
        else:
            computed = self._py_michael_mic(self.key.rx_mic_key, da, sa,
                                           priority, data)
            valid = (computed == mic)

        if not valid:
            self.countermeasures.report_mic_failure()
            log.warning(f"TKIP MIC failure from {sa.hex()}")

        return valid

    def _get_phase1_key(self, tsc_hi: int) -> bytes:
        """Get Phase 1 key, using cache if TSC upper bits unchanged."""
        if self._p1k_cache is not None and self._p1k_tsc_hi == tsc_hi:
            return self._p1k_cache

        if _HAS_NATIVE:
            p1k = phase1_key_mixing(self.key.tk, self.ta, tsc_hi)
        else:
            p1k = self._py_phase1(self.key.tk, self.ta, tsc_hi)

        self._p1k_cache = p1k
        self._p1k_tsc_hi = tsc_hi
        return p1k

    def _get_rc4_key(self, tsc: int) -> bytes:
        """Derive per-packet RC4 key from TSC."""
        tsc_hi = (tsc >> 16) & 0xFFFFFFFF
        tsc_lo = tsc & 0xFFFF

        p1k = self._get_phase1_key(tsc_hi)

        if _HAS_NATIVE:
            return phase2_key_mixing(self.key.tk, p1k, tsc_lo)
        return self._py_phase2(self.key.tk, p1k, tsc_lo)

    def encapsulate(self, msdu: bytes, da: bytes, sa: bytes,
                    priority: int = 0, key_id: int = 0) -> bytes:
        """
        TKIP encapsulate an MSDU for transmission.

        Performs:
        1. Compute Michael MIC over MSDU
        2. Append MIC to MSDU
        3. Fragment if needed (not implemented here)
        4. Generate per-packet IV from TSC
        5. Derive RC4 key via key mixing
        6. RC4 encrypt (MSDU + MIC + ICV)

        Args:
            msdu: Plaintext MSDU payload
            da: Destination MAC address
            sa: Source MAC address
            priority: QoS TID
            key_id: Key ID (0-3)

        Returns:
            TKIP-encapsulated frame: IV(8) + encrypted(MSDU + MIC + ICV)
        """
        if self.countermeasures.is_blocked:
            raise RuntimeError("TKIP countermeasures active - cannot transmit")

        # Step 1: Compute Michael MIC
        mic = self.compute_mic(da, sa, msdu, priority)

        # Step 2: Build plaintext = MSDU + MIC
        plaintext = msdu + mic

        # Step 3: Compute ICV (CRC-32 over plaintext)
        icv = self._crc32(plaintext)
        plaintext_with_icv = plaintext + icv

        # Step 4: Build IV
        if _HAS_NATIVE:
            iv = build_iv(self.tx_tsc, key_id)
        else:
            iv = self._py_build_iv(self.tx_tsc, key_id)

        # Step 5: Derive RC4 key
        rc4_key = self._get_rc4_key(self.tx_tsc)

        # Step 6: RC4 encrypt
        encrypted = self._rc4_encrypt(rc4_key, plaintext_with_icv)

        # Increment TSC
        self.tx_tsc = (self.tx_tsc + 1) & 0xFFFFFFFFFFFF

        return iv + encrypted

    def decapsulate(self, frame: bytes, da: bytes, sa: bytes,
                    priority: int = 0) -> Optional[bytes]:
        """
        TKIP decapsulate a received encrypted frame.

        Performs:
        1. Extract IV and derive TSC
        2. Check TSC replay
        3. Derive RC4 key via key mixing
        4. RC4 decrypt
        5. Verify ICV (CRC-32)
        6. Verify Michael MIC

        Args:
            frame: Received frame: IV(8) + encrypted data
            da: Destination MAC address
            sa: Source MAC address
            priority: QoS TID

        Returns:
            Decrypted MSDU payload or None on failure.
        """
        if self.countermeasures.is_blocked:
            log.warning("TKIP: countermeasures active, dropping frame")
            return None

        if len(frame) < TKIP_IV_LEN + TKIP_MIC_LEN + TKIP_ICV_LEN + 1:
            log.warning("TKIP: frame too short for decapsulation")
            return None

        # Step 1: Extract IV and reconstruct TSC
        iv = frame[:TKIP_IV_LEN]
        encrypted = frame[TKIP_IV_LEN:]

        tsc = self._iv_to_tsc(iv)

        # Step 2: Replay check
        if self.rx_tsc >= 0 and tsc <= self.rx_tsc:
            log.warning(f"TKIP: replay detected (TSC {tsc} <= {self.rx_tsc})")
            return None

        # Step 3: Derive RC4 key (use sender's TA for phase1)
        tsc_hi = (tsc >> 16) & 0xFFFFFFFF
        tsc_lo = tsc & 0xFFFF

        # For decryption, use the peer's TA (which is our RA = sa)
        if _HAS_NATIVE:
            p1k = phase1_key_mixing(self.key.tk, sa, tsc_hi)
            rc4_key = phase2_key_mixing(self.key.tk, p1k, tsc_lo)
        else:
            p1k = self._py_phase1(self.key.tk, sa, tsc_hi)
            rc4_key = self._py_phase2(self.key.tk, p1k, tsc_lo)

        # Step 4: RC4 decrypt
        plaintext_with_icv = self._rc4_encrypt(rc4_key, encrypted)  # RC4 is symmetric

        # Step 5: Verify ICV
        if len(plaintext_with_icv) < TKIP_ICV_LEN:
            return None

        plaintext_with_mic = plaintext_with_icv[:-TKIP_ICV_LEN]
        received_icv = plaintext_with_icv[-TKIP_ICV_LEN:]
        computed_icv = self._crc32(plaintext_with_mic)

        if received_icv != computed_icv:
            log.warning("TKIP: ICV check failed")
            return None

        # Step 6: Verify Michael MIC
        if len(plaintext_with_mic) < TKIP_MIC_LEN:
            return None

        msdu = plaintext_with_mic[:-TKIP_MIC_LEN]
        received_mic = plaintext_with_mic[-TKIP_MIC_LEN:]

        if not self.verify_mic(da, sa, msdu, received_mic, priority):
            return None

        # Success - update RX TSC
        self.rx_tsc = tsc
        return msdu

    def get_tsc(self) -> int:
        """Get current TX TSC value."""
        return self.tx_tsc

    def set_tsc(self, tsc: int) -> None:
        """Set TX TSC (e.g., after rekeying)."""
        self.tx_tsc = tsc & 0xFFFFFFFFFFFF
        # Invalidate phase1 cache
        self._p1k_cache = None
        self._p1k_tsc_hi = -1

    # --- Internal helpers ---

    @staticmethod
    def _rc4_encrypt(key: bytes, data: bytes) -> bytes:
        """RC4 stream cipher (encrypt/decrypt are identical)."""
        # RC4 KSA (Key Scheduling Algorithm)
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]

        # RC4 PRGA (Pseudo-Random Generation Algorithm)
        out = bytearray(len(data))
        i = j = 0
        for k in range(len(data)):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[k] = data[k] ^ s[(s[i] + s[j]) & 0xFF]

        return bytes(out)

    @staticmethod
    def _crc32(data: bytes) -> bytes:
        """Compute CRC-32 (WEP ICV) as 4 little-endian bytes."""
        import zlib
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return struct.pack("<I", crc)

    @staticmethod
    def _iv_to_tsc(iv: bytes) -> int:
        """Reconstruct 48-bit TSC from IV/Extended IV field."""
        # IV layout:
        # iv[0] = TSC1, iv[1] = WEP seed, iv[2] = TSC0, iv[3] = KeyID|flags
        # iv[4] = TSC2, iv[5] = TSC3, iv[6] = TSC4, iv[7] = TSC5
        tsc0 = iv[2]
        tsc1 = iv[0]
        tsc2 = iv[4]
        tsc3 = iv[5]
        tsc4 = iv[6]
        tsc5 = iv[7]
        return (tsc0 | (tsc1 << 8) | (tsc2 << 16) |
                (tsc3 << 24) | (tsc4 << 32) | (tsc5 << 40))

    # --- Python fallback implementations ---

    @staticmethod
    def _py_michael_mic(key: bytes, da: bytes, sa: bytes,
                        priority: int, data: bytes) -> bytes:
        """Python fallback for Michael MIC."""
        def michael_block(l, r):
            mask = 0xFFFFFFFF
            l = (l ^ (((r << 17) | (r >> 15)) & mask)) & mask
            r = (r + l) & mask
            r_swapped = (((r & 0x00FF00FF) << 8) | ((r & 0xFF00FF00) >> 8)) & mask
            l = (l ^ r_swapped) & mask
            r = (r + l) & mask
            l = (l ^ (((r << 3) | (r >> 29)) & mask)) & mask
            r = (r + l) & mask
            l = (l ^ (((r >> 2) | (r << 30)) & mask)) & mask
            r = (r + l) & mask
            return l, r

        l = struct.unpack_from("<I", key, 0)[0]
        r = struct.unpack_from("<I", key, 4)[0]

        header = da + sa + bytes([priority, 0, 0, 0])
        for i in range(4):
            l ^= struct.unpack_from("<I", header, i * 4)[0]
            l, r = michael_block(l, r)

        # Data + padding
        msg = data + b'\x5a' + b'\x00' * ((-len(data) - 1) % 4 + 4)
        for i in range(0, len(msg), 4):
            l ^= struct.unpack_from("<I", msg, i)[0]
            l, r = michael_block(l, r)

        return struct.pack("<II", l, r)

    @staticmethod
    def _py_phase1(tk: bytes, ta: bytes, tsc_hi: int) -> bytes:
        """Python fallback for Phase 1 mixing."""
        if _HAS_NATIVE:
            return phase1_key_mixing(tk, ta, tsc_hi)
        # Import from native module's fallback
        from posframework.native.tkip_mic import _py_phase1
        return _py_phase1(tk, ta, tsc_hi)

    @staticmethod
    def _py_phase2(tk: bytes, p1k: bytes, tsc_lo: int) -> bytes:
        """Python fallback for Phase 2 mixing."""
        if _HAS_NATIVE:
            return phase2_key_mixing(tk, p1k, tsc_lo)
        from posframework.native.tkip_mic import _py_phase2
        return _py_phase2(tk, p1k, tsc_lo)

    @staticmethod
    def _py_build_iv(tsc: int, key_id: int) -> bytes:
        """Python fallback for IV construction."""
        if _HAS_NATIVE:
            return build_iv(tsc, key_id)
        from posframework.native.tkip_mic import _py_build_iv
        return _py_build_iv(tsc, key_id)
