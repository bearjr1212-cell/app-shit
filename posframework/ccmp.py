"""
posframework.ccmp - Counter mode with CBC-MAC Protocol (CCMP) implementation

Complete CCMP module implementing IEEE 802.11-2020 Section 12.5.3:
- AES-CCM encryption/decryption (128-bit key, M=8, L=2)
- Nonce construction from Packet Number, address, priority
- AAD (Additional Authentication Data) construction from 802.11 header
- CCMP encapsulation (encrypt + MIC generation)
- CCMP decapsulation (decrypt + MIC verification)
- Packet Number (PN) management and replay detection

CCMP uses AES in CCM mode (Counter with CBC-MAC):
  - Counter mode provides confidentiality
  - CBC-MAC provides authentication (8-byte MIC)
  - Nonce ensures unique keystream per packet

Key hierarchy within PTK for CCMP:
  PTK[0:16]   = KCK (Key Confirmation Key)
  PTK[16:32]  = KEK (Key Encryption Key)
  PTK[32:48]  = TK (Temporal Key) - used for AES-CCM

CCMP header (8 bytes) in encrypted frame:
  Byte 0: PN0
  Byte 1: PN1
  Byte 2: Reserved (0)
  Byte 3: Key ID (bits 6-7) | ExtIV flag (bit 5) | Reserved
  Byte 4: PN2
  Byte 5: PN3
  Byte 6: PN4
  Byte 7: PN5

Integration:
  - handshake.py: Uses CCMPEngine for frame decryption after PTK derivation
    from captured 4-way handshake.
  - krack.py: Uses ccmp_decapsulate() to decrypt frames after KRACK key
    reinstallation, demonstrating nonce reuse impact.
  - tshark_decrypt.py: Uses NativeDecryptionEngine backed by CCMPEngine for
    real-time decryption of captured WPA2 traffic.
  - orchestrator.py: References CCMP cipher suite when selecting attack
    parameters for WPA2-CCMP targets.
  - recon.py: Identifies CCMP cipher from handshake key descriptor version
    (v2 = HMAC-SHA1/AES = CCMP).
"""

import struct
import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

from posframework.config import log

# Try native acceleration
try:
    from posframework.native.ccmp_aes import (
        ccmp_encrypt, ccmp_decrypt, build_nonce, build_aad,
        aes128_encrypt_block,
    )
    _HAS_NATIVE = True
except ImportError:
    _HAS_NATIVE = False

# --- Constants ---

CCMP_TK_LEN = 16          # Temporal Key length (AES-128)
CCMP_MIC_LEN = 8          # Authentication tag length
CCMP_PN_LEN = 6           # Packet Number length (48-bit)
CCMP_NONCE_LEN = 13       # Nonce: priority(1) + addr2(6) + PN(6)
CCMP_HDR_LEN = 8          # CCMP header in encrypted frame
CCMP_AAD_MAX_LEN = 30     # Maximum AAD length


@dataclass
class CCMPKey:
    """CCMP key material derived from PTK."""
    tk: bytes              # 16-byte Temporal Key (AES-128)

    @classmethod
    def from_ptk(cls, ptk: bytes) -> "CCMPKey":
        """
        Extract CCMP Temporal Key from PTK.

        For CCMP, PTK is 384 bits (48 bytes):
          [0:16]  KCK
          [16:32] KEK
          [32:48] TK

        Args:
            ptk: Pairwise Transient Key (at least 48 bytes)

        Returns:
            CCMPKey with Temporal Key.
        """
        if len(ptk) < 48:
            raise ValueError("PTK must be at least 48 bytes for CCMP")
        return cls(tk=ptk[32:48])


class CCMPEngine:
    """
    CCMP encryption/decryption engine.

    Manages per-session CCMP state including:
    - Temporal Key
    - TX/RX Packet Numbers (PN)
    - Replay detection
    """

    def __init__(self, key: CCMPKey, own_addr: bytes, peer_addr: bytes):
        """
        Initialize CCMP engine.

        Args:
            key: CCMP key material (Temporal Key)
            own_addr: 6-byte own MAC address (transmitter for TX)
            peer_addr: 6-byte peer MAC address
        """
        if len(own_addr) != 6 or len(peer_addr) != 6:
            raise ValueError("MAC addresses must be 6 bytes")

        self.key = key
        self.own_addr = own_addr
        self.peer_addr = peer_addr

        # Packet Numbers (48-bit counters)
        self.tx_pn: int = 0       # Transmit PN (incremented per packet)
        self.rx_pn: int = -1      # Last valid RX PN (-1 = none received)

    def build_ccmp_nonce(self, priority: int, addr2: bytes, pn: int) -> bytes:
        """
        Construct CCMP nonce from frame parameters.

        Nonce = Priority(1) || A2(6) || PN(6)

        Args:
            priority: QoS TID (0 for non-QoS)
            addr2: 6-byte Address 2 (transmitter)
            pn: 48-bit Packet Number

        Returns:
            13-byte nonce.
        """
        pn_bytes = self._pn_to_bytes(pn)
        if _HAS_NATIVE:
            return build_nonce(priority, addr2, pn_bytes)
        return bytes([priority & 0xFF]) + addr2 + pn_bytes

    def build_ccmp_aad(self, mac_header: bytes) -> bytes:
        """
        Construct AAD from 802.11 MAC header.

        Masks mutable fields per IEEE 802.11-2020 12.5.3.3.3.

        Args:
            mac_header: 802.11 MAC header (24-30 bytes)

        Returns:
            AAD bytes.
        """
        if _HAS_NATIVE:
            return build_aad(mac_header)
        return self._py_build_aad(mac_header)

    def build_ccmp_header(self, pn: int, key_id: int = 0) -> bytes:
        """
        Construct 8-byte CCMP header for encrypted frame.

        Header format:
          [0] PN0
          [1] PN1
          [2] Reserved (0)
          [3] Key ID (bits 6-7) | ExtIV (bit 5) | Reserved
          [4] PN2
          [5] PN3
          [6] PN4
          [7] PN5

        Args:
            pn: 48-bit Packet Number
            key_id: Key ID (0-3)

        Returns:
            8-byte CCMP header.
        """
        pn0 = pn & 0xFF
        pn1 = (pn >> 8) & 0xFF
        pn2 = (pn >> 16) & 0xFF
        pn3 = (pn >> 24) & 0xFF
        pn4 = (pn >> 32) & 0xFF
        pn5 = (pn >> 40) & 0xFF

        hdr = bytearray(8)
        hdr[0] = pn0
        hdr[1] = pn1
        hdr[2] = 0x00              # Reserved
        hdr[3] = (key_id << 6) | 0x20  # Key ID + ExtIV flag
        hdr[4] = pn2
        hdr[5] = pn3
        hdr[6] = pn4
        hdr[7] = pn5

        return bytes(hdr)

    def parse_ccmp_header(self, hdr: bytes) -> Tuple[int, int]:
        """
        Parse CCMP header to extract PN and Key ID.

        Args:
            hdr: 8-byte CCMP header

        Returns:
            Tuple of (packet_number, key_id).
        """
        if len(hdr) < CCMP_HDR_LEN:
            raise ValueError("CCMP header must be 8 bytes")

        pn = (hdr[0] | (hdr[1] << 8) | (hdr[4] << 16) |
              (hdr[5] << 24) | (hdr[6] << 32) | (hdr[7] << 40))
        key_id = (hdr[3] >> 6) & 0x03

        return pn, key_id

    def encapsulate(self, mac_header: bytes, plaintext: bytes,
                    priority: int = 0, key_id: int = 0) -> bytes:
        """
        CCMP encapsulate: encrypt plaintext and generate MIC.

        Produces encrypted MPDU body:
          CCMP Header (8) + Encrypted Data + MIC (8)

        Args:
            mac_header: 802.11 MAC header (for AAD construction)
            plaintext: MSDU/payload to encrypt
            priority: QoS TID (0 for non-QoS)
            key_id: Key ID (0-3)

        Returns:
            CCMP-encapsulated data: ccmp_hdr(8) + ciphertext + mic(8)
        """
        # Build CCMP header from current TX PN
        ccmp_hdr = self.build_ccmp_header(self.tx_pn, key_id)

        # Build nonce
        nonce = self.build_ccmp_nonce(priority, self.own_addr, self.tx_pn)

        # Build AAD
        aad = self.build_ccmp_aad(mac_header)

        # Encrypt
        if _HAS_NATIVE:
            ciphertext, mic = ccmp_encrypt(self.key.tk, nonce, aad, plaintext)
        else:
            ciphertext, mic = self._py_ccmp_encrypt(self.key.tk, nonce,
                                                     aad, plaintext)

        # Increment TX PN
        self.tx_pn = (self.tx_pn + 1) & 0xFFFFFFFFFFFF

        return ccmp_hdr + ciphertext + mic

    def decapsulate(self, mac_header: bytes, encrypted_body: bytes,
                    priority: int = 0) -> Optional[bytes]:
        """
        CCMP decapsulate: decrypt and verify MIC.

        Args:
            mac_header: 802.11 MAC header (for AAD)
            encrypted_body: CCMP header(8) + ciphertext + MIC(8)
            priority: QoS TID

        Returns:
            Decrypted plaintext or None on failure (MIC mismatch or replay).
        """
        if len(encrypted_body) < CCMP_HDR_LEN + CCMP_MIC_LEN:
            log.warning("CCMP: encrypted body too short")
            return None

        # Parse CCMP header
        ccmp_hdr = encrypted_body[:CCMP_HDR_LEN]
        pn, key_id = self.parse_ccmp_header(ccmp_hdr)

        # Replay detection
        if self.rx_pn >= 0 and pn <= self.rx_pn:
            log.warning(f"CCMP: replay detected (PN {pn} <= {self.rx_pn})")
            return None

        # Extract ciphertext and MIC
        ciphertext = encrypted_body[CCMP_HDR_LEN:-CCMP_MIC_LEN]
        mic = encrypted_body[-CCMP_MIC_LEN:]

        # Build nonce using sender's address (A2 from header)
        sender_addr = mac_header[10:16]  # Address 2
        nonce = self.build_ccmp_nonce(priority, sender_addr, pn)

        # Build AAD
        aad = self.build_ccmp_aad(mac_header)

        # Decrypt and verify
        if _HAS_NATIVE:
            plaintext = ccmp_decrypt(self.key.tk, nonce, aad, ciphertext, mic)
        else:
            plaintext = self._py_ccmp_decrypt(self.key.tk, nonce, aad,
                                              ciphertext, mic)

        if plaintext is None:
            log.warning("CCMP: MIC verification failed")
            return None

        # Update RX PN on success
        self.rx_pn = pn
        return plaintext

    def get_pn(self) -> int:
        """Get current TX Packet Number."""
        return self.tx_pn

    def set_pn(self, pn: int) -> None:
        """Set TX Packet Number (e.g., after rekeying)."""
        self.tx_pn = pn & 0xFFFFFFFFFFFF

    # --- Internal helpers ---

    @staticmethod
    def _pn_to_bytes(pn: int) -> bytes:
        """Convert 48-bit PN to 6-byte big-endian representation."""
        return bytes([
            (pn >> 40) & 0xFF,
            (pn >> 32) & 0xFF,
            (pn >> 24) & 0xFF,
            (pn >> 16) & 0xFF,
            (pn >> 8) & 0xFF,
            pn & 0xFF,
        ])

    @staticmethod
    def _py_build_aad(mac_header: bytes) -> bytes:
        """Python fallback for AAD construction."""
        fc = mac_header[0] | (mac_header[1] << 8)
        is_qos = (len(mac_header) >= 26) and ((fc & 0x0080) != 0)

        fc0_masked = mac_header[0] & 0x8F
        fc1_masked = mac_header[1] & 0xC7

        aad = bytearray()
        aad.append(fc0_masked)
        aad.append(fc1_masked)
        aad.extend(mac_header[4:10])   # A1
        aad.extend(mac_header[10:16])  # A2
        aad.extend(mac_header[16:22])  # A3
        aad.append(mac_header[22] & 0x0F)  # SC fragment only
        aad.append(0x00)

        if is_qos and len(mac_header) >= 26:
            aad.append(mac_header[24] & 0x0F)  # TID
            aad.append(0x00)

        return bytes(aad)

    @staticmethod
    def _py_ccmp_encrypt(tk: bytes, nonce: bytes, aad: bytes,
                         plaintext: bytes) -> Tuple[bytes, bytes]:
        """Python fallback for CCMP encryption."""
        from posframework.native.ccmp_aes import _py_ccmp_encrypt
        return _py_ccmp_encrypt(tk, nonce, aad, plaintext)

    @staticmethod
    def _py_ccmp_decrypt(tk: bytes, nonce: bytes, aad: bytes,
                         ciphertext: bytes, mic: bytes) -> Optional[bytes]:
        """Python fallback for CCMP decryption."""
        from posframework.native.ccmp_aes import _py_ccmp_decrypt
        return _py_ccmp_decrypt(tk, nonce, aad, ciphertext, mic)


# --- Convenience functions ---

def ccmp_encapsulate(tk: bytes, mac_header: bytes, plaintext: bytes,
                     pn: int, own_addr: bytes, priority: int = 0) -> bytes:
    """
    One-shot CCMP encapsulation (stateless).

    Args:
        tk: 16-byte Temporal Key
        mac_header: 802.11 MAC header
        plaintext: Data to encrypt
        pn: Packet Number to use
        own_addr: Own MAC address (transmitter)
        priority: QoS TID

    Returns:
        CCMP header(8) + ciphertext + MIC(8)
    """
    key = CCMPKey(tk=tk)
    engine = CCMPEngine(key, own_addr, b'\x00' * 6)
    engine.tx_pn = pn
    return engine.encapsulate(mac_header, plaintext, priority)


def ccmp_decapsulate(tk: bytes, mac_header: bytes, encrypted_body: bytes,
                     priority: int = 0) -> Optional[bytes]:
    """
    One-shot CCMP decapsulation (stateless, no replay check).

    Args:
        tk: 16-byte Temporal Key
        mac_header: 802.11 MAC header
        encrypted_body: CCMP header + ciphertext + MIC
        priority: QoS TID

    Returns:
        Decrypted plaintext or None on MIC failure.
    """
    key = CCMPKey(tk=tk)
    engine = CCMPEngine(key, b'\x00' * 6, b'\x00' * 6)
    engine.rx_pn = -1  # Disable replay check
    return engine.decapsulate(mac_header, encrypted_body, priority)
