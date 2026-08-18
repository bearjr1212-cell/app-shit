"""
posframework.wpa2 - WPA2 (IEEE 802.11i) protocol state machine

Complete WPA2 implementation including:
- 4-way handshake (supplicant and authenticator sides)
- PMK derivation (PBKDF2-SHA1 from passphrase + SSID)
- PTK derivation (PRF-384 for CCMP, PRF-512 for TKIP)
- GTK derivation and installation
- Key hierarchy (PMK -> PTK -> KCK/KEK/TK)
- EAPOL-Key frame construction and parsing
- Replay counter management
- Key installation and rekeying

The WPA2 key hierarchy:
  PSK/802.1X -> PMK (256 bits)
  PMK + Nonces + MACs -> PTK
  PTK components:
    KCK (128 bits) - Key Confirmation Key (EAPOL MIC)
    KEK (128 bits) - Key Encryption Key (EAPOL key data encryption)
    TK  (128/256 bits) - Temporal Key (data encryption)
    [TKIP only: TX/RX MIC keys (64 bits each)]

4-Way Handshake:
  Msg 1: AP -> STA: ANonce
  Msg 2: STA -> AP: SNonce + MIC
  Msg 3: AP -> STA: GTK (encrypted) + MIC
  Msg 4: STA -> AP: ACK + MIC

Group Key Handshake:
  Msg 1: AP -> STA: New GTK (encrypted) + MIC
  Msg 2: STA -> AP: ACK + MIC
"""

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum, Enum
from typing import Optional, Tuple, Dict, Callable, List

from posframework.config import log

# Try native crypto acceleration
try:
    from posframework.native.crypto_accel import (
        pbkdf2_derive_pmk, derive_ptk, verify_mic, generate_nonce,
    )
    _HAS_NATIVE_CRYPTO = True
except ImportError:
    _HAS_NATIVE_CRYPTO = False

# --- Constants ---

PMK_LEN = 32             # 256-bit Pairwise Master Key
KCK_LEN = 16             # Key Confirmation Key
KEK_LEN = 16             # Key Encryption Key
TK_CCMP_LEN = 16         # Temporal Key for CCMP (128 bits)
TK_TKIP_LEN = 16         # Temporal Key for TKIP (128 bits)
PTK_CCMP_LEN = 48        # PTK for CCMP: KCK(16) + KEK(16) + TK(16)
PTK_TKIP_LEN = 64        # PTK for TKIP: KCK(16) + KEK(16) + TK(16) + MICKeys(16)
NONCE_LEN = 32           # Nonce length
MIC_LEN = 16             # EAPOL MIC length
GTK_LEN = 16             # Group Temporal Key (CCMP)
GTK_TKIP_LEN = 32        # Group Temporal Key (TKIP)
REPLAY_COUNTER_LEN = 8   # 64-bit replay counter

# EAPOL constants
EAPOL_VERSION = 2        # 802.1X-2004
EAPOL_KEY_TYPE = 3       # EAPOL-Key
EAPOL_KEY_DESC_WPA2 = 2  # RSN Key Descriptor

# Key Information field bits
KEY_INFO_TYPE_HMAC_MD5 = 1
KEY_INFO_TYPE_HMAC_SHA1 = 2
KEY_INFO_TYPE_AES_CMAC = 3
KEY_INFO_PAIRWISE = 0x0008
KEY_INFO_INSTALL = 0x0040
KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200
KEY_INFO_ERROR = 0x0400
KEY_INFO_REQUEST = 0x0800
KEY_INFO_ENCRYPTED_DATA = 0x1000
KEY_INFO_SMK = 0x2000

# PBKDF2 iterations for WPA
WPA_PBKDF2_ITERATIONS = 4096


class CipherSuite(Enum):
    """Cipher suite for pairwise/group encryption."""
    CCMP = "ccmp"           # AES-CCM (WPA2 default)
    TKIP = "tkip"           # TKIP (legacy WPA)
    GCMP = "gcmp"           # AES-GCM (WPA3)
    CCMP_256 = "ccmp-256"   # AES-CCM-256 (WPA3)


class HandshakeState(Enum):
    """4-way handshake state machine states."""
    IDLE = "idle"
    AWAITING_MSG1 = "awaiting_msg1"      # STA waiting for Msg 1
    AWAITING_MSG2 = "awaiting_msg2"      # AP waiting for Msg 2
    AWAITING_MSG3 = "awaiting_msg3"      # STA waiting for Msg 3
    AWAITING_MSG4 = "awaiting_msg4"      # AP waiting for Msg 4
    COMPLETED = "completed"
    FAILED = "failed"


class HandshakeRole(Enum):
    """Role in the 4-way handshake."""
    AUTHENTICATOR = "authenticator"  # AP
    SUPPLICANT = "supplicant"        # Station


@dataclass
class EAPOLKeyFrame:
    """
    Parsed EAPOL-Key frame.

    EAPOL-Key frame format:
      [0]      Protocol Version (1)
      [1]      Packet Type (3 = EAPOL-Key)
      [2:4]    Body Length (big-endian)
      [4]      Descriptor Type (2 = RSN)
      [5:7]    Key Information (big-endian)
      [7:9]    Key Length (big-endian)
      [9:17]   Replay Counter (big-endian, 8 bytes)
      [17:49]  Key Nonce (32 bytes)
      [49:65]  Key IV (16 bytes)
      [65:73]  Key RSC (8 bytes)
      [73:81]  Key ID (8 bytes, reserved)
      [81:97]  Key MIC (16 bytes)
      [97:99]  Key Data Length (big-endian)
      [99:]    Key Data (variable)
    """
    version: int = EAPOL_VERSION
    packet_type: int = EAPOL_KEY_TYPE
    descriptor_type: int = EAPOL_KEY_DESC_WPA2
    key_info: int = 0
    key_length: int = 0
    replay_counter: int = 0
    nonce: bytes = field(default_factory=lambda: b'\x00' * NONCE_LEN)
    key_iv: bytes = field(default_factory=lambda: b'\x00' * 16)
    key_rsc: bytes = field(default_factory=lambda: b'\x00' * 8)
    key_id: bytes = field(default_factory=lambda: b'\x00' * 8)
    mic: bytes = field(default_factory=lambda: b'\x00' * MIC_LEN)
    key_data: bytes = field(default_factory=bytes)

    @property
    def key_descriptor_version(self) -> int:
        """Key descriptor version (bits 0-2 of key_info)."""
        return self.key_info & 0x07

    @property
    def is_pairwise(self) -> bool:
        return bool(self.key_info & KEY_INFO_PAIRWISE)

    @property
    def has_install(self) -> bool:
        return bool(self.key_info & KEY_INFO_INSTALL)

    @property
    def has_ack(self) -> bool:
        return bool(self.key_info & KEY_INFO_ACK)

    @property
    def has_mic(self) -> bool:
        return bool(self.key_info & KEY_INFO_MIC)

    @property
    def has_secure(self) -> bool:
        return bool(self.key_info & KEY_INFO_SECURE)

    @property
    def has_encrypted_data(self) -> bool:
        return bool(self.key_info & KEY_INFO_ENCRYPTED_DATA)

    def serialize(self) -> bytes:
        """Serialize EAPOL-Key frame to bytes."""
        body_len = 95 + len(self.key_data)  # 95 = key frame fields after length

        frame = bytearray()
        frame.append(self.version)
        frame.append(self.packet_type)
        frame.extend(struct.pack(">H", body_len))
        frame.append(self.descriptor_type)
        frame.extend(struct.pack(">H", self.key_info))
        frame.extend(struct.pack(">H", self.key_length))
        frame.extend(struct.pack(">Q", self.replay_counter))
        frame.extend(self.nonce[:NONCE_LEN].ljust(NONCE_LEN, b'\x00'))
        frame.extend(self.key_iv[:16].ljust(16, b'\x00'))
        frame.extend(self.key_rsc[:8].ljust(8, b'\x00'))
        frame.extend(self.key_id[:8].ljust(8, b'\x00'))
        frame.extend(self.mic[:MIC_LEN].ljust(MIC_LEN, b'\x00'))
        frame.extend(struct.pack(">H", len(self.key_data)))
        frame.extend(self.key_data)

        return bytes(frame)

    @classmethod
    def parse(cls, data: bytes) -> Optional["EAPOLKeyFrame"]:
        """
        Parse raw bytes into an EAPOLKeyFrame.

        Args:
            data: Raw EAPOL frame bytes (minimum 99 bytes)

        Returns:
            Parsed frame or None if invalid.
        """
        if len(data) < 99:
            return None

        frame = cls()
        frame.version = data[0]
        frame.packet_type = data[1]

        if frame.packet_type != EAPOL_KEY_TYPE:
            return None

        body_len = struct.unpack(">H", data[2:4])[0]
        frame.descriptor_type = data[4]
        frame.key_info = struct.unpack(">H", data[5:7])[0]
        frame.key_length = struct.unpack(">H", data[7:9])[0]
        frame.replay_counter = struct.unpack(">Q", data[9:17])[0]
        frame.nonce = data[17:49]
        frame.key_iv = data[49:65]
        frame.key_rsc = data[65:73]
        frame.key_id = data[73:81]
        frame.mic = data[81:97]

        key_data_len = struct.unpack(">H", data[97:99])[0]
        if len(data) >= 99 + key_data_len:
            frame.key_data = data[99:99 + key_data_len]
        else:
            frame.key_data = data[99:]

        return frame

    def get_mic_data(self) -> bytes:
        """Get frame bytes with MIC field zeroed (for MIC computation)."""
        frame = bytearray(self.serialize())
        # Zero out MIC field (bytes 81-97)
        frame[81:97] = b'\x00' * MIC_LEN
        return bytes(frame)


@dataclass
class DerivedKeys:
    """Complete derived key material from WPA2 handshake."""
    pmk: bytes = field(default_factory=lambda: b'\x00' * PMK_LEN)
    ptk: bytes = field(default_factory=bytes)
    kck: bytes = field(default_factory=lambda: b'\x00' * KCK_LEN)
    kek: bytes = field(default_factory=lambda: b'\x00' * KEK_LEN)
    tk: bytes = field(default_factory=bytes)
    gtk: bytes = field(default_factory=bytes)
    # TKIP-specific
    tx_mic_key: bytes = field(default_factory=bytes)
    rx_mic_key: bytes = field(default_factory=bytes)

    @property
    def is_valid(self) -> bool:
        return len(self.tk) > 0 and len(self.kck) == KCK_LEN


# --- Key Derivation Functions ---

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """
    Derive PMK from passphrase and SSID.

    PMK = PBKDF2-SHA1(passphrase, SSID, 4096, 256)

    Args:
        passphrase: WiFi password (8-63 chars for WPA-PSK)
        ssid: Network SSID

    Returns:
        32-byte PMK.
    """
    if _HAS_NATIVE_CRYPTO:
        return pbkdf2_derive_pmk(passphrase, ssid)

    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"),
                               WPA_PBKDF2_ITERATIONS, dklen=PMK_LEN)


def prf(key: bytes, label: bytes, data: bytes, length: int) -> bytes:
    """
    PRF (Pseudo-Random Function) as defined in IEEE 802.11-2020.

    PRF-X(K, A, B) = HMAC-SHA1(K, A || 0x00 || B || i) for i = 0,1,...

    Args:
        key: HMAC key (PMK)
        label: ASCII label string
        data: Concatenated MAC addresses and nonces
        length: Desired output length in bytes

    Returns:
        PRF output of specified length.
    """
    result = b""
    counter = 0
    while len(result) < length:
        msg = label + b'\x00' + data + bytes([counter])
        result += hmac.new(key, msg, hashlib.sha1).digest()
        counter += 1
    return result[:length]


def derive_ptk(pmk: bytes, ap_mac: bytes, sta_mac: bytes,
               anonce: bytes, snonce: bytes,
               cipher: CipherSuite = CipherSuite.CCMP) -> bytes:
    """
    Derive PTK from PMK and handshake parameters.

    PTK = PRF-X(PMK, "Pairwise key expansion",
                min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce))

    where X = 384 for CCMP, 512 for TKIP.

    Args:
        pmk: 32-byte Pairwise Master Key
        ap_mac: 6-byte AP MAC address
        sta_mac: 6-byte Station MAC address
        anonce: 32-byte AP nonce
        snonce: 32-byte Station nonce
        cipher: Target cipher suite

    Returns:
        PTK bytes (48 for CCMP, 64 for TKIP).
    """
    if len(pmk) != PMK_LEN:
        raise ValueError(f"PMK must be {PMK_LEN} bytes")
    if len(ap_mac) != 6 or len(sta_mac) != 6:
        raise ValueError("MAC addresses must be 6 bytes")
    if len(anonce) != NONCE_LEN or len(snonce) != NONCE_LEN:
        raise ValueError(f"Nonces must be {NONCE_LEN} bytes")

    # Sort MACs and nonces
    mac_min = min(ap_mac, sta_mac)
    mac_max = max(ap_mac, sta_mac)
    nonce_min = min(anonce, snonce)
    nonce_max = max(anonce, snonce)

    data = mac_min + mac_max + nonce_min + nonce_max
    label = b"Pairwise key expansion"

    if cipher == CipherSuite.TKIP:
        ptk_len = PTK_TKIP_LEN
    else:
        ptk_len = PTK_CCMP_LEN

    return prf(pmk, label, data, ptk_len)


def extract_key_hierarchy(ptk: bytes, cipher: CipherSuite = CipherSuite.CCMP) -> DerivedKeys:
    """
    Extract individual keys from PTK.

    Args:
        ptk: Full PTK bytes
        cipher: Cipher suite (determines key layout)

    Returns:
        DerivedKeys with KCK, KEK, TK, and optional MIC keys.
    """
    keys = DerivedKeys()
    keys.ptk = ptk
    keys.kck = ptk[0:16]
    keys.kek = ptk[16:32]

    if cipher == CipherSuite.TKIP:
        keys.tk = ptk[32:48]
        if len(ptk) >= 64:
            keys.tx_mic_key = ptk[48:56]
            keys.rx_mic_key = ptk[56:64]
    else:
        keys.tk = ptk[32:48]

    return keys


def compute_eapol_mic(kck: bytes, eapol_frame: bytes,
                      key_version: int = KEY_INFO_TYPE_HMAC_SHA1) -> bytes:
    """
    Compute MIC over an EAPOL-Key frame.

    Args:
        kck: 16-byte Key Confirmation Key
        eapol_frame: Full EAPOL frame with MIC field zeroed
        key_version: Key descriptor version (1=MD5, 2=SHA1)

    Returns:
        16-byte MIC.
    """
    if key_version == KEY_INFO_TYPE_HMAC_MD5:
        return hmac.new(kck, eapol_frame, hashlib.md5).digest()[:MIC_LEN]
    elif key_version == KEY_INFO_TYPE_HMAC_SHA1:
        return hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:MIC_LEN]
    else:
        # AES-CMAC (WPA3) - simplified
        return hmac.new(kck, eapol_frame, hashlib.sha256).digest()[:MIC_LEN]


def verify_eapol_mic(kck: bytes, frame: EAPOLKeyFrame) -> bool:
    """
    Verify the MIC on an EAPOL-Key frame.

    Args:
        kck: 16-byte Key Confirmation Key
        frame: Parsed EAPOL-Key frame

    Returns:
        True if MIC is valid.
    """
    key_ver = frame.key_descriptor_version
    mic_data = frame.get_mic_data()
    computed = compute_eapol_mic(kck, mic_data, key_ver)
    return hmac.compare_digest(computed, frame.mic)


def aes_key_unwrap(kek: bytes, wrapped: bytes) -> Optional[bytes]:
    """
    AES Key Unwrap (RFC 3394) for GTK decryption.

    Args:
        kek: 16-byte Key Encryption Key
        wrapped: Wrapped key data (multiple of 8 bytes)

    Returns:
        Unwrapped key or None on integrity check failure.
    """
    if len(wrapped) < 16 or len(wrapped) % 8 != 0:
        return None

    n = len(wrapped) // 8 - 1  # number of 64-bit blocks
    a = bytearray(wrapped[:8])
    r = [bytearray(wrapped[i*8:(i+1)*8]) for i in range(1, n + 1)]

    # Import AES for key unwrap
    try:
        from posframework.native.ccmp_aes import aes128_encrypt_block
        has_aes = True
    except ImportError:
        has_aes = False

    def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
        """AES-128 decrypt (inverse of encrypt for key unwrap)."""
        # For key unwrap we need AES decrypt, but we only have encrypt.
        # Use a simple approach: try the cryptography library if available
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            dec = cipher.decryptor()
            return dec.update(block) + dec.finalize()
        except ImportError:
            pass
        # Fallback: implement AES inverse (simplified)
        return _py_aes128_decrypt(key, block)

    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            todec = bytearray(8)
            # A XOR (n*j + i)
            t = n * j + i
            a_xor = bytearray(a)
            a_xor[7] ^= t & 0xFF
            a_xor[6] ^= (t >> 8) & 0xFF
            a_xor[5] ^= (t >> 16) & 0xFF
            a_xor[4] ^= (t >> 24) & 0xFF

            block = bytes(a_xor + r[i-1])
            decrypted = aes_decrypt_block(kek, block)
            a = bytearray(decrypted[:8])
            r[i-1] = bytearray(decrypted[8:])

    # Check integrity (A should be default IV 0xA6A6A6A6A6A6A6A6)
    if a != bytearray(b'\xA6' * 8):
        return None

    result = b""
    for block in r:
        result += bytes(block)
    return result


def aes_key_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """
    AES Key Wrap (RFC 3394) for GTK encryption.

    Args:
        kek: 16-byte Key Encryption Key
        plaintext: Key data to wrap (multiple of 8 bytes)

    Returns:
        Wrapped key data (8 bytes longer than input).
    """
    if len(plaintext) % 8 != 0:
        # Pad to multiple of 8
        pad_len = 8 - (len(plaintext) % 8)
        plaintext = plaintext + b'\x00' * pad_len

    n = len(plaintext) // 8
    a = bytearray(b'\xA6' * 8)  # Default IV
    r = [bytearray(plaintext[i*8:(i+1)*8]) for i in range(n)]

    try:
        from posframework.native.ccmp_aes import aes128_encrypt_block
        def aes_enc(key, block):
            return aes128_encrypt_block(key, block)
    except ImportError:
        from posframework.native.ccmp_aes import _py_aes128_encrypt
        def aes_enc(key, block):
            return _py_aes128_encrypt(key, block)

    for j in range(6):
        for i in range(n):
            block = bytes(a) + bytes(r[i])
            encrypted = aes_enc(kek, block)
            t = n * j + i + 1
            a = bytearray(encrypted[:8])
            a[7] ^= t & 0xFF
            a[6] ^= (t >> 8) & 0xFF
            a[5] ^= (t >> 16) & 0xFF
            a[4] ^= (t >> 24) & 0xFF
            r[i] = bytearray(encrypted[8:])

    result = bytes(a)
    for block in r:
        result += bytes(block)
    return result


# --- WPA2 4-Way Handshake State Machine ---

class WPA2Handshake:
    """
    WPA2 4-way handshake state machine.

    Implements both authenticator (AP) and supplicant (STA) sides
    of the IEEE 802.11i 4-way handshake.
    """

    def __init__(self, role: HandshakeRole, own_mac: bytes, peer_mac: bytes,
                 pmk: bytes, cipher: CipherSuite = CipherSuite.CCMP):
        """
        Initialize handshake state machine.

        Args:
            role: AUTHENTICATOR (AP) or SUPPLICANT (STA)
            own_mac: Own 6-byte MAC address
            peer_mac: Peer 6-byte MAC address
            pmk: 32-byte Pre-shared Master Key
            cipher: Negotiated cipher suite
        """
        if len(own_mac) != 6 or len(peer_mac) != 6:
            raise ValueError("MAC addresses must be 6 bytes")
        if len(pmk) != PMK_LEN:
            raise ValueError(f"PMK must be {PMK_LEN} bytes")

        self.role = role
        self.own_mac = own_mac
        self.peer_mac = peer_mac
        self.pmk = pmk
        self.cipher = cipher

        # Handshake state
        self.state = HandshakeState.IDLE
        self.replay_counter: int = 0

        # Nonces
        self.own_nonce: bytes = b''
        self.peer_nonce: bytes = b''

        # Derived keys
        self.keys: Optional[DerivedKeys] = None
        self.gtk: Optional[bytes] = None

        # Callbacks
        self._on_complete: Optional[Callable[[DerivedKeys], None]] = None
        self._on_failure: Optional[Callable[[str], None]] = None

        # Frame history for debugging/analysis
        self.frame_history: List[Tuple[str, EAPOLKeyFrame]] = []

    @property
    def ap_mac(self) -> bytes:
        if self.role == HandshakeRole.AUTHENTICATOR:
            return self.own_mac
        return self.peer_mac

    @property
    def sta_mac(self) -> bytes:
        if self.role == HandshakeRole.SUPPLICANT:
            return self.own_mac
        return self.peer_mac

    def on_complete(self, callback: Callable[[DerivedKeys], None]) -> None:
        """Register callback for handshake completion."""
        self._on_complete = callback

    def on_failure(self, callback: Callable[[str], None]) -> None:
        """Register callback for handshake failure."""
        self._on_failure = callback

    def _generate_nonce(self) -> bytes:
        """Generate a random 32-byte nonce."""
        if _HAS_NATIVE_CRYPTO:
            return generate_nonce()
        return os.urandom(NONCE_LEN)

    def _derive_ptk(self) -> None:
        """Derive PTK from current handshake state."""
        ptk = derive_ptk(self.pmk, self.ap_mac, self.sta_mac,
                         self.peer_nonce if self.role == HandshakeRole.SUPPLICANT
                         else self.own_nonce,
                         self.own_nonce if self.role == HandshakeRole.SUPPLICANT
                         else self.peer_nonce,
                         self.cipher)

        self.keys = extract_key_hierarchy(ptk, self.cipher)
        self.keys.pmk = self.pmk

    def _fail(self, reason: str) -> None:
        """Transition to failed state."""
        self.state = HandshakeState.FAILED
        log.error(f"WPA2 handshake failed: {reason}")
        if self._on_failure:
            self._on_failure(reason)

    # --- Authenticator (AP) Side ---

    def start_authenticator(self) -> bytes:
        """
        Start handshake as authenticator. Generates and sends Msg 1.

        Returns:
            Serialized EAPOL-Key Msg 1 frame.
        """
        if self.role != HandshakeRole.AUTHENTICATOR:
            raise RuntimeError("Must be authenticator to initiate handshake")

        self.own_nonce = self._generate_nonce()
        self.replay_counter += 1
        self.state = HandshakeState.AWAITING_MSG2

        # Build Msg 1: ANonce, no MIC, ACK set
        msg1 = EAPOLKeyFrame()
        msg1.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_PAIRWISE | KEY_INFO_ACK)
        msg1.key_length = TK_CCMP_LEN if self.cipher == CipherSuite.CCMP else TK_TKIP_LEN
        msg1.replay_counter = self.replay_counter
        msg1.nonce = self.own_nonce

        self.frame_history.append(("tx_msg1", msg1))
        log.info("WPA2: Authenticator sent Msg 1 (ANonce)")
        return msg1.serialize()

    def process_msg2(self, raw_frame: bytes) -> Optional[bytes]:
        """
        Process Msg 2 from supplicant (authenticator side).

        Args:
            raw_frame: Raw EAPOL-Key Msg 2 bytes

        Returns:
            Serialized EAPOL-Key Msg 3 frame, or None on failure.
        """
        if self.state != HandshakeState.AWAITING_MSG2:
            self._fail("Unexpected Msg 2 in state " + self.state.value)
            return None

        msg2 = EAPOLKeyFrame.parse(raw_frame)
        if msg2 is None:
            self._fail("Failed to parse Msg 2")
            return None

        self.frame_history.append(("rx_msg2", msg2))

        # Extract SNonce from Msg 2
        self.peer_nonce = msg2.nonce

        # Derive PTK
        self._derive_ptk()

        # Verify Msg 2 MIC
        if not verify_eapol_mic(self.keys.kck, msg2):
            self._fail("Msg 2 MIC verification failed")
            return None

        log.info("WPA2: Authenticator received valid Msg 2")

        # Build Msg 3: ANonce + GTK (encrypted) + MIC + Install + Secure
        self.replay_counter += 1
        self.state = HandshakeState.AWAITING_MSG4

        # Generate GTK if needed
        if self.gtk is None:
            if self.cipher == CipherSuite.TKIP:
                self.gtk = os.urandom(GTK_TKIP_LEN)
            else:
                self.gtk = os.urandom(GTK_LEN)

        # Wrap GTK with KEK
        gtk_kde = self._build_gtk_kde(self.gtk)
        wrapped_data = aes_key_wrap(self.keys.kek, gtk_kde)

        msg3 = EAPOLKeyFrame()
        msg3.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_PAIRWISE |
                        KEY_INFO_INSTALL | KEY_INFO_ACK | KEY_INFO_MIC |
                        KEY_INFO_SECURE | KEY_INFO_ENCRYPTED_DATA)
        msg3.key_length = TK_CCMP_LEN if self.cipher == CipherSuite.CCMP else TK_TKIP_LEN
        msg3.replay_counter = self.replay_counter
        msg3.nonce = self.own_nonce
        msg3.key_data = wrapped_data

        # Compute MIC
        mic_data = msg3.get_mic_data()
        msg3.mic = compute_eapol_mic(self.keys.kck, mic_data,
                                     KEY_INFO_TYPE_HMAC_SHA1)

        self.frame_history.append(("tx_msg3", msg3))
        log.info("WPA2: Authenticator sent Msg 3 (GTK + Install)")
        return msg3.serialize()

    def process_msg4(self, raw_frame: bytes) -> bool:
        """
        Process Msg 4 from supplicant (authenticator side).

        Args:
            raw_frame: Raw EAPOL-Key Msg 4 bytes

        Returns:
            True if handshake completed successfully.
        """
        if self.state != HandshakeState.AWAITING_MSG4:
            self._fail("Unexpected Msg 4 in state " + self.state.value)
            return False

        msg4 = EAPOLKeyFrame.parse(raw_frame)
        if msg4 is None:
            self._fail("Failed to parse Msg 4")
            return False

        self.frame_history.append(("rx_msg4", msg4))

        # Verify MIC
        if not verify_eapol_mic(self.keys.kck, msg4):
            self._fail("Msg 4 MIC verification failed")
            return False

        # Verify replay counter
        if msg4.replay_counter != self.replay_counter:
            self._fail("Msg 4 replay counter mismatch")
            return False

        # Handshake complete!
        self.state = HandshakeState.COMPLETED
        self.keys.gtk = self.gtk
        log.info("WPA2: 4-way handshake COMPLETED (authenticator)")

        if self._on_complete:
            self._on_complete(self.keys)

        return True

    # --- Supplicant (STA) Side ---

    def process_msg1(self, raw_frame: bytes) -> Optional[bytes]:
        """
        Process Msg 1 from authenticator (supplicant side).

        Args:
            raw_frame: Raw EAPOL-Key Msg 1 bytes

        Returns:
            Serialized EAPOL-Key Msg 2 frame, or None on failure.
        """
        msg1 = EAPOLKeyFrame.parse(raw_frame)
        if msg1 is None:
            self._fail("Failed to parse Msg 1")
            return None

        self.frame_history.append(("rx_msg1", msg1))

        # Extract ANonce
        self.peer_nonce = msg1.nonce
        self.replay_counter = msg1.replay_counter

        # Generate SNonce
        self.own_nonce = self._generate_nonce()

        # Derive PTK
        self._derive_ptk()

        self.state = HandshakeState.AWAITING_MSG3

        # Build Msg 2: SNonce + MIC
        msg2 = EAPOLKeyFrame()
        msg2.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_PAIRWISE | KEY_INFO_MIC)
        msg2.key_length = TK_CCMP_LEN if self.cipher == CipherSuite.CCMP else TK_TKIP_LEN
        msg2.replay_counter = self.replay_counter
        msg2.nonce = self.own_nonce

        # Compute MIC
        mic_data = msg2.get_mic_data()
        msg2.mic = compute_eapol_mic(self.keys.kck, mic_data,
                                     KEY_INFO_TYPE_HMAC_SHA1)

        self.frame_history.append(("tx_msg2", msg2))
        log.info("WPA2: Supplicant sent Msg 2 (SNonce + MIC)")
        return msg2.serialize()

    def process_msg3(self, raw_frame: bytes) -> Optional[bytes]:
        """
        Process Msg 3 from authenticator (supplicant side).

        Args:
            raw_frame: Raw EAPOL-Key Msg 3 bytes

        Returns:
            Serialized EAPOL-Key Msg 4 frame, or None on failure.
        """
        if self.state != HandshakeState.AWAITING_MSG3:
            self._fail("Unexpected Msg 3 in state " + self.state.value)
            return None

        msg3 = EAPOLKeyFrame.parse(raw_frame)
        if msg3 is None:
            self._fail("Failed to parse Msg 3")
            return None

        self.frame_history.append(("rx_msg3", msg3))

        # Verify MIC
        if not verify_eapol_mic(self.keys.kck, msg3):
            self._fail("Msg 3 MIC verification failed")
            return None

        # Verify replay counter
        if msg3.replay_counter <= self.replay_counter:
            self._fail("Msg 3 replay counter too low")
            return None
        self.replay_counter = msg3.replay_counter

        # Decrypt GTK from key data
        if msg3.key_data:
            gtk_data = aes_key_unwrap(self.keys.kek, msg3.key_data)
            if gtk_data is not None:
                self.gtk = self._extract_gtk_from_kde(gtk_data)
                self.keys.gtk = self.gtk
            else:
                log.warning("WPA2: GTK unwrap failed (non-fatal)")

        # Build Msg 4: ACK + MIC
        msg4 = EAPOLKeyFrame()
        msg4.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_PAIRWISE |
                        KEY_INFO_MIC | KEY_INFO_SECURE)
        msg4.key_length = TK_CCMP_LEN if self.cipher == CipherSuite.CCMP else TK_TKIP_LEN
        msg4.replay_counter = self.replay_counter
        msg4.nonce = b'\x00' * NONCE_LEN

        # Compute MIC
        mic_data = msg4.get_mic_data()
        msg4.mic = compute_eapol_mic(self.keys.kck, mic_data,
                                     KEY_INFO_TYPE_HMAC_SHA1)

        # Handshake complete!
        self.state = HandshakeState.COMPLETED
        self.frame_history.append(("tx_msg4", msg4))
        log.info("WPA2: 4-way handshake COMPLETED (supplicant)")

        if self._on_complete:
            self._on_complete(self.keys)

        return msg4.serialize()

    # --- Group Key Handshake ---

    def send_group_key(self, new_gtk: bytes) -> Optional[bytes]:
        """
        Send Group Key Handshake Msg 1 (authenticator side).

        Args:
            new_gtk: New Group Temporal Key

        Returns:
            Serialized EAPOL-Key Group Msg 1.
        """
        if self.role != HandshakeRole.AUTHENTICATOR:
            raise RuntimeError("Only authenticator can send group key")
        if self.state != HandshakeState.COMPLETED:
            raise RuntimeError("Handshake must be completed first")
        if self.keys is None:
            raise RuntimeError("No keys available")

        self.replay_counter += 1
        self.gtk = new_gtk

        # Wrap GTK
        gtk_kde = self._build_gtk_kde(new_gtk)
        wrapped_data = aes_key_wrap(self.keys.kek, gtk_kde)

        msg = EAPOLKeyFrame()
        msg.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_ACK |
                       KEY_INFO_MIC | KEY_INFO_SECURE | KEY_INFO_ENCRYPTED_DATA)
        msg.key_length = len(new_gtk)
        msg.replay_counter = self.replay_counter
        msg.nonce = self.own_nonce
        msg.key_data = wrapped_data

        # Compute MIC
        mic_data = msg.get_mic_data()
        msg.mic = compute_eapol_mic(self.keys.kck, mic_data,
                                    KEY_INFO_TYPE_HMAC_SHA1)

        return msg.serialize()

    def process_group_key(self, raw_frame: bytes) -> Optional[bytes]:
        """
        Process Group Key Handshake Msg 1 (supplicant side).

        Args:
            raw_frame: Raw EAPOL-Key frame

        Returns:
            Serialized Group Key Msg 2 response, or None on failure.
        """
        if self.role != HandshakeRole.SUPPLICANT:
            return None
        if self.keys is None:
            return None

        msg = EAPOLKeyFrame.parse(raw_frame)
        if msg is None:
            return None

        # Verify MIC
        if not verify_eapol_mic(self.keys.kck, msg):
            log.warning("WPA2: Group key msg MIC failed")
            return None

        # Verify replay counter
        if msg.replay_counter <= self.replay_counter:
            log.warning("WPA2: Group key replay counter too low")
            return None
        self.replay_counter = msg.replay_counter

        # Decrypt GTK
        if msg.key_data:
            gtk_data = aes_key_unwrap(self.keys.kek, msg.key_data)
            if gtk_data is not None:
                self.gtk = self._extract_gtk_from_kde(gtk_data)
                self.keys.gtk = self.gtk
                log.info("WPA2: New GTK installed via group key handshake")

        # Send Msg 2 response
        resp = EAPOLKeyFrame()
        resp.key_info = (KEY_INFO_TYPE_HMAC_SHA1 | KEY_INFO_MIC | KEY_INFO_SECURE)
        resp.replay_counter = self.replay_counter

        mic_data = resp.get_mic_data()
        resp.mic = compute_eapol_mic(self.keys.kck, mic_data,
                                     KEY_INFO_TYPE_HMAC_SHA1)

        return resp.serialize()

    # --- Rekeying ---

    def initiate_rekey(self) -> Optional[bytes]:
        """
        Initiate a PTK rekey (authenticator side).

        Starts a new 4-way handshake with fresh nonces.

        Returns:
            Msg 1 of new handshake, or None if not applicable.
        """
        if self.role != HandshakeRole.AUTHENTICATOR:
            return None
        if self.state != HandshakeState.COMPLETED:
            return None

        log.info("WPA2: Initiating PTK rekey")
        # Reset state for new handshake
        self.state = HandshakeState.IDLE
        self.own_nonce = b''
        self.peer_nonce = b''

        return self.start_authenticator()

    # --- Helper methods ---

    @staticmethod
    def _build_gtk_kde(gtk: bytes, key_id: int = 1) -> bytes:
        """
        Build GTK KDE (Key Data Encapsulation) for Msg 3.

        KDE format:
          Type: 0xDD
          Length: len + 6
          OUI: 00-0F-AC
          Data Type: 1 (GTK)
          Key ID + Tx: key_id(bits 0-1) | Tx(bit 2)
          Reserved: 0
          GTK data

        Args:
            gtk: Group Temporal Key
            key_id: Key ID (1-3)

        Returns:
            KDE-wrapped GTK data (padded to multiple of 8 bytes).
        """
        kde = bytearray()
        kde.append(0xDD)  # Type
        kde.append(len(gtk) + 6)  # Length
        kde.extend(b'\x00\x0F\xAC')  # OUI (IEEE)
        kde.append(0x01)  # Data type: GTK
        kde.append(key_id & 0x03)  # Key ID + Tx bit
        kde.append(0x00)  # Reserved
        kde.extend(gtk)

        # Pad to multiple of 8 bytes for AES key wrap
        while len(kde) % 8 != 0:
            kde.append(0x00)

        return bytes(kde)

    @staticmethod
    def _extract_gtk_from_kde(kde_data: bytes) -> Optional[bytes]:
        """
        Extract GTK from KDE data.

        Args:
            kde_data: Unwrapped KDE data

        Returns:
            GTK bytes or None if KDE is invalid.
        """
        if len(kde_data) < 8:
            return None

        # Look for GTK KDE (Type 0xDD, OUI 00-0F-AC, Data Type 1)
        offset = 0
        while offset < len(kde_data) - 2:
            if kde_data[offset] == 0xDD:
                length = kde_data[offset + 1]
                if (offset + 2 + length <= len(kde_data) and
                    length >= 6 and
                    kde_data[offset+2:offset+5] == b'\x00\x0F\xAC' and
                    kde_data[offset+5] == 0x01):
                    # Found GTK KDE
                    gtk_start = offset + 8  # Skip type+len+oui+datatype+keyid+reserved
                    gtk_end = offset + 2 + length
                    return kde_data[gtk_start:gtk_end]
                offset += 2 + length
            else:
                offset += 1

        # Fallback: return data after first 8 bytes (header)
        if len(kde_data) > 8:
            return kde_data[8:]
        return None


# --- AES-128 Decrypt (for key unwrap fallback) ---

# Inverse S-box for AES decrypt
_AES_INV_SBOX = [
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D,
]

_AES_SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]

_AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _py_aes128_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Pure Python AES-128 block decryption (for key unwrap only).

    This is a minimal implementation for the AES key unwrap fallback.
    """
    def xtime(x):
        return ((x << 1) ^ (0x1B if (x & 0x80) else 0)) & 0xFF

    def mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p

    # Key expansion
    rk = bytearray(176)
    rk[:16] = key
    for i in range(4, 44):
        temp = list(rk[(i-1)*4:i*4])
        if i % 4 == 0:
            t = temp[0]
            temp[0] = _AES_SBOX[temp[1]] ^ _AES_RCON[i // 4]
            temp[1] = _AES_SBOX[temp[2]]
            temp[2] = _AES_SBOX[temp[3]]
            temp[3] = _AES_SBOX[t]
        for j in range(4):
            rk[i*4+j] = rk[(i-4)*4+j] ^ temp[j]

    state = bytearray(ciphertext)

    # Initial AddRoundKey (round 10)
    for i in range(16):
        state[i] ^= rk[160 + i]

    for rnd in range(9, 0, -1):
        # InvShiftRows
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[10] = state[10], state[2]
        state[6], state[14] = state[14], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

        # InvSubBytes
        for i in range(16):
            state[i] = _AES_INV_SBOX[state[i]]

        # AddRoundKey
        for i in range(16):
            state[i] ^= rk[rnd * 16 + i]

        # InvMixColumns
        for c in range(4):
            ci = c * 4
            s0, s1, s2, s3 = state[ci], state[ci+1], state[ci+2], state[ci+3]
            state[ci]   = mul(0x0E, s0) ^ mul(0x0B, s1) ^ mul(0x0D, s2) ^ mul(0x09, s3)
            state[ci+1] = mul(0x09, s0) ^ mul(0x0E, s1) ^ mul(0x0B, s2) ^ mul(0x0D, s3)
            state[ci+2] = mul(0x0D, s0) ^ mul(0x09, s1) ^ mul(0x0E, s2) ^ mul(0x0B, s3)
            state[ci+3] = mul(0x0B, s0) ^ mul(0x0D, s1) ^ mul(0x09, s2) ^ mul(0x0E, s3)

    # Final round (no InvMixColumns)
    # InvShiftRows
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[10] = state[10], state[2]
    state[6], state[14] = state[14], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    # InvSubBytes
    for i in range(16):
        state[i] = _AES_INV_SBOX[state[i]]

    # AddRoundKey (round 0)
    for i in range(16):
        state[i] ^= rk[i]

    return bytes(state)
