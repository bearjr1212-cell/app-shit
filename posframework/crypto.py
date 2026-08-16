"""
RSN / WPA Information Element Parsing
──────────────────────────────────────
Real byte-level parsing of 802.11 security IEs per IEEE 802.11-2020
Section 9.4.2.25. Extracts AKM suites, cipher suites, PMF capabilities
for accurate security classification (WPA2/WPA3/WEP/Open/OWE).
"""

import struct

AKM_SUITES = {
    1: "WPA2-EAP", 2: "WPA2-PSK", 3: "FT-EAP", 4: "FT-PSK",
    5: "WPA2-EAP-SHA256", 6: "WPA2-PSK-SHA256", 8: "SAE",
    9: "FT-SAE", 12: "EAP-SHA384", 18: "OWE",
}

CIPHER_SUITES = {
    1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
    8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
}


def parse_rsn_ie(data: bytes) -> dict:
    """Parse RSN IE bytes into group cipher, pairwise ciphers, AKM suites, capabilities."""
    result = {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": [], "capabilities": 0}
    if not data or len(data) < 10:
        return result
    offset = 0
    version = struct.unpack_from("<H", data, offset)[0]
    if version != 1:
        return result
    offset += 2
    if offset + 4 > len(data):
        return result
    result["group_cipher"] = CIPHER_SUITES.get(data[offset + 3], f"Unknown({data[offset+3]})")
    offset += 4
    if offset + 2 > len(data):
        return result
    pw_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    for _ in range(pw_count):
        if offset + 4 > len(data):
            break
        result["pairwise_ciphers"].append(CIPHER_SUITES.get(data[offset + 3], f"Unknown({data[offset+3]})"))
        offset += 4
    if offset + 2 > len(data):
        return result
    akm_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    for _ in range(akm_count):
        if offset + 4 > len(data):
            break
        result["akm_suites"].append(AKM_SUITES.get(data[offset + 3], f"Unknown({data[offset+3]})"))
        offset += 4
    if offset + 2 <= len(data):
        result["capabilities"] = struct.unpack_from("<H", data, offset)[0]
    return result


def parse_wpa_ie(data: bytes) -> dict:
    """Parse WPA vendor IE (OUI 00:50:f2 type 1) into cipher/AKM info."""
    result = {"group_cipher": None, "pairwise_ciphers": [], "akm_suites": []}
    if not data or len(data) < 10 or data[0:4] != b'\x00\x50\xf2\x01':
        return result
    offset = 4
    version = struct.unpack_from("<H", data, offset)[0]
    if version != 1:
        return result
    offset += 2
    if offset + 4 > len(data):
        return result
    result["group_cipher"] = CIPHER_SUITES.get(data[offset + 3], "TKIP")
    offset += 4
    if offset + 2 > len(data):
        return result
    pw_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    for _ in range(pw_count):
        if offset + 4 > len(data):
            break
        result["pairwise_ciphers"].append(CIPHER_SUITES.get(data[offset + 3], "TKIP"))
        offset += 4
    if offset + 2 > len(data):
        return result
    akm_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2
    for _ in range(akm_count):
        if offset + 4 > len(data):
            break
        akm_type = data[offset + 3]
        if akm_type == 1:
            result["akm_suites"].append("WPA-EAP")
        elif akm_type == 2:
            result["akm_suites"].append("WPA-PSK")
        else:
            result["akm_suites"].append(f"WPA-Unknown({akm_type})")
        offset += 4
    return result


def classify_security(rsn_info: dict, wpa_info: dict, has_privacy: bool) -> str:
    """Produce human-readable security string from parsed IE data."""
    if not has_privacy:
        if rsn_info and "OWE" in rsn_info.get("akm_suites", []):
            return "OWE (Enhanced Open)"
        return "Open"
    parts = []
    if rsn_info and rsn_info["akm_suites"]:
        for akm in rsn_info["akm_suites"]:
            if "SAE" in akm:
                parts.append("WPA3-Personal")
            elif "EAP-SHA384" in akm:
                parts.append("WPA3-Enterprise")
            elif "EAP" in akm:
                parts.append("WPA2-Enterprise")
            elif "PSK" in akm:
                parts.append("WPA2-Personal")
            else:
                parts.append(akm)
        ciphers = rsn_info.get("pairwise_ciphers", [])
        if ciphers:
            parts.append(f"[{'/'.join(sorted(set(ciphers)))}]")
        caps = rsn_info.get("capabilities", 0)
        mfpr = (caps >> 6) & 1
        mfpc = (caps >> 7) & 1
        if mfpr:
            parts.append("(PMF-Required)")
        elif mfpc:
            parts.append("(PMF-Capable)")
    elif wpa_info and wpa_info["akm_suites"]:
        parts.append("WPA")
        parts.extend(wpa_info["akm_suites"])
        ciphers = wpa_info.get("pairwise_ciphers", [])
        if ciphers:
            parts.append(f"[{'/'.join(sorted(set(ciphers)))}]")
    elif has_privacy:
        parts.append("WEP")
    return " ".join(parts) if parts else "Unknown"
