"""
POS Vendor & SSID Intelligence
───────────────────────────────
OUI vendor string matching and SSID pattern detection for identifying
Point-of-Sale terminals, payment infrastructure, and retail networking.
"""

POS_VENDORS = frozenset([
    # Payment terminals
    "verifone", "ingenico", "pax", "newland", "castles technology",
    "nexgo", "bbpos", "miura systems", "datecs", "bitel",
    "sunmi", "wisecash", "worldline", "equinox payments",
    "dejavoo", "valor paytech",
    # POS platforms & retail hardware
    "ncr", "diebold nixdorf", "toshiba global commerce", "fujitsu",
    "square", "block", "clover network", "fiserv", "toast",
    "shopify", "lightspeed", "revel systems", "oracle",
    "micros", "par technology", "heartland payment",
    "shift4", "elo touch", "posiflex", "partner tech", "aures",
    "j2 retail", "hp retail", "panasonic",
    # ATMs & self-service kiosks
    "nautilus hyosung", "hyosung", "triton systems", "genmega",
    "hantle", "hitachi-omron", "oki electric",
    # Receipt printers & peripherals
    "epson", "seiko epson", "star micronics", "bixolon",
    "citizen systems", "custom spa", "sewoo", "hprt",
    # Barcode scanners & mobile computers
    "zebra technologies", "honeywell", "datalogic", "socket mobile",
    "unitech", "cipherlab", "newland auto-id", "opticon",
    # Card readers & payment dongles
    "magtek", "id tech", "idtech", "acs", "advanced card systems",
    "feitian", "yubico",
    # Retail-focused networking
    "aruba", "hewlett packard enterprise", "meraki", "cisco meraki",
    "ruckus", "commscope ruckus", "cradlepoint", "digi international",
    "ventev", "extreme networks",
])

POS_SSID_PATTERNS = frozenset([
    "pos", "register", "payment", "terminal", "kiosk",
    "retail", "store-", "merchant", "micros", "aloha",
    "toast-", "clover-", "square-", "verifone", "ingenico",
    "backoffice", "back-office", "boh-", "foh-", "lottery",
    "fuel", "pump", "atm", "vending", "self-checkout",
    "pay-at-", "lane-", "till-", "pinpad",
])


def is_pos_vendor(vendor: str) -> bool:
    """Check if OUI vendor string matches known POS manufacturers."""
    vendor_lower = vendor.lower()
    return any(v in vendor_lower for v in POS_VENDORS)


def is_pos_ssid(ssid: str) -> bool:
    """Check if SSID matches common POS/retail naming patterns."""
    if not ssid:
        return False
    ssid_lower = ssid.lower()
    return any(p in ssid_lower for p in POS_SSID_PATTERNS)
