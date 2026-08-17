"""
Unit tests for posframework.pywhat_analyzer

Tests the PyWhatAnalyzer and PyWhatCallback classes in fallback mode
(no pywhat installed). Validates regex pattern matching for:
- API keys (AWS, GitHub, Slack, Google, Stripe)
- Hashes (MD5, SHA1, SHA256, SHA512, NTLM)
- URLs, IPv4/IPv6 addresses
- Email addresses
- Credit card numbers
- Crypto wallet addresses (BTC, ETH)
- JWT tokens
- Private keys
- Connection strings
- Base64 blobs
- Password assignments
"""

import sys
import os
import unittest

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from posframework.pywhat_analyzer import PyWhatAnalyzer, PyWhatCallback, _PYWHAT_AVAILABLE


class TestPyWhatAnalyzerFallback(unittest.TestCase):
    """Test PyWhatAnalyzer in fallback regex mode."""

    def setUp(self):
        self.analyzer = PyWhatAnalyzer()

    def test_fallback_mode_active(self):
        """Verify fallback mode is used when pywhat is not installed."""
        # In this test environment, pywhat is not available
        if not _PYWHAT_AVAILABLE:
            self.assertFalse(self.analyzer.using_pywhat)

    def test_empty_input(self):
        """analyze() returns empty list for empty/None input."""
        self.assertEqual(self.analyzer.analyze(""), [])
        self.assertEqual(self.analyzer.analyze(None), [])  # type: ignore[arg-type]

    # ---- API Keys ----

    def test_aws_access_key(self):
        """Detect AWS Access Key ID pattern."""
        text = "key=AKIAIOSFODNN7EXAMPLE"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("AWS Access Key ID", names)
        matched = next(r for r in results if r["name"] == "AWS Access Key ID")
        self.assertEqual(matched["value"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(matched["category"], "credentials")

    def test_github_token(self):
        """Detect GitHub personal access token."""
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("GitHub Token", names)

    def test_slack_token(self):
        """Detect Slack API token."""
        text = "slack_token_placeholder"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Slack Token", names)

    def test_google_api_key(self):
        """Detect Google API key."""
        text = "AIzaSyA1234567890abcdefghijklmnopqrstuvw"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Google API Key", names)

    def test_stripe_secret_key(self):
        """Detect Stripe secret key."""
        text = "stripe_key_placeholder"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Stripe Secret Key", names)

    # ---- Hashes ----

    def test_md5_hash(self):
        """Detect MD5 hash."""
        text = "hash: d41d8cd98f00b204e9800998ecf8427e"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("MD5 Hash", names)
        matched = next(r for r in results if r["name"] == "MD5 Hash")
        self.assertEqual(matched["category"], "hashes")

    def test_sha1_hash(self):
        """Detect SHA1 hash."""
        text = "sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("SHA1 Hash", names)

    def test_sha256_hash(self):
        """Detect SHA256 hash."""
        text = "checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("SHA256 Hash", names)

    def test_sha512_hash(self):
        """Detect SHA512 hash."""
        sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"  # noqa: E501
        text = f"sha512={sha512}"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("SHA512 Hash", names)

    def test_ntlm_hash(self):
        """Detect NTLM hash pair."""
        text = "hash=aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("NTLM Hash", names)

    # ---- URLs and IPs ----

    def test_url_detection(self):
        """Detect HTTP/HTTPS URLs."""
        text = "Visit https://api.example.com/v2/endpoint?key=abc for more info"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("URL", names)
        matched = next(r for r in results if r["name"] == "URL")
        self.assertEqual(matched["category"], "network")

    def test_ipv4_address(self):
        """Detect IPv4 addresses."""
        text = "server at 192.168.1.100 listening"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("IPv4 Address", names)
        matched = next(r for r in results if r["name"] == "IPv4 Address")
        self.assertEqual(matched["value"], "192.168.1.100")

    def test_ipv6_address(self):
        """Detect IPv6 addresses."""
        text = "host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 is up"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("IPv6 Address", names)

    # ---- Email ----

    def test_email_address(self):
        """Detect email addresses."""
        text = "Contact admin@example.com for support"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Email Address", names)
        matched = next(r for r in results if r["name"] == "Email Address")
        self.assertEqual(matched["value"], "admin@example.com")
        self.assertEqual(matched["category"], "identifiers")

    # ---- Credit Cards ----

    def test_visa_card(self):
        """Detect Visa card number."""
        text = "card: 4111111111111111"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Visa Card Number", names)
        matched = next(r for r in results if r["name"] == "Visa Card Number")
        self.assertEqual(matched["category"], "financial")

    def test_mastercard(self):
        """Detect Mastercard number."""
        text = "payment: 5500000000000004"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Mastercard Number", names)

    # ---- Crypto Wallets ----

    def test_bitcoin_address(self):
        """Detect Bitcoin address."""
        text = "Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Bitcoin Address", names)
        matched = next(r for r in results if r["name"] == "Bitcoin Address")
        self.assertEqual(matched["category"], "crypto")

    def test_ethereum_address(self):
        """Detect Ethereum address."""
        text = "wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD10"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Ethereum Address", names)

    # ---- JWT ----

    def test_jwt_token(self):
        """Detect JWT token."""
        text = "auth: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("JWT Token", names)
        matched = next(r for r in results if r["name"] == "JWT Token")
        self.assertEqual(matched["category"], "credentials")
        self.assertEqual(matched["confidence"], 0.95)

    # ---- Private Keys ----

    def test_rsa_private_key(self):
        """Detect RSA private key header."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ..."
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("RSA Private Key", names)
        matched = next(r for r in results if r["name"] == "RSA Private Key")
        self.assertEqual(matched["confidence"], 0.99)

    # ---- Connection Strings ----

    def test_database_connection_string(self):
        """Detect database connection string."""
        text = "DATABASE_URL=postgres://user:pass@host:5432/dbname"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Database Connection String", names)

    # ---- Bearer/Basic Auth ----

    def test_bearer_token(self):
        """Detect Bearer token in Authorization header."""
        text = "Authorization: Bearer abc123def456.ghi789jkl012.mno345pqr678"
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Bearer Token", names)

    def test_basic_auth(self):
        """Detect Basic auth header."""
        text = "Authorization: Basic YWRtaW46cGFzc3dvcmQ="
        results = self.analyzer.analyze(text)
        names = [r["name"] for r in results]
        self.assertIn("Basic Auth", names)


class TestPyWhatAnalyzerTraffic(unittest.TestCase):
    """Test analyze_traffic() with mock LiveDecryptionSession output."""

    def setUp(self):
        self.analyzer = PyWhatAnalyzer()

    def test_analyze_dns_traffic(self):
        """analyze_traffic processes DNS queries and responses."""
        summary = {
            "dns_queries": [
                {"query": "api.stripe.com", "response": "192.168.1.50"},
            ],
            "http_requests": [],
            "dhcp_leases": [],
            "eapol_events": [],
            "credentials": [],
        }
        results = self.analyzer.analyze_traffic(summary)
        # Should find the IP at minimum
        sources = [r.get("source") for r in results]
        self.assertIn("dns_response", sources)

    def test_analyze_http_traffic(self):
        """analyze_traffic processes HTTP requests with auth headers."""
        summary = {
            "dns_queries": [],
            "http_requests": [
                {
                    "host": "api.example.com",
                    "method": "POST",
                    "uri": "/v1/charges?key=stripe_key_placeholder",
                    "user_agent": "Mozilla/5.0",
                    "cookie": "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                    "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                },
            ],
            "dhcp_leases": [],
            "eapol_events": [],
            "credentials": [],
        }
        results = self.analyzer.analyze_traffic(summary)
        # Should find JWT in cookie and auth header, Stripe key in URI
        names = [r["name"] for r in results]
        self.assertTrue(
            any("JWT" in n or "Stripe" in n or "Bearer" in n for n in names),
            f"Expected JWT/Stripe/Bearer token, got: {names}"
        )

    def test_analyze_dhcp_traffic(self):
        """analyze_traffic processes DHCP lease data."""
        summary = {
            "dns_queries": [],
            "http_requests": [],
            "dhcp_leases": [
                {
                    "hostname": "POS-Terminal-01",
                    "requested_ip": "10.0.0.50",
                    "mac_addr": "aa:bb:cc:dd:ee:ff",
                },
            ],
            "eapol_events": [],
            "credentials": [],
        }
        results = self.analyzer.analyze_traffic(summary)
        sources = [r.get("source") for r in results]
        self.assertIn("dhcp_ip", sources)

    def test_analyze_credentials(self):
        """analyze_traffic processes stored credentials."""
        summary = {
            "dns_queries": [],
            "http_requests": [],
            "dhcp_leases": [],
            "eapol_events": [],
            "credentials": [
                {
                    "protocol": "http",
                    "type": "authorization_header",
                    "value": "Basic YWRtaW46cGFzc3dvcmQxMjM=",
                },
            ],
        }
        results = self.analyzer.analyze_traffic(summary)
        names = [r["name"] for r in results]
        self.assertIn("Basic Auth", names)

    def test_empty_summary(self):
        """analyze_traffic handles empty summary gracefully."""
        results = self.analyzer.analyze_traffic({})
        self.assertEqual(results, [])


class TestPyWhatAnalyzerSurfaces(unittest.TestCase):
    """Test get_attack_surfaces() categorization."""

    def setUp(self):
        self.analyzer = PyWhatAnalyzer()

    def test_categorizes_findings(self):
        """get_attack_surfaces returns categorized results."""
        # Feed some data through
        self.analyzer.analyze("AKIAIOSFODNN7EXAMPLE")
        self.analyzer.analyze("https://api.example.com/endpoint")
        self.analyzer.analyze("admin@company.com")
        self.analyzer.analyze("4111111111111111")

        surfaces = self.analyzer.get_attack_surfaces()

        # Check categories exist
        self.assertIn("credentials", surfaces)
        self.assertIn("keys", surfaces)
        self.assertIn("network", surfaces)
        self.assertIn("identifiers", surfaces)
        self.assertIn("financial", surfaces)
        self.assertIn("crypto", surfaces)
        self.assertIn("hashes", surfaces)
        self.assertIn("encoded", surfaces)

        # Verify some items landed in correct category
        self.assertTrue(len(surfaces["network"]) > 0, "Expected network findings")
        self.assertTrue(len(surfaces["identifiers"]) > 0, "Expected identifier findings")

    def test_clear_findings(self):
        """clear_findings resets accumulated data."""
        self.analyzer.analyze("https://example.com")
        self.assertTrue(len(self.analyzer.findings) > 0)
        self.analyzer.clear_findings()
        self.assertEqual(len(self.analyzer.findings), 0)


class TestPyWhatCallback(unittest.TestCase):
    """Test PyWhatCallback integration with LiveDecryptionSession interface."""

    def test_callback_callable(self):
        """PyWhatCallback is callable with event dict."""
        callback = PyWhatCallback()
        # Simulate a DNS event
        event = {
            "protocol": "dns",
            "data": {"query": "api.stripe.com", "response": "192.168.1.1"},
            "timestamp": 1234567890.0,
        }
        # Should not raise
        callback(event)
        self.assertEqual(callback.event_count, 1)

    def test_callback_detects_patterns(self):
        """PyWhatCallback detects patterns in HTTP traffic."""
        callback = PyWhatCallback()
        event = {
            "protocol": "http",
            "data": {
                "host": "api.example.com",
                "uri": "/v1/auth",
                "cookie": "",
                "user_agent": "curl/7.68.0",
                "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            },
            "timestamp": 1234567890.0,
        }
        callback(event)
        self.assertGreater(callback.finding_count, 0)

    def test_callback_chains_existing(self):
        """PyWhatCallback chains to an existing callback."""
        chain_events = []

        def existing_callback(event):
            chain_events.append(event)

        callback = PyWhatCallback(chain=existing_callback)
        event = {
            "protocol": "dns",
            "data": {"query": "example.com", "response": "1.2.3.4"},
            "timestamp": 1234567890.0,
        }
        callback(event)
        # Original callback should have been called
        self.assertEqual(len(chain_events), 1)
        self.assertEqual(chain_events[0]["protocol"], "dns")

    def test_callback_handles_eapol(self):
        """PyWhatCallback processes EAPOL events without errors."""
        callback = PyWhatCallback()
        event = {
            "protocol": "eapol",
            "data": {
                "type": "3",
                "source": "aa:bb:cc:dd:ee:ff",
                "destination": "11:22:33:44:55:66",
            },
            "timestamp": 1234567890.0,
        }
        callback(event)
        self.assertEqual(callback.event_count, 1)

    def test_callback_handles_dhcp(self):
        """PyWhatCallback processes DHCP events."""
        callback = PyWhatCallback()
        event = {
            "protocol": "dhcp",
            "data": {
                "hostname": "POS-Register-03",
                "requested_ip": "10.0.0.100",
                "mac_addr": "aa:bb:cc:dd:ee:ff",
            },
            "timestamp": 1234567890.0,
        }
        callback(event)
        self.assertEqual(callback.event_count, 1)

    def test_callback_analyzer_access(self):
        """PyWhatCallback exposes its analyzer instance."""
        analyzer = PyWhatAnalyzer()
        callback = PyWhatCallback(analyzer=analyzer)
        self.assertIs(callback.analyzer, analyzer)

    def test_callback_unknown_protocol(self):
        """PyWhatCallback handles unknown protocol gracefully."""
        callback = PyWhatCallback()
        event = {
            "protocol": "unknown",
            "data": {"field": "value"},
            "timestamp": 1234567890.0,
        }
        callback(event)
        self.assertEqual(callback.event_count, 1)


if __name__ == "__main__":
    unittest.main()
