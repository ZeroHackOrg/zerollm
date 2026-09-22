# src/zerollm/cli/webserver.py
"""Standalone demo telemetry dashboard (stdlib only)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional

from ..metrics import DEFAULT_METRICS

INTERCEPTED_LOGS: List[dict] = []


class ZeroLLMTelemetryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/api/v1/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "engine": "ZeroLLM",
                        "metrics": DEFAULT_METRICS.snapshot(),
                        "logs": INTERCEPTED_LOGS,
                    }
                ).encode()
            )
        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(DEFAULT_METRICS.prometheus_text().encode())
        else:
            self._serve_dashboard()

    def _serve_dashboard(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        html = f"""
        <html>
            <head><title>ZeroLLM Dashboard</title>
            <style>
                body {{ font-family: monospace; background: #050b0f; color: #00ffcc; padding: 30px; }}
                h1 {{ color: #00ffcc; }}
                a {{ color: #00ffcc; }}
            </style>
            </head>
            <body>
                <h1>ZeroLLM // Reverse Proxy Firewall & Prompt Injection Sandbox</h1>
                <p>Demo telemetry. Production telemetry is served by the gateway
                at <code>/api/v1/telemetry</code> and <code>/metrics</code>.</p>
                <p>Blocked/scrubbed events: {len(INTERCEPTED_LOGS)}</p>
                <p><a href="/api/v1/telemetry">JSON API Stream (/api/v1/telemetry)</a></p>
                <p><a href="/metrics">Prometheus Metrics (/metrics)</a></p>
            </body>
        </html>
        """
        self.wfile.write(html.encode())


def run_zerollm_server(
    port: int = 9494, logs_store: Optional[List[dict]] = None, host: str = "127.0.0.1"
) -> HTTPServer:
    global INTERCEPTED_LOGS
    if logs_store is not None:
        INTERCEPTED_LOGS = logs_store
    server = HTTPServer((host, port), ZeroLLMTelemetryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[ZeroLLM UI Platform] Telemetry stream active at http://{host}:{port}")
    return server
