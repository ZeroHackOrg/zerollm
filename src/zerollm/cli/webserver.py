# src/zerollm/cli/webserver.py
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List

from ..metrics import DEFAULT_METRICS

INTERCEPTED_LOGS: List[dict] = []


class ZeroLLMTelemetryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/api/v1/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "engine": "ZeroLLM",
                "metrics": DEFAULT_METRICS.snapshot(),
                "logs": INTERCEPTED_LOGS
            }).encode())
        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(DEFAULT_METRICS.prometheus_text().encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = f"""
            <html>
                <head><title>ZeroLLM Dashboard</title>
                <style>
                    body {{ font-family: monospace; background: #050b0f; color: #00ffcc; padding: 30px; }}
                    h1 {{ color: #00ffcc; text-shadow: 0 0 10px rgba(0,255,204,0.5); }}
                    .card {{ background: #0c1520; border: 1px solid #1a3045; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
                </style>
                </head>
                <body>
                    <h1>🛡️ ZeroLLM // Reverse Proxy Firewall & Prompt Injection Sandbox</h1>
                    <div class="card">
                        <p>Status: <span style="color:#00ffcc;">ACTIVE // SANITIZING API STREAMS</span></p>
                        <p>Blocked Attacks / Scrubbed Payloads: <span style="color:#ffff33;">{len(INTERCEPTED_LOGS)}</span></p>
                    </div>
                    <div class="card">
                        <h3>📊 Telemetry & Metrics</h3>
                        <p><a href="/api/v1/telemetry" style="color:#00ffcc;">JSON API Stream (/api/v1/telemetry)</a></p>
                        <p><a href="/metrics" style="color:#00ffcc;">Prometheus Metrics (/metrics)</a></p>
                    </div>
                </body>
            </html>
            """
            self.wfile.write(html.encode())


def run_zerollm_server(port: int = 9494, logs_store: list = None) -> HTTPServer:
    global INTERCEPTED_LOGS
    if logs_store is not None:
        INTERCEPTED_LOGS = logs_store
    server = HTTPServer(("", port), ZeroLLMTelemetryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"📡 [ZeroLLM UI Platform] Telemetry stream active at http://localhost:{port}")
    return server