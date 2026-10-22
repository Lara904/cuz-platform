"""Simulateur de l'API Defender for Cloud (fictif, AcmeCorp local).

GET /health            → 200
GET /alerts            → toutes les alertes
GET /alerts/stream     → alertes après le curseur ?since=<n> ; renvoie un nouveau curseur
GET /recommendations   → recommandations
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA = json.loads((Path(__file__).parent / "alerts.json").read_text(encoding="utf-8"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (nom imposé par http.server)
        url = urlparse(self.path)
        if url.path == "/health":
            self._send({"status": "ok", "simulated": True})
        elif url.path == "/alerts":
            self._send({"alerts": DATA["alerts"]})
        elif url.path == "/alerts/stream":
            since = int(parse_qs(url.query).get("since", ["0"])[0])
            alerts = DATA["alerts"][since:]
            self._send({"alerts": alerts, "cursor": str(len(DATA["alerts"]))})
        elif url.path == "/recommendations":
            self._send({"recommendations": DATA["recommendations"]})
        else:
            self._send({"error": "not found"}, status=404)

    def log_message(self, fmt, *args):  # journal minimal
        return


if __name__ == "__main__":
    port = int(os.getenv("PORT", "9100"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
