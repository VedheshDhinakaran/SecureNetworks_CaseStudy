#!/usr/bin/env python3
"""Stand-in EMR web application / patient portal (H_EMR_APP).

Serves plain HTTP on the given port (443 in the lab) on purpose, so that
Suricata can read the requests in experiment E6 without TLS inspection.
  /portal/...  -> 200, a fake patient page
  /admin/...   -> 200, a fake admin page (the firewall's D-01 must stop this from outside)
  /health      -> 200 "ok"
Every request is logged with the client address.
"""
import argparse
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = "<html><head><title>{t}</title></head><body><h1>{t}</h1><p>{b}</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    server_version = "SJV-EMR/1.0"

    def _send(self, code: int, title: str, body: str):
        data = PAGE.format(t=title, b=body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, "ok", "ok")
        elif self.path.startswith("/portal/"):
            self._send(200, "Sanjivani patient portal", "Synthetic test page. No real patient data.")
        elif self.path.startswith("/admin/"):
            self._send(200, "EMR administration", "If you can see this from outside, rule D-01 is not working.")
        else:
            self._send(200, "Sanjivani EMR (lab)", "Try /portal/ or /admin/")

    def log_message(self, fmt, *args):
        ua = self.headers.get("User-Agent", "-")
        print(f"{datetime.datetime.now().isoformat(timespec='seconds')} {self.client_address[0]} "
              f"\"{self.requestline}\" ua=\"{ua}\" {args[1] if len(args) > 1 else ''}", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=443)
    a = ap.parse_args()
    ThreadingHTTPServer((a.bind, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
