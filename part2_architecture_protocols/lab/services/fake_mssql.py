#!/usr/bin/env python3
"""Stand-in for the EMR database listener (H_EMR_DB, tcp/1433).

It speaks no real TDS protocol. It only accepts TCP connections and logs
who connected, which is all experiments E1/E2 need: if a radiology or
vendor host appears in this log, the segmentation has failed.
"""
import argparse
import datetime
import socketserver


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print(f"{datetime.datetime.now().isoformat(timespec='seconds')} connection from "
              f"{self.client_address[0]}:{self.client_address[1]}", flush=True)
        try:
            self.request.settimeout(3)
            self.request.recv(1024)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=1433)
    a = ap.parse_args()
    with Server((a.bind, a.port), Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
