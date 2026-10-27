#!/usr/bin/env python3
"""Stand-in HL7 interface engine (H_IFENGINE, tcp/2575).

Accepts MLLP-framed HL7 v2 messages, checks that each one has a valid MSH
segment, logs it and replies with an ACK (AA) or a reject (AR).
Interface-engine validation is one of the controls the firewall cannot
provide by itself (report Section 3.6).
"""
import argparse
import datetime
import socketserver

from hl7 import ack, frame, parse, unframe


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        buf = b""
        while True:
            data = self.request.recv(4096)
            if not data:
                break
            buf += data
            messages, buf = unframe(buf)
            for msg in messages:
                now = datetime.datetime.now().isoformat(timespec="seconds")
                try:
                    info = parse(msg)
                    reply = ack(msg, "AA")
                    print(f"{now} {peer} {info['type']} id={info['control_id']} segs={','.join(info['segments'])} -> AA", flush=True)
                except ValueError as exc:
                    reply = "MSH|^~\\&|SJV-IFENGINE|SJV|||||ACK||P|2.5.1\rMSA|AR||" + str(exc)
                    print(f"{now} {peer} REJECTED: {exc}", flush=True)
                self.request.sendall(frame(reply))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2575)
    a = ap.parse_args()
    with Server((a.bind, a.port), Handler) as srv:
        print(f"MLLP interface engine listening on {a.bind}:{a.port}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
