#!/usr/bin/env python3
"""Send one HL7 ORU^R01 from a 'pump' or 'PACS broker' to the interface engine.

Exit code 0 = ACK received, 1 = rejected, 2 = connection failed (e.g. the
firewall blocked it). Used by experiments E2 and E3.
"""
import argparse
import socket
import sys

from hl7 import frame, oru_vitals, parse, unframe


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="192.168.10.40")
    ap.add_argument("--port", type=int, default=2575)
    ap.add_argument("--source", help="source IP to bind (e.g. 192.168.40.12 for the PACS broker)")
    ap.add_argument("--device", default="PUMP-030-010")
    ap.add_argument("--timeout", type=float, default=5.0)
    a = ap.parse_args()

    msg = oru_vitals(a.device)
    try:
        with socket.create_connection((a.host, a.port), timeout=a.timeout,
                                      source_address=(a.source, 0) if a.source else None) as s:
            s.sendall(frame(msg))
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                replies, buf = unframe(buf)
                if replies:
                    msa = [seg for seg in replies[0].split("\r") if seg.startswith("MSA")]
                    code = msa[0].split("|")[1] if msa else "??"
                    print(f"sent {parse(msg)['control_id']} -> {code}")
                    return 0 if code == "AA" else 1
    except OSError as exc:
        print(f"connection to {a.host}:{a.port} failed: {exc}")
        return 2
    print("no ACK received")
    return 1


if __name__ == "__main__":
    sys.exit(main())
