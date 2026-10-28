"""Small Windows-host UDP syslog receiver for the isolated Part IV lab.

Keeps received syslog datagrams unchanged apart from a terminal newline, accepts
only 192.168.90.1 on the host-only address, and stores bounded ignored local logs.
It supports the existing E2/E8 scripts through a WSL file link. This is a lab
alternative to the original Linux rsyslog collector, not production retention.
"""
from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
import socket

EXECUTION = Path(__file__).resolve().parents[1]
MAX_BYTES = 16 * 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loopback-test", action="store_true", help="Bind only loopback port 15514 and exit after one packet")
    args = parser.parse_args()
    address, sender, port = ("127.0.0.1", "127.0.0.1", 15514) if args.loopback_test else ("192.168.90.5", "192.168.90.1", 514)
    output = EXECUTION / ".local" / ("collector_test" if args.loopback_test else "collector")
    output.mkdir(parents=True, exist_ok=True)
    path = output / "opnsense.log"
    path.touch(exist_ok=True)
    count = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, port))
    print(f"Listening for syslog from {sender} on {address}:{port}; output {path}", flush=True)
    try:
        while True:
            data, peer = sock.recvfrom(65535)
            if peer[0] != sender:
                continue
            if path.stat().st_size + len(data) + 1 > MAX_BYTES:
                previous = output / "opnsense.previous.log"
                # These are this receiver's two bounded, ignored runtime logs.
                path.replace(previous)
                path.touch()
                print("Rotated local lab log; export experiment evidence before another rotation", flush=True)
            with path.open("ab") as stream:
                stream.write(data.rstrip(b"\r\n") + b"\n")
            count += 1
            print(dt.datetime.now().astimezone().isoformat(timespec="seconds") + f" received packet {count}", flush=True)
            if args.loopback_test:
                break
    except KeyboardInterrupt:
        print("Stopped lab syslog receiver", flush=True)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
