"""Exercise the original stand-in services over real loopback sockets.

These checks verify service processes, HTTP and MLLP framing/ACKs. They do
not pass through OPNsense and are explicitly not segmentation evidence.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent / "lab" / "services"
sys.path.insert(0, str(SERVICES))
import hl7


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_ready(process: subprocess.Popen, port: int) -> None:
    limit = time.monotonic() + 10
    while time.monotonic() < limit:
        if process.poll() is not None:
            raise RuntimeError("Service exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("Service did not listen within 10 seconds")


def mllp_request(port: int, message: str) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(hl7.frame(message))
        buf = b""
        while len(buf) < 65536:
            block = sock.recv(4096)
            if not block:
                break
            buf += block
            messages, _ = hl7.unframe(buf)
            if messages:
                return messages[0]
    raise RuntimeError("No complete MLLP reply")


def main() -> int:
    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30)))
    out = HERE / "results" / ("local_services_" + now.strftime("%Y%m%dT%H%M%S"))
    out.mkdir(parents=True, exist_ok=False)
    processes = []
    logs = []
    checks = []
    try:
        ports = {}
        for name, filename in (("emr", "emr_app.py"), ("mssql_listener", "fake_mssql.py"),
                               ("mllp", "mllp_server.py")):
            port = free_port()
            ports[name] = port
            log = (out / (name + "_process.txt")).open("w", encoding="utf-8")
            logs.append(log)
            proc = subprocess.Popen([sys.executable, "-B", "-u", str(SERVICES / filename),
                                     "--bind", "127.0.0.1", "--port", str(port)],
                                    cwd=SERVICES, stdout=log, stderr=subprocess.STDOUT)
            processes.append(proc)
            wait_ready(proc, port)
        for path, content in (("/health", "ok"), ("/portal/test", "Synthetic test page")):
            conn = http.client.HTTPConnection("127.0.0.1", ports["emr"], timeout=3)
            try:
                conn.request("GET", path)
                response = conn.getresponse()
                body = response.read().decode()
                ok = response.status == 200 and content in body
                checks.append({"name": "emr_http_" + path.strip("/").replace("/", "_"),
                               "passed": ok, "http_status": response.status, "body": body})
            finally:
                conn.close()
        with socket.create_connection(("127.0.0.1", ports["mssql_listener"]), timeout=3) as sock:
            sock.sendall(b"CS07 connectivity check; not a TDS or SQL query")
        checks.append({"name": "mssql_tcp_listener", "passed": True,
                       "limitation": "TCP listener only; no real SQL database or TDS protocol"})
        message = hl7.oru_vitals("LOCAL-SERVICE-CHECK")
        reply = mllp_request(ports["mllp"], message)
        control_id = hl7.parse(message)["control_id"]
        checks.append({"name": "hl7_valid_observation_ack", "passed": "MSA|AA|" + control_id in reply,
                       "request": message, "reply": reply})
        rejected = mllp_request(ports["mllp"], "INVALID TEST MESSAGE")
        checks.append({"name": "hl7_malformed_message_rejected", "passed": "MSA|AR|" in rejected,
                       "reply": rejected})
        client = subprocess.run([sys.executable, "-B", str(SERVICES / "mllp_client.py"),
                                 "--host", "127.0.0.1", "--port", str(ports["mllp"]),
                                 "--device", "LOCAL-CLIENT-CHECK"],
                                capture_output=True, text=True, timeout=10)
        checks.append({"name": "original_mllp_client", "passed": client.returncode == 0,
                       "exit_code": client.returncode, "stdout": client.stdout, "stderr": client.stderr})
    except Exception as exc:
        checks.append({"name": "service_execution_error", "passed": False,
                       "error": type(exc).__name__ + ": " + str(exc)})
    finally:
        for proc in reversed(processes):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        for log in logs:
            log.close()
    report = {"recorded_at": now.isoformat(), "kind": "local_service_integration_only",
              "firewall_lab_verified": False, "bind_address": "127.0.0.1", "checks": checks}
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    hashes = [hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name
              for p in sorted(out.iterdir()) if p.is_file()]
    (out / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    for check in checks:
        print(check["name"] + ": " + ("PASS" if check["passed"] else "FAIL"))
    print("Saved: " + str(out))
    return int(any(not check["passed"] for check in checks))


if __name__ == "__main__":
    raise SystemExit(main())
