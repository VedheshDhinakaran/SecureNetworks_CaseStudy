"""Minimal HL7 v2 + MLLP helpers (standard library only).

MLLP frames one HL7 message as:  <VT> message <FS><CR>
where VT = 0x0B, FS = 0x1C, CR = 0x0D. Segments inside the message are
separated by CR. This is enough to show the device -> interface engine
flow (rule DV-03) and the broker flow (R-02) in the lab.
"""
from __future__ import annotations

import datetime as _dt
import itertools

VT, FS, CR = b"\x0b", b"\x1c", b"\x0d"
_ids = itertools.count(1)


def frame(message: str) -> bytes:
    return VT + message.replace("\n", "\r").encode("utf-8") + FS + CR


def unframe(buffer: bytes) -> tuple[list[str], bytes]:
    """Split a byte buffer into complete messages; return (messages, leftover)."""
    out = []
    while True:
        start = buffer.find(VT)
        end = buffer.find(FS + CR, start + 1)
        if start == -1 or end == -1:
            return out, buffer
        out.append(buffer[start + 1:end].decode("utf-8", errors="replace"))
        buffer = buffer[end + 2:]


def parse(message: str) -> dict:
    segments = [s for s in message.split("\r") if s]
    if not segments or not segments[0].startswith("MSH"):
        raise ValueError("message does not start with an MSH segment")
    msh = segments[0].split("|")
    if len(msh) < 12:
        raise ValueError("MSH segment too short")
    return {
        "sending_app": msh[2], "sending_facility": msh[3],
        "type": msh[8], "control_id": msh[9], "version": msh[11],
        "segments": [s[:3] for s in segments],
    }


def _ts() -> str:
    return _dt.datetime.now().strftime("%Y%m%d%H%M%S")


def oru_vitals(device_id: str, patient_id: str = "MRN000123", rate_ml_h: float = 25.0) -> str:
    """ORU^R01 observation from an infusion pump (synthetic test patient)."""
    cid = f"{device_id}-{next(_ids):06d}"
    return "\r".join([
        f"MSH|^~\\&|{device_id}|SJV-ICU|SJV-IFENGINE|SJV|{_ts()}||ORU^R01|{cid}|P|2.5.1",
        f"PID|1||{patient_id}^^^SJV^MR||TEST^PATIENT",
        f"OBR|1|||INFUSION^Infusion status|||{_ts()}",
        f"OBX|1|NM|RATE^Infusion rate||{rate_ml_h}|mL/h|||||F",
    ])


def ack(original: str, code: str = "AA", text: str = "") -> str:
    info = parse(original)
    return "\r".join([
        f"MSH|^~\\&|SJV-IFENGINE|SJV|{info['sending_app']}|{info['sending_facility']}|{_ts()}||ACK|ACK{info['control_id']}|P|{info['version']}",
        f"MSA|{code}|{info['control_id']}|{text}",
    ])
