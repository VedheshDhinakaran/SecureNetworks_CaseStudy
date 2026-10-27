"""Part II lab services: MLLP framing and HL7 parsing."""
import hl7


def test_frame_roundtrip_and_partial_buffer():
    msg = hl7.oru_vitals("PUMP-030-010")
    framed = hl7.frame(msg)
    assert framed[:1] == b"\x0b" and framed[-2:] == b"\x1c\r"
    msgs, rest = hl7.unframe(framed + framed[:10])
    assert msgs == [msg] and rest == framed[:10]


def test_parse_and_ack():
    msg = hl7.oru_vitals("PUMP-030-010")
    info = hl7.parse(msg)
    assert info["type"] == "ORU^R01" and info["segments"] == ["MSH", "PID", "OBR", "OBX"]
    ack = hl7.parse(hl7.ack(msg))
    assert ack["type"] == "ACK"


def test_parse_rejects_non_hl7():
    import pytest
    with pytest.raises(ValueError):
        hl7.parse("hello not hl7")
