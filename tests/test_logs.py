"""Part IV log tooling on synthetic fixtures (see fixtures/README.md)."""
from pathlib import Path

import correlate
import eve_summary
import hit_counter_review
import timeline
from sjvnet.model import ObjectModel
from sjvnet.opnsense import label_map_from_debug, parse_filterlog

FIX = Path(__file__).parent / "fixtures"
LABELS = label_map_from_debug((FIX / "rules_debug_SYNTHETIC.txt").read_text())


def events():
    with open(FIX / "filterlog_SYNTHETIC.log") as fh:
        return list(parse_filterlog(fh, LABELS, year=2030))


def test_label_map():
    assert LABELS["aaaa0001"] == "DV-01"
    assert LABELS["bbbb0003"] == "G-03"


def test_filterlog_fields_rfc5424_and_bsd():
    evs = events()
    assert len(evs) == 8                       # comment and sshd lines skipped
    first = evs[0]
    assert (first.src, first.dst, first.proto, first.dport, first.action, first.rule_id) == \
        ("192.168.40.100", "192.168.10.20", "tcp", 1433, "block", "G-03")
    assert first.time.utcoffset().total_seconds() == 5.5 * 3600
    bsd = evs[-1]
    assert bsd.time.year == 2030 and bsd.dport == 443 and bsd.rule_id == "DV-05"
    udp = evs[6]
    assert udp.proto == "udp" and udp.dport == 123


def test_timeline_marks(tmp_path, capsys):
    marks = tmp_path / "attempt_times.csv"
    marks.write_text("2030-01-01T10:00:04+05:30,rad,F2 attempt 1\n2030-01-01T11:00:00+05:30,rad,never logged\n")
    rc = timeline.main([str(FIX / "filterlog_SYNTHETIC.log"), "--rules-debug", str(FIX / "rules_debug_SYNTHETIC.txt"),
                        "--year", "2030", "--src", "192.168.40.100", "--marks", str(marks)])
    err = capsys.readouterr().err
    assert rc == 1 and "FOUND" in err and "MISSING" in err


def test_correlation_use_cases():
    alerts = correlate.correlate(events(), ObjectModel.load(), correlate.LAB)
    ucs = [a.uc for a in alerts]
    assert ucs.count("UC-02") == 2
    assert "UC-01" in ucs and "UC-04" in ucs and "UC-03" in ucs
    uc01 = next(a for a in alerts if a.uc == "UC-01")
    assert uc01.src == "10.61.0.50"


def test_production_thresholds_are_quieter():
    alerts = correlate.correlate(events(), ObjectModel.load(), correlate.PROD)
    assert {a.uc for a in alerts} == {"UC-01", "UC-02"}


def test_hit_counter_review():
    counters = hit_counter_review.parse_pfctl((FIX / "pfctl_vvsr_SYNTHETIC.txt").read_text())
    agg = hit_counter_review.aggregate(counters, LABELS)
    assert agg["DV-01"].packets == 10                # TCP + UDP rules summed
    rows = {r["rule"]: r for r in hit_counter_review.review(agg, None, {"G-03", "DV-05"})}
    assert "DEAD" in rows["DV-03"]["flags"]
    assert "ALERT" in rows["G-03"]["flags"]
    assert any(k.startswith("UNMAPPED") for k in rows)


def test_hit_counter_hot_against_baseline():
    counters = hit_counter_review.parse_pfctl((FIX / "pfctl_vvsr_SYNTHETIC.txt").read_text())
    cur = hit_counter_review.aggregate(counters, LABELS)
    base = hit_counter_review.aggregate(counters, LABELS)
    base["DV-05"].packets = 1
    rows = {r["rule"]: r for r in hit_counter_review.review(cur, base, set())}
    assert "HOT" in rows["DV-05"]["flags"] and rows["DV-05"]["delta_packets"] == 11


def test_eve_summary(capsys):
    eve_summary.main([str(FIX / "eve_SYNTHETIC.json")])
    out = capsys.readouterr().out
    assert "3 alert(s), 2 dropped by IPS" in out
