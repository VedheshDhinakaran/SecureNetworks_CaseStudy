# Test fixtures

Every file here is **synthetic**: written by hand so the parsers and
reviewers have something deterministic to test against. The `_SYNTHETIC`
suffix and the header comment in each file say so. None of these files
is lab evidence and none should be quoted in the report as a result.

| File | Used by |
|---|---|
| `pfctl_vvsr_SYNTHETIC.txt` | `test_logs.py` → `hit_counter_review.py` |
| `rules_debug_SYNTHETIC.txt` | label-hash → rule-ID mapping |
| `filterlog_SYNTHETIC.log` | `timeline.py`, `correlate.py` |
| `eve_SYNTHETIC.json` | `eve_summary.py` |
| `shadowed_policy.yaml` | `test_policy.py`: a deliberately broken rule base the linter must reject |
