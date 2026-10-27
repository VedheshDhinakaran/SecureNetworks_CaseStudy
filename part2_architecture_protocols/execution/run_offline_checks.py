"""Run the existing offline gates and keep their real output in Part II.

No existing source or generated design file is rewritten. Pytest's temporary
files and caches stay in this directory's ignored .local folder.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def main() -> int:
    stamp = dt.datetime.now(IST).strftime("%Y%m%dT%H%M%S")
    out = HERE / "results" / ("offline_" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    temp = HERE / ".local" / "pytest" / uuid.uuid4().hex
    temp.parent.mkdir(parents=True, exist_ok=True)
    # Pytest may clear --basetemp. Only pass a new path inside our own .local.
    assert not temp.exists() and temp.resolve().is_relative_to(HERE / ".local")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
               PYTHONIOENCODING="utf-8")
    checks = [
        ("part2_unit_tests", ["-m", "pytest", "-q", "-p", "no:cacheprovider",
          "tests/test_model.py", "tests/test_hl7.py"]),
        ("object_validation", ["part2_architecture_protocols/tools/validate_objects.py"]),
        ("policy_lint", ["part3_rulebase_policy/tools/lint_policy.py"]),
        ("policy_probes", ["part3_rulebase_policy/tools/verify_matrix.py", "-q"]),
        ("lab_subset", ["part3_rulebase_policy/tools/check_lab_subset.py"]),
        ("all_existing_tests", ["-m", "pytest", "-q", "-p", "no:cacheprovider",
          "--basetemp", str(temp)]),
    ]
    records = []
    for name, args in checks:
        command = [sys.executable, "-B", *args]
        started = dt.datetime.now(IST).isoformat()
        proc = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=180)
        transcript = "command: " + subprocess.list2cmdline(command) + "\n"
        transcript += "started: " + started + "\nexit_code: " + str(proc.returncode)
        transcript += "\n\nSTDOUT\n" + proc.stdout + "\nSTDERR\n" + proc.stderr
        (out / (name + ".txt")).write_text(transcript, encoding="utf-8")
        records.append({"name": name, "exit_code": proc.returncode,
                        "transcript": name + ".txt", "started_at": started})
        print(name + ": " + ("PASS" if proc.returncode == 0 else "FAIL"), flush=True)
    baseline = json.loads((HERE / "baseline_sha256.json").read_text(encoding="utf-8"))
    changed = [p for p, sha in baseline["source_files"].items()
               if not (ROOT / p).is_file()
               or hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != sha]
    report = {
        "recorded_at": dt.datetime.now(IST).isoformat(), "kind": "offline_only",
        "firewall_lab_verified": False, "python_version": sys.version,
        "git_commit": baseline["git_commit"], "checks": records,
        "existing_source_files_changed": changed,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    hashes = [hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name
              for p in sorted(out.iterdir()) if p.is_file()]
    (out / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    print("Saved: " + str(out))
    print("Existing source files changed: " + str(len(changed)))
    return int(bool(changed) or any(r["exit_code"] for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
