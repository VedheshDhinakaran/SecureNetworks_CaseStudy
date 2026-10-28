"""Keep the historical source hashes while distinguishing committed team updates.

An intentional teammate commit is not a local modification made by the Part II
scripts. Uncommitted changes to original source still fail the preservation gate.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess


def audit_sources(root: Path, baseline: dict) -> dict:
    originals = set(baseline["source_files"])
    differences = sorted(name for name, digest in baseline["source_files"].items()
                         if not (root / name).is_file()
                         or hashlib.sha256((root / name).read_bytes()).hexdigest() != digest)
    dirty = set(subprocess.check_output(
        ["git", "diff", "HEAD", "--name-only", "--no-renames", "-z", "--", *sorted(originals)], cwd=root
    ).decode("utf-8").split("\0")) - {""}
    unexpected = sorted(originals & dirty)
    return {
        "baseline_commit": baseline["git_commit"],
        "reviewed_head_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(),
        "original_source_files_checked": len(originals),
        "original_source_files_changed": unexpected,
        "committed_source_updates_since_baseline": sorted(set(differences) - dirty),
        "source_audit_basis": "Historical hashes retained; committed team updates recorded separately; uncommitted original-source edits fail",
    }
