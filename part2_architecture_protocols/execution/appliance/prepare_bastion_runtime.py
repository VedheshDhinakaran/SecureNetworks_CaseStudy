"""Copy public experiment/tools sources to an ignored runtime with Unix shell endings.

Windows Git checkouts can contain CRLF, which breaks the original POSIX shell
scripts in WSL. Only these deployed copies are normalised; original source and
already collected runtime evidence are never overwritten by this preparation.
"""
from pathlib import Path
import hashlib
import json

EXECUTION = Path(__file__).resolve().parents[1]
ROOT = EXECUTION.parents[1]
RUNTIME = EXECUTION / ".local/part4_runtime"
DIRECTORIES = ("common", "part2_architecture_protocols/network", "part3_rulebase_policy", "part4_lab_monitoring_response")
SUFFIXES = {".py", ".sh", ".yaml", ".yml", ".csv", ".rules", ".xml", ".conf", ".md", ".ios"}


def main() -> None:
    records = []
    for directory in DIRECTORIES:
        for source in sorted((ROOT / directory).rglob("*")):
            if not source.is_file() or source.suffix not in SUFFIXES:
                continue
            relative = source.relative_to(ROOT)
            if any(part in {".local", ".git", "__pycache__", "evidence"} for part in relative.parts):
                continue
            data = source.read_bytes()
            deployed = data.replace(b"\r\n", b"\n") if source.suffix == ".sh" else data
            target = RUNTIME / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(deployed)
            records.append({"source": relative.as_posix(), "source_sha256": hashlib.sha256(data).hexdigest(),
                            "deployed_sha256": hashlib.sha256(deployed).hexdigest()})
    (RUNTIME / "source_manifest.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print("Bastion runtime: " + str(RUNTIME))
    print("Public sources copied: " + str(len(records)) + "; original sources and evidence retained")


if __name__ == "__main__":
    main()
