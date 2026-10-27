"""Download the original lab's installer media from official HTTPS servers.

Media is saved only to execution/.local/media and verified against the
publisher's SHA256 manifest. Existing verified downloads are reused.
"""
from __future__ import annotations

import argparse
import bz2
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import urllib.request

HERE = Path(__file__).resolve().parent
MEDIA = HERE / ".local" / "media"
SPECS = {
    "virtualbox": {
        "file": "VirtualBox-7.2.22-175245-Win.exe",
        "base": "https://download.virtualbox.org/virtualbox/7.2.22/",
        "manifest": "SHA256SUMS",
    },
    "opnsense": {
        "file": "OPNsense-25.7-dvd-amd64.iso.bz2",
        "base": "https://pkg.opnsense.org/releases/25.7/",
        "manifest": "OPNsense-25.7-checksums-amd64.sha256",
    },
    "alpine": {
        "file": "alpine-virt-3.20.10-x86_64.iso",
        "base": "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/",
        "manifest": "alpine-virt-3.20.10-x86_64.iso.sha256",
    },
}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(kind: str) -> dict:
    spec = SPECS[kind]
    MEDIA.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(spec["base"] + spec["manifest"], timeout=60) as response:
        manifest = response.read().decode("utf-8")
    matching = [line for line in manifest.splitlines() if spec["file"] in line]
    if len(matching) != 1:
        raise RuntimeError("Cannot identify publisher checksum for " + spec["file"])
    matches = re.findall(r"\b[a-fA-F0-9]{64}\b", matching[0])
    if len(matches) != 1:
        raise RuntimeError("Ambiguous publisher checksum")
    expected = matches[0].lower()
    path = MEDIA / spec["file"]
    if path.exists():
        if sha256(path) != expected:
            raise RuntimeError("Existing media has a different checksum: " + str(path))
        print("Already verified: " + path.name, flush=True)
    else:
        partial = path.with_name(path.name + ".part")
        total = 0
        milestone = 0
        request = urllib.request.Request(spec["base"] + spec["file"],
                                         headers={"User-Agent": "CS07-lab-media/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as stream:
            while block := response.read(1024 * 1024):
                stream.write(block)
                total += len(block)
                if total // (32 * 1024 * 1024) > milestone:
                    milestone = total // (32 * 1024 * 1024)
                    print(path.name + ": " + str(total // (1024 * 1024)) + " MiB", flush=True)
        if sha256(partial) != expected:
            raise RuntimeError("Downloaded media checksum failed: " + str(partial))
        partial.replace(path)
        print("Verified: " + path.name, flush=True)
    (MEDIA / (kind + "_publisher_checksums.txt")).write_text(manifest, encoding="utf-8")
    record = {"filename": path.name, "url": spec["base"] + spec["file"],
              "checksum_url": spec["base"] + spec["manifest"], "sha256": expected,
              "bytes": path.stat().st_size, "verified_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    if kind == "opnsense":
        iso = path.with_suffix("")
        marker = iso.with_suffix(".iso.sha256")
        if not iso.exists():
            partial = iso.with_name(iso.name + ".part")
            print("Decompressing OPNsense ISO", flush=True)
            with bz2.open(path, "rb") as src, partial.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            partial.replace(iso)
            marker.write_text(sha256(iso) + "  " + iso.name + "\n", encoding="utf-8")
        if not marker.exists() or marker.read_text().split()[0] != sha256(iso):
            raise RuntimeError("Decompressed ISO differs from the saved verified extraction")
        record["iso_sha256"] = sha256(iso)
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("media", choices=[*SPECS, "all"], default="all", nargs="?")
    args = parser.parse_args()
    kinds = list(SPECS) if args.media == "all" else [args.media]
    records = {}
    manifest_path = HERE / "results" / "media_manifest.json"
    if manifest_path.exists():
        records = json.loads(manifest_path.read_text(encoding="utf-8"))
    for kind in kinds:
        records[kind] = fetch(kind)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
