"""Fetch specific official signed APKs when a guest download is interrupted.

Packages remain ignored. HTTPS authenticates the download; Alpine apk must
still verify the embedded package signature when installing (no untrusted flag).
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import concurrent.futures
import io
import shutil
import tarfile
import time

HERE = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="*")
    parser.add_argument("--build-cache", action="store_true", help="Cache the working HIS package set with official signed indexes")
    args = parser.parse_args()
    if args.build_cache:
        build_cache()
        return
    if not args.packages:
        parser.error("Supply package filenames or --build-cache")
    target = HERE / ".local/bootstrap/packages"
    target.mkdir(parents=True, exist_ok=True)
    records = []
    for name in args.packages:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+_-]*\.apk", name):
            parser.error("Supply APK filenames from Alpine 3.20 main/x86_64")
        url = "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64/" + name
        temporary = target / (name + ".partial")
        size = 0
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > 64 * 1024 * 1024:
                    raise ValueError("Unexpected package size")
                output.write(block)
        path = target / name
        temporary.replace(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append({"file": name, "url": url, "bytes": size, "sha256": digest,
                        "signature_check": "Required by guest apk at installation; not bypassed"})
        print(name + ": " + str(size) + " bytes downloaded over verified HTTPS")
    record = HERE / "results/bootstrap_package_downloads.json"
    previous = json.loads(record.read_text()) if record.exists() else []
    record.write_text(json.dumps(previous + records, indent=2) + "\n", encoding="utf-8")


def build_cache() -> None:
    directory = HERE / ".local/bootstrap/http/apk"
    packages = {}
    providers = {}
    for repository in ["main", "community"]:
        target = directory / repository / "x86_64"
        target.mkdir(parents=True, exist_ok=True)
        url = "https://dl-cdn.alpinelinux.org/alpine/v3.20/" + repository + "/x86_64/APKINDEX.tar.gz"
        data = urllib.request.urlopen(url, timeout=60).read()
        (target / "APKINDEX.tar.gz").write_bytes(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            text = archive.extractfile("APKINDEX").read().decode()
        for paragraph in text.split("\n\n"):
            record = dict(line.split(":", 1) for line in paragraph.splitlines() if ":" in line)
            if "P" not in record or record["P"] in packages:
                continue
            record["repository"] = repository
            packages[record["P"]] = record
            for capability in record.get("p", "").split():
                name = re.split(r"[<>=~]", capability)[0]
                providers.setdefault(name, []).append(record["P"])
    logs = sorted((HERE / "results/guest_setup").glob("his-vm_installed_package_names_*.txt"))
    if not logs:
        raise ValueError("First record apk info from the working HIS guest")
    seeds = {line for line in logs[-1].read_text().splitlines() if re.fullmatch(r"[a-z0-9][a-z0-9.+_-]*", line)}
    seeds.update(["alpine-base", "linux-virt", "syslinux", "linux-firmware-none", "e2fsprogs", "sfdisk"])
    selected = set()
    pending = list(seeds)
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        record = packages[name]
        selected.add(name)
        for requirement in record.get("D", "").split():
            dependency = re.split(r"[<>=~]", requirement)[0]
            if dependency.startswith("!"):
                continue
            if dependency in packages:
                pending.append(dependency)
            elif dependency in providers:
                choices = providers[dependency]
                pending.append(next((value for value in choices if value in seeds), choices[0]))
            else:
                raise ValueError("Cannot resolve signed cache dependency: " + dependency)

    def download(name):
        record = packages[name]
        filename = name + "-" + record["V"] + ".apk"
        target = directory / record["repository"] / "x86_64" / filename
        expected_size = int(record["S"])
        cached = HERE / ".local/bootstrap/packages" / filename
        if not target.exists() and cached.exists() and cached.stat().st_size == expected_size:
            shutil.copyfile(cached, target)
        url = "https://dl-cdn.alpinelinux.org/alpine/v3.20/" + record["repository"] + "/x86_64/" + filename
        if not target.exists() or target.stat().st_size != expected_size:
            for attempt in range(3):
                try:
                    data = urllib.request.urlopen(url, timeout=60).read()
                    if len(data) != expected_size:
                        raise ValueError("Incomplete package: " + filename)
                    target.write_bytes(data)
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(1)
        return {"package": name, "file": record["repository"] + "/x86_64/" + filename,
                "bytes": target.stat().st_size, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}

    print("Caching " + str(len(selected)) + " packages; signatures remain verified by guest apk", flush=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(download, sorted(selected)):
            results.append(result)
            if len(results) % 20 == 0:
                print(str(len(results)) + "/" + str(len(selected)) + " cached", flush=True)
    (HERE / "results/alpine_cache_manifest.json").write_text(json.dumps({
        "source": "Official Alpine 3.20 signed indexes and packages over verified HTTPS",
        "git_ignored": True, "bytes": sum(row["bytes"] for row in results),
        "packages": results}, indent=2) + "\n", encoding="utf-8")
    print("Signed local cache prepared: " + str(len(results)) + " packages, "
          + str(round(sum(row["bytes"] for row in results) / 1048576, 2)) + " MiB", flush=True)


if __name__ == "__main__":
    main()
