"""Headless console access restricted to this project's five lab VMs.

Uses VBoxManage rather than a desktop automation tool. Captures stay in
Part II. It does not delete VMs or alter host network/VirtualBox settings.
"""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import os
from pathlib import Path
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
NAMES = ("opnsense", "his-vm", "pump-vm", "rad-vm", "vendor-vm")
KEYS = {"enter": ["1c", "9c"], "tab": ["0f", "8f"], "space": ["39", "b9"],
        "up": ["e0", "48", "e0", "c8"], "down": ["e0", "50", "e0", "d0"],
        "left": ["e0", "4b", "e0", "cb"], "right": ["e0", "4d", "e0", "cd"],
        "escape": ["01", "81"], "ctrl_c": ["1d", "2e", "ae", "9d"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vm", choices=NAMES)
    parser.add_argument("--vm-root", type=Path, default=Path.home() / "VirtualBox VMs" / "CS07")
    parser.add_argument("--text")
    parser.add_argument("--keys", nargs="*", choices=KEYS, default=[])
    parser.add_argument("--wait", type=float, default=2)
    parser.add_argument("--capture", default="console")
    parser.add_argument("--evidence", action="store_true", help="Keep this screenshot in public results; otherwise store ignored debug output")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--eject-iso", action="store_true", help="Detach installer DVD from a powered-off lab VM")
    args = parser.parse_args()
    if not 0 <= args.wait <= 10:
        parser.error("--wait must be between 0 and 10 seconds")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.capture):
        parser.error("Use a simple screenshot label")
    vbox = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Oracle/VirtualBox/VBoxManage.exe"

    def run(*parts):
        return subprocess.run([str(vbox), *parts], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", check=True, timeout=45).stdout

    info = run("showvminfo", args.vm, "--machinereadable")
    cfg = next(line.split("=", 1)[1] for line in info.splitlines() if line.startswith("CfgFile="))
    registered_path = Path(ast.literal_eval(cfg)).resolve()
    expected_path = (args.vm_root / args.vm / (args.vm + ".vbox")).resolve()
    if registered_path != expected_path:
        raise RuntimeError("Refusing to control a VM outside the specified CS07 lab directory")
    if args.eject_iso:
        if 'VMState="poweroff"' not in info:
            raise RuntimeError("Shut down the installed guest before detaching its installer DVD")
        run("storageattach", args.vm, "--storagectl", "SATA", "--port", "1", "--device", "0",
            "--type", "dvddrive", "--medium", "none")
    if args.start and 'VMState="running"' not in info:
        print(run("startvm", args.vm, "--type", "headless"), end="")
    if args.text is not None:
        # A long burst can overflow the guest's virtual keyboard buffer,
        # particularly while several guests boot under Hyper-V. Pace input.
        for offset in range(0, len(args.text), 12):
            run("controlvm", args.vm, "keyboardputstring", args.text[offset:offset + 12])
            time.sleep(0.15)
    for key in args.keys:
        run("controlvm", args.vm, "keyboardputscancode", *KEYS[key])
        time.sleep(0.2)
    time.sleep(args.wait)
    stamp = dt.datetime.now(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime("%Y%m%dT%H%M%S")
    directory = HERE / "results/vm_installation" if args.evidence else HERE / ".local/console_debug"
    dest = directory / (args.vm + "_" + args.capture + "_" + stamp + ".png")
    dest.parent.mkdir(parents=True, exist_ok=True)
    run("controlvm", args.vm, "screenshotpng", str(dest))
    print("Screenshot: " + str(dest))


if __name__ == "__main__":
    main()
