"""CLI:  python3 -m fwsim {scenarios|incidents|trace}"""
import argparse
import sys

from sjvnet.model import ObjectModel
from sjvnet.policy import Packet, Policy

from . import incidents, scenarios
from .engines import StatefulFirewall


def trace(args) -> int:
    pol = Policy.load(model=ObjectModel.load())
    fw = StatefulFirewall(pol, ngfw=True)
    pkt = Packet(args.src, args.dst, args.proto, args.dport, args.sport, args.flags,
                 tuple(args.group or ()), args.path, args.app)
    d = fw.process(pkt)
    print(f"{pkt}\n  -> {d}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fwsim", description="Firewall generation simulator (CS07 Part I)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scenarios", help="five stateless failures, App-ID and rule order")
    sub.add_parser("incidents", help="replay F1-F3 and other risks through old vs new design")
    t = sub.add_parser("trace", help="evaluate one packet against the new policy")
    t.add_argument("src"); t.add_argument("dst")
    t.add_argument("--proto", default="tcp"); t.add_argument("--dport", type=int)
    t.add_argument("--sport", type=int, default=50000); t.add_argument("--flags", default="S")
    t.add_argument("--group", action="append", help="directory group of the user (repeatable)")
    t.add_argument("--path", help="URL path, for portal rules"); t.add_argument("--app", help="App-ID result, e.g. ssh")
    args = ap.parse_args(argv)
    if args.cmd == "scenarios":
        scenarios.run_all()
    elif args.cmd == "incidents":
        rows = incidents.run()
        return 0 if all(r[-1] is not False for r in rows) else 1
    else:
        return trace(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
