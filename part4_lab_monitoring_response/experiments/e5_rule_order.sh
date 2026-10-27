#!/bin/sh
# E5: Rule order / shadowing (report Section 11.5, E5)
# Run on: vendor-vm (and bastion for VW-01 counters).
. "$(dirname "$0")/common.sh"
start_experiment E5 "Rule order" "vendor bastion"

case "$ROLE" in
  vendor)
    phase "WRONG ORDER: 'Pass VENDOR net -> any:443' ABOVE VW-01"
    run "curl -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect reachable
    phase "RIGHT ORDER: same pass rule moved BELOW VW-01"
    run "curl -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' http://192.168.10.21:443/"   # expect blocked
    ;;
  bastion)
    phase "WRONG ORDER in place (after vendor-vm curl)"
    fw "pfctl -vvsr | grep -B1 -A2 'VW-01'"
    phase "RIGHT ORDER in place (after vendor-vm curl)"
    fw "pfctl -vvsr | grep -B1 -A2 'VW-01'"
    echo "[i] OPNsense labels rules by hash; use rules.debug or hit_counter_review.py to map them."
    ;;
  *) no_steps "vendor-vm, bastion" ;;
esac
finish
