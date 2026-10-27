#!/bin/sh
# =====================================================================
#  Shared helpers for experiments E1-E8 (report Ch. 11).
#  Sourced by eN_*.sh. POSIX sh, so it runs on Alpine (busybox ash) and
#  on the bastion host alike.
#
#  Every command is written to a timestamped transcript under
#  $RESULTS/<EXP>/<role>_<time>.txt together with the exact command line,
#  the time it ran and its exit code. The transcript is the raw evidence;
#  nothing in it is edited afterwards. Copy it into ../evidence/<EXP>/.
# =====================================================================
set -u

RESULTS="${RESULTS:-/opt/sjv/results}"
FW="${FW:-192.168.90.1}"          # firewall LAN (MGMT) address

detect_role() {
  ips="$(ip -4 -o addr show 2>/dev/null | awk '{print $4}')"
  case "$ips" in
    *192.168.40.100/*) echo rad ;;
    *192.168.30.10/*)  echo pump ;;
    *192.168.10.20/*)  echo his ;;
    *10.61.0.*)        echo vendor ;;
    *192.168.90.5/*)   echo bastion ;;
    *)                 echo unknown ;;
  esac
}

start_experiment() {   # start_experiment E2 "short title" "rad vendor bastion"
  EXP="$1"; TITLE="$2"; ROLES="${3:-}"
  ROLE="${ROLE:-$(detect_role)}"
  if [ -n "$ROLES" ]; then
    case " $ROLES " in
      *" $ROLE "*) ;;
      *) echo "[-] $EXP has no steps for role '$ROLE'. Run it on: $ROLES"; exit 0 ;;
    esac
  fi
  STAMP="$(date +%Y%m%dT%H%M%S)"
  mkdir -p "$RESULTS/$EXP"
  OUT="$RESULTS/$EXP/${ROLE}_${STAMP}.txt"
  {
    echo "# $EXP - $TITLE"
    echo "# role=$ROLE host=$(hostname) started=$(date -Iseconds 2>/dev/null || date)"
    echo "# addresses: $(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
    echo "# This transcript is raw tool output. Do not edit it."
  } > "$OUT"
  echo "[*] $EXP on $ROLE -> $OUT"
}

run() {   # run <command line> : execute, log command + output + exit code
  {
    echo
    echo "### $(date -Iseconds 2>/dev/null || date) $ROLE\$ $*"
  } >> "$OUT"
  sh -c "$*" >> "$OUT" 2>&1
  rc=$?
  echo "### exit=$rc" >> "$OUT"
  echo "    [$rc] $*"
  return 0
}

phase() {   # phase "Suricata OFF": pause until the operator confirms the GUI state
  echo
  printf '[?] Set the firewall to: %s\n    Press Enter when done (or type a note first): ' "$1"
  read -r reply || reply=""
  {
    echo
    echo "=== PHASE: $1 ==="
    echo "=== operator confirmed at $(date -Iseconds 2>/dev/null || date)${reply:+, note: $reply}"
  } >> "$OUT"
}

mark_time() {   # mark_time "F2 attempt 1" : record a wall-clock mark for E8 timelines
  echo "$(date -Iseconds 2>/dev/null || date),$ROLE,$1" >> "$RESULTS/attempt_times.csv"
  echo "=== MARK $(date -Iseconds 2>/dev/null || date) $1" >> "$OUT"
}

fw() {   # fw <command> : run a command on OPNsense over SSH (bastion only)
  run "ssh -o BatchMode=yes root@$FW '$*'"
}

no_steps() {
  echo "[-] $EXP has no steps for role '$ROLE'. Run it on: $1"
  rm -f "$OUT"
  exit 0
}

finish() {
  echo "# finished=$(date -Iseconds 2>/dev/null || date)" >> "$OUT"
  echo "[+] done. Transcript: $OUT"
  echo "    Record what you OBSERVED in ../evidence/$EXP/README.md (not what was expected)."
}
