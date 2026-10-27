#!/bin/sh
# E6: Attack on a permitted port, IPS off then on (matrix test 9)
# Run on: rad-vm and vendor-vm. Requires the ET Open web_server and
# attack_response sets plus ../ids/suricata/sjv-custom.rules.
. "$(dirname "$0")/common.sh"
start_experiment E6 "IPS on a permitted port" "rad vendor"

attack() {
  case "$ROLE" in
    rad)
      run "curl -sS -m 5 -A 'sqlmap/1.8' -o /dev/null -w 'http=%{http_code}\n' \"http://192.168.10.21:443/portal/?id=1%27%20OR%20%271%27=%271\""
      run "curl -sS -m 5 -o /dev/null -w 'http=%{http_code}\n' \"http://192.168.10.21:443/portal/?q=1%20UNION%20SELECT%20username,password%20FROM%20users\""
      ;;
    vendor)
      run "curl -sS -m 5 http://testmynids.org/uid/index.html"
      ;;
  esac
}

case "$ROLE" in
  rad|vendor)
    phase "Suricata IPS OFF"
    attack
    phase "Suricata IPS ON (IPS mode, ET Open drop policy, sjv-custom loaded)"
    attack
    ;;
  *) no_steps "rad-vm, vendor-vm" ;;
esac
finish
echo "[i] Also export Services > Intrusion Detection > Alerts, or eve.json, into evidence/E6/."
