# Lab configuration export

Put here, from the real lab:

1. `config-sanitised.xml`: System > Configuration > Backups > Download, then
   remove password hashes, API keys, certificates' private keys and the
   Zenarmor licence before committing. Never commit the unsanitised file.
2. `pfctl_sr.txt`: `ssh root@192.168.90.1 'pfctl -sr' > pfctl_sr.txt`
   (the auditable record of the lab policy, as the report asks).
3. `rules_debug.txt`: `ssh root@192.168.90.1 'cat /tmp/rules.debug'`
   (maps pf label hashes to our rule IDs for hit_counter_review.py and timeline.py).

Checklist before committing:
- [ ] no `<password>` / `<bcrypt-hash>` values
- [ ] no `<apikeys>` entries
- [ ] no `<prv>` private keys
