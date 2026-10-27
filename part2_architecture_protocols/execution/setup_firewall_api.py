"""Create the lab API key required by the existing Part III loader.

Uses the same OPNsense user/API-key endpoint as the GUI. Credentials are
stored only in ignored .local/api/apikey.txt and never printed. Factory
password is used only for this isolated lab's initial setup; override it
with OPN_BOOTSTRAP_PASSWORD after changing the VM's password.
"""
from __future__ import annotations

import argparse
import datetime as dt
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re

import requests
import urllib3

HERE = Path(__file__).resolve().parent
HOST = "192.168.90.1"
BASE = "https://" + HOST


class HiddenFields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-key", action="store_true", help="Create a key through the lab GUI's API")
    args = parser.parse_args()
    if not args.create_key:
        parser.error("Key creation is explicit: pass --create-key for the isolated CS07 lab")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    dest = HERE / ".local" / "api" / "apikey.txt"
    if dest.exists():
        credentials = dict(line.split("=", 1) for line in dest.read_text().splitlines() if "=" in line)
        response = requests.post(BASE + "/api/firewall/filter/searchRule",
                                 auth=(credentials["key"], credentials["secret"]),
                                 json={"current": 1, "rowCount": 1}, verify=False, timeout=60)
        response.raise_for_status()
        if "rows" not in response.json():
            raise RuntimeError("Saved API credentials were not accepted; refusing to create another key automatically")
        print("Existing lab API credentials verified; secret values were not printed")
        return
    session = requests.Session()
    response = session.get(BASE + "/", verify=False, timeout=60)
    response.raise_for_status()
    fields = HiddenFields()
    fields.feed(response.text)
    data = dict(fields.fields, usernamefld="root",
                passwordfld=os.environ.get("OPN_BOOTSTRAP_PASSWORD", "opnsense"), login="Login")
    response = session.post(BASE + "/", data=data, verify=False, timeout=60,
                            headers={"Referer": BASE + "/"})
    response.raise_for_status()
    if 'name="passwordfld"' in response.text or 'name="usernamefld"' in response.text:
        raise RuntimeError("Lab GUI login did not succeed")
    # Login rotates CSRF state. Read the same authenticated page used by
    # the GUI before posting, and use its fresh form/script token.
    response = session.get(BASE + "/ui/auth/user/", verify=False, timeout=60)
    response.raise_for_status()
    fresh = HiddenFields()
    fresh.feed(response.text)
    name = re.search(r'csrfMagicName\s*=\s*[\'"]([^\'"]+)', response.text)
    token = re.search(r'csrfMagicToken\s*=\s*[\'"]([^\'"]+)', response.text)
    if name and token:
        fresh.fields[name.group(1)] = token.group(1)
    data = fresh.fields or fields.fields
    api_headers = {"Referer": BASE + "/ui/auth/user", "X-Requested-With": "XMLHttpRequest"}
    header_token = re.search(r'X-CSRFToken[\'"]\s*,\s*[\'"]([^\'"]+)', response.text)
    if header_token:
        api_headers["X-CSRFToken"] = header_token.group(1)
    result = session.post(BASE + "/api/auth/user/addApiKey/root", data=data,
                          headers=api_headers,
                          verify=False, timeout=60)
    if result.status_code != 200:
        dest.parent.mkdir(parents=True, exist_ok=True)
        (dest.parent / "last_api_error.txt").write_text(result.text, encoding="utf-8")
        raise RuntimeError("Lab API returned HTTP " + str(result.status_code)
                           + "; private diagnostic saved in .local/api/last_api_error.txt")
    payload = result.json()
    if payload.get("result") != "ok" or not payload.get("key") or not payload.get("secret"):
        raise RuntimeError("The lab GUI did not return a new API key; response values withheld")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("key=" + payload["key"] + "\nsecret=" + payload["secret"] + "\n", encoding="utf-8")
    dest.chmod(0o600)
    record = {"recorded_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "host": HOST, "account": "root", "status": "API key created through OPNsense GUI endpoint",
              "credential_file": ".local/api/apikey.txt", "secret_values_logged": False}
    (HERE / "results" / "api_setup.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("Created the lab API key; credentials saved in ignored .local/api/apikey.txt")


if __name__ == "__main__":
    main()
