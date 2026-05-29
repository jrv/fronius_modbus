#!/usr/bin/env python3
"""Read Fronius GEN24 Export Limit Control (Soft Limit) value."""

import hashlib
import json
import os
import re
import getpass
import requests
from requests.utils import parse_dict_header

HOST = "10.16.16.19"
USERNAME = "technician"
PATH = "/api/config/limit_settings/powerLimits"


def _hash_mode(host: str, user: str) -> str:
    resp = requests.get(f"http://{host}/api/status/common", timeout=5)
    version = resp.json().get("authenticationOptions", {}).get("digest", {}).get(f"{user}HashingVersion")
    return "md5" if version == 1 else "sha256"


def _fronius_request(host: str, path: str, username: str, password: str, mode: str, method: str = "GET", body=None) -> requests.Response:
    url = f"http://{host}{path}"
    r1 = requests.request(method, url, timeout=5)
    if r1.status_code != 401:
        return r1

    challenge_header = r1.headers.get("X-WWW-Authenticate") or r1.headers.get("www-authenticate", "")
    ch = parse_dict_header(re.sub(r"^Digest\s+", "", challenge_header, flags=re.IGNORECASE))
    realm = ch["realm"]
    nonce = ch["nonce"]
    qop = ch["qop"].split(",")[0]
    nc = "00000001"
    cnonce = os.urandom(8).hex()

    payload = f"{username}:{realm}:{password}".encode()
    h1 = hashlib.md5(payload).hexdigest() if mode == "md5" else hashlib.sha256(payload).hexdigest()
    ha2 = hashlib.sha256(f"{method}:{path}".encode()).hexdigest()
    digest = hashlib.sha256(f"{h1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()

    auth = (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
        f'uri="{path}", response="{digest}", qop={qop}, nc={nc}, cnonce="{cnonce}"'
    )
    if ch.get("opaque"):
        auth += f', opaque="{ch["opaque"]}"'

    headers = {"Authorization": auth}
    if body is not None:
        headers["Content-Type"] = "application/json"

    return requests.request(method, url, headers=headers, json=body, timeout=5)


def main():
    password = getpass.getpass(f"Fronius {USERNAME} password for {HOST}: ")
    mode = _hash_mode(HOST, USERNAME)
    print(f"Hash mode: {mode}\n")

    # Read current config
    resp = _fronius_request(HOST, PATH, USERNAME, password, mode)
    print(f"GET {PATH} -> HTTP {resp.status_code}")
    if not resp.ok:
        print(resp.text[:500])
        return

    data = resp.json()
    print(json.dumps(data, indent=2))
    soft = data.get("exportLimits", {}).get("activePower", {}).get("softLimit", {})
    if soft:
        enabled = soft.get("enabled", False)
        power_w = soft.get("powerLimit", 0)
        print(f"\nExport Soft Limit: {'ENABLED' if enabled else 'DISABLED'}, {power_w} W")

    # Optionally test a write
    test_w = input("\nEnter new soft limit in W to test write (or Enter to skip): ").strip()
    if test_w:
        config = data
        active = config.setdefault("exportLimits", {}).setdefault("activePower", {})
        active.setdefault("softLimit", {})["enabled"] = True
        active.setdefault("softLimit", {})["powerLimit"] = int(test_w)

        resp2 = _fronius_request(HOST, PATH, USERNAME, password, mode, method="POST", body=config)
        print(f"POST {PATH} -> HTTP {resp2.status_code}")
        print(resp2.text[:300])


if __name__ == "__main__":
    main()
