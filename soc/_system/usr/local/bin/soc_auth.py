#!/usr/bin/env python3
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen

BASE = Path("/home/ubuntu/auth-lab")
BASE.mkdir(parents=True, exist_ok=True)

EVENTS = BASE / "events.json"
ALERT = BASE / "alerts.log"
RESPONSE = BASE / "response.log"

SERVER = "http://172.29.116.20:8080"
ATTACKER_IP = "172.29.116.10"

def collect():
    with urlopen(SERVER + "/events", timeout=8) as r:
        data = json.load(r)

    events = data["events"]
    EVENTS.write_text(json.dumps(events, indent=2))

    failures = sum(
        e.get("event") == "AUTH_FAILURE"
        for e in events
    )

    print(f"SOC_COLLECT_OK events={len(events)} failures={failures}")

def detect():
    if not EVENTS.exists():
        sys.exit("RUN_COLLECT_FIRST")

    events = json.loads(EVENTS.read_text())
    failures = {}

    for e in events:
        if e.get("event") != "AUTH_FAILURE":
            continue

        ip = e["source_ip"]
        ts = datetime.fromisoformat(e["timestamp"])
        failures.setdefault(ip, []).append(ts)

    for ip, times in failures.items():
        times.sort()

        for start in range(len(times)):
            window = [
                t for t in times[start:]
                if 0 <= (t - times[start]).total_seconds() <= 60
            ]

            if len(window) >= 5:
                message = (
                    f"HTTP_BRUTEFORCE_DETECTED "
                    f"source_ip={ip} failures={len(window)}"
                )

                with ALERT.open("a") as f:
                    f.write(message + "\n")

                print(message)
                return

    sys.exit("NO_BRUTEFORCE_DETECTED")

def block():
    if not ALERT.exists():
        sys.exit("RUN_DETECT_FIRST")

    evidence = ALERT.read_text()

    if f"source_ip={ATTACKER_IP}" not in evidence:
        sys.exit("NO_MATCHING_ATTACKER_ALERT")

    body = json.dumps({"ip": ATTACKER_IP}).encode()

    req = Request(
        SERVER + "/block",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urlopen(req, timeout=8) as r:
        result = json.load(r)

    if result.get("result") != "block_applied":
        sys.exit("BLOCK_FAILED")

    message = f"SOC_BLOCK_APPLIED source_ip={ATTACKER_IP}"

    with RESPONSE.open("a") as f:
        f.write(message + "\n")

    print(message)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: soc_auth.py collect|detect|block")

    commands = {
        "collect": collect,
        "detect": detect,
        "block": block
    }

    command = commands.get(sys.argv[1])

    if command is None:
        sys.exit("UNKNOWN_MODE")

    command()
