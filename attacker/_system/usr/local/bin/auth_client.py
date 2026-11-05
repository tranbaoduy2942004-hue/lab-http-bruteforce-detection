#!/usr/bin/env python3
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

URL = "http://172.29.116.20:8080/login"
LOG = Path("/home/ubuntu/auth-lab/client.log")

def login(password):
    body = json.dumps({
        "username": "student",
        "password": password
    }).encode()

    req = Request(
        URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urlopen(req, timeout=5) as response:
            return response.status
    except HTTPError as error:
        return error.code

def save(message):
    with LOG.open("a") as f:
        f.write(message + "\n")
    print(message, flush=True)

def main():
    if len(sys.argv) != 2:
        sys.exit("Usage: auth_client.py normal|attack|verify")

    mode = sys.argv[1]

    if mode == "normal":
        status = login("Lab7@2026")
        if status != 200:
            sys.exit(f"NORMAL_FAILED: HTTP {status}")
        save("NORMAL_LOGIN_OK")

    elif mode == "attack":
        for i in range(6):
            status = login(f"wrong_password_{i}")
            if status != 401:
                sys.exit(f"ATTACK_FAILED: HTTP {status}")
            print(f"AUTH_FAILURE_OK {i+1}/6")
            if i < 5:
                time.sleep(1)
        save("HTTP_BRUTEFORCE_SENT count=6")

    elif mode == "verify":
        status = login("Lab7@2026")
        if status != 403:
            sys.exit(f"BLOCK_NOT_VERIFIED: HTTP {status}")
        save("HTTP_BLOCK_VERIFIED")

    else:
        sys.exit("UNKNOWN_MODE")

if __name__ == "__main__":
    main()
