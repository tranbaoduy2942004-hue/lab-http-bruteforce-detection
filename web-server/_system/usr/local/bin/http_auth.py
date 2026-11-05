#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = Path("/home/ubuntu/auth-lab")
BASE.mkdir(parents=True, exist_ok=True)

LOG = BASE / "access.log"
BLOCK = BASE / "blocked_ips.txt"
SOC_IP = "172.29.116.30"
ATTACKER_IP = "172.29.116.10"

def record(event, ip, username="", status=0):
    item = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "source_ip": ip,
        "username": username,
        "status": status
    }
    with LOG.open("a") as f:
        f.write(json.dumps(item) + "\n")

def blocked(ip):
    return BLOCK.exists() and ip in BLOCK.read_text().splitlines()

class Handler(BaseHTTPRequestHandler):
    def reply(self, code, data):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ok"})

        if self.path != "/events":
            return self.reply(404, {"error": "not_found"})

        if self.client_address[0] != SOC_IP:
            return self.reply(403, {"error": "soc_only"})

        lines = LOG.read_text().splitlines() if LOG.exists() else []
        events = [json.loads(line) for line in lines if line]
        self.reply(200, {"events": events})

    def do_POST(self):
        ip = self.client_address[0]

        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 4096:
                return self.reply(400, {"error": "invalid_size"})
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                return self.reply(400, {"error": "invalid_json"})
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_json"})

        if self.path == "/login":
            username = data.get("username", "")
            password = data.get("password", "")

            if not isinstance(username, str) or not isinstance(password, str):
                return self.reply(400, {"error": "invalid_credentials"})

            username = username[:64]

            if blocked(ip):
                record("AUTH_BLOCKED", ip, username, 403)
                return self.reply(403, {"result": "blocked"})

            if username == "student" and password == "Lab7@2026":
                record("AUTH_SUCCESS", ip, username, 200)
                return self.reply(200, {"result": "login_success"})

            record("AUTH_FAILURE", ip, username, 401)
            return self.reply(401, {"result": "login_failed"})

        if self.path == "/block":
            if ip != SOC_IP:
                return self.reply(403, {"error": "soc_only"})

            target = data.get("ip")
            if target != ATTACKER_IP:
                return self.reply(400, {"error": "invalid_target"})

            if not blocked(target):
                with BLOCK.open("a") as f:
                    f.write(target + "\n")

            record("BLOCK_APPLIED", ip, target, 200)
            return self.reply(200, {"result": "block_applied"})

        self.reply(404, {"error": "not_found"})

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    print("HTTP_AUTH_SERVER_READY", flush=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
