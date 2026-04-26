"""
HoneyTrack - HTTP Honeypot
---------------------------
Emulates a vulnerable web server on port 8080.
Detects SQLi, XSS, path traversal, scanners.
Pushes events to the shared queue.
"""

import socket
import threading
import logging
import json
import re
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime

from core.event_queue import push

# ── Logging ───────────────────────────────────
LOG_DIR = Path(__file__).parent.parent / "logs"
logger = logging.getLogger("http_honeypot")
logger.setLevel(logging.INFO)
if not logger.handlers:
    h = RotatingFileHandler(LOG_DIR / "http.log", maxBytes=5*1024*1024, backupCount=3)
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(h)

# ── Attack Pattern Detection ──────────────────
PATTERNS = {
    "sql_injection":   [r"union.*select", r"' or '", r"1=1", r"drop table", r"insert into"],
    "path_traversal":  [r"\.\./", r"etc/passwd", r"win/system32"],
    "xss":             [r"<script", r"javascript:", r"onerror=", r"onload="],
    "cmd_injection":   [r"cmd=", r"exec\(", r";ls", r"&&cat", r"\|whoami"],
    "scanner":         [r"/wp-admin", r"/phpmyadmin", r"/.env", r"/config", r"/.git"],
    "webshell":        [r"/shell", r"base64_decode", r"eval\(", r"system\("],
}

def _detect(text: str) -> dict:
    text = text.lower()
    found = {}
    for category, rules in PATTERNS.items():
        hits = [r for r in rules if re.search(r, text, re.I)]
        if hits:
            found[category] = hits
    return found

# ── Fake Responses ────────────────────────────
def _fake_response(path: str, method: str) -> bytes:
    if any(x in path.lower() for x in ["admin", "login", "wp-admin"]):
        body = b"<html><body><h2>Admin Panel</h2><form method='POST'><input name='user'><input type='password' name='pass'><button>Login</button></form></body></html>"
        return b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body
    elif any(x in path.lower() for x in ["passwd", ".env", "config"]):
        return b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>403 Forbidden</h1>"
    else:
        return b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>404 Not Found</h1>"

# ── Parse HTTP Request ────────────────────────
def _parse(raw: bytes):
    try:
        text   = raw.decode(errors="ignore")
        lines  = text.split("\r\n")
        parts  = lines[0].split(" ") if lines else []
        method = parts[0] if len(parts) > 0 else "UNKNOWN"
        path   = parts[1] if len(parts) > 1 else "/"
        headers = {}
        i = 1
        while i < len(lines) and lines[i]:
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                headers[k.strip().lower()] = v.strip()
            i += 1
        body = "\r\n".join(lines[i+1:]) if i < len(lines) else ""
        return method, path, headers, body
    except Exception:
        return "UNKNOWN", "/", {}, ""

# ── Client Handler ────────────────────────────
def _handle(sock, ip):
    try:
        sock.settimeout(10)
        raw = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw:
                break

        if not raw:
            return

        method, path, headers, body = _parse(raw)
        full_text = f"{method} {path} {body}"
        attack_patterns = _detect(full_text)
        is_attack = len(attack_patterns) > 0

        event = {
            "type":             "http_request",
            "src_ip":           ip,
            "method":           method,
            "path":             path,
            "user_agent":       headers.get("user-agent", "unknown"),
            "attack_patterns":  attack_patterns,
            "is_attack":        is_attack,
            "body_snippet":     body[:300],
        }
        push(event)
        logger.info(json.dumps(event))

        if is_attack:
            print(f"  [HTTP ATTACK] {ip} {method} {path} → {list(attack_patterns.keys())}")
        else:
            print(f"  [HTTP] {ip} {method} {path}")

        sock.send(_fake_response(path, method))

    except Exception:
        pass
    finally:
        sock.close()

# ── Main Listener ─────────────────────────────
def start(host="0.0.0.0", port=8080):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"  [HTTP] Listening on {host}:{port}")

    while True:
        try:
            sock, addr = srv.accept()
            threading.Thread(target=_handle, args=(sock, addr[0]), daemon=True).start()
        except Exception:
            break
    srv.close()
