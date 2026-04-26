"""
HoneyTrack - VirusTotal Client
--------------------------------
Checks attacker IPs against 70+ security vendors.
Rate-limited queue for free API (4 req/min).
"""

import requests
import time
import os
import threading
from datetime import datetime

VT_API_KEY   = os.getenv("VT_API_KEY", "")
VT_BASE_URL  = "https://www.virustotal.com/api/v3"
VT_DELAY     = 16   # seconds between requests (free tier = 4/min)


def check_ip(ip: str) -> dict:
    """Query VirusTotal for one IP. Returns structured result."""
    if not VT_API_KEY or VT_API_KEY == "YOUR_VT_API_KEY_HERE":
        print(f"  [VT] No API key — skipping {ip}")
        return {"ip": ip, "verdict": "skipped", "malicious": 0}

    url     = f"{VT_BASE_URL}/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 200:
            data  = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)

            if malicious >= 10:
                verdict = "MALICIOUS"
            elif malicious >= 3 or suspicious >= 5:
                verdict = "SUSPICIOUS"
            elif malicious >= 1:
                verdict = "LOW_RISK"
            else:
                verdict = "CLEAN"

            result = {
                "ip":           ip,
                "checked_at":   datetime.utcnow().isoformat(),
                "malicious":    malicious,
                "suspicious":   suspicious,
                "harmless":     stats.get("harmless",   0),
                "undetected":   stats.get("undetected", 0),
                "reputation":   attrs.get("reputation", 0),
                "country":      attrs.get("country",    "Unknown"),
                "as_owner":     attrs.get("as_owner",   "Unknown"),
                "tags":         attrs.get("tags",       []),
                "verdict":      verdict,
            }
            print(f"  [VT] {ip} → {verdict} (malicious={malicious})")
            return result

        elif resp.status_code == 429:
            print(f"  [VT] Rate limited, waiting 60s...")
            time.sleep(60)
            return check_ip(ip)

        elif resp.status_code == 404:
            return {"ip": ip, "verdict": "not_found", "malicious": 0}

        else:
            print(f"  [VT] Error {resp.status_code} for {ip}")
            return {"ip": ip, "verdict": "error", "malicious": 0}

    except Exception as e:
        print(f"  [VT] Exception for {ip}: {e}")
        return {"ip": ip, "verdict": "error", "malicious": 0}


# ── Background Queue ──────────────────────────
class VTQueue:
    """
    Thread-safe queue that processes IPs one-by-one
    with rate limiting. Calls callback(result) after each check.
    """
    def __init__(self):
        self._queue    = []
        self._seen     = set()
        self._lock     = threading.Lock()
        self._callback = None

    def set_callback(self, fn):
        """fn(result: dict) called after each VT check"""
        self._callback = fn

    def enqueue(self, ip: str):
        with self._lock:
            if ip not in self._seen:
                self._queue.append(ip)
                self._seen.add(ip)

    def run_forever(self):
        """Call this in a background thread"""
        print("  [VT] Queue worker started")
        while True:
            ip = None
            with self._lock:
                if self._queue:
                    ip = self._queue.pop(0)
            if ip:
                result = check_ip(ip)
                if self._callback and result.get("verdict") not in ("error", "skipped"):
                    try:
                        self._callback(result)
                    except Exception as e:
                        print(f"  [VT] Callback error: {e}")
                time.sleep(VT_DELAY)
            else:
                time.sleep(3)

    def size(self) -> int:
        with self._lock:
            return len(self._queue)


# Singleton
vt_queue = VTQueue()
