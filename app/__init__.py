"""
Dashboard API - Flask backend
Serves real-time data to the frontend dashboard
Also orchestrates the full honeypot pipeline
"""

from flask import Flask, jsonify, render_template_string
from flask_cors import CORS
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ssh_honeypot import start_ssh_honeypot, get_and_clear_queue
from core.http_honeypot import start_http_honeypot
from database.db_manager import (
    initialize_database, upsert_attacker, log_credential_attempt,
    log_http_request, save_ml_result, create_alert,
    update_vt_result, get_dashboard_stats
)
from ml.analyzer import ml_engine, extract_features
from virustotal.vt_client import vt_queue

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# In-memory event buffer (per IP)
# ─────────────────────────────────────────────
ip_events = {}
ip_events_lock = threading.Lock()

# ─────────────────────────────────────────────
# Event Pipeline Worker
# ─────────────────────────────────────────────
def process_events_loop():
    """
    Every 5 seconds: drain the event queue,
    save to DB, run ML analysis, enqueue for VT check
    """
    while True:
        time.sleep(5)
        events = get_and_clear_queue()
        if not events:
            continue

        # Group events by IP
        by_ip = {}
        for event in events:
            ip = event.get("src_ip", "unknown")
            by_ip.setdefault(ip, []).append(event)

        for ip, ip_ev in by_ip.items():
            # 1. Upsert attacker in DB
            attacker_id = upsert_attacker(ip)

            # 2. Save events to DB
            for e in ip_ev:
                if e.get("type") == "ssh_auth_attempt":
                    log_credential_attempt(
                        attacker_id,
                        e.get("username"), e.get("password"), "SSH"
                    )
                elif e.get("type") == "http_request":
                    log_http_request(
                        attacker_id,
                        e.get("method"), e.get("path"),
                        e.get("user_agent"),
                        e.get("suspicious_patterns", []),
                        e.get("is_attack", False),
                        e.get("body_snippet", "")
                    )

            # 3. Accumulate events per IP for ML
            with ip_events_lock:
                ip_events.setdefault(ip, []).extend(ip_ev)
                all_events_for_ip = ip_events[ip]

            # 4. ML analysis
            ml_result = ml_engine.analyze(all_events_for_ip, ip)
            save_ml_result(
                attacker_id,
                ml_result["anomaly_score"],
                ml_result["is_anomaly"],
                ml_result["features"],
                ml_result["mitre_tactics"]
            )

            # 5. Create alert if anomaly detected
            if ml_result["is_anomaly"]:
                severity = ml_result["severity"]
                tactics = ", ".join(
                    t["technique_id"] for t in ml_result["mitre_tactics"]
                ) or "Unknown"
                create_alert(
                    attacker_id,
                    "ML_ANOMALY",
                    severity,
                    f"Anomalous behavior from {ip}. "
                    f"Score: {ml_result['anomaly_score']:.3f}. "
                    f"MITRE: {tactics}"
                )

            # 6. Enqueue for VirusTotal check
            vt_queue.enqueue(ip)

        # Retrain model periodically
        for ip, evs in ip_events.items():
            ml_engine.add_training_sample(evs)
        ml_engine.train()


def vt_worker_loop():
    """Background thread to process VirusTotal queue"""
    while True:
        result = vt_queue.process_next()
        if result and result.get("verdict") not in ("error", "not_found"):
            update_vt_result(result["ip"], result.get("malicious", 0))


# ─────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    try:
        stats = get_dashboard_stats()
        # Convert datetime objects to strings for JSON
        for attacker in stats.get("recent_attackers", []):
            for k, v in attacker.items():
                if hasattr(v, "isoformat"):
                    attacker[k] = v.isoformat()
        for alert in stats.get("recent_alerts", []):
            for k, v in alert.items():
                if hasattr(v, "isoformat"):
                    alert[k] = v.isoformat()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "running",
        "ml_trained": ml_engine.is_trained,
        "vt_queue_size": len(vt_queue._queue),
    })


@app.route("/")
def dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return f.read()


# ─────────────────────────────────────────────
# Extra API endpoints for charts
# ─────────────────────────────────────────────
@app.route("/api/chart/timeline")
def api_timeline():
    """Attacks per hour for last 24h"""
    try:
        from database.db_manager import get_connection
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT DATE_FORMAT(last_seen, '%Y-%m-%d %H:00') AS hour,
                       SUM(attack_count) AS count
                FROM attackers
                WHERE last_seen >= NOW() - INTERVAL 24 HOUR
                GROUP BY hour
                ORDER BY hour
            """)
            rows = cursor.fetchall()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/chart/protocols")
def api_protocols():
    """SSH vs HTTP breakdown"""
    try:
        from database.db_manager import get_connection
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT COUNT(*) AS count FROM credential_attempts WHERE protocol='SSH'")
            ssh = cursor.fetchone()["count"]
            cursor.execute("SELECT COUNT(*) AS count FROM http_requests")
            http = cursor.fetchone()["count"]
        return jsonify({"SSH": ssh, "HTTP": http})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/chart/attack_types")
def api_attack_types():
    """Count of each attack category"""
    try:
        from database.db_manager import get_connection
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT COUNT(*) AS c FROM credential_attempts WHERE protocol='SSH'")
            brute = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) AS c FROM http_requests WHERE JSON_CONTAINS(suspicious_patterns, '\"union.*select\"')")
            sqli = cursor.fetchone()["c"]
            cursor.execute("SELECT COUNT(*) AS c FROM http_requests WHERE is_attack=1")
            total_http_attacks = cursor.fetchone()["c"]
        return jsonify({
            "Brute Force": brute,
            "SQL Injection": sqli,
            "HTTP Attacks": total_http_attacks,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  HoneyTrack - Service-Emulating Honeypot")
    print("=" * 50)

    # Initialize DB
    initialize_database()

    # Start honeypots in background threads
    threading.Thread(target=start_ssh_honeypot,  daemon=True).start()
    threading.Thread(target=start_http_honeypot, daemon=True).start()

    # Start event pipeline
    threading.Thread(target=process_events_loop, daemon=True).start()

    # Start VT worker
    threading.Thread(target=vt_worker_loop, daemon=True).start()

    print("[*] All services started.")
    print("[*] Dashboard → http://localhost:5000")
    print("[*] SSH Honeypot → port 2222")
    print("[*] HTTP Honeypot → port 8080")

    # Start Flask
    app.run(host="0.0.0.0", port=5000, debug=False)
