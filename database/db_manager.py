"""
╔══════════════════════════════════════════════════════════════╗
║         HoneyTrack - Database Manager                       ║
║         MySQL External Database                             ║
║         Tables: attackers, credentials, sessions,           ║
║                 commands, http_requests, ml_results,        ║
║                 alerts, vt_reports, geolocation             ║
╚══════════════════════════════════════════════════════════════╝
"""

import mysql.connector
import json
import os
from datetime import datetime
from contextlib import contextmanager

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "user":     os.getenv("DB_USER", "honeypot_user"),
    "password": os.getenv("DB_PASS", "honeypot_pass"),
    "database": os.getenv("DB_NAME", "honeypot_db"),
}

# ─────────────────────────────────────────────
# Connection
# ─────────────────────────────────────────────
@contextmanager
def get_connection():
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Schema — All 9 Tables
# ─────────────────────────────────────────────
TABLES = {}

TABLES['attackers'] = """
CREATE TABLE IF NOT EXISTS attackers (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45)  NOT NULL,
    country      VARCHAR(100),
    city         VARCHAR(100),
    first_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    attack_count INT DEFAULT 1,
    vt_malicious INT DEFAULT 0,
    vt_checked   BOOLEAN DEFAULT FALSE,
    UNIQUE KEY uq_ip (ip_address),
    INDEX idx_last_seen (last_seen),
    INDEX idx_country   (country)
)"""

TABLES['geolocation'] = """
CREATE TABLE IF NOT EXISTS geolocation (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id  INT NOT NULL,
    ip_address   VARCHAR(45),
    country      VARCHAR(100),
    country_code VARCHAR(5),
    region       VARCHAR(100),
    city         VARCHAR(100),
    latitude     FLOAT,
    longitude    FLOAT,
    isp          VARCHAR(255),
    org          VARCHAR(255),
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    UNIQUE KEY uq_attacker_geo (attacker_id)
)"""

TABLES['credential_attempts'] = """
CREATE TABLE IF NOT EXISTS credential_attempts (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id INT NOT NULL,
    username    VARCHAR(255),
    password    VARCHAR(255),
    protocol    ENUM('SSH','HTTP') DEFAULT 'SSH',
    success     BOOLEAN DEFAULT FALSE,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    INDEX idx_attacker  (attacker_id),
    INDEX idx_timestamp (timestamp)
)"""

TABLES['sessions'] = """
CREATE TABLE IF NOT EXISTS sessions (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id      INT NOT NULL,
    protocol         ENUM('SSH','HTTP'),
    start_time       DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time         DATETIME,
    duration_seconds FLOAT DEFAULT 0,
    commands_executed INT DEFAULT 0,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    INDEX idx_attacker (attacker_id)
)"""

TABLES['command_logs'] = """
CREATE TABLE IF NOT EXISTS command_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    session_id  INT NOT NULL,
    attacker_id INT NOT NULL,
    command     TEXT,
    response    TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id)  REFERENCES sessions(id),
    FOREIGN KEY (attacker_id) REFERENCES attackers(id)
)"""

TABLES['http_requests'] = """
CREATE TABLE IF NOT EXISTS http_requests (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id         INT NOT NULL,
    method              VARCHAR(10),
    path                TEXT,
    user_agent          TEXT,
    suspicious_patterns JSON,
    is_attack           BOOLEAN DEFAULT FALSE,
    attack_type         VARCHAR(100),
    body_snippet        TEXT,
    timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    INDEX idx_attacker  (attacker_id),
    INDEX idx_is_attack (is_attack),
    INDEX idx_timestamp (timestamp)
)"""

TABLES['ml_results'] = """
CREATE TABLE IF NOT EXISTS ml_results (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id   INT NOT NULL,
    anomaly_score FLOAT,
    is_anomaly    BOOLEAN,
    attack_type   VARCHAR(100),
    attack_prob   FLOAT,
    severity      ENUM('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT 'LOW',
    features      JSON,
    mitre_tactics JSON,
    analyzed_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    INDEX idx_attacker (attacker_id),
    INDEX idx_anomaly  (is_anomaly),
    INDEX idx_severity (severity)
)"""

TABLES['vt_reports'] = """
CREATE TABLE IF NOT EXISTS vt_reports (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id  INT NOT NULL,
    ip_address   VARCHAR(45),
    malicious    INT DEFAULT 0,
    suspicious   INT DEFAULT 0,
    harmless     INT DEFAULT 0,
    undetected   INT DEFAULT 0,
    reputation   INT DEFAULT 0,
    verdict      VARCHAR(50),
    country      VARCHAR(100),
    as_owner     VARCHAR(255),
    tags         JSON,
    raw_response JSON,
    checked_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    UNIQUE KEY uq_attacker_vt (attacker_id)
)"""

TABLES['alerts'] = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    attacker_id INT,
    alert_type  VARCHAR(100),
    severity    ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    message     TEXT,
    resolved    BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attacker_id) REFERENCES attackers(id),
    INDEX idx_severity   (severity),
    INDEX idx_resolved   (resolved),
    INDEX idx_created_at (created_at)
)"""

TABLE_ORDER = [
    'attackers', 'geolocation', 'credential_attempts',
    'sessions', 'command_logs', 'http_requests',
    'ml_results', 'vt_reports', 'alerts'
]


def initialize_database():
    """Create all tables in correct FK order"""
    with get_connection() as conn:
        cursor = conn.cursor()
        for table in TABLE_ORDER:
            cursor.execute(TABLES[table])
            print(f"  [DB] ✔ Table ready: {table}")
    print("  [DB] All 9 tables initialized successfully.")


# ══════════════════════════════════════════════
# WRITE Operations
# ══════════════════════════════════════════════

def upsert_attacker(ip: str, country: str = None, city: str = None) -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attackers (ip_address, country, city, attack_count)
            VALUES (%s, %s, %s, 1)
            ON DUPLICATE KEY UPDATE
                attack_count = attack_count + 1,
                last_seen    = CURRENT_TIMESTAMP,
                country      = COALESCE(%s, country),
                city         = COALESCE(%s, city)
        """, (ip, country, city, country, city))
        cursor.execute("SELECT id FROM attackers WHERE ip_address=%s", (ip,))
        row = cursor.fetchone()
        return row[0] if row else None


def save_geolocation(attacker_id: int, geo: dict):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO geolocation
                (attacker_id, ip_address, country, country_code,
                 region, city, latitude, longitude, isp, org)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                country      = VALUES(country),
                country_code = VALUES(country_code),
                region       = VALUES(region),
                city         = VALUES(city),
                latitude     = VALUES(latitude),
                longitude    = VALUES(longitude),
                isp          = VALUES(isp),
                org          = VALUES(org),
                updated_at   = CURRENT_TIMESTAMP
        """, (
            attacker_id, geo.get('ip'), geo.get('country'),
            geo.get('country_code'), geo.get('region'), geo.get('city'),
            geo.get('latitude'), geo.get('longitude'),
            geo.get('isp'), geo.get('org'),
        ))


def log_credential_attempt(attacker_id: int, username: str,
                           password: str, protocol: str = "SSH"):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO credential_attempts
                (attacker_id, username, password, protocol)
            VALUES (%s,%s,%s,%s)
        """, (attacker_id, username, password, protocol))

def execute(self, query: str, params: tuple = ()) -> bool:
    """Execute query with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot execute query")
        return False
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        self.connection.commit()
        cursor.close()
        return True
    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        return False

def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
    """Fetch one row with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot fetch")
        return None
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()
        cursor.close()
        return result
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return None

def fetch_all(self, query: str, params: tuple = ()) -> List[tuple]:
    """Fetch all rows with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot fetch")
        return []
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return result
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return []
def create_session(attacker_id: int, protocol: str) -> int:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sessions (attacker_id, protocol)
            VALUES (%s,%s)
        """, (attacker_id, protocol))
        return cursor.lastrowid


def close_session(session_id: int, commands_count: int = 0):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET end_time          = CURRENT_TIMESTAMP,
                duration_seconds  = TIMESTAMPDIFF(SECOND, start_time, CURRENT_TIMESTAMP),
                commands_executed = %s
            WHERE id = %s
        """, (commands_count, session_id))


def log_command(session_id: int, attacker_id: int,
                command: str, response: str = ""):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO command_logs
                (session_id, attacker_id, command, response)
            VALUES (%s,%s,%s,%s)
        """, (session_id, attacker_id, command, response))


def log_http_request(attacker_id: int, method: str, path: str,
                     user_agent: str, suspicious_patterns: list,
                     is_attack: bool, body_snippet: str,
                     attack_type: str = None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO http_requests
                (attacker_id, method, path, user_agent,
                 suspicious_patterns, is_attack, attack_type, body_snippet)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (attacker_id, method, path, user_agent,
              json.dumps(suspicious_patterns), is_attack,
              attack_type, body_snippet))


def save_ml_result(attacker_id: int, anomaly_score: float,
                   is_anomaly: bool, features: dict,
                   mitre_tactics: list, attack_type: str = None,
                   attack_prob: float = 0.0, severity: str = 'LOW'):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO ml_results
                (attacker_id, anomaly_score, is_anomaly, attack_type,
                 attack_prob, severity, features, mitre_tactics)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (attacker_id, anomaly_score, is_anomaly, attack_type,
              attack_prob, severity,
              json.dumps(features), json.dumps(mitre_tactics)))


def save_vt_report(attacker_id: int, vt_result: dict):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO vt_reports
                (attacker_id, ip_address, malicious, suspicious,
                 harmless, undetected, reputation, verdict,
                 country, as_owner, tags, raw_response)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                malicious  = VALUES(malicious),
                suspicious = VALUES(suspicious),
                verdict    = VALUES(verdict),
                checked_at = CURRENT_TIMESTAMP
        """, (
            attacker_id, vt_result.get('ip'),
            vt_result.get('malicious', 0), vt_result.get('suspicious', 0),
            vt_result.get('harmless', 0),  vt_result.get('undetected', 0),
            vt_result.get('reputation', 0), vt_result.get('verdict'),
            vt_result.get('country'), vt_result.get('as_owner'),
            json.dumps(vt_result.get('tags', [])),
            json.dumps(vt_result),
        ))
    update_vt_result(vt_result.get('ip', ''), vt_result.get('malicious', 0))


def update_vt_result(ip: str, malicious_count: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE attackers
            SET vt_malicious=%s, vt_checked=TRUE
            WHERE ip_address=%s
        """, (malicious_count, ip))


def create_alert(attacker_id: int, alert_type: str,
                 severity: str, message: str):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (attacker_id, alert_type, severity, message)
            VALUES (%s,%s,%s,%s)
        """, (attacker_id, alert_type, severity, message))


def resolve_alert(alert_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE alerts
            SET resolved=TRUE, resolved_at=CURRENT_TIMESTAMP
            WHERE id=%s
        """, (alert_id,))


# ══════════════════════════════════════════════
# READ Operations — Dashboard
# ══════════════════════════════════════════════

def _serialize(rows):
    """Convert datetime objects to ISO strings for JSON"""
    if rows is None:
        return None
    if isinstance(rows, dict):
        return {k: (v.isoformat() if hasattr(v, 'isoformat') else v)
                for k, v in rows.items()}
    return [{k: (v.isoformat() if hasattr(v, 'isoformat') else v)
             for k, v in row.items()} for row in rows]


def get_dashboard_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)

        # KPIs
        cur.execute("SELECT COALESCE(SUM(attack_count),0) AS v FROM attackers")
        total_attacks = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM attackers")
        total_ips = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM alerts WHERE resolved=FALSE")
        open_alerts = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM ml_results WHERE is_anomaly=TRUE")
        anomalies = int(cur.fetchone()['v'])

        # Protocol counts
        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts WHERE protocol='SSH'")
        ssh_count = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM http_requests")
        http_count = int(cur.fetchone()['v'])

        # Attack type counts
        cur.execute("SELECT COUNT(*) AS v FROM credential_attempts")
        brute_force = int(cur.fetchone()['v'])

        cur.execute("SELECT COUNT(*) AS v FROM http_requests WHERE is_attack=TRUE")
        http_attacks = int(cur.fetchone()['v'])

        # Timeline (last 24h)
        cur.execute("""
            SELECT DATE_FORMAT(last_seen,'%Y-%m-%d %H:00') AS hour,
                   SUM(attack_count) AS count
            FROM attackers
            WHERE last_seen >= NOW() - INTERVAL 24 HOUR
            GROUP BY hour ORDER BY hour
        """)
        timeline = _serialize(cur.fetchall())

        # Recent attackers with geo + ML
        cur.execute("""
            SELECT a.ip_address, a.country, a.attack_count,
                   a.vt_malicious, a.vt_checked,
                   a.first_seen, a.last_seen,
                   g.latitude, g.longitude, g.city, g.isp,
                   m.attack_type, m.severity, m.anomaly_score
            FROM attackers a
            LEFT JOIN geolocation g ON g.attacker_id = a.id
            LEFT JOIN ml_results  m ON m.attacker_id = a.id
                AND m.analyzed_at = (
                    SELECT MAX(analyzed_at) FROM ml_results r2
                    WHERE r2.attacker_id = a.id
                )
            ORDER BY a.last_seen DESC
            LIMIT 20
        """)
        recent_attackers = _serialize(cur.fetchall())

        # Recent alerts
        cur.execute("""
            SELECT al.id, al.alert_type, al.severity,
                   al.message, al.created_at, al.resolved,
                   at.ip_address, at.country
            FROM alerts al
            JOIN attackers at ON al.attacker_id = at.id
            ORDER BY al.created_at DESC
            LIMIT 15
        """)
        recent_alerts = _serialize(cur.fetchall())

        # MITRE counts
        cur.execute("""
            SELECT mitre_tactics FROM ml_results
            WHERE mitre_tactics IS NOT NULL
            ORDER BY analyzed_at DESC LIMIT 500
        """)
        mitre_counts = {}
        for row in cur.fetchall():
            tactics = row.get('mitre_tactics') or []
            if isinstance(tactics, str):
                try: tactics = json.loads(tactics)
                except: continue
            for t in tactics:
                tid = t.get('technique_id', '')
                if tid:
                    mitre_counts[tid] = mitre_counts.get(tid, 0) + 1

        # Top credentials
        cur.execute("""
            SELECT username, password, COUNT(*) AS count
            FROM credential_attempts
            GROUP BY username, password
            ORDER BY count DESC LIMIT 10
        """)
        top_creds = _serialize(cur.fetchall())

        # Geo points for map
        cur.execute("""
            SELECT a.ip_address, a.attack_count, a.country,
                   g.latitude, g.longitude, g.city
            FROM attackers a
            JOIN geolocation g ON g.attacker_id = a.id
            WHERE g.latitude IS NOT NULL
        """)
        geo_points = _serialize(cur.fetchall())

        return {
            "total_attacks":      total_attacks,
            "total_unique_ips":   total_ips,
            "open_alerts":        open_alerts,
            "anomalies_detected": anomalies,
            "ssh_count":          ssh_count,
            "http_count":         http_count,
            "brute_force_count":  brute_force,
            "http_attack_count":  http_attacks,
            "timeline":           timeline,
            "mitre_counts":       mitre_counts,
            "top_credentials":    top_creds,
            "geo_points":         geo_points,
            "recent_attackers":   recent_attackers,
            "recent_alerts":      recent_alerts,
        }


def get_attacker_detail(ip: str) -> dict:
    """Full profile for one attacker"""
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT * FROM attackers WHERE ip_address=%s", (ip,))
        attacker = cur.fetchone()
        if not attacker:
            return {}
        aid = attacker['id']

        cur.execute("SELECT * FROM geolocation       WHERE attacker_id=%s", (aid,))
        geo = cur.fetchone()

        cur.execute("SELECT * FROM vt_reports        WHERE attacker_id=%s", (aid,))
        vt  = cur.fetchone()

        cur.execute("""SELECT * FROM credential_attempts
                       WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50""", (aid,))
        creds = cur.fetchall()

        cur.execute("""SELECT * FROM sessions
                       WHERE attacker_id=%s ORDER BY start_time DESC LIMIT 20""", (aid,))
        sessions = cur.fetchall()

        cur.execute("""SELECT * FROM command_logs
                       WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50""", (aid,))
        commands = cur.fetchall()

        cur.execute("""SELECT * FROM http_requests
                       WHERE attacker_id=%s ORDER BY timestamp DESC LIMIT 50""", (aid,))
        http_reqs = cur.fetchall()

        cur.execute("""SELECT * FROM ml_results
                       WHERE attacker_id=%s ORDER BY analyzed_at DESC LIMIT 1""", (aid,))
        ml = cur.fetchone()

        return {
            "attacker":      _serialize(attacker),
            "geolocation":   _serialize(geo),
            "vt_report":     _serialize(vt),
            "credentials":   _serialize(creds),
            "sessions":      _serialize(sessions),
            "commands":      _serialize(commands),
            "http_requests": _serialize(http_reqs),
            "ml_result":     _serialize(ml),
        }
