"""
HoneyTrack - ML Predictor
--------------------------
Loads the trained models (.pkl) and predicts on live traffic.
Uses: Isolation Forest + Random Forest + MITRE ATT&CK mapping.
"""

import joblib
import numpy as np
import pandas as pd
import os
from pathlib import Path

# ── Model paths ───────────────────────────────
MODELS_DIR = Path(__file__).parent / "models"

_models = {}

def _load():
    """Lazy-load models once"""
    global _models
    if _models:
        return
    try:
        _models = {
            "scaler":       joblib.load(MODELS_DIR / "scaler.pkl"),
            "iforest":      joblib.load(MODELS_DIR / "isolation_forest.pkl"),
            "rf_binary":    joblib.load(MODELS_DIR / "rf_binary.pkl"),
            "rf_multi":     joblib.load(MODELS_DIR / "rf_multiclass.pkl"),
            "le_attack":    joblib.load(MODELS_DIR / "label_encoder.pkl"),
            "feature_cols": joblib.load(MODELS_DIR / "feature_cols.pkl"),
            "encoders":     joblib.load(MODELS_DIR / "encoders.pkl"),
        }
        print("  [ML] ✔ Models loaded successfully")
    except Exception as e:
        print(f"  [ML] ✗ Could not load models: {e}")
        _models = {}


# ── MITRE ATT&CK Mapping ──────────────────────
MITRE_MAP = {
    "Reconnaissance": [
        {"technique_id": "T1595",     "technique": "Active Scanning",              "tactic": "Reconnaissance"},
        {"technique_id": "T1590",     "technique": "Gather Victim Network Info",   "tactic": "Reconnaissance"},
    ],
    "Exploits": [
        {"technique_id": "T1190",     "technique": "Exploit Public-Facing App",    "tactic": "Initial Access"},
        {"technique_id": "T1203",     "technique": "Exploitation for Execution",   "tactic": "Execution"},
    ],
    "DoS": [
        {"technique_id": "T1499",     "technique": "Endpoint Denial of Service",   "tactic": "Impact"},
        {"technique_id": "T1498",     "technique": "Network Denial of Service",    "tactic": "Impact"},
    ],
    "Generic": [
        {"technique_id": "T1110",     "technique": "Brute Force",                  "tactic": "Credential Access"},
        {"technique_id": "T1071",     "technique": "Application Layer Protocol",   "tactic": "Command and Control"},
    ],
    "Fuzzers": [
        {"technique_id": "T1595.002", "technique": "Vulnerability Scanning",       "tactic": "Reconnaissance"},
        {"technique_id": "T1190",     "technique": "Exploit Public-Facing App",    "tactic": "Initial Access"},
    ],
    "Backdoor": [
        {"technique_id": "T1543",     "technique": "Create/Modify System Process", "tactic": "Persistence"},
        {"technique_id": "T1078",     "technique": "Valid Accounts",               "tactic": "Defense Evasion"},
    ],
    "Analysis": [
        {"technique_id": "T1046",     "technique": "Network Service Discovery",    "tactic": "Discovery"},
        {"technique_id": "T1040",     "technique": "Network Sniffing",             "tactic": "Credential Access"},
    ],
    "Shellcode": [
        {"technique_id": "T1055",     "technique": "Process Injection",            "tactic": "Defense Evasion"},
        {"technique_id": "T1059",     "technique": "Command and Scripting",        "tactic": "Execution"},
    ],
    "Worms": [
        {"technique_id": "T1210",     "technique": "Exploitation of Remote Svc",  "tactic": "Lateral Movement"},
        {"technique_id": "T1570",     "technique": "Lateral Tool Transfer",        "tactic": "Lateral Movement"},
    ],
}

# ── Feature builder from honeypot events ──────
def build_features(events: list) -> dict:
    """
    Convert raw honeypot events for one IP
    into the same feature space as training data.
    """
    ssh_events  = [e for e in events if e.get("type") == "ssh_auth"]
    http_events = [e for e in events if e.get("type") == "http_request"]
    cmd_events  = [e for e in events if e.get("type") == "ssh_command"]
    atk_http    = [e for e in http_events if e.get("is_attack")]

    usernames = set(e.get("username", "") for e in ssh_events)
    passwords = set(e.get("password", "") for e in ssh_events)
    paths     = set(e.get("path", "")     for e in http_events)

    all_patterns = []
    for e in atk_http:
        all_patterns.extend(e.get("attack_patterns", {}).keys())

    return {
        "dur":              len(events) * 0.5,
        "spkts":            len(ssh_events) + len(http_events),
        "dpkts":            len(events),
        "sbytes":           len(ssh_events) * 50,
        "dbytes":           len(http_events) * 200,
        "rate":             len(events) / max(1, len(set(e.get("src_ip","") for e in events))),
        "sttl":             64,
        "dttl":             64,
        "sload":            len(ssh_events) * 100.0,
        "dload":            len(http_events) * 100.0,
        "sloss":            0,
        "dloss":            0,
        "sinpkt":           1.0,
        "dinpkt":           1.0,
        "sjit":             float(len(cmd_events)),
        "djit":             float(len(atk_http)),
        "swin":             255,
        "stcpb":            0,
        "dtcpb":            0,
        "dwin":             255,
        "tcprtt":           0.0,
        "synack":           0.0,
        "ackdat":           0.0,
        "smean":            50,
        "dmean":            200,
        "trans_depth":      0,
        "response_body_len":0,
        "ct_srv_src":       len(ssh_events),
        "ct_state_ttl":     1,
        "ct_dst_ltm":       1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm":   len(events),
        "is_ftp_login":     0,
        "ct_ftp_cmd":       0,
        "ct_flw_http_mthd": len(http_events),
        "ct_src_ltm":       len(events),
        "ct_srv_dst":       len(paths),
        "is_sm_ips_ports":  1 if len(ssh_events) > 5 else 0,
        # proto / service / state (encoded as 0=tcp approximation)
        "proto":            6,
        "service":          0,
        "state":            2,
        # engineered
        "byte_ratio":       (len(ssh_events)*50) / max(1, len(http_events)*200),
        "pkt_diff":         len(ssh_events) - len(http_events),
        "load_ratio":       len(ssh_events) / max(1, len(http_events)),
        "jit_ratio":        float(len(cmd_events)) / max(1, len(atk_http)),
        "conn_intensity":   len(ssh_events) * len(paths),
    }


# ── Severity calculator ───────────────────────
def _severity(prob: float, attack_type: str) -> str:
    high_risk = {"Exploits", "Backdoor", "Shellcode", "Worms"}
    if attack_type in high_risk or prob >= 0.9:
        return "CRITICAL"
    elif prob >= 0.7:
        return "HIGH"
    elif prob >= 0.5:
        return "MEDIUM"
    return "LOW"


# ── Main predict function ─────────────────────
def predict(events: list, ip: str) -> dict:
    """
    Analyze events for one IP.
    Returns full prediction result for DB + dashboard.
    """
    _load()

    if not _models:
        # Fallback if models not loaded
        ssh_count = sum(1 for e in events if e.get("type") == "ssh_auth")
        http_atk  = sum(1 for e in events if e.get("is_attack"))
        is_anomaly = ssh_count > 5 or http_atk > 0
        return {
            "ip": ip, "is_attack": is_anomaly,
            "attack_probability": 90.0 if is_anomaly else 10.0,
            "attack_type": "Generic" if is_anomaly else "Normal",
            "anomaly_score": -0.5 if is_anomaly else 0.5,
            "is_anomaly": is_anomaly,
            "mitre_tactics": MITRE_MAP.get("Generic", []) if is_anomaly else [],
            "severity": "HIGH" if is_anomaly else "LOW",
        }

    # Build features
    raw_features = build_features(events)
    feature_cols = _models["feature_cols"]

    vec = pd.DataFrame([raw_features]).reindex(columns=feature_cols, fill_value=0)
    vec_scaled = _models["scaler"].transform(vec)

    # Isolation Forest
    if_score   = float(_models["iforest"].score_samples(vec_scaled)[0])
    is_anomaly = _models["iforest"].predict(vec_scaled)[0] == -1

    # Random Forest binary
    is_attack    = bool(_models["rf_binary"].predict(vec_scaled)[0])
    attack_prob  = float(_models["rf_binary"].predict_proba(vec_scaled)[0][1])

    # Random Forest multi-class
    attack_type = "Normal"
    mitre       = []
    if is_attack:
        enc         = _models["rf_multi"].predict(vec_scaled)[0]
        attack_type = _models["le_attack"].inverse_transform([enc])[0]
        mitre       = MITRE_MAP.get(attack_type, [])

    severity = _severity(attack_prob, attack_type)

    result = {
        "ip":                ip,
        "is_attack":         is_attack,
        "attack_probability": round(attack_prob * 100, 1),
        "attack_type":        attack_type,
        "anomaly_score":      round(if_score, 4),
        "is_anomaly":         is_anomaly,
        "mitre_tactics":      mitre,
        "severity":           severity,
        "features":           raw_features,
    }

    print(f"  [ML] {ip} → {attack_type} ({severity}) prob={attack_prob:.0%} "
          f"anomaly={is_anomaly}")
    return result
