"""
Machine Learning Anomaly Detection using Isolation Forest and One-Class SVM.
Detects: unusual login times, impossible travel, abnormal network traffic, rare executables.
"""
import numpy as np
from typing import List, Optional
from datetime import datetime

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# In-memory models (in production, save/load from disk)
_isolation_forest: Optional[object] = None
_scaler: Optional[object] = None
_trained = False


def _extract_features(log: dict) -> list:
    """Extract numeric features from a log entry."""
    ts = log.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.now()
    
    hour = ts.hour if ts else 12
    day_of_week = ts.weekday() if ts else 0
    
    # Feature vector: [hour, day_of_week, is_auth_failure, is_admin_user, has_encoded_command]
    features = [
        hour,
        day_of_week,
        1 if log.get("event_type") == "authentication_failure" else 0,
        1 if "admin" in str(log.get("user", "")).lower() else 0,
        1 if log.get("command") and "-enc" in str(log.get("command", "")).lower() else 0,
        1 if log.get("process_name") in ["mimikatz.exe", "psexec.exe"] else 0,
        len(str(log.get("command") or "")) / 1000,  # Command length normalized
    ]
    return features


def train_model(logs: List[dict]) -> bool:
    """Train the anomaly detection model on a set of logs."""
    global _isolation_forest, _scaler, _trained
    
    if not ML_AVAILABLE or len(logs) < 10:
        return False
    
    try:
        X = [_extract_features(log) for log in logs]
        X = np.array(X)
        
        _scaler = StandardScaler()
        X_scaled = _scaler.fit_transform(X)
        
        _isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        _isolation_forest.fit(X_scaled)
        _trained = True
        return True
    except Exception as e:
        print(f"ML training error: {e}")
        return False


def predict_anomaly(log: dict) -> dict:
    """Predict if a log event is anomalous."""
    if not ML_AVAILABLE or not _trained or _isolation_forest is None:
        return _rule_based_anomaly(log)
    
    try:
        features = _extract_features(log)
        X = np.array([features])
        X_scaled = _scaler.transform(X)
        
        prediction = _isolation_forest.predict(X_scaled)[0]
        score = _isolation_forest.score_samples(X_scaled)[0]
        
        is_anomaly = prediction == -1
        anomaly_score = max(0, min(100, (1 - (score + 0.5)) * 100))
        
        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 2),
            "method": "isolation_forest",
            "features_used": ["hour", "day_of_week", "auth_failure", "admin_user", "encoded_cmd", "known_malware", "cmd_length"]
        }
    except Exception:
        return _rule_based_anomaly(log)


def _rule_based_anomaly(log: dict) -> dict:
    """Fallback rule-based anomaly detection when ML is not available."""
    score = 0.0
    reasons = []
    
    ts = log.get("timestamp")
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.now()
    
    # Off-hours login (before 7am or after 10pm)
    if ts and (ts.hour < 7 or ts.hour > 22):
        score += 20
        reasons.append("off_hours_activity")
    
    # Weekend activity
    if ts and ts.weekday() >= 5:
        score += 10
        reasons.append("weekend_activity")
    
    # Admin user
    if "admin" in str(log.get("user", "")).lower():
        score += 15
        reasons.append("admin_account_used")
    
    # Encoded command
    cmd = str(log.get("command") or "")
    if "-enc" in cmd.lower() or "base64" in cmd.lower() or "frombase64string" in cmd.lower():
        score += 40
        reasons.append("encoded_command_detected")
    
    # Known malicious process
    if log.get("process_name") in ["mimikatz.exe", "psexec.exe", "mshta.exe", "wscript.exe"]:
        score += 50
        reasons.append("known_malicious_process")
    
    # Very long command
    if len(cmd) > 500:
        score += 20
        reasons.append("unusually_long_command")
    
    return {
        "is_anomaly": score >= 40,
        "anomaly_score": min(100, score),
        "reasons": reasons,
        "method": "rule_based"
    }


# ─────────────────────────── Advanced ML Models ───────────────────────────────

_svm_model = None
_dbscan_model = None


def train_one_class_svm(logs: list) -> dict:
    """Train a One-Class SVM for outlier detection (complements Isolation Forest)."""
    global _svm_model
    if not ML_AVAILABLE:
        return {"status": "sklearn not available", "trained": False}

    try:
        from sklearn.svm import OneClassSVM
        features = [_extract_features(log) for log in logs if log]
        if len(features) < 10:
            return {"status": "insufficient data (need 10+)", "trained": False}

        X = np.array(features)
        _svm_model = OneClassSVM(kernel="rbf", gamma="auto", nu=0.1)
        _svm_model.fit(X)
        return {"status": "trained", "trained": True, "samples": len(features), "model": "OneClassSVM"}
    except Exception as e:
        return {"status": f"error: {e}", "trained": False}


def predict_svm(log: dict) -> dict:
    """Predict using One-Class SVM model."""
    if not _svm_model:
        return {"method": "svm", "available": False, "note": "SVM model not trained"}

    try:
        features = _extract_features(log)
        pred = _svm_model.predict([features])[0]
        score = _svm_model.decision_function([features])[0]
        return {
            "is_anomaly": pred == -1,
            "decision_score": float(score),
            "method": "one_class_svm",
        }
    except Exception:
        return {"method": "svm", "available": False}


def cluster_login_patterns(logs: list) -> dict:
    """Use DBSCAN to identify unusual login behavior clusters."""
    if not ML_AVAILABLE:
        return {"status": "sklearn not available", "clusters": []}

    try:
        from sklearn.cluster import DBSCAN
        from collections import Counter

        features = []
        for log in logs:
            if log.get("event_type") in ("authentication_success", "authentication_failure"):
                ts = log.get("timestamp")
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts)
                    except Exception:
                        continue
                features.append([
                    ts.hour,
                    ts.weekday(),
                    1 if log.get("event_type") == "authentication_failure" else 0,
                ])

        if len(features) < 5:
            return {"status": "insufficient login events", "clusters": []}

        X = np.array(features)
        db = DBSCAN(eps=2.0, min_samples=3)
        labels = db.fit_predict(X)

        cluster_counts = Counter(labels)
        noise_count = cluster_counts.get(-1, 0)

        return {
            "status": "analyzed",
            "total_events": len(features),
            "clusters_found": len(set(labels) - {-1}),
            "noise_points": noise_count,
            "noise_percentage": round(noise_count / len(features) * 100, 1) if features else 0,
            "cluster_sizes": {str(k): v for k, v in cluster_counts.items() if k != -1},
            "anomalous_logins": noise_count,
            "method": "dbscan",
        }
    except Exception as e:
        return {"status": f"error: {e}", "clusters": []}


# ─────────────────────────── Geo / Impossible Travel ──────────────────────────

# Simplified city → lat/lon lookup for demo (no external GeoIP library needed)
GEO_LOOKUP = {
    "US": (37.7749, -122.4194), "RU": (55.7558, 37.6173),
    "CN": (39.9042, 116.4074), "DE": (52.5200, 13.4050),
    "GB": (51.5074, -0.1278), "IN": (28.6139, 77.2090),
    "BR": (-23.5505, -46.6333), "AU": (-33.8688, 151.2093),
    "JP": (35.6762, 139.6503), "KR": (37.5665, 126.9780),
    "FR": (48.8566, 2.3522), "NL": (52.3676, 4.9041),
}

import math

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two points on Earth."""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def detect_impossible_travel(login_events: list) -> dict:
    """
    Detect impossible travel — two logins from far-apart locations in a
    physically impossible timeframe.

    Each event: {"user": "...", "timestamp": "...", "country": "US"}
    """
    from collections import defaultdict

    user_events = defaultdict(list)
    for evt in login_events:
        user = evt.get("user")
        country = evt.get("country")
        ts = evt.get("timestamp")
        if user and country and ts:
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except Exception:
                    continue
            user_events[user].append({"timestamp": ts, "country": country})

    alerts = []
    for user, events in user_events.items():
        events.sort(key=lambda x: x["timestamp"])
        for i in range(1, len(events)):
            prev, curr = events[i - 1], events[i]
            if prev["country"] == curr["country"]:
                continue

            geo_prev = GEO_LOOKUP.get(prev["country"])
            geo_curr = GEO_LOOKUP.get(curr["country"])
            if not geo_prev or not geo_curr:
                continue

            distance_km = _haversine_km(*geo_prev, *geo_curr)
            time_diff_h = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 3600

            # Max commercial flight speed ~900 km/h
            max_possible_km = time_diff_h * 900
            if distance_km > max_possible_km and time_diff_h < 24:
                alerts.append({
                    "user": user,
                    "from_country": prev["country"],
                    "to_country": curr["country"],
                    "distance_km": round(distance_km),
                    "time_diff_hours": round(time_diff_h, 2),
                    "max_possible_km": round(max_possible_km),
                    "verdict": "impossible_travel",
                    "severity": "critical" if time_diff_h < 2 else "high",
                })

    return {
        "alerts": alerts,
        "users_analyzed": len(user_events),
        "events_analyzed": sum(len(v) for v in user_events.values()),
        "impossible_travel_detected": len(alerts),
    }


def get_model_status() -> dict:
    return {
        "ml_available": ML_AVAILABLE,
        "model_trained": _trained,
        "isolation_forest": "trained" if _trained else "not_trained",
        "one_class_svm": "trained" if _svm_model else "not_trained",
        "dbscan": "available" if ML_AVAILABLE else "unavailable",
        "impossible_travel": "available",
        "methods": [
            "isolation_forest",
            "one_class_svm",
            "dbscan_clustering",
            "impossible_travel",
            "rule_based_fallback",
        ]
    }

