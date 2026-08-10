"""
ai_detector.py
Lightweight AI detection engine.

Approach: aggregate recent logs into per-device sliding-window feature
vectors (failed logins, distinct destination ports touched, malware/exfil
signal counts, critical-severity count). An IsolationForest, pre-trained on
a simulated baseline of "normal" windows, scores each live window. Windows
that score as anomalous are cross-checked against simple rule signatures to
produce a labeled incident (attack_type + MITRE ATT&CK technique) rather
than a bare "anomaly" — this hybrid (unsupervised score + rule labeling)
is what keeps false-positive noise down while still catching things the
static rules alone would miss.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
import random
import time

FEATURE_NAMES = [
    "auth_failure_count",
    "distinct_dest_ports",
    "malware_signal_count",
    "critical_count",
    "large_transfer_count",
    "privilege_escalation_count",
]


def _features_from_window(logs):
    auth_failures = sum(1 for l in logs if l["event_type"] == "auth_failure")
    ports = set(l["dest_port"] for l in logs if l["dest_port"])
    malware = sum(1 for l in logs if l["event_type"] in ("malware_alert", "network_beacon"))
    critical = sum(1 for l in logs if l["severity"] == "critical")
    transfers = sum(1 for l in logs if l["event_type"] == "large_data_transfer")
    privesc = sum(1 for l in logs if l["event_type"] == "privilege_escalation")
    return [auth_failures, len(ports), malware, critical, transfers, privesc]


def _simulate_baseline(n=400):
    """Simulated normal-traffic windows used to fit the IsolationForest.
    In production this would be historical labeled-normal data from the SIEM
    itself; here we generate it so the model works out-of-the-box."""
    rows = []
    for _ in range(n):
        rows.append([
            random.choice([0, 0, 0, 0, 1]),      # auth_failure_count - rare
            random.randint(1, 4),                 # distinct_dest_ports
            0,                                      # malware_signal_count
            random.choice([0, 0, 0, 1]),          # critical_count
            0,                                      # large_transfer_count
            0,                                      # privilege_escalation_count
        ])
    return np.array(rows)


class AIDetector:
    def __init__(self):
        self.model = IsolationForest(n_estimators=150, contamination=0.08, random_state=42)
        self.model.fit(_simulate_baseline())

    def score_window(self, logs):
        if not logs:
            return 0.0, [0, 0, 0, 0, 0, 0]
        feats = _features_from_window(logs)
        score = self.model.decision_function([feats])[0]   # higher = more normal
        return float(score), feats

    def classify(self, logs, feats):
        """Rule-based labeling layered on top of the anomaly score, so incidents
        get a human-readable attack type and MITRE technique instead of just
        a raw anomaly number."""
        auth_failures, distinct_ports, malware, critical, transfers, privesc = feats
        if auth_failures >= 6:
            return ("Brute Force Authentication Attack", "T1110 - Brute Force", "high")
        if distinct_ports >= 10:
            return ("Port Scanning / Reconnaissance", "T1046 - Network Service Discovery", "medium")
        if malware >= 1:
            return ("Malware / C2 Beaconing Detected", "T1071 - Application Layer Protocol (C2)", "critical")
        if privesc >= 1 and transfers >= 1:
            return ("Data Exfiltration via Compromised Account", "T1078 + T1041 - Valid Accounts / Exfiltration", "critical")
        if transfers >= 1:
            return ("Anomalous Large Data Transfer", "T1041 - Exfiltration Over C2 Channel", "high")
        if critical >= 2:
            return ("Multiple Critical Severity Events", "TA0040 - Impact", "high")
        return ("Unclassified Behavioral Anomaly", "TA0000 - Unclassified", "medium")

    def analyze(self, db, window_seconds=15, anomaly_threshold=-0.02):
        """Pull recent logs per device, score each device's window, and file
        an incident for any device whose window looks anomalous AND hasn't
        already been flagged very recently (avoids duplicate spam)."""
        recent = db.logs_since(window_seconds)
        by_device = {}
        for row in recent:
            by_device.setdefault(row["device"], []).append(dict(row))

        new_incidents = []
        for device, logs in by_device.items():
            score, feats = self.score_window(logs)
            if score < anomaly_threshold:
                attack_type, mitre, severity = self.classify(logs, feats)
                if db.recent_incident_exists(attack_type, device, window_seconds=window_seconds * 2):
                    continue
                related_ids = [l["log_id"] for l in logs]
                detail = (f"{mitre}. Window features -> auth_failures={feats[0]}, "
                          f"distinct_ports={feats[1]}, malware_signals={feats[2]}, "
                          f"critical_events={feats[3]}, large_transfers={feats[4]}, "
                          f"privesc_events={feats[5]}. Anomaly score={score:.3f}")
                incident_id = db.insert_incident(attack_type, severity, device, detail, related_ids, score)
                new_incidents.append({
                    "incident_id": incident_id, "attack_type": attack_type, "device": device,
                    "severity": severity, "mitre": mitre, "score": score,
                })
        return new_incidents
