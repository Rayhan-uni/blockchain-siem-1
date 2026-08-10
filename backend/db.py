"""
db.py
SQLite storage for the off-chain data (the full log content, devices,
incidents). Only SHA-256 hashes of logs ever go on the blockchain — this
mirrors the real architecture: bulk data off-chain, integrity proofs on-chain.
"""

import sqlite3
import time
import json
import os

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    hostname TEXT,
    ip TEXT,
    type TEXT
);

CREATE TABLE IF NOT EXISTS logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    device TEXT,
    event_type TEXT,
    severity TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    user TEXT,
    message TEXT,
    log_hash TEXT,
    block_index INTEGER,
    tampered INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL,
    attack_type TEXT,
    severity TEXT,
    status TEXT,
    device TEXT,
    detail TEXT,
    related_log_ids TEXT,
    anomaly_score REAL
);

CREATE TABLE IF NOT EXISTS pending_hashes (
    log_id INTEGER PRIMARY KEY
);
"""

DEFAULT_DEVICES = [
    ("FW-01", "edge-firewall-01", "10.0.0.1", "firewall"),
    ("WIN-DC01", "win-dc01", "10.0.1.5", "windows_server"),
    ("LNX-WEB01", "lnx-web01", "10.0.2.10", "linux_server"),
    ("IDS-01", "ids-sensor-01", "10.0.0.2", "ids"),
    ("VPN-01", "vpn-gateway", "10.0.0.3", "vpn"),
    ("CLOUD-AWS", "aws-vpc-flow", "172.31.0.1", "cloud"),
]


class Database:
    def __init__(self, path):
        self.path = path
        first_init = not os.path.exists(path)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        if first_init:
            self._seed_devices()

    def _seed_devices(self):
        cur = self.conn.cursor()
        cur.executemany(
            "INSERT OR IGNORE INTO devices (device_id, hostname, ip, type) VALUES (?,?,?,?)",
            DEFAULT_DEVICES,
        )
        self.conn.commit()

    # ---------- logs ----------
    def insert_log(self, entry, log_hash):
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO logs
               (timestamp, device, event_type, severity, src_ip, dest_ip, dest_port, user, message, log_hash, block_index)
               VALUES (?,?,?,?,?,?,?,?,?,?,NULL)""",
            (
                entry["timestamp"], entry["device"], entry["event_type"], entry["severity"],
                entry.get("src_ip"), entry.get("dest_ip"), entry.get("dest_port"),
                entry.get("user"), entry["message"], log_hash,
            ),
        )
        self.conn.commit()
        log_id = cur.lastrowid
        cur.execute("INSERT INTO pending_hashes (log_id) VALUES (?)", (log_id,))
        self.conn.commit()
        return log_id

    def get_pending(self):
        cur = self.conn.cursor()
        cur.execute("""SELECT logs.log_id, logs.log_hash FROM pending_hashes
                       JOIN logs ON logs.log_id = pending_hashes.log_id
                       ORDER BY logs.log_id ASC""")
        return cur.fetchall()

    def clear_pending_and_assign_block(self, log_ids, block_index):
        cur = self.conn.cursor()
        cur.executemany("UPDATE logs SET block_index=? WHERE log_id=?",
                         [(block_index, lid) for lid in log_ids])
        cur.executemany("DELETE FROM pending_hashes WHERE log_id=?", [(lid,) for lid in log_ids])
        self.conn.commit()

    def get_log(self, log_id):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM logs WHERE log_id=?", (log_id,))
        return cur.fetchone()

    def get_recent_logs(self, limit=100, device=None, severity=None):
        cur = self.conn.cursor()
        q = "SELECT * FROM logs"
        clauses, params = [], []
        if device:
            clauses.append("device=?"); params.append(device)
        if severity:
            clauses.append("severity=?"); params.append(severity)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY log_id DESC LIMIT ?"
        params.append(limit)
        cur.execute(q, params)
        return cur.fetchall()

    def mark_tampered(self, log_id, new_message):
        """Simulates an attacker directly editing the off-chain DB record."""
        cur = self.conn.cursor()
        cur.execute("UPDATE logs SET message=?, tampered=1 WHERE log_id=?", (new_message, log_id))
        self.conn.commit()

    def logs_since(self, seconds_ago):
        cur = self.conn.cursor()
        cutoff = time.time() - seconds_ago
        cur.execute("SELECT * FROM logs WHERE timestamp >= ? ORDER BY timestamp ASC", (cutoff,))
        return cur.fetchall()

    def count_logs(self):
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM logs")
        return cur.fetchone()["c"]

    def severity_breakdown(self):
        cur = self.conn.cursor()
        cur.execute("SELECT severity, COUNT(*) as c FROM logs GROUP BY severity")
        return {r["severity"]: r["c"] for r in cur.fetchall()}

    # ---------- devices ----------
    def list_devices(self):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM devices")
        return cur.fetchall()

    # ---------- incidents ----------
    def insert_incident(self, attack_type, severity, device, detail, related_log_ids, anomaly_score):
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO incidents (created_at, attack_type, severity, status, device, detail, related_log_ids, anomaly_score)
               VALUES (?,?,?,?,?,?,?,?)""",
            (time.time(), attack_type, severity, "open", device, detail,
             json.dumps(related_log_ids), anomaly_score),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_incidents(self, limit=50):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM incidents ORDER BY incident_id DESC LIMIT ?", (limit,))
        return cur.fetchall()

    def update_incident_status(self, incident_id, status):
        cur = self.conn.cursor()
        cur.execute("UPDATE incidents SET status=? WHERE incident_id=?", (status, incident_id))
        self.conn.commit()

    def recent_incident_exists(self, attack_type, device, window_seconds=30):
        cur = self.conn.cursor()
        cutoff = time.time() - window_seconds
        cur.execute(
            "SELECT COUNT(*) as c FROM incidents WHERE attack_type=? AND device=? AND created_at>=?",
            (attack_type, device, cutoff),
        )
        return cur.fetchone()["c"] > 0
