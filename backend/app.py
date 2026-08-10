"""
app.py
Blockchain SIEM - main API server.

Endpoints:
  POST /api/ingest/simulate     -> generate + ingest a batch of synthetic logs
  POST /api/mine                -> force-mine all pending log hashes into a new block
  GET  /api/logs                -> recent logs (optionally filtered)
  GET  /api/logs/<id>/verify    -> re-hash a log and check it against the blockchain
  POST /api/logs/<id>/tamper    -> DEMO ONLY: simulate an attacker editing a log in the DB
  GET  /api/blockchain          -> full chain
  GET  /api/blockchain/validate -> validate entire chain integrity
  GET  /api/incidents           -> recent AI-flagged incidents
  POST /api/incidents/<id>/status
  GET  /api/dashboard/stats     -> summary counters for the dashboard
  GET  /api/devices             -> device inventory
"""

import os
import time
import threading
import hashlib
import json

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from blockchain import Blockchain, sha256
from db import Database
from ai_detector import AIDetector
import log_simulator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("CHAIN_DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")

app = Flask(__name__, static_folder=None)
CORS(app)

db = Database(os.path.join(DATA_DIR, "siem.db"))
chain = Blockchain(os.path.join(DATA_DIR, "chain.json"))
ai = AIDetector()

BATCH_SIZE = 6          # auto-mine once this many logs are pending
lock = threading.Lock()


def hash_log_entry(entry, log_id):
    """Canonical hash of a log's content. This is what gets committed to the chain."""
    canonical = json.dumps({
        "log_id": log_id,
        "timestamp": entry["timestamp"],
        "device": entry["device"],
        "event_type": entry["event_type"],
        "severity": entry["severity"],
        "src_ip": entry.get("src_ip"),
        "dest_ip": entry.get("dest_ip"),
        "dest_port": entry.get("dest_port"),
        "user": entry.get("user"),
        "message": entry["message"],
    }, sort_keys=True)
    return sha256(canonical)


def recompute_log_hash(row):
    return hash_log_entry({
        "timestamp": row["timestamp"], "device": row["device"], "event_type": row["event_type"],
        "severity": row["severity"], "src_ip": row["src_ip"], "dest_ip": row["dest_ip"],
        "dest_port": row["dest_port"], "user": row["user"], "message": row["message"],
    }, row["log_id"])


def ingest_entry(entry):
    """Hash placeholder first (log_id unknown until insert), then store, then
    recompute the *real* canonical hash including the assigned log_id, and
    update the record. This keeps the hash bound to a specific log_id so a
    tamper on message/severity/etc is always detectable."""
    log_id = db.insert_log(entry, log_hash="")
    real_hash = hash_log_entry(entry, log_id)
    db.conn.execute("UPDATE logs SET log_hash=? WHERE log_id=?", (real_hash, log_id))
    db.conn.commit()
    return log_id, real_hash


def maybe_mine():
    pending = db.get_pending()
    if len(pending) >= BATCH_SIZE:
        log_ids = [r["log_id"] for r in pending]
        log_hashes = [r["log_hash"] for r in pending]
        block = chain.mine_block(log_hashes, log_ids)
        db.clear_pending_and_assign_block(log_ids, block.index)
        return block
    return None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/api/ingest/simulate", methods=["POST"])
def api_ingest_simulate():
    with lock:
        body = request.get_json(silent=True) or {}
        n_normal = int(body.get("n_normal", 6))
        attack_probability = float(body.get("attack_probability", 0.3))
        batch = log_simulator.generate_batch(n_normal=n_normal, attack_probability=attack_probability)

        ingested = []
        for entry in batch:
            log_id, h = ingest_entry(entry)
            ingested.append(log_id)

        mined_block = maybe_mine()
        new_incidents = ai.analyze(db)

        return jsonify({
            "ingested_count": len(ingested),
            "log_ids": ingested,
            "mined_block": mined_block.to_dict() if mined_block else None,
            "new_incidents": new_incidents,
        })


@app.route("/api/mine", methods=["POST"])
def api_mine():
    with lock:
        pending = db.get_pending()
        if not pending:
            return jsonify({"mined": False, "message": "No pending logs to mine."})
        log_ids = [r["log_id"] for r in pending]
        log_hashes = [r["log_hash"] for r in pending]
        block = chain.mine_block(log_hashes, log_ids)
        db.clear_pending_and_assign_block(log_ids, block.index)
        return jsonify({"mined": True, "block": block.to_dict()})


@app.route("/api/logs", methods=["GET"])
def api_logs():
    limit = int(request.args.get("limit", 100))
    device = request.args.get("device")
    severity = request.args.get("severity")
    rows = db.get_recent_logs(limit=limit, device=device, severity=severity)
    return jsonify([dict(r) for r in rows])


@app.route("/api/logs/<int:log_id>/verify", methods=["GET"])
def api_verify_log(log_id):
    row = db.get_log(log_id)
    if not row:
        return jsonify({"error": "log not found"}), 404

    stored_hash = row["log_hash"]
    recomputed_hash = recompute_log_hash(row)
    content_matches = (stored_hash == recomputed_hash)

    block = chain.find_block_for_log(log_id)
    on_chain = False
    chain_valid_at_block = None
    if block:
        on_chain = stored_hash in block.log_hashes
        chain_valid_at_block = block.recompute_hash() == block.hash

    chain_ok, broken_blocks = chain.validate_chain()

    verified = content_matches and on_chain and chain_ok

    return jsonify({
        "log_id": log_id,
        "tampered_flag_in_db": bool(row["tampered"]),
        "stored_hash": stored_hash,
        "recomputed_hash_from_current_content": recomputed_hash,
        "content_matches_stored_hash": content_matches,
        "block_index": block.index if block else None,
        "hash_present_in_block": on_chain,
        "block_internally_valid": chain_valid_at_block,
        "full_chain_valid": chain_ok,
        "broken_block_indices": broken_blocks,
        "verified": verified,
        "verdict": "AUTHENTIC - matches blockchain record" if verified
                   else "TAMPERING DETECTED - log content does not match its blockchain-committed hash",
    })


@app.route("/api/logs/<int:log_id>/tamper", methods=["POST"])
def api_tamper_log(log_id):
    """DEMO ENDPOINT: simulates a privileged attacker directly editing the
    off-chain database to cover their tracks (e.g. rewriting an auth_failure
    to look like routine traffic). The blockchain hash was computed BEFORE
    this edit, so /verify will now detect the mismatch."""
    row = db.get_log(log_id)
    if not row:
        return jsonify({"error": "log not found"}), 404
    fake_message = "Routine scheduled maintenance task completed successfully"
    db.mark_tampered(log_id, fake_message)
    return jsonify({
        "log_id": log_id,
        "message": "Log content altered directly in the database (simulated attacker action).",
        "new_message": fake_message,
        "hint": "Call /api/logs/{}/verify to see this get caught.".format(log_id),
    })


@app.route("/api/blockchain", methods=["GET"])
def api_blockchain():
    return jsonify(chain.to_list())


@app.route("/api/blockchain/validate", methods=["GET"])
def api_blockchain_validate():
    valid, broken = chain.validate_chain()
    return jsonify({"valid": valid, "broken_block_indices": broken, "chain_length": len(chain.chain)})


@app.route("/api/incidents", methods=["GET"])
def api_incidents():
    limit = int(request.args.get("limit", 50))
    rows = db.list_incidents(limit=limit)
    return jsonify([dict(r) for r in rows])


@app.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
def api_incident_status(incident_id):
    body = request.get_json(silent=True) or {}
    status = body.get("status", "resolved")
    db.update_incident_status(incident_id, status)
    return jsonify({"incident_id": incident_id, "status": status})


@app.route("/api/devices", methods=["GET"])
def api_devices():
    rows = db.list_devices()
    return jsonify([dict(r) for r in rows])


@app.route("/api/health", methods=["GET"])
def api_health():
    valid, broken = chain.validate_chain()
    return jsonify({
        "status": "ok",
        "service": "chainsiem-backend",
        "chain_valid": valid,
        "chain_length": len(chain.chain),
        "broken_block_indices": broken,
    })


@app.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    valid, broken = chain.validate_chain()
    pending = db.get_pending()
    return jsonify({
        "total_logs": db.count_logs(),
        "severity_breakdown": db.severity_breakdown(),
        "block_count": len(chain.chain),
        "pending_logs": len(pending),
        "chain_valid": valid,
        "broken_block_indices": broken,
        "open_incidents": sum(1 for r in db.list_incidents(limit=1000) if r["status"] == "open"),
        "total_incidents": len(db.list_incidents(limit=1000)),
    })


# --------------------------------------------------------------------------
# Serve frontend
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def frontend_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
