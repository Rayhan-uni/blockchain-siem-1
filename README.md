# ChainSIEM — Blockchain-Anchored SIEM (Working Prototype)

A fully functional, runnable implementation of the Blockchain SIEM concept:
security logs are stored off-chain, but every log's SHA-256 hash is
committed to a real hash-chained ledger, so any tampering with the stored
log is mathematically detectable. An AI (IsolationForest) anomaly engine
watches the live log stream and files incidents automatically.

This is a **from-scratch, dependency-light prototype** — it does not spin up
Kafka, Kubernetes, or a real Ethereum/Hyperledger node (that's a
multi-service infra project, not something you run with one command). What
it does instead is implement the *actual mechanism* — hashing, block
linking, chain validation, tamper detection, batching, AI-driven incident
detection — for real, in Python, so you can run it, click around, and watch
tampering get caught live. Swapping the custom `blockchain.py` module for a
real Ethereum/Hyperledger smart-contract client, or SQLite for PostgreSQL,
is a drop-in replacement later — the architecture and API contract stay the
same.

## What's actually implemented (and works)

- **Hash-chained ledger** (`backend/blockchain.py`): each block header includes
  a merkle-root of its logs' hashes + the previous block's hash, and is mined
  with a lightweight proof-of-work. Changing any log breaks the chain from
  that block forward — `/api/blockchain/validate` will tell you exactly
  which block broke.
- **Off-chain encrypted-at-rest-ready storage** (`backend/db.py`): SQLite
  table holding full log content, devices, incidents.
- **Log collector + simulator** (`backend/log_simulator.py`): generates
  realistic normal traffic plus scripted attack scenarios — brute force,
  port scan, malware/C2 beacon, privilege-escalation + exfiltration.
- **AI Detection Engine** (`backend/ai_detector.py`): an IsolationForest
  scores sliding windows of per-device log features; anomalous windows are
  labeled with an attack type + MITRE ATT&CK technique and filed as an
  incident.
- **Verification** (`GET /api/logs/<id>/verify`): re-hashes the log's
  *current* database content and checks it against what's committed on the
  chain. This is the actual tamper-evidence mechanism working live.
- **Tamper demo** (`POST /api/logs/<id>/tamper`): simulates a privileged
  attacker directly rewriting a log's content in the database (as they
  could with a traditional centralized SIEM) — then verification catches it.
- **Dashboard** (`frontend/index.html`): live log stream, a visual ledger
  ribbon of linked blocks (broken links glow red if tampered), incident
  feed, severity breakdown, one-click Verify / Tamper demo.

## Quick start

```bash
cd backend
pip install -r requirements.txt      # or: pip install -r requirements.txt --break-system-packages
python3 app.py
```

Then open **http://localhost:5000** in your browser. The Flask server
serves both the API and the dashboard.

## Using the dashboard

1. **Generate batch** — ingests ~6 simulated log events (mostly normal
   traffic, occasionally an attack burst). Once 6+ logs are pending they're
   automatically mined into a new block.
2. **Auto-generate traffic** — ingests a batch every 4 seconds so you can
   watch the ledger and incident feed grow live.
3. Click **Verify** on any log row to see its hash re-checked against the
   blockchain (should show ✓ AUTHENTIC).
4. In the verify panel, click **Simulate attacker tamper** — this directly
   rewrites that log's message in the database (bypassing the app layer,
   like a real attacker with DB access would). Click **Re-verify** and
   watch it flip to ✕ TAMPERING DETECTED, with the mismatched hash shown.
5. Watch the **Immutable Ledger** ribbon at the top — each block shows its
   hash and links to the next. The link would glow red if the *chain
   itself* were corrupted (as opposed to an off-chain DB edit, which is
   caught at the per-log verification level instead — this mirrors the real
   design: the chain proves what the original content *was*, even if
   someone edits the copy sitting in the database).
6. Watch the **AI-Flagged Incidents** panel — brute-force bursts, port
   scans, and exfiltration patterns get automatically detected and labeled
   with MITRE ATT&CK techniques.

## API reference

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/ingest/simulate` | Generate + ingest a batch of synthetic logs |
| POST | `/api/mine` | Force-mine all pending log hashes into a new block |
| GET | `/api/logs?limit=&device=&severity=` | Recent logs |
| GET | `/api/logs/<id>/verify` | Re-hash a log and check it against the chain |
| POST | `/api/logs/<id>/tamper` | Demo: simulate an attacker editing a log |
| GET | `/api/blockchain` | Full chain |
| GET | `/api/blockchain/validate` | Validate chain integrity |
| GET | `/api/incidents` | AI-flagged incidents |
| POST | `/api/incidents/<id>/status` | Update incident status |
| GET | `/api/devices` | Device inventory |
| GET | `/api/dashboard/stats` | Summary counters |

## Taking this toward the full spec in the document

The uploaded project brief describes an enterprise-scale system (Ethereum/
Hyperledger, Kafka, Kubernetes, ASP.NET Core, OpenSearch, etc.). This
prototype is built so each piece can be upgraded independently without
changing the overall design:

- Swap `blockchain.py` for a Web3.py client against a deployed Solidity
  contract (`StoreHash`, `VerifyHash`) — the `mine_block`/`validate_chain`
  call sites in `app.py` stay the same shape.
- Swap SQLite in `db.py` for PostgreSQL (same SQL, different connection).
- Point `log_simulator.py`'s ingestion call at real Syslog/Filebeat/Winlogbeat
  feeds instead of synthetic data.
- Add Kafka between collection and hashing for high log volume.
- Containerize with the provided `requirements.txt` + a simple Dockerfile,
  then orchestrate with Kubernetes for horizontal scaling.

## Notes on scope

- The proof-of-work difficulty is intentionally low (2 leading zero hex
  chars) — this is a demonstration of the *mechanism*, not a
  production-hardened chain.
- Auth/RBAC/MFA/AES-256-at-rest from the original spec's security-features
  list aren't implemented in this prototype (no login system) — this build
  focuses on proving out the core tamper-evidence + AI-detection pipeline,
  which is the hard, novel part of the concept.

## Vercel deployment fix

The dashboard can be hosted on Vercel while the Flask API runs on a persistent
backend service such as Render. The repository now includes:

- `api/[...path].js` — Vercel serverless proxy for `/api/*` requests.
- `vercel.json` — Node.js runtime configuration for the proxy.
- `render.yaml` — Render backend + persistent `/data` disk configuration.
- `backend/Dockerfile` — optional container deployment.
- `DEPLOY_VERCEL_RENDER.md` — exact deployment steps.

Set `BACKEND_URL` in Vercel to the deployed Flask backend URL, then redeploy.

## Vercel-only deployment

The Vercel-only version exposes the Flask application through the top-level `app.py` entry point. Import the GitHub repository into Vercel from its repository root. No Render service and no `BACKEND_URL` environment variable are required.

For the demo, SQLite and the hash-chain file use Vercel's `/tmp` filesystem and are ephemeral. Use persistent external storage for production data.
