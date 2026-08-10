# ChainSIEM — Vercel-only deployment

This version runs the Flask API and dashboard in one Vercel project.

## Deploy

1. Push the repository to GitHub.
2. In Vercel, choose **Add New → Project** and import `Rayhan-uni/blockchain-siem`.
3. Keep the repository root as the project root.
4. Do not set a Root Directory to `backend`.
5. Do not add `BACKEND_URL`.
6. Do not add a Build Command or Output Directory.
7. Deploy.

Vercel detects the top-level `app.py` Flask WSGI application and uses the root `requirements.txt`.

## Important demo-storage note

The application uses SQLite and `chain.json`. On Vercel these files are stored under `/tmp/chainsiem-data` and are therefore **ephemeral**. They are suitable for a demo/FYP presentation, but not for permanent SIEM records. A production deployment should move the database and ledger to persistent external storage.
