"""Vercel entry point for ChainSIEM.

Vercel detects the top-level ``app`` WSGI application and runs the Flask
application as a Python Function.  The original application code remains in
backend/ so it can still be run locally.
"""
import os
import sys

# Vercel Functions have a read-only filesystem except for /tmp.  The demo
# ledger/database are therefore kept in /tmp in the Vercel deployment.
if os.environ.get("VERCEL"):
    os.environ.setdefault("CHAIN_DATA_DIR", "/tmp/chainsiem-data")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from backend.app import app  # noqa: E402,F401
