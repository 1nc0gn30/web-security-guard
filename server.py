#!/usr/bin/env python3
"""Web Security Guard Standalone Production Server on Port 8125.

Provides real REST API endpoints:
  - /health & /api/health
  - /api/audit
  - /api/csp/generate
  - /api/sri/hash & /api/sri/inject
  - /api/wcag/contrast
  - /api/ssl/inspect
  - /api/mcp/config
  - /api/export-zip
and serves the standalone Web Security Studio from public/.
"""

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
PUBLIC_DIR = ROOT_DIR / "public"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from web_security_guard.ui_server import start_ui_server

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Web Security Guard Standalone Workstation")
    parser.add_argument("--port", type=int, default=8125, help="Port to listen on (default: 8125)")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()

    print(f"Starting Web Security Guard Server on {args.host}:{args.port}...")
    start_ui_server(host=args.host, port=args.port, public_dir=PUBLIC_DIR)
