#!/usr/bin/env python3
"""Detach a uvicorn server so it survives the launching shell session."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(ROOT, ".venv", "bin", "python")
LOG = "/tmp/opencode/fareguard_server.log"

devnull = open(os.devnull, "wb")
proc = subprocess.Popen(
    [PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
    cwd=ROOT,
    stdout=open(LOG, "ab"),
    stderr=subprocess.STDOUT,
    stdin=devnull,
    start_new_session=True,
    close_fds=True,
)
print(f"spawned pid {proc.pid}; log: {LOG}")
sys.exit(0)
