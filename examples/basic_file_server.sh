#!/usr/bin/env bash
# Serve the selected folder on loopback over self-signed HTTPS.
# Generate file-backed credentials first through `xferry config` → Password.
set -euo pipefail

FILES_DIR="${1:-$(pwd)}"
PORT="${PORT:-8443}"

exec xferry run \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --files-dir "${FILES_DIR}" \
  --https self-signed \
  --max-size 100
