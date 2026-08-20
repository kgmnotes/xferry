#!/usr/bin/env bash
# Serve the current directory over HTTPS on port 8443 with a random Basic Auth
# password. File access is restricted to `uploads/` by default.
# Self-signed certificate is generated automatically.

set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"
PORT="${PORT:-8443}"

exec xferry run \
  --host 127.0.0.1 \
  --port "${PORT}" \
  --dir "${ROOT_DIR}" \
  --tls \
  --auth random \
  --max-size 100
