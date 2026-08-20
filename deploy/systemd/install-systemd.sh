#!/usr/bin/env bash
set -euo pipefail

XFERRY_EXECUTABLE="${XFERRY_EXECUTABLE:-/opt/xferry/current/xferry}"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-systemd.sh must be run as root" >&2
  exit 1
fi

if [ ! -x "${XFERRY_EXECUTABLE}" ]; then
  echo "installed XFerry executable is missing: ${XFERRY_EXECUTABLE}" >&2
  exit 1
fi

exec "${XFERRY_EXECUTABLE}" setup "$@"
