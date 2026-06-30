#!/bin/zsh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT_DIR/.run"

stop_pid_file() {
  local file="$1"
  if [ -f "$file" ]; then
    local pid
    pid="$(cat "$file")"
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
    rm -f "$file"
  fi
}

stop_pid_file "$RUN_DIR/backend.pid"
stop_pid_file "$RUN_DIR/frontend.pid"

echo "Stopped AegisHealth services."
