#!/bin/zsh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="$ROOT_DIR/.run"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
BACKEND_LOG="$RUN_DIR/backend.log"
FRONTEND_LOG="$RUN_DIR/frontend.log"
BACKEND_PID_FILE="$RUN_DIR/backend.pid"
FRONTEND_PID_FILE="$RUN_DIR/frontend.pid"

mkdir -p "$RUN_DIR"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required but not installed."
    exit 1
  fi
}

port_is_listening() {
  lsof -tiTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

wait_for_http() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "$name is ready."
      return 0
    fi
    sleep 1
  done

  echo "$name failed to start."
  return 1
}

start_backend() {
  if port_is_listening 8000; then
    echo "Backend already running on port 8000."
    return 0
  fi

  echo "Starting backend..."
  cd "$BACKEND_DIR"

  if [ ! -d venv ]; then
    python3 -m venv venv
  fi

  source venv/bin/activate
  pip install -r requirements.txt >/dev/null

  nohup ./venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 \
    >"$BACKEND_LOG" 2>&1 &
  echo $! > "$BACKEND_PID_FILE"

  wait_for_http "http://127.0.0.1:8000/health" "Backend" || {
    echo "Backend log:"
    tail -n 40 "$BACKEND_LOG" || true
    exit 1
  }
}

start_frontend() {
  if port_is_listening 5173; then
    echo "Frontend already running on port 5173."
    return 0
  fi

  echo "Starting frontend..."
  cd "$FRONTEND_DIR"

  if [ ! -d node_modules ]; then
    npm install >/dev/null
  fi

  nohup npm run dev -- --host 127.0.0.1 \
    >"$FRONTEND_LOG" 2>&1 &
  echo $! > "$FRONTEND_PID_FILE"

  wait_for_http "http://127.0.0.1:5173" "Frontend" || {
    echo "Frontend log:"
    tail -n 40 "$FRONTEND_LOG" || true
    exit 1
  }
}

require_cmd python3
require_cmd npm
require_cmd curl
require_cmd lsof

start_backend
start_frontend

echo ""
echo "AegisHealth is running:"
echo "Frontend: http://localhost:5173/login"
echo "Backend:  http://localhost:8000/docs"
echo "Logs:"
echo "  $BACKEND_LOG"
echo "  $FRONTEND_LOG"

open "http://localhost:5173/login" >/dev/null 2>&1 || true
