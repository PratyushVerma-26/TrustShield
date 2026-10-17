#!/usr/bin/env bash
# ==============================================================================
# TrustShield Multi-Service Orchestrator (POSIX / Linux / macOS)
# Builds fat jars once and launches microservices as background processes with java -jar.
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PID_FILE="$REPO_ROOT/.run-all-pids.json"
LOGS_DIR="$REPO_ROOT/logs"

mkdir -p "$LOGS_DIR"

declare -A PORTS=(
  ["trustshield-gateway"]=8080
  ["trustshield-phishing-service"]=8083
  ["trustshield-breach-service"]=8084
  ["trustshield-deepfake-service"]=8085
  ["trustshield-fakenews-service"]=8086
  ["trustshield-integrity-service"]=8087
  ["trustshield-fusion-service"]=8088
  ["trustshield-bot-service"]=8089
)

SERVICES=(
  "trustshield-gateway"
  "trustshield-phishing-service"
  "trustshield-breach-service"
  "trustshield-deepfake-service"
  "trustshield-fakenews-service"
  "trustshield-integrity-service"
  "trustshield-fusion-service"
  "trustshield-bot-service"
)

test_port() {
  local port=$1
  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$port" >/dev/null 2>&1
  else
    (echo > "/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1
  fi
}

show_status() {
  echo ""
  echo "=== TrustShield Services Status ==="
  printf "%-6s %-32s %-12s %-8s\n" "Port" "Service" "Status" "PID"
  printf "%-6s %-32s %-12s %-8s\n" "----" "-------" "------" "---"

  for svc in "${SERVICES[@]}"; do
    local port="${PORTS[$svc]}"
    local jar="$REPO_ROOT/$svc/target/$svc-1.0.0-SNAPSHOT.jar"
    local status="DOWN"
    local pid="-"

    if [ -f "$PID_FILE" ]; then
      local extracted_pid
      extracted_pid=$(grep -o "\"$svc\":[0-9]*" "$PID_FILE" 2>/dev/null | cut -d: -f2 || true)
      if [ -n "$extracted_pid" ] && kill -0 "$extracted_pid" 2>/dev/null; then
        pid="$extracted_pid"
      fi
    fi

    if test_port "$port"; then
      status="HEALTHY"
    elif [ ! -f "$jar" ]; then
      status="NOT_BUILT"
    fi

    printf "%-6s %-32s %-12s %-8s\n" "$port" "$svc" "$status" "$pid"
  done
  echo ""
}

stop_services() {
  echo "Stopping TrustShield services..."
  if [ -f "$PID_FILE" ]; then
    for svc in "${SERVICES[@]}"; do
      local extracted_pid
      extracted_pid=$(grep -o "\"$svc\":[0-9]*" "$PID_FILE" 2>/dev/null | cut -d: -f2 || true)
      if [ -n "$extracted_pid" ] && kill -0 "$extracted_pid" 2>/dev/null; then
        echo "  Stopping $svc (PID $extracted_pid)..."
        kill "$extracted_pid" 2>/dev/null || true
      fi
    done
    rm -f "$PID_FILE"
  fi

  # Fallback check on ports
  for svc in "${SERVICES[@]}"; do
    local port="${PORTS[$svc]}"
    if test_port "$port"; then
      local lsof_pid
      lsof_pid=$(lsof -ti :"$port" 2>/dev/null || true)
      if [ -n "$lsof_pid" ]; then
        echo "  Freeing port $port (PID $lsof_pid)..."
        kill -9 "$lsof_pid" 2>/dev/null || true
      fi
    fi
  done
  echo "All services stopped."
}

start_services() {
  local no_wait=$1

  # Check if JARs exist
  local missing=0
  for svc in "${SERVICES[@]}"; do
    local jar="$REPO_ROOT/$svc/target/$svc-1.0.0-SNAPSHOT.jar"
    if [ ! -f "$jar" ]; then
      missing=1
      break
    fi
  done

  if [ "$missing" -eq 1 ]; then
    echo "One or more JAR files missing. Running Maven package..."
    (cd "$REPO_ROOT" && mvn package -DskipTests)
  fi

  echo "Launching TrustShield microservice mesh..."
  local pids_json="{"
  local first=1

  for svc in "${SERVICES[@]}"; do
    local port="${PORTS[$svc]}"
    local jar="$REPO_ROOT/$svc/target/$svc-1.0.0-SNAPSHOT.jar"
    local log_file="$LOGS_DIR/$svc.log"

    if test_port "$port"; then
      echo "  [SKIP] Port $port is already active ($svc)"
      continue
    fi

    echo "  Starting $svc on port $port..."
    nohup java -XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -jar "$jar" > "$log_file" 2>&1 &
    local new_pid=$!

    if [ "$first" -eq 1 ]; then
      pids_json="$pids_json\"$svc\":$new_pid"
      first=0
    else
      pids_json="$pids_json,\"$svc\":$new_pid"
    fi
  done
  pids_json="$pids_json}"
  echo "$pids_json" > "$PID_FILE"

  if [ "$no_wait" != "1" ]; then
    echo "Waiting for microservices to become healthy..."
    for svc in "${SERVICES[@]}"; do
      local port="${PORTS[$svc]}"
      local attempts=0
      while ! test_port "$port" && [ "$attempts" -lt 30 ]; do
        sleep 1
        attempts=$((attempts + 1))
      done
    done
  fi

  show_status
}

case "$1" in
  --stop|-Stop|-stop)
    stop_services
    ;;
  --status|-Status|-status)
    show_status
    ;;
  --build|-Build|-build)
    (cd "$REPO_ROOT" && mvn clean package -DskipTests)
    start_services 0
    ;;
  --no-wait|-NoWait)
    start_services 1
    ;;
  *)
    start_services 0
    ;;
esac
