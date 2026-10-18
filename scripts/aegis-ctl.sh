#!/usr/bin/env bash
# Aegis Sentinel — service control for native (non-container) deployment.
#
# Intended for IBM LinuxONE s390x hosts that have no container runtime.
# All services bind to 127.0.0.1 only; reach them through an SSH tunnel:
#   ssh -i <key> linux1@<host> -L 8080:127.0.0.1:8080
#
# Usage: bash scripts/aegis-ctl.sh {start|stop|restart|status} [replay|procfs]
#
# MODE is an argument (default: replay) so the whole invocation stays one
# command over SSH:
#   bash aegis-ctl.sh start procfs    # LIVE /proc sensor
#   bash aegis-ctl.sh start replay    # deterministic fixtures

set -uo pipefail

MODE="${2:-replay}"
if [ "$MODE" != "replay" ] && [ "$MODE" != "procfs" ]; then
  echo "usage: $0 {start|stop|restart|status} [replay|procfs]" >&2
  exit 1
fi

APP_DIR="${APP_DIR:-$HOME/aegis}"
VENV="${VENV:-$APP_DIR/.venv/bin/python}"
LOG_DIR="${LOG_DIR:-$HOME/aegis-logs}"
FIFO="${FIFO:-/tmp/aegis-feed.jsonl}"
FIXTURE="${FIXTURE:-$APP_DIR/fixtures/sample-tetragon-raw.jsonl}"
FEED_INTERVAL="${FEED_INTERVAL:-20}"

mkdir -p "$LOG_DIR"

stop_all() {
  # Patterns must cover:
  #   - the forwarder        (-m forwarder.main)
  #   - the dashboard API    (dashboard_api.py)
  #   - the FIFO feed writer (bash -c ... aegis-feed.jsonl ...) which is NOT
  #     a python process, so a python-only pattern silently misses it and it
  #     will re-inject events forever.
  # aegis-ctl is excluded so this script never signals itself, and grep
  # excludes its own argv.
  local pattern='dashboard_api\.py|forwarder\.main|aegis-feed\.jsonl'
  local sig="-TERM" pids

  for _ in 1 2; do
    pids=$(ps -eo pid,args \
           | grep -E "$pattern" \
           | grep -v grep \
           | grep -v 'aegis-ctl' \
           | awk '{print $1}' | tr '\n' ' ')
    [ -z "${pids// /}" ] && break
    kill $sig $pids 2>/dev/null
    sleep 3
    sig="-KILL"   # second pass escalates if anything ignored SIGTERM
  done

  rm -f "$FIFO"

  # Verify rather than assume.
  sleep 1
  local left
  left=$(ps -eo pid,args | grep -E "$pattern" | grep -v grep | grep -v 'aegis-ctl' | awk '{print $1}')
  if [ -n "$left" ]; then
    echo "  WARNING: still running: $left" >&2
    return 1
  fi
  echo "stopped"
}

start_redis() {
  if ! redis-cli ping >/dev/null 2>&1; then
    sudo -n systemctl start redis-server 2>/dev/null || sudo systemctl start redis-server
    sleep 2
  fi
  echo "redis: $(redis-cli ping 2>&1)"
}

start_forwarder() {
  # MODE selects the ingestion source:
  #   replay  - deterministic fixtures via a FIFO (default, fully offline)
  #   procfs  - LIVE process sensor reading /proc on this host
  #
  # Neither mode needs a container runtime, which is what makes this the only
  # workable path on the LinuxONE host.
  #
  # The forwarder has no API-only mode: it starts its API thread and then runs
  # the ingestion stream to completion. Feeding it a named FIFO that a writer
  # keeps open holds the process (and port 8081) alive indefinitely, while
  # events keep arriving.
  #
  # --file <fifo> keeps capture_mode honestly reported as fixture_replay,
  # which a --stdin mode would not.

  if [ "$MODE" = "procfs" ]; then
    # Live sensor. Runs indefinitely; no FIFO needed because scan_once()
    # blocks on its own poll interval.
    ( setsid nohup "$VENV" -m forwarder.main \
        --mode procfs \
        > "$LOG_DIR/forwarder.log" 2>&1 < /dev/null & ) \
      > /dev/null 2>&1 < /dev/null
    sleep 5
    echo "forwarder: LIVE procfs sensor started (interval=${PROCFS_POLL_INTERVAL:-2.0}s)"
    return
  fi

  rm -f "$FIFO"; mkfifo "$FIFO"

  # NOTE: the redirections apply to the whole subshell, not just the inner
  # command. Without them a background process inherits this script's stdout,
  # and `ssh host 'aegis-ctl.sh start'` then blocks forever waiting for EOF
  # even though every service started correctly.
  ( setsid nohup "$VENV" -m forwarder.main \
      --mode fixture_replay --file "$FIFO" \
      > "$LOG_DIR/forwarder.log" 2>&1 < /dev/null & ) \
    > /dev/null 2>&1 < /dev/null
  sleep 4

  ( setsid nohup bash -c \
      "exec 3> $FIFO; while true; do cat '$FIXTURE' >&3; sleep $FEED_INTERVAL; done" \
      > "$LOG_DIR/feed.log" 2>&1 < /dev/null & ) \
    > /dev/null 2>&1 < /dev/null
  sleep 3
  echo "forwarder: started (fixtures re-fed every ${FEED_INTERVAL}s)"
}

start_dashboard() {
  ( setsid nohup "$VENV" dashboard_api.py \
      > "$LOG_DIR/dashboard.log" 2>&1 < /dev/null & ) \
    > /dev/null 2>&1 < /dev/null
  sleep 8
  echo "dashboard: started"
}

status() {
  echo "=== LISTENERS (expect 127.0.0.1 only) ==="
  ss -ltn | grep -E '6379|8080|8081' || echo "  none"

  echo
  echo "=== HEALTH ==="
  if [ -x "$VENV" ]; then
    curl -s --max-time 10 http://127.0.0.1:8080/api/health \
      | "$VENV" -m json.tool 2>&1 | head -45
  else
    echo "  (venv not found at $VENV)"
  fi

  echo
  echo "=== STREAM ==="
  redis-cli XLEN "${REDIS_STREAM_KEY:-security:events}" 2>/dev/null || echo "  n/a"
}

case "${1:-status}" in
  start)   start_redis; start_forwarder; start_dashboard; status ;;
  stop)    stop_all ;;
  restart) stop_all; start_redis; start_forwarder; start_dashboard; status ;;
  status)  status ;;
  *)       echo "usage: $0 {start|stop|restart|status} [replay|procfs]"; exit 1 ;;
esac