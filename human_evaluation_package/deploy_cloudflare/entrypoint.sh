#!/bin/bash
# Start one artifact plus the harness proxy. If either dies, the container dies,
# so Cloudflare restarts it rather than serving a half-broken app to a judge.
set -eu

: "${ARTIFACT:?ARTIFACT must name a file in artifacts/, without the .ts suffix}"

APP="artifacts/${ARTIFACT}.ts"
if [ ! -f "$APP" ]; then
  echo "no such artifact: $APP" >&2
  echo "available:" >&2
  ls artifacts/ >&2
  exit 1
fi

echo "[entrypoint] artifact  : ${ARTIFACT}"
echo "[entrypoint] sha256    : $((sha256sum "$APP" 2>/dev/null || shasum -a 256 "$APP") | cut -d" " -f1)"
echo "[entrypoint] app port  : ${APP_PORT} (https, loopback only)"
echo "[entrypoint] proxy port: ${PROXY_PORT} (http, reached by Cloudflare)"

# The artifact reads its port from PORT; a few also honour HTTPS_PORT.
PORT="$APP_PORT" HTTPS_PORT="$APP_PORT" bun "$APP" &
APP_PID=$!

# Wait for the artifact to bind before accepting public traffic, so a judge
# never sees a 502 on first load.
i=0
while [ $i -lt 60 ]; do
  if bun -e "await fetch('https://127.0.0.1:${APP_PORT}/',{tls:{rejectUnauthorized:false}})" 2>/dev/null; then
    echo "[entrypoint] artifact is serving"
    break
  fi
  kill -0 "$APP_PID" 2>/dev/null || { echo "[entrypoint] artifact exited during startup" >&2; exit 1; }
  i=$((i + 1))
  sleep 0.5
done

bun proxy.ts &
PROXY_PID=$!

# Propagate a graceful stop to both, then exit as soon as either dies. Polled
# rather than `wait -n`, which needs bash 5 and so cannot be checked on a macOS
# workstation before deploying.
trap 'kill "$APP_PID" "$PROXY_PID" 2>/dev/null || true' TERM INT
while kill -0 "$APP_PID" 2>/dev/null && kill -0 "$PROXY_PID" 2>/dev/null; do
  sleep 1
done

echo "[entrypoint] a process exited; shutting the container down" >&2
kill "$APP_PID" "$PROXY_PID" 2>/dev/null || true
exit 1
