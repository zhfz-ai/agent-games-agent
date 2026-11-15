#!/bin/bash
# Health check for the zkVerify Agent Games Proof Gatekeeper agent.
# Run every 5 min via cron. Restarts the server and/or the pinggy tunnel if gone.
# NEVER prints or logs any secret value.
set -u
AGENT_DIR="$HOME/workspace/agentgames"
LOG="$AGENT_DIR/agent/health.log"
URL_FILE="$AGENT_DIR/current-tunnel-url.txt"
SECRET_FILE="$AGENT_DIR/agent/agent-secret.json"
TEMP_SECRET_FILE="$AGENT_DIR/agent/.hmac-secret"

log() { echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >> "$LOG"; }

# ---- 1. Agent server (port 18080) ----
if ! curl -s --max-time 5 -o /dev/null http://127.0.0.1:18080/healthz; then
  log "server down — restarting"
  if [ -f "$SECRET_FILE" ]; then
    SECRET=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["secret"])' "$SECRET_FILE")
  else
    SECRET=$(cat "$TEMP_SECRET_FILE")
  fi
  cd "$AGENT_DIR/agent" || exit 1
  nohup env AGENT_GAMES_HMAC_SECRET="$SECRET" AGENT_GAMES_HMAC_SECRET_ENCODING=auto PORT=18080 node server.mjs >> server.log 2>&1 &
  unset SECRET
  sleep 3
  if curl -s --max-time 5 -o /dev/null http://127.0.0.1:18080/healthz; then
    log "server restarted OK"
  else
    log "server restart FAILED"
  fi
fi

# ---- 2. Pinggy tunnel ----
check_tunnel() {
  [ -f "$URL_FILE" ] || return 1
  local url
  url=$(cat "$URL_FILE")
  [ -n "$url" ] || return 1
  curl -s --max-time 15 -o /dev/null "$url/healthz"
}

if ! check_tunnel; then
  log "tunnel down or URL stale — restarting tunnel"
  pkill -f 'a.pinggy.i[o]' 2>/dev/null
  sleep 2
  rm -f /tmp/agentgames-pinggy-health.log
  nohup ssh -o ProxyCommand='socat - PROXY:hatch-egress-proxy:%h:%p,proxyport=3128' \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 -o ConnectTimeout=25 -o ExitOnForwardFailure=yes \
    -p 443 -R0:localhost:18080 a.pinggy.io > /tmp/agentgames-pinggy-health.log 2>&1 &
  # wait up to 90s for the public URL to appear in the log
  NEW_URL=""
  for _ in $(seq 1 30); do
    sleep 3
    NEW_URL=$(grep -oE 'https://[a-z0-9.-]+\.free\.pinggy\.net' /tmp/agentgames-pinggy-health.log 2>/dev/null | head -1)
    [ -n "$NEW_URL" ] && break
  done
  if [ -n "$NEW_URL" ]; then
    printf '%s' "$NEW_URL" > "$URL_FILE"
    log "tunnel restarted, new URL recorded (see current-tunnel-url.txt)"
    sleep 2
    if curl -s --max-time 15 -o /dev/null "$NEW_URL/healthz"; then
      log "tunnel public check OK"
    else
      log "tunnel public check FAILED"
    fi
  else
    log "tunnel restart FAILED — no URL in log"
  fi
fi
