#!/usr/bin/env bash
# Redstrike container entrypoint.
#
#   docker compose up                         -> start the console control plane (UI + API)
#   docker compose run --rm redstrike <cmd>   -> run <cmd> instead, e.g.:
#       docker compose run --rm redstrike claude login     # persist a Claude login (volume)
#       docker compose run --rm redstrike codex login      # persist a Codex login
#       docker compose run --rm redstrike gemini           # Gemini CLI (first run does OAuth)
#       docker compose run --rm redstrike redstrike doctor # engine + auth + tool preflight
#       docker compose run --rm redstrike bash             # a shell in the image
#
# AUTHORIZED TESTING ONLY.
set -euo pipefail

cd /opt/redstrike
export REDSTRIKE_REPO=/opt/redstrike

# Any extra args -> run them instead of the server (login flows, doctor, a shell, …).
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

# --- Claude auth preflight (warn only; a mounted login or keys may be present) ------------
have_claude_auth=0
[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && have_claude_auth=1
[ -n "${ANTHROPIC_API_KEY:-}" ] && have_claude_auth=1
if [ -d /root/.claude ] && [ -n "$(ls -A /root/.claude 2>/dev/null || true)" ]; then have_claude_auth=1; fi
if [ "$have_claude_auth" -eq 0 ]; then
  echo "=============================================================================="
  echo " WARNING: no Claude authentication detected."
  echo "   Claude is the only LIVE engine today. Provide ONE of:"
  echo "     - CLAUDE_CODE_OAUTH_TOKEN   (unattended; create it with: claude setup-token)"
  echo "     - ANTHROPIC_API_KEY"
  echo "     - a persisted login:  docker compose run --rm redstrike claude login"
  echo "   Pin Opus 5.5 with:  ANTHROPIC_MODEL=claude-opus-5-5"
  echo "=============================================================================="
fi

mkdir -p engagements

PORT="${REDSTRIKE_CONSOLE_PORT:-8788}"
echo ":: Redstrike control plane starting — open  http://localhost:${PORT}/"
echo ":: paste the bearer token below into the console's 'Control plane' view."

exec python3 scripts/console_control.py --enable-control \
  --host "${REDSTRIKE_CONSOLE_HOST:-0.0.0.0}" \
  --port "${PORT}" \
  "${REDSTRIKE_TARGET:-engagements}"
