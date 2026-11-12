#!/usr/bin/env bash
# MedTrace secret rotation + deploy + live verification (post-leak remediation).
#
# WHY: the production MEDTRACE_MCP_SECRET and webtrigger URL were committed to the public
# repo (.env.example). Even after placeholders landed, the leaked secret stays valid until
# rotated. This script performs the full rotation in one shot and proves the new state live.
#
# WHAT IT DOES (in order):
#   1. forge lint                     — gate on manifest validity
#   2. generate a 256-bit secret
#   3. forge variables set            — install the new secret in the Forge environment
#   4. forge deploy                   — ship the manifest changes (rovo:action inputs schemas)
#   5. update local .env (if present) — keep local MCP tooling working
#   6. live verification against the deployed webtrigger:
#        a. OLD secret  -> expect HTTP 401 (leaked credential is dead)
#        b. NEW secret  -> expect HTTP 200 (GET full compliance suite)
#        c. 4-step replay proof -> 200 / 409 / 409 / 200
#        d. verify-release-gate  -> expect HTTP 403 while the demo suite has open gaps
#
# USAGE:
#   credentials ready: forge login OR ~/.forge-env with FORGE_EMAIL + FORGE_API_TOKEN
#   bash scripts/rotate-mcp-secret.sh
#
# Env overrides: ENVIRONMENT (default: development), SKIP_DEPLOY=1, SKIP_ROTATE=1 (verify only)

set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
fi

CI=true
FORGE_DISABLE_ANALYTICS=true
export CI FORGE_DISABLE_ANALYTICS

# Keychain-less machines: source credentials from ~/.forge-env (chmod 600, outside the repo):
#   export FORGE_EMAIL="you@example.com"
#   export FORGE_API_TOKEN="<forge-cli-scoped token>"
FORGE_ENV_FILE="${FORGE_ENV_FILE:-$HOME/.forge-env}"
if [ -f "$FORGE_ENV_FILE" ]; then
  # shellcheck source=/dev/null
  . "$FORGE_ENV_FILE"
fi

ENVIRONMENT="${ENVIRONMENT:-development}"
ENVIRONMENTS="${ENVIRONMENTS:-production development}"
FORGE_BIN="${FORGE_BIN:-forge}"
ENV_FILE=".env"

command -v "$FORGE_BIN" >/dev/null || { echo "❌ forge CLI not found. npm install -g @forge/cli"; exit 1; }
if [ -z "${FORGE_API_TOKEN:-}" ]; then
  "$FORGE_BIN" whoami >/dev/null 2>&1 || {
    echo "❌ No credentials. Either run:  forge login   (needs libsecret/keychain)"
    echo "   or create ~/.forge-env (chmod 600) containing:"
    echo "      export FORGE_EMAIL=\"you@example.com\""
    echo "      export FORGE_API_TOKEN=\"<token from go.atlassian.com/forge-cli-api-token>\""
    exit 1
  }
fi
openssl rand -hex 1 >/dev/null 2>&1 || { echo "❌ openssl not found"; exit 1; }

echo "== 1/6 Linting manifest =="
"$FORGE_BIN" lint --approve MAJOR_VERSION_RULE

echo "== 2/6 Generating new 256-bit secret =="
NEW_SECRET="$(openssl rand -hex 32)"
# The pre-rotation secret leaked to the public repo (it remains in git history) and was
# rotated on 2026-11-09. To re-demonstrate its 401, pass it via LEAKED_SECRET — it is
# intentionally NOT stored in this file. Never derive it from MEDTRACE_MCP_SECRET
# (that is the NEW secret's channel).
OLD_SECRET="${LEAKED_SECRET:-}"

if [ "${SKIP_ROTATE:-0}" != "1" ]; then
  # Rotate + deploy every environment that serves the webtrigger. Variables are snapshotted
  # at deploy time (a variables set alone does not affect running deployments).
  for ENV in $ENVIRONMENTS; do
    echo "== 3/6 Setting MEDTRACE_MCP_SECRET in environment: $ENV =="
    "$FORGE_BIN" variables set MEDTRACE_MCP_SECRET "$NEW_SECRET" --environment "$ENV" --encrypt
    if [ "${SKIP_DEPLOY:-0}" != "1" ]; then
      echo "== 4/6 Deploying manifest to $ENV =="
      "$FORGE_BIN" deploy --environment "$ENV" --non-interactive --approve MAJOR_VERSION_RULE
    fi
  done
else
  echo "== 3/6 SKIP_ROTATE=1 — keeping existing secret (pass MEDTRACE_MCP_SECRET) =="
  NEW_SECRET="${MEDTRACE_MCP_SECRET:?Set MEDTRACE_MCP_SECRET when using SKIP_ROTATE=1}"
fi

echo "== 5/6 Syncing local .env (if present) =="
WEBTRIGGER_URL=""
for ENV in $ENVIRONMENTS; do
  WEBTRIGGER_URL="$("$FORGE_BIN" webtrigger list -f mcp-sync-webtrigger --environment "$ENV" -s "${FORGE_SITE:-one-atlas-feur.atlassian.net}" -p jira 2>/dev/null | grep -o 'https://[^ ]*' | head -1 || true)"
  [ -n "$WEBTRIGGER_URL" ] && break
done
if [ -z "$WEBTRIGGER_URL" ] && [ -f "$ENV_FILE" ]; then
  WEBTRIGGER_URL="$(grep '^MEDTRACE_WEBTRIGGER_URL=' "$ENV_FILE" | cut -d= -f2- || true)"
fi
if [ -z "$WEBTRIGGER_URL" ]; then
  echo "⚠️  Could not auto-detect webtrigger URL — paste it into .env manually."
elif [ -f "$ENV_FILE" ]; then
  if grep -q '^MEDTRACE_MCP_SECRET=' "$ENV_FILE"; then
    sed -i "s|^MEDTRACE_MCP_SECRET=.*|MEDTRACE_MCP_SECRET=$NEW_SECRET|" "$ENV_FILE"
  else
    printf '\nMEDTRACE_MCP_SECRET=%s\n' "$NEW_SECRET" >> "$ENV_FILE"
  fi
  if grep -q '^MEDTRACE_WEBTRIGGER_URL=' "$ENV_FILE"; then
    sed -i "s|^MEDTRACE_WEBTRIGGER_URL=.*|MEDTRACE_WEBTRIGGER_URL=$WEBTRIGGER_URL|" "$ENV_FILE"
  else
    printf 'MEDTRACE_WEBTRIGGER_URL=%s\n' "$WEBTRIGGER_URL" >> "$ENV_FILE"
  fi
  echo "   .env updated (git-ignored)."
else
  printf 'MEDTRACE_MCP_SECRET=%s\nMEDTRACE_WEBTRIGGER_URL=%s\n' "$NEW_SECRET" "$WEBTRIGGER_URL" > "$ENV_FILE"
  echo "   .env created (git-ignored)."
fi

if [ -z "$WEBTRIGGER_URL" ]; then
  echo "❌ No webtrigger URL — cannot verify live. Re-run verification after checking 'forge webtrigger list'."
  exit 1
fi

echo "== 6/6 Live verification against $WEBTRIGGER_URL =="
FAIL=0

echo -n "   a. OLD secret (leaked)  -> expect 401: "
if [ -n "$OLD_SECRET" ]; then
  TS_A="$(date +%s%3N)"; NONCE_A="old-$(openssl rand -hex 8)"
  SIG_A="$(printf '%s.%s.' "$TS_A" "$NONCE_A" | openssl dgst -sha256 -hmac "$OLD_SECRET" -hex | awk '{print $2}')"
  CODE_A="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "x-medtrace-timestamp: $TS_A" -H "x-medtrace-nonce: $NONCE_A" -H "x-medtrace-signature: sha256=$SIG_A" "$WEBTRIGGER_URL")"
  echo "$CODE_A"; [ "$CODE_A" = "401" ] || { echo "      ❌ old secret still accepted!"; FAIL=1; }
else
  echo "skipped (set LEAKED_SECRET to verify the pre-rotation secret is dead)"
fi

echo -n "   b. NEW secret GET suite -> expect 200: "
TS_B="$(date +%s%3N)"; NONCE_B="get-$(openssl rand -hex 8)"; SIG_B="$(printf '%s.%s.' "$TS_B" "$NONCE_B" | openssl dgst -sha256 -hmac "$NEW_SECRET" -hex | awk '{print $2}')"
CODE_B="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "x-medtrace-timestamp: $TS_B" -H "x-medtrace-nonce: $NONCE_B" -H "x-medtrace-signature: sha256=$SIG_B" "$WEBTRIGGER_URL")"
echo "$CODE_B"; [ "$CODE_B" = "200" ] || { echo "      ❌ new secret rejected (did deploy finish?)"; FAIL=1; }

echo "   c. 4-step replay proof  -> expect 200 / 409 / 409 / 200:"
BODY='{"action":"simulate_transition","issueKey":"MED-42"}'
for STEP in 1 2 3 4; do
  if [ "$STEP" = "3" ]; then
    TS="$(date +%s%3N)"   # attacker refreshes timestamp, keeps consumed nonce
  elif [ "$STEP" = "4" ]; then
    TS="$(date +%s%3N)"; NONCE="verify-$(openssl rand -hex 8)"
  elif [ "$STEP" = "1" ]; then
    TS="$(date +%s%3N)"; NONCE="verify-$(openssl rand -hex 8)"
  fi
  SIG="$(printf '%s.%s.%s' "$TS" "$NONCE" "$BODY" | openssl dgst -sha256 -hmac "$NEW_SECRET" -hex | awk '{print $2}')"
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "$WEBTRIGGER_URL" \
    -H "x-medtrace-timestamp: $TS" \
    -H "x-medtrace-nonce: $NONCE" -H "x-medtrace-signature: sha256=$SIG" \
    -H "Content-Type: application/json" -d "$BODY")"
  echo "      step $STEP -> $CODE"
  case "$STEP" in 1|4) [ "$CODE" = "200" ] || FAIL=1 ;; 2|3) [ "$CODE" = "409" ] || FAIL=1 ;; esac
done

echo -n "   d. verify-release-gate  -> expect 403 (demo suite has open gaps): "
TS="$(date +%s%3N)"; NONCE="gate-$(openssl rand -hex 8)"; GBODY='{"action":"verify-release-gate"}'
GSIG="$(printf '%s.%s.%s' "$TS" "$NONCE" "$GBODY" | openssl dgst -sha256 -hmac "$NEW_SECRET" -hex | awk '{print $2}')"
CODE_D="$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -X POST "$WEBTRIGGER_URL" \
  -H "x-medtrace-timestamp: $TS" \
  -H "x-medtrace-nonce: $NONCE" -H "x-medtrace-signature: sha256=$GSIG" \
  -H "Content-Type: application/json" -d "$GBODY")"
echo "$CODE_D"; [ "$CODE_D" = "403" ] || { echo "      ❌ gate did not block — check suite state"; FAIL=1; }

if [ "$FAIL" = "0" ]; then
  echo "✅ ALL LIVE CHECKS PASSED — rotated secret is live, replay defense verified, CI gate blocks."
  echo "   New secret written to .env (git-ignored) — never echoed to logs."
  echo "   → Update any Cursor/Claude Desktop MCP config that uses the old secret."
else
  echo "❌ One or more live checks failed — see output above."
  exit 1
fi
