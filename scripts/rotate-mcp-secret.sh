#!/usr/bin/env bash
# MedTrace MCP secret rotation, deployment, and live verification.
#
# Rotates MEDTRACE_MCP_SECRET across all target Forge environments, optionally
# deploys updated manifests/code, atomically updates the local .env file (0600),
# and verifies live HMAC authentication, replay protection, action validation,
# and release-gate behavior across every rotated environment.
#
# Security boundaries:
# - MEDTRACE_PART11_SECRET (21 CFR Part 11 HMAC-SHA256 seal) is independent of
#   MEDTRACE_MCP_SECRET and is NOT rotated by this script. Rotate it separately via:
#     forge variables set MEDTRACE_PART11_SECRET "<secret>" --encrypt -e <env>
# - Rotating MEDTRACE_MCP_SECRET invalidates pre-rotation secrets on deployed Forge
#   endpoints, but does NOT purge unencrypted secrets committed in git history.
#   If an unencrypted secret ever existed in git history, rewrite history manually
#   with `git filter-repo` (outside standard PRs) and rotate all exposed tokens.

set -euo pipefail

usage() {
  cat <<'EOF'
MedTrace MCP secret rotation, Forge deployment, and live verification.

Usage:
  scripts/rotate-mcp-secret.sh [options]

Options:
  -h, --help          Show this help message and exit 0.
  --force             Continue without failing if a target environment has no deployed
                      webtrigger URL yet (still checks all remaining environments).
  --skip-rotate       Read-only verification mode: skips forge lint, secret rotation,
                      forge deploy, and never modifies .env.
  --skip-deploy       Update Forge variables and local .env without running forge deploy.
  --approve-major     Opt into passing --approve MAJOR_VERSION_RULE to forge lint/deploy.

Environment Variables:
  ENVIRONMENT                      Single target environment fallback when ENVIRONMENTS is unset.
  ENVIRONMENTS                     Space-separated Forge environments (default: "production development").
  FORGE_SITE                       Optional Atlassian site hostname (passed via -s and -p only if set).
  FORGE_PRODUCT                    Atlassian product name used with FORGE_SITE (default: "Jira").
  FORGE_BIN                        Forge CLI binary override (default: "forge").
  FORGE_ENV_FILE                   Optional file sourced for FORGE_EMAIL / FORGE_API_TOKEN
                                   (default: "$HOME/.forge-env").
  FORGE_APPROVE_MAJOR              Set to 1 to opt into --approve MAJOR_VERSION_RULE.
  SKIP_ROTATE                      Set to 1 for strictly read-only verification on .env and forge lint.
  SKIP_DEPLOY                      Set to 1 to skip forge deploy during rotation.
  FORCE                            Set to 1 (equivalent to --force).
  ENV_FILE                         Local dotenv file path (default: ".env").
  MEDTRACE_MCP_SECRET              Existing secret (used when SKIP_ROTATE=1 if not read from .env).
  MEDTRACE_WEBTRIGGER_URL          Target webtrigger URL override (optional).
  MEDTRACE_ALLOW_INSECURE_LOCALHOST
                                   Set to 1 or true to permit http:// loopback URLs for local tests only.
  LEAKED_SECRET                    Optional pre-rotation secret to prove HTTP 401 rejection.

Verification (Step 6, run for every target environment):
  a. Optional pre-rotation LEAKED_SECRET -> HTTP 401
  b. Invalid / forged HMAC signature     -> HTTP 401
  c. GET suite with NEW secret           -> HTTP 200
  d. 4-step POST status replay defense   -> HTTP 200 / 409 / 409 / 200
  e. Unknown POST action                 -> HTTP 400
  f. POST verify-release-gate            -> HTTP 200 (result: true) OR HTTP 403 (result: false)

Security Reminders:
  - MEDTRACE_PART11_SECRET is independent and must be managed/rotated separately.
  - Rotating secrets does not clean historical git commits; use `git filter-repo` if
    an unencrypted secret ever existed in git history.
EOF
}

FORCE="${FORCE:-0}"
SKIP_ROTATE="${SKIP_ROTATE:-0}"
SKIP_DEPLOY="${SKIP_DEPLOY:-0}"
FORGE_APPROVE_MAJOR="${FORGE_APPROVE_MAJOR:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --force)
      FORCE=1
      ;;
    --skip-rotate)
      SKIP_ROTATE=1
      ;;
    --skip-deploy)
      SKIP_DEPLOY=1
      ;;
    --approve-major)
      FORGE_APPROVE_MAJOR=1
      ;;
    *)
      echo "❌ Unknown option: $1" >&2
      echo "Run '$0 --help' for usage." >&2
      exit 2
      ;;
  esac
  shift
done

CI=true
FORGE_DISABLE_ANALYTICS=true
export CI FORGE_DISABLE_ANALYTICS

FORGE_ENV_FILE="${FORGE_ENV_FILE:-$HOME/.forge-env}"
if [ -f "$FORGE_ENV_FILE" ]; then
  # shellcheck source=/dev/null
  . "$FORGE_ENV_FILE"
fi

if [ -z "${ENVIRONMENTS:-}" ]; then
  if [ -n "${ENVIRONMENT:-}" ]; then
    ENVIRONMENTS="$ENVIRONMENT"
  else
    ENVIRONMENTS="production development"
  fi
fi
ENVIRONMENT="${ENVIRONMENT:-}"
FORGE_BIN="${FORGE_BIN:-forge}"
FORGE_SITE="${FORGE_SITE:-}"
FORGE_PRODUCT="${FORGE_PRODUCT:-Jira}"
ENV_FILE="${ENV_FILE:-.env}"
MEDTRACE_ALLOW_INSECURE_LOCALHOST="${MEDTRACE_ALLOW_INSECURE_LOCALHOST:-0}"

command -v node >/dev/null 2>&1 || { echo "❌ node is required but was not found in PATH."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "❌ curl is required but was not found in PATH."; exit 1; }

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_forge_cli() {
  command -v "$FORGE_BIN" >/dev/null 2>&1 || {
    echo "❌ Forge CLI ('$FORGE_BIN') not found. Install @forge/cli or set FORGE_BIN."
    exit 1
  }
}

require_forge_auth() {
  require_forge_cli
  if [ -z "${FORGE_API_TOKEN:-}" ]; then
    "$FORGE_BIN" whoami >/dev/null 2>&1 || {
      echo "❌ No Forge credentials. Either run 'forge login' or configure ~/.forge-env (chmod 600) with:"
      echo "     export FORGE_EMAIL=\"you@example.com\""
      echo "     export FORGE_API_TOKEN=\"<token>\""
      exit 1
    }
  fi
}

run_forge_with_retry() {
  local attempt=1
  local max_attempts=3
  while true; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      return 1
    fi
    echo "⚠️  Forge command failed (attempt $attempt/$max_attempts); retrying in 5s..." >&2
    sleep 5
    attempt=$((attempt + 1))
  done
}

now_ms() {
  node -e 'process.stdout.write(String(Date.now()));'
}

new_nonce() {
  node -e 'process.stdout.write(require("node:crypto").randomUUID());'
}

sign_payload() {
  SIGN_SECRET="$1" SIGN_TS="$2" SIGN_NONCE="$3" SIGN_BODY="${4:-}" node -e '
    const crypto = require("node:crypto");
    const secret = process.env.SIGN_SECRET || "";
    const ts = process.env.SIGN_TS || "";
    const nonce = process.env.SIGN_NONCE || "";
    const body = process.env.SIGN_BODY || "";
    const hex = crypto.createHmac("sha256", secret).update(`${ts}.${nonce}.${body}`).digest("hex");
    process.stdout.write(`sha256=${hex}`);
  '
}

parse_dotenv_key() {
  local target_file="$1"
  local target_key="$2"
  [ -f "$target_file" ] || return 0
  DOTENV_PATH="$target_file" TARGET_KEY="$target_key" node -e '
    const fs = require("node:fs");
    const content = fs.readFileSync(process.env.DOTENV_PATH, "utf8");
    const env = {};
    for (const rawLine of content.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      line = line.replace(/^export\s+/, "");
      const m = line.match(/^([\w.-]+)\s*=\s*(.*)$/);
      if (!m) continue;
      const key = m[1];
      const rest = m[2].trimStart();
      let val = "";
      if (rest.startsWith("\"") || rest.startsWith("\x27")) {
        const q = rest[0];
        let out = "";
        let closed = false;
        for (let i = 1; i < rest.length; i += 1) {
          const ch = rest[i];
          if (ch === "\\" && i + 1 < rest.length) {
            const next = rest[i + 1];
            if (next === q || next === "\\") {
              out += next;
              i += 1;
              continue;
            }
          }
          if (ch === q) {
            closed = true;
            break;
          }
          out += ch;
        }
        val = closed ? out : out.replace(/\s+#.*$/, "").trim();
      } else if (rest.startsWith("#") || rest === "") {
        val = "";
      } else {
        val = rest.replace(/\s+#.*$/, "").trim();
      }
      env[key] = val;
    }
    const found = env[process.env.TARGET_KEY];
    if (typeof found === "string") {
      process.stdout.write(found);
    }
  '
}

validate_webtrigger_url() {
  local raw_url="$1"
  RAW_URL="$raw_url" ALLOW_INSECURE="$MEDTRACE_ALLOW_INSECURE_LOCALHOST" node -e '
    const raw = (process.env.RAW_URL || "").trim();
    if (!raw) process.exit(1);
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(raw)) process.exit(1);
    let u;
    try {
      u = new URL(raw);
    } catch {
      process.exit(1);
    }
    if (u.username !== "" || u.password !== "") process.exit(1);
    const host = (u.hostname || "").toLowerCase();
    if (!host) process.exit(1);
    const allowInsecure =
      process.env.ALLOW_INSECURE === "1" || process.env.ALLOW_INSECURE === "true";
    const loopback = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
    if (u.protocol === "https:") {
      process.stdout.write(u.toString());
      process.exit(0);
    }
    if (u.protocol === "http:" && loopback.has(host) && allowInsecure) {
      process.stdout.write(u.toString());
      process.exit(0);
    }
    process.exit(1);
  '
}

lookup_webtrigger_url() {
  local target_env="$1"
  local args=(webtrigger list -f mcp-sync-webtrigger -e "$target_env" --json)
  if [ -n "$FORGE_SITE" ]; then
    args+=(-s "$FORGE_SITE" -p "$FORGE_PRODUCT")
  fi

  local err_file="$TMP_DIR/wt-err-${target_env}.log"
  local raw_out=""
  if ! raw_out="$("$FORGE_BIN" "${args[@]}" </dev/null 2>"$err_file")"; then
    echo "⚠️  forge webtrigger list returned non-zero for environment '$target_env' (continuing)." >&2
    return 0
  fi

  WT_RAW="$raw_out" ALLOW_INSECURE="$MEDTRACE_ALLOW_INSECURE_LOCALHOST" node -e '
    const raw = (process.env.WT_RAW || "").trim();
    if (!raw) process.exit(0);

    function parseJsonLoose(text) {
      try {
        return JSON.parse(text);
      } catch {
        const arrStart = text.indexOf("[");
        const arrEnd = text.lastIndexOf("]");
        if (arrStart !== -1 && arrEnd > arrStart) {
          try { return JSON.parse(text.slice(arrStart, arrEnd + 1)); } catch {}
        }
        const objStart = text.indexOf("{");
        const objEnd = text.lastIndexOf("}");
        if (objStart !== -1 && objEnd > objStart) {
          try { return JSON.parse(text.slice(objStart, objEnd + 1)); } catch {}
        }
        return null;
      }
    }

    function normalizeValidUrl(rawUrl) {
      if (typeof rawUrl !== "string") return "";
      const trimmed = rawUrl.trim();
      // eslint-disable-next-line no-control-regex
      if (!trimmed || /[\u0000-\u001f\u007f]/.test(trimmed)) return "";
      let u;
      try { u = new URL(trimmed); } catch { return ""; }
      if (u.username !== "" || u.password !== "") return "";
      const host = (u.hostname || "").toLowerCase();
      if (!host) return "";
      const allowInsecure =
        process.env.ALLOW_INSECURE === "1" || process.env.ALLOW_INSECURE === "true";
      const loopback = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
      if (u.protocol === "https:") return u.toString();
      if (u.protocol === "http:" && loopback.has(host) && allowInsecure) return u.toString();
      return "";
    }

    const parsed = parseJsonLoose(raw);
    if (!parsed) process.exit(0);

    let items = [];
    if (Array.isArray(parsed)) {
      items = parsed;
    } else if (typeof parsed === "object") {
      for (const key of ["webtriggers", "webTriggers", "items", "data", "results"]) {
        if (Array.isArray(parsed[key])) {
          items = parsed[key];
          break;
        }
      }
      if (items.length === 0 && typeof parsed.url === "string") {
        items = [parsed];
      }
    }

    const preferred =
      items.find(
        (item) =>
          item &&
          typeof item === "object" &&
          (item.triggerKey === "mcp-sync-webtrigger" ||
            item.key === "mcp-sync-webtrigger" ||
            item.functionKey === "mcp-sync-webtrigger" ||
            item.functionKey === "mcp-webtrigger-fn") &&
          normalizeValidUrl(item.url)
      ) ||
      items.find((item) => item && typeof item === "object" && normalizeValidUrl(item.url));

    if (preferred) {
      process.stdout.write(normalizeValidUrl(preferred.url));
    }
  '
}

upsert_dotenv_atomic() {
  local target_file="$1"
  local secret_val="$2"
  local url_val="${3:-}"

  DOTENV_PATH="$target_file" NEW_MCP_SECRET="$secret_val" NEW_WEBTRIGGER_URL="$url_val" node -e '
    const fs = require("node:fs");
    const path = require("node:path");
    const crypto = require("node:crypto");

    const envPath = path.resolve(process.env.DOTENV_PATH || ".env");
    const newSecret = process.env.NEW_MCP_SECRET || "";
    const newUrl = process.env.NEW_WEBTRIGGER_URL || "";

    const exists = fs.existsSync(envPath);
    const raw = exists ? fs.readFileSync(envPath, "utf8") : "";
    const eol = raw.includes("\r\n") ? "\r\n" : "\n";
    const lines = raw ? raw.split(/\r?\n/) : [];
    if (lines.length > 0 && lines[lines.length - 1] === "") {
      lines.pop();
    }

    function formatValue(rawRest, value) {
      const trimmed = rawRest.trimStart();
      let quote = "";
      let trailing = "";

      if (trimmed.startsWith("\"") || trimmed.startsWith("\x27")) {
        quote = trimmed[0];
        let closedIdx = -1;
        for (let i = 1; i < trimmed.length; i += 1) {
          const ch = trimmed[i];
          if (ch === "\\" && i + 1 < trimmed.length) {
            i += 1;
            continue;
          }
          if (ch === quote) {
            closedIdx = i;
            break;
          }
        }
        if (closedIdx !== -1) {
          trailing = trimmed.slice(closedIdx + 1);
        }
      } else {
        const hashMatch = trimmed.match(/(\s+#.*)$/);
        if (hashMatch) {
          trailing = hashMatch[1];
        }
      }

      let formatted;
      if (quote === "\x27" && !value.includes("\x27")) {
        formatted = `\x27${value}\x27`;
      } else if (quote === "\"" || (quote === "\x27" && value.includes("\x27")) || /[\s#"\x27\\]/.test(value)) {
        const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
        formatted = `"${escaped}"`;
      } else {
        formatted = value;
      }
      return `${formatted}${trailing}`;
    }

    const updates = new Map();
    if (newSecret) updates.set("MEDTRACE_MCP_SECRET", newSecret);
    if (newUrl) updates.set("MEDTRACE_WEBTRIGGER_URL", newUrl);

    const seen = new Set();
    const outLines = [];
    for (const line of lines) {
      const m = line.match(/^(\s*(?:export\s+)?)([\w.-]+)(\s*=\s*)(.*)$/);
      if (m && updates.has(m[2])) {
        const key = m[2];
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        outLines.push(`${m[1]}${key}${m[3]}${formatValue(m[4], updates.get(key))}`);
      } else {
        outLines.push(line);
      }
    }

    for (const [key, val] of updates.entries()) {
      if (!seen.has(key)) {
        outLines.push(`${key}=${formatValue("", val)}`);
      }
    }

    const dir = path.dirname(envPath);
    fs.mkdirSync(dir, { recursive: true });
    const tmpName = `.${path.basename(envPath)}.tmp.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}`;
    const tmpPath = path.join(dir, tmpName);
    const content = outLines.join(eol) + eol;

    try {
      fs.writeFileSync(tmpPath, content, { encoding: "utf8", mode: 0o600 });
      fs.chmodSync(tmpPath, 0o600);
      fs.renameSync(tmpPath, envPath);
      fs.chmodSync(envPath, 0o600);
    } catch (err) {
      try { fs.unlinkSync(tmpPath); } catch {}
      throw err;
    }
  '
}

http_request() {
  local method="$1"
  local url="$2"
  local ts="$3"
  local nonce="$4"
  local sig="$5"
  local body="${6:-}"
  local out_file="$7"
  local code=""
  local rc=0

  if [ "$method" = "GET" ]; then
    code="$(curl -sS -o "$out_file" -w '%{http_code}' \
      --connect-timeout 10 --max-time 15 \
      -H "Accept: application/json" \
      -H "x-medtrace-timestamp: $ts" \
      -H "x-medtrace-nonce: $nonce" \
      -H "x-medtrace-signature: $sig" \
      "$url")" || rc=$?
  else
    code="$(curl -sS -o "$out_file" -w '%{http_code}' \
      --connect-timeout 10 --max-time 15 \
      -X "$method" \
      -H "Accept: application/json" \
      -H "Content-Type: application/json" \
      -H "x-medtrace-timestamp: $ts" \
      -H "x-medtrace-nonce: $nonce" \
      -H "x-medtrace-signature: $sig" \
      -d "$body" \
      "$url")" || rc=$?
  fi

  if [ "$rc" -ne 0 ] && [ -z "$code" ]; then
    code="000"
  fi
  printf '%s' "$code"
}

verify_target_url() {
  local label="$1"
  local url="$2"
  local env_fail=0
  local body_file="$TMP_DIR/resp.json"

  echo "== 6/6 Live verification [$label] against $url =="

  echo -n "   a. OLD secret (leaked)     -> expect 401: "
  if [ -n "${OLD_SECRET:-}" ]; then
    local ts_a nonce_a sig_a code_a
    ts_a="$(now_ms)"
    nonce_a="old-$(new_nonce)"
    sig_a="$(sign_payload "$OLD_SECRET" "$ts_a" "$nonce_a" "")"
    code_a="$(http_request GET "$url" "$ts_a" "$nonce_a" "$sig_a" "" "$body_file")"
    echo "$code_a"
    if [ "$code_a" != "401" ]; then
      echo "      ❌ old secret still accepted!"
      env_fail=1
    fi
  else
    echo "skipped (set LEAKED_SECRET to verify pre-rotation secret is rejected)"
  fi

  echo -n "   b. Invalid signature       -> expect 401: "
  local ts_inv nonce_inv sig_inv code_inv
  ts_inv="$(now_ms)"
  nonce_inv="invsig-$(new_nonce)"
  sig_inv="$(sign_payload "__medtrace_invalid_signature_probe__" "$ts_inv" "$nonce_inv" "")"
  code_inv="$(http_request GET "$url" "$ts_inv" "$nonce_inv" "$sig_inv" "" "$body_file")"
  echo "$code_inv"
  if [ "$code_inv" != "401" ]; then
    echo "      ❌ invalid signature was not rejected with 401!"
    env_fail=1
  fi

  echo -n "   c. NEW secret GET suite    -> expect 200: "
  local ts_get nonce_get sig_get code_get
  ts_get="$(now_ms)"
  nonce_get="get-$(new_nonce)"
  sig_get="$(sign_payload "$NEW_SECRET" "$ts_get" "$nonce_get" "")"
  code_get="$(http_request GET "$url" "$ts_get" "$nonce_get" "$sig_get" "" "$body_file")"
  echo "$code_get"
  if [ "$code_get" != "200" ]; then
    echo "      ❌ new secret GET rejected (did deploy finish?)"
    env_fail=1
  fi

  echo "   d. POST status replay proof -> expect 200 / 409 / 409 / 200:"
  local status_body='{"action":"status"}'
  local step ts_r nonce_r sig_r code_r
  ts_r="$(now_ms)"
  nonce_r="status-$(new_nonce)"
  sig_r="$(sign_payload "$NEW_SECRET" "$ts_r" "$nonce_r" "$status_body")"
  for step in 1 2 3 4; do
    if [ "$step" = "3" ]; then
      ts_r="$(now_ms)"
      sig_r="$(sign_payload "$NEW_SECRET" "$ts_r" "$nonce_r" "$status_body")"
    elif [ "$step" = "4" ]; then
      ts_r="$(now_ms)"
      nonce_r="status-$(new_nonce)"
      sig_r="$(sign_payload "$NEW_SECRET" "$ts_r" "$nonce_r" "$status_body")"
    fi
    code_r="$(http_request POST "$url" "$ts_r" "$nonce_r" "$sig_r" "$status_body" "$body_file")"
    echo "      step $step -> $code_r"
    case "$step" in
      1|4) [ "$code_r" = "200" ] || env_fail=1 ;;
      2|3) [ "$code_r" = "409" ] || env_fail=1 ;;
    esac
  done

  echo -n "   e. Unknown POST action     -> expect 400: "
  local unk_body='{"action":"__unknown_action_probe__"}'
  local ts_unk nonce_unk sig_unk code_unk
  ts_unk="$(now_ms)"
  nonce_unk="unk-$(new_nonce)"
  sig_unk="$(sign_payload "$NEW_SECRET" "$ts_unk" "$nonce_unk" "$unk_body")"
  code_unk="$(http_request POST "$url" "$ts_unk" "$nonce_unk" "$sig_unk" "$unk_body" "$body_file")"
  echo "$code_unk"
  if [ "$code_unk" != "400" ]; then
    echo "      ❌ unknown POST action did not return 400!"
    env_fail=1
  fi

  echo -n "   f. verify-release-gate     -> expect 200 or 403: "
  local gate_body='{"action":"verify-release-gate"}'
  local ts_gate nonce_gate sig_gate code_gate gate_desc=""
  ts_gate="$(now_ms)"
  nonce_gate="gate-$(new_nonce)"
  sig_gate="$(sign_payload "$NEW_SECRET" "$ts_gate" "$nonce_gate" "$gate_body")"
  code_gate="$(http_request POST "$url" "$ts_gate" "$nonce_gate" "$sig_gate" "$gate_body" "$body_file")"
  if gate_desc="$(GATE_BODY_FILE="$body_file" GATE_HTTP_CODE="$code_gate" node -e '
    const fs = require("node:fs");
    const code = Number(process.env.GATE_HTTP_CODE);
    const raw = fs.readFileSync(process.env.GATE_BODY_FILE, "utf8");
    let data;
    try { data = JSON.parse(raw); } catch { process.exit(1); }
    if (!data || typeof data.result !== "boolean") process.exit(1);
    if (code === 200 && data.result === true) {
      process.stdout.write("LIVE/COMPLIANT (result: true)");
      process.exit(0);
    }
    if (code === 403 && data.result === false) {
      process.stdout.write("BLOCKED/DEMO/UNINITIALIZED (result: false)");
      process.exit(0);
    }
    process.exit(1);
  ')"; then
    echo "$code_gate ($gate_desc)"
  else
    echo "$code_gate (unexpected response)"
    echo "      ❌ verify-release-gate failed validation (expected 200 result:true or 403 result:false)"
    env_fail=1
  fi

  return "$env_fail"
}

OLD_SECRET="${LEAKED_SECRET:-}"
NEW_SECRET=""
TARGET_ENVS=()
TARGET_URLS=()
MISSING_URL_ENVS=()

if [ "$SKIP_ROTATE" != "1" ]; then
  require_forge_auth

  echo "== 1/6 Linting manifest =="
  if [ "$FORGE_APPROVE_MAJOR" = "1" ]; then
    run_forge_with_retry "$FORGE_BIN" lint --approve MAJOR_VERSION_RULE
  else
    run_forge_with_retry "$FORGE_BIN" lint
  fi

  echo "== 2/6 Generating new 256-bit secret =="
  NEW_SECRET="$(node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"));')"

  for ENV in $ENVIRONMENTS; do
    echo "== 3/6 Setting MEDTRACE_MCP_SECRET in environment: $ENV =="
    "$FORGE_BIN" variables set MEDTRACE_MCP_SECRET "$NEW_SECRET" --environment "$ENV" --encrypt

    if [ "${SKIP_DEPLOY:-0}" != "1" ]; then
      echo "== 4/6 Deploying manifest to $ENV =="
      if [ "$FORGE_APPROVE_MAJOR" = "1" ]; then
        run_forge_with_retry "$FORGE_BIN" deploy --environment "$ENV" --non-interactive --approve MAJOR_VERSION_RULE
      else
        run_forge_with_retry "$FORGE_BIN" deploy --environment "$ENV" --non-interactive
      fi
    else
      echo "== 4/6 SKIP_DEPLOY=1 — skipping deploy for $ENV =="
    fi
  done

  echo "== 5/6 Discovering webtrigger URLs and updating $ENV_FILE atomically =="
  PRIMARY_URL=""
  for ENV in $ENVIRONMENTS; do
    ENV_URL="$(lookup_webtrigger_url "$ENV")"
    if [ -n "$ENV_URL" ]; then
      TARGET_ENVS+=("$ENV")
      TARGET_URLS+=("$ENV_URL")
      if [ -n "$ENVIRONMENT" ] && [ "$ENV" = "$ENVIRONMENT" ]; then
        PRIMARY_URL="$ENV_URL"
      elif [ -z "$PRIMARY_URL" ]; then
        PRIMARY_URL="$ENV_URL"
      fi
    else
      MISSING_URL_ENVS+=("$ENV")
    fi
  done

  if [ "${#TARGET_URLS[@]}" -eq 0 ] && [ -n "${MEDTRACE_WEBTRIGGER_URL:-}" ]; then
    if VALID_OVERRIDE="$(validate_webtrigger_url "$MEDTRACE_WEBTRIGGER_URL")"; then
      TARGET_ENVS+=("override")
      TARGET_URLS+=("$VALID_OVERRIDE")
      PRIMARY_URL="$VALID_OVERRIDE"
    else
      echo "❌ MEDTRACE_WEBTRIGGER_URL is invalid or insecure (https:// required)."
      exit 1
    fi
  fi

  if [ "${#TARGET_URLS[@]}" -eq 0 ] && [ -f "$ENV_FILE" ]; then
    DOTENV_URL="$(parse_dotenv_key "$ENV_FILE" "MEDTRACE_WEBTRIGGER_URL")"
    if [ -n "$DOTENV_URL" ]; then
      if VALID_DOTENV_URL="$(validate_webtrigger_url "$DOTENV_URL")"; then
        TARGET_ENVS+=("dotenv")
        TARGET_URLS+=("$VALID_DOTENV_URL")
        PRIMARY_URL="$VALID_DOTENV_URL"
      else
        echo "❌ Existing $ENV_FILE MEDTRACE_WEBTRIGGER_URL is invalid or insecure (https:// required)."
        exit 1
      fi
    fi
  fi

  if [ -n "$PRIMARY_URL" ] || [ -f "$ENV_FILE" ]; then
    upsert_dotenv_atomic "$ENV_FILE" "$NEW_SECRET" "$PRIMARY_URL"
    echo "   $ENV_FILE updated atomically (mode 0600, git-ignored)."
  else
    echo "⚠️  Could not auto-detect webtrigger URL — skipped creating $ENV_FILE."
  fi
else
  echo "== 1-4/6 SKIP_ROTATE=1 — read-only verification mode (skipping forge lint, rotation, deploy) =="
  NEW_SECRET="${MEDTRACE_MCP_SECRET:-}"
  if [ -z "$NEW_SECRET" ] && [ -f "$ENV_FILE" ]; then
    NEW_SECRET="$(parse_dotenv_key "$ENV_FILE" "MEDTRACE_MCP_SECRET")"
  fi
  if [ -z "$NEW_SECRET" ]; then
    echo "❌ MEDTRACE_MCP_SECRET is required when SKIP_ROTATE=1 (set env var or configure $ENV_FILE)."
    exit 1
  fi

  echo "== 5/6 Resolving target webtrigger URLs (read-only on $ENV_FILE) =="
  RAW_CONFIGURED_URL="${MEDTRACE_WEBTRIGGER_URL:-}"
  if [ -z "$RAW_CONFIGURED_URL" ] && [ -f "$ENV_FILE" ]; then
    RAW_CONFIGURED_URL="$(parse_dotenv_key "$ENV_FILE" "MEDTRACE_WEBTRIGGER_URL")"
  fi

  if [ -n "$RAW_CONFIGURED_URL" ]; then
    if VALID_CONFIGURED_URL="$(validate_webtrigger_url "$RAW_CONFIGURED_URL")"; then
      TARGET_ENVS+=("configured")
      TARGET_URLS+=("$VALID_CONFIGURED_URL")
    else
      echo "❌ Configured MEDTRACE_WEBTRIGGER_URL is invalid or insecure (https:// required)."
      exit 1
    fi
  else
    require_forge_cli
    for ENV in $ENVIRONMENTS; do
      ENV_URL="$(lookup_webtrigger_url "$ENV")"
      if [ -n "$ENV_URL" ]; then
        TARGET_ENVS+=("$ENV")
        TARGET_URLS+=("$ENV_URL")
      else
        MISSING_URL_ENVS+=("$ENV")
      fi
    done
  fi
fi

if [ "${#TARGET_URLS[@]}" -eq 0 ]; then
  echo "❌ No valid webtrigger URL found — cannot run live verification."
  exit 1
fi

FAIL=0
IDX=0
while [ "$IDX" -lt "${#TARGET_URLS[@]}" ]; do
  if ! verify_target_url "${TARGET_ENVS[$IDX]}" "${TARGET_URLS[$IDX]}"; then
    FAIL=1
  fi
  IDX=$((IDX + 1))
done

if [ "${#MISSING_URL_ENVS[@]}" -gt 0 ]; then
  echo "⚠️  No webtrigger URL resolved for environment(s): ${MISSING_URL_ENVS[*]}"
  if [ "$FORCE" != "1" ]; then
    echo "❌ Re-run with --force to ignore unconfigured environments, or verify Forge site installation."
    FAIL=1
  fi
fi

echo ""
echo "Security Reminders:"
echo "  • MEDTRACE_PART11_SECRET (21 CFR Part 11 signature sealing) is independent of MEDTRACE_MCP_SECRET"
echo "    and was NOT rotated here. Manage/rotate it separately with: forge variables set MEDTRACE_PART11_SECRET --encrypt"
echo "  • Rotating secrets invalidates old tokens on live endpoints, but does NOT purge historical git commits."
echo "    If an unencrypted secret ever existed in git history, scrub it with \`git filter-repo\`."

if [ "$FAIL" = "0" ]; then
  echo "✅ ALL LIVE CHECKS PASSED across ${#TARGET_URLS[@]} target(s)."
  echo "   → Update any IDE MCP config (Cursor / Claude Desktop) and CI secrets using the previous secret."
else
  echo "❌ One or more live checks failed — see output above."
  exit 1
fi
