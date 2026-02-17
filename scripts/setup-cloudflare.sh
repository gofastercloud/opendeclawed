#!/usr/bin/env bash
# setup-cloudflare.sh — Create Cloudflare Tunnel + Access policy via API
# Requires: CF_API_TOKEN, CF_ACCOUNT_ID, CF_ZONE_ID, CF_DOMAIN, CF_SUBDOMAIN
# Optional: GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, CF_ACCESS_ALLOWED_EMAILS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# ── Load .env ───────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: $ENV_FILE not found. Run scripts/setup.sh first." >&2
  exit 1
fi

# Source .env (only export lines without spaces around =)
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# ── Validate required vars ──────────────────────────────────────────────
MISSING=()
for var in CF_API_TOKEN CF_ACCOUNT_ID CF_ZONE_ID CF_DOMAIN CF_SUBDOMAIN; do
  if [[ -z "${!var:-}" ]]; then
    MISSING+=("$var")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Error: Missing required variables in .env:" >&2
  printf '  %s\n' "${MISSING[@]}" >&2
  echo "Set these values and re-run this script." >&2
  exit 1
fi

CF_API="https://api.cloudflare.com/client/v4"
AUTH_HEADER="Authorization: Bearer $CF_API_TOKEN"
FQDN="${CF_SUBDOMAIN}.${CF_DOMAIN}"

# Helper: make Cloudflare API call and check for success
cf_api() {
  local method="$1" endpoint="$2"
  shift 2
  local response
  response=$(curl -sf -X "$method" \
    "$CF_API$endpoint" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    "$@") || { echo "Error: API call failed: $method $endpoint" >&2; exit 1; }

  local success
  success=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "False")
  if [[ "$success" != "True" ]]; then
    echo "Error: API returned failure for $method $endpoint" >&2
    echo "$response" | python3 -c "import sys,json; errs=json.load(sys.stdin).get('errors',[]); [print(f'  {e}') for e in errs]" 2>/dev/null
    exit 1
  fi
  echo "$response"
}

# Helper: update a var in .env (append if missing, replace if present)
set_env_var() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    # Use a temp file for portable sed -i
    local tmp
    tmp=$(mktemp)
    sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

echo "=== Cloudflare Setup for $FQDN ==="
echo ""

# ── 1. Create Tunnel ────────────────────────────────────────────────────
TUNNEL_NAME="${CF_TUNNEL_NAME:-$CF_SUBDOMAIN}"

echo "Creating tunnel '$TUNNEL_NAME'..."
# Generate a random tunnel secret
TUNNEL_SECRET=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")

TUNNEL_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/cfd_tunnel" \
  -d "{\"name\":\"$TUNNEL_NAME\",\"tunnel_secret\":\"$TUNNEL_SECRET\",\"config_src\":\"local\"}")

TUNNEL_ID=$(echo "$TUNNEL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
TUNNEL_TOKEN=$(echo "$TUNNEL_RESP" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; import base64; print(base64.b64encode(json.dumps({'a':r['account_tag'],'t':r['id'],'s':'$TUNNEL_SECRET'}).encode()).decode())" 2>/dev/null || true)

echo "✓ Tunnel created: $TUNNEL_ID"

set_env_var "CF_TUNNEL_ID" "$TUNNEL_ID"
set_env_var "CF_TUNNEL_NAME" "$TUNNEL_NAME"
set_env_var "CLOUDFLARE_TUNNEL_ROUTE" "$FQDN"

# If we got a token, set it; otherwise construct from components
if [[ -n "$TUNNEL_TOKEN" ]]; then
  set_env_var "CLOUDFLARE_TOKEN" "$TUNNEL_TOKEN"
  echo "✓ Tunnel token saved to .env"
fi

# ── 2. Create DNS CNAME ────────────────────────────────────────────────
echo "Creating DNS CNAME: $FQDN → ${TUNNEL_ID}.cfargotunnel.com..."
cf_api POST "/zones/$CF_ZONE_ID/dns_records" \
  -d "{\"type\":\"CNAME\",\"name\":\"$CF_SUBDOMAIN\",\"content\":\"${TUNNEL_ID}.cfargotunnel.com\",\"proxied\":true}" >/dev/null

echo "✓ DNS record created"

# ── 3. Create Cloudflare Access Application (if GitHub OAuth configured) ─
if [[ -n "${GITHUB_OAUTH_CLIENT_ID:-}" && -n "${GITHUB_OAUTH_CLIENT_SECRET:-}" ]]; then
  echo ""
  echo "Setting up Cloudflare Access with GitHub OAuth..."

  # Create GitHub OAuth IDP
  IDP_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/access/identity_providers" \
    -d "{
      \"name\":\"GitHub\",
      \"type\":\"github\",
      \"config\":{
        \"client_id\":\"$GITHUB_OAUTH_CLIENT_ID\",
        \"client_secret\":\"$GITHUB_OAUTH_CLIENT_SECRET\"
      }
    }")
  IDP_ID=$(echo "$IDP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
  echo "✓ GitHub OAuth IDP created: $IDP_ID"
  set_env_var "CF_IDP_ID" "$IDP_ID"

  # Create Access Application
  APP_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/access/apps" \
    -d "{
      \"name\":\"$TUNNEL_NAME\",
      \"domain\":\"$FQDN\",
      \"type\":\"self_hosted\",
      \"session_duration\":\"24h\",
      \"allowed_idps\":[\"$IDP_ID\"],
      \"auto_redirect_to_identity\":true
    }")
  APP_ID=$(echo "$APP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
  echo "✓ Access application created: $APP_ID"
  set_env_var "CF_ACCESS_APP_ID" "$APP_ID"

  # Create Access Policy (allow specific emails)
  if [[ -n "${CF_ACCESS_ALLOWED_EMAILS:-}" ]]; then
    # Convert comma-separated emails to JSON array of include rules
    EMAIL_RULES=$(echo "$CF_ACCESS_ALLOWED_EMAILS" | python3 -c "
import sys, json
emails = [e.strip() for e in sys.stdin.read().strip().split(',') if e.strip()]
rules = [{'email': {'email': e}} for e in emails]
print(json.dumps(rules))
")
    cf_api POST "/accounts/$CF_ACCOUNT_ID/access/apps/$APP_ID/policies" \
      -d "{
        \"name\":\"Allow listed emails\",
        \"decision\":\"allow\",
        \"include\":$EMAIL_RULES,
        \"precedence\":1
      }" >/dev/null
    echo "✓ Access policy created (allowed emails: $CF_ACCESS_ALLOWED_EMAILS)"
  else
    echo "⚠ No CF_ACCESS_ALLOWED_EMAILS set — add an Access policy manually"
  fi
else
  echo ""
  echo "⚠ Skipping Cloudflare Access setup (GITHUB_OAUTH_CLIENT_ID/SECRET not set)"
  echo "  Set these in .env and re-run to configure GitHub OAuth login gate."
fi

echo ""
echo "=== Cloudflare setup complete ==="
echo "Tunnel:  $TUNNEL_ID"
echo "DNS:     $FQDN → ${TUNNEL_ID}.cfargotunnel.com"
echo ""
echo "Next steps:"
echo "  1. Start the tunnel: docker compose --profile tunnel up -d"
echo "  2. Visit: https://$FQDN"
