#!/usr/bin/env bash
# setup-cloudflare.sh — Create Cloudflare Tunnel + Access policy via API
# Requires: CF_API_TOKEN, CF_ACCOUNT_ID, CF_ZONE_ID, CF_DOMAIN, CF_SUBDOMAIN
# Optional: GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET, CF_ACCESS_ALLOWED_EMAILS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# ── Load shared libraries ────────────────────────────────────────────────
source "${SCRIPT_DIR}/lib/env-helpers.sh"
source "${SCRIPT_DIR}/lib/cloudflare-helpers.sh"

# ── Load .env ───────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  error "$ENV_FILE not found. Run scripts/setup.sh first."
  exit 1
fi

load_env "$ENV_FILE"

# ── Validate required vars ──────────────────────────────────────────────
MISSING=()
for var in CF_API_TOKEN CF_ACCOUNT_ID CF_ZONE_ID CF_DOMAIN CF_SUBDOMAIN; do
  if [[ -z "${!var:-}" ]]; then
    MISSING+=("$var")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  error "Missing required variables in .env:"
  printf '  %s\n' "${MISSING[@]}" >&2
  echo "Set these values and re-run this script." >&2
  exit 1
fi

FQDN="${CF_SUBDOMAIN}.${CF_DOMAIN}"

echo "=== Cloudflare Setup for $FQDN ==="
echo ""

# ── 0. Clean up existing tunnel if present ─────────────────────────────
if [[ -n "${CF_TUNNEL_ID:-}" ]]; then
  echo "Existing tunnel detected ($CF_TUNNEL_ID). Tearing down first..."
  "${SCRIPT_DIR}/teardown-cloudflare.sh" --force || warn "Teardown had errors (continuing with fresh setup)"
  # Reload .env after teardown cleared values
  load_env "$ENV_FILE"
  echo ""
fi

# ── 1. Create Tunnel ────────────────────────────────────────────────────
TUNNEL_NAME="${CF_TUNNEL_NAME:-$CF_SUBDOMAIN}"

echo "Creating tunnel '$TUNNEL_NAME'..."
# Generate a random tunnel secret
TUNNEL_SECRET=$(python3 -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())")

PAYLOAD=$(json_obj name "$TUNNEL_NAME" tunnel_secret "$TUNNEL_SECRET" config_src "cloudflare")
TUNNEL_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/cfd_tunnel" -d "$PAYLOAD")

TUNNEL_ID=$(echo "$TUNNEL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
TUNNEL_TOKEN=$(echo "$TUNNEL_RESP" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; import base64; print(base64.b64encode(json.dumps({'a':r['account_tag'],'t':r['id'],'s':'$TUNNEL_SECRET'}).encode()).decode())" 2>/dev/null || true)

echo "✓ Tunnel created: $TUNNEL_ID"

save_env "CF_TUNNEL_ID" "$TUNNEL_ID" "$ENV_FILE"
save_env "CF_TUNNEL_NAME" "$TUNNEL_NAME" "$ENV_FILE"
save_env "CLOUDFLARE_TUNNEL_ROUTE" "$FQDN" "$ENV_FILE"

# If we got a token, set it; otherwise construct from components
if [[ -n "$TUNNEL_TOKEN" ]]; then
  save_env "CLOUDFLARE_TOKEN" "$TUNNEL_TOKEN" "$ENV_FILE"
  echo "✓ Tunnel token saved to .env"
fi

# ── 2. Create DNS CNAME ────────────────────────────────────────────────
echo "Creating DNS CNAME: $FQDN → ${TUNNEL_ID}.cfargotunnel.com..."
# proxied must be a JSON boolean (not string), so use python3 for this payload
PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
    'type': 'CNAME',
    'name': sys.argv[1],
    'content': sys.argv[2],
    'proxied': True
}))
" "$CF_SUBDOMAIN" "${TUNNEL_ID}.cfargotunnel.com")
cf_api POST "/zones/$CF_ZONE_ID/dns_records" -d "$PAYLOAD" >/dev/null

echo "✓ DNS record created"

# ── 2b. Configure Tunnel Ingress Rules ───────────────────────────────
echo "Configuring tunnel ingress rules..."
INGRESS_PAYLOAD=$(python3 -c "
import json, sys
hostname = sys.argv[1]
gw_port = sys.argv[2]
dozzle_port = sys.argv[3]
print(json.dumps({
    'config': {
        'ingress': [
            {
                'hostname': hostname,
                'path': '/dozzle*',
                'service': 'http://dozzle:' + dozzle_port
            },
            {
                'hostname': hostname,
                'service': 'http://openclaw-gateway:' + gw_port
            },
            {
                'service': 'http_status:404'
            }
        ]
    }
}))
" "$FQDN" "${GATEWAY_PORT:-18789}" "${DOZZLE_PORT:-5005}")
cf_api PUT "/accounts/$CF_ACCOUNT_ID/cfd_tunnel/${TUNNEL_ID}/configurations" \
  -d "$INGRESS_PAYLOAD" >/dev/null

echo "✓ Tunnel ingress: $FQDN → openclaw-gateway:${GATEWAY_PORT:-18789}"
echo "✓ Tunnel ingress: $FQDN/dozzle → dozzle:${DOZZLE_PORT:-5005}"

# ── 3. Create Cloudflare Access Application (if GitHub OAuth configured) ─
if [[ -n "${GITHUB_OAUTH_CLIENT_ID:-}" && -n "${GITHUB_OAUTH_CLIENT_SECRET:-}" ]]; then
  echo ""
  echo "Setting up Cloudflare Access with GitHub OAuth..."

  # Create GitHub OAuth IDP — nested JSON needs python3 for safety
  IDP_PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
    'name': 'GitHub',
    'type': 'github',
    'config': {
        'client_id': sys.argv[1],
        'client_secret': sys.argv[2]
    }
}))
" "$GITHUB_OAUTH_CLIENT_ID" "$GITHUB_OAUTH_CLIENT_SECRET")
  IDP_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/access/identity_providers" -d "$IDP_PAYLOAD")
  IDP_ID=$(echo "$IDP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
  echo "✓ GitHub OAuth IDP created: $IDP_ID"
  save_env "CF_IDP_ID" "$IDP_ID" "$ENV_FILE"

  # Create Access Application — nested JSON with array needs python3
  APP_PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({
    'name': sys.argv[1],
    'domain': sys.argv[2],
    'type': 'self_hosted',
    'session_duration': '24h',
    'allowed_idps': [sys.argv[3]],
    'auto_redirect_to_identity': True
}))
" "$TUNNEL_NAME" "$FQDN" "$IDP_ID")
  APP_RESP=$(cf_api POST "/accounts/$CF_ACCOUNT_ID/access/apps" -d "$APP_PAYLOAD")
  APP_ID=$(echo "$APP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
  echo "✓ Access application created: $APP_ID"
  save_env "CF_ACCESS_APP_ID" "$APP_ID" "$ENV_FILE"

  # Create Access Policy (allow specific emails)
  if [[ -n "${CF_ACCESS_ALLOWED_EMAILS:-}" ]]; then
    # Build complete policy payload safely with python3
    POLICY_PAYLOAD=$(python3 -c "
import sys, json
emails = [e.strip() for e in sys.argv[1].split(',') if e.strip()]
rules = [{'email': {'email': e}} for e in emails]
print(json.dumps({
    'name': 'Allow listed emails',
    'decision': 'allow',
    'include': rules,
    'precedence': 1
}))
" "$CF_ACCESS_ALLOWED_EMAILS")
    cf_api POST "/accounts/$CF_ACCOUNT_ID/access/apps/$APP_ID/policies" \
      -d "$POLICY_PAYLOAD" >/dev/null
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
