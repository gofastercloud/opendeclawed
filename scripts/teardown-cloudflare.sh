#!/usr/bin/env bash
# teardown-cloudflare.sh — Delete Cloudflare Tunnel + Access resources
# Deletes in reverse creation order: Access App → IDP → DNS → Tunnel
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# ── Parse flags ──────────────────────────────────────────────────────────
FORCE=false
for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=true ;;
    *) echo "Usage: $0 [--force|-f]" >&2; exit 1 ;;
  esac
done

# ── Load .env ────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: $ENV_FILE not found." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# ── Validate minimum required vars ──────────────────────────────────────
MISSING=()
for var in CF_API_TOKEN CF_ACCOUNT_ID; do
  if [[ -z "${!var:-}" ]]; then
    MISSING+=("$var")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Error: Missing required variables in .env:" >&2
  printf '  %s\n' "${MISSING[@]}" >&2
  exit 1
fi

CF_API="https://api.cloudflare.com/client/v4"
AUTH_HEADER="Authorization: Bearer $CF_API_TOKEN"

# ── Helpers (mirrored from setup-cloudflare.sh) ─────────────────────────

# Make Cloudflare API call and check for success
cf_api() {
  local method="$1" endpoint="$2"
  shift 2
  local response
  response=$(curl -sf -X "$method" \
    "$CF_API$endpoint" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    "$@") || { echo "Error: API call failed: $method $endpoint" >&2; return 1; }

  local success
  success=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "False")
  if [[ "$success" != "True" ]]; then
    echo "Error: API returned failure for $method $endpoint" >&2
    echo "$response" | python3 -c "import sys,json; errs=json.load(sys.stdin).get('errors',[]); [print(f'  {e}') for e in errs]" 2>/dev/null
    return 1
  fi
  echo "$response"
}

# Update a var in .env (append if missing, replace if present)
set_env_var() {
  local key="$1" value="$2"
  if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
    local tmp
    tmp=$(mktemp)
    sed "s|^${key}=.*|${key}=${value}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

# ── Show what will be deleted ────────────────────────────────────────────
echo "=== Cloudflare Teardown ==="
echo ""
echo "Resources to remove:"
[[ -n "${CF_ACCESS_APP_ID:-}" ]]  && echo "  Access Application: $CF_ACCESS_APP_ID"
[[ -n "${CF_IDP_ID:-}" ]]         && echo "  Access IDP:         $CF_IDP_ID"
if [[ -n "${CF_ZONE_ID:-}" && -n "${CF_SUBDOMAIN:-}" && -n "${CF_DOMAIN:-}" ]]; then
  echo "  DNS CNAME:          ${CF_SUBDOMAIN}.${CF_DOMAIN}"
fi
[[ -n "${CF_TUNNEL_ID:-}" ]]      && echo "  Tunnel:             ${CF_TUNNEL_ID}"
echo ""

# ── Confirmation ─────────────────────────────────────────────────────────
if [[ "$FORCE" != true ]]; then
  read -rp "Delete these Cloudflare resources? [y/N] " confirm
  if [[ "$confirm" != [yY] ]]; then
    echo "Aborted."
    exit 0
  fi
  echo ""
fi

ERRORS=0

# ── 1. Stop tunnel containers ───────────────────────────────────────────
echo "Stopping tunnel containers..."
docker compose --profile tunnel down 2>/dev/null && echo "✓ Tunnel containers stopped" \
  || echo "  (no tunnel containers running)"

# ── 2. Delete Access Application ─────────────────────────────────────────
if [[ -n "${CF_ACCESS_APP_ID:-}" ]]; then
  echo "Deleting Access application $CF_ACCESS_APP_ID..."
  if cf_api DELETE "/accounts/$CF_ACCOUNT_ID/access/apps/$CF_ACCESS_APP_ID" >/dev/null; then
    echo "✓ Access application deleted"
    set_env_var "CF_ACCESS_APP_ID" ""
  else
    echo "✗ Failed to delete Access application" >&2
    ((ERRORS++))
  fi
else
  echo "  Skipping Access application (CF_ACCESS_APP_ID not set)"
fi

# ── 3. Delete Access IDP ────────────────────────────────────────────────
if [[ -n "${CF_IDP_ID:-}" ]]; then
  echo "Deleting Access IDP $CF_IDP_ID..."
  if cf_api DELETE "/accounts/$CF_ACCOUNT_ID/access/identity_providers/$CF_IDP_ID" >/dev/null; then
    echo "✓ Access IDP deleted"
    set_env_var "CF_IDP_ID" ""
  else
    echo "✗ Failed to delete Access IDP" >&2
    ((ERRORS++))
  fi
else
  echo "  Skipping Access IDP (CF_IDP_ID not set)"
fi

# ── 4. Lookup + delete DNS CNAME ─────────────────────────────────────────
if [[ -n "${CF_ZONE_ID:-}" && -n "${CF_SUBDOMAIN:-}" && -n "${CF_DOMAIN:-}" ]]; then
  FQDN="${CF_SUBDOMAIN}.${CF_DOMAIN}"
  echo "Looking up DNS CNAME for $FQDN..."
  DNS_RESP=$(cf_api GET "/zones/$CF_ZONE_ID/dns_records?type=CNAME&name=$FQDN" 2>/dev/null) || true

  if [[ -n "$DNS_RESP" ]]; then
    RECORD_ID=$(echo "$DNS_RESP" | python3 -c "
import sys, json
records = json.load(sys.stdin).get('result', [])
print(records[0]['id'] if records else '')
" 2>/dev/null)

    if [[ -n "$RECORD_ID" ]]; then
      echo "Deleting DNS record $RECORD_ID..."
      if cf_api DELETE "/zones/$CF_ZONE_ID/dns_records/$RECORD_ID" >/dev/null; then
        echo "✓ DNS CNAME deleted ($FQDN)"
      else
        echo "✗ Failed to delete DNS record" >&2
        ((ERRORS++))
      fi
    else
      echo "  No CNAME record found for $FQDN"
    fi
  else
    echo "  Could not look up DNS records" >&2
    ((ERRORS++))
  fi
else
  echo "  Skipping DNS cleanup (CF_ZONE_ID/CF_SUBDOMAIN/CF_DOMAIN not set)"
fi

# ── 5. Clean up tunnel connections + delete tunnel ───────────────────────
if [[ -n "${CF_TUNNEL_ID:-}" ]]; then
  echo "Cleaning up tunnel connections for $CF_TUNNEL_ID..."
  cf_api DELETE "/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$CF_TUNNEL_ID/connections" >/dev/null 2>&1 || true

  echo "Deleting tunnel $CF_TUNNEL_ID..."
  if cf_api DELETE "/accounts/$CF_ACCOUNT_ID/cfd_tunnel/$CF_TUNNEL_ID" >/dev/null; then
    echo "✓ Tunnel deleted"
    set_env_var "CF_TUNNEL_ID" ""
    set_env_var "CLOUDFLARE_TOKEN" ""
  else
    echo "✗ Failed to delete tunnel" >&2
    ((ERRORS++))
  fi
else
  echo "  Skipping tunnel deletion (CF_TUNNEL_ID not set)"
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
if [[ $ERRORS -eq 0 ]]; then
  echo "=== Cloudflare teardown complete ==="
else
  echo "=== Cloudflare teardown finished with $ERRORS error(s) ==="
  exit 1
fi
