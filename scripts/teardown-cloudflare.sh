#!/usr/bin/env bash
# teardown-cloudflare.sh — Delete Cloudflare Tunnel + Access resources
# Deletes in reverse creation order: Access App → IDP → DNS → Tunnel
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# ── Load shared libraries ────────────────────────────────────────────────
source "${SCRIPT_DIR}/lib/env-helpers.sh"
source "${SCRIPT_DIR}/lib/cloudflare-helpers.sh"

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
  error "$ENV_FILE not found."
  exit 1
fi

load_env "$ENV_FILE"

# ── Validate minimum required vars ──────────────────────────────────────
MISSING=()
for var in CF_API_TOKEN CF_ACCOUNT_ID; do
  if [[ -z "${!var:-}" ]]; then
    MISSING+=("$var")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  error "Missing required variables in .env:"
  printf '  %s\n' "${MISSING[@]}" >&2
  exit 1
fi

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
    save_env "CF_ACCESS_APP_ID" "" "$ENV_FILE"
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
    save_env "CF_IDP_ID" "" "$ENV_FILE"
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
    save_env "CF_TUNNEL_ID" "" "$ENV_FILE"
    save_env "CLOUDFLARE_TOKEN" "" "$ENV_FILE"
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
