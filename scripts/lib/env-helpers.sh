#!/usr/bin/env bash
# Shared environment helpers for OpenDeclawed scripts
# Sourced by setup-cloudflare.sh, teardown-cloudflare.sh, etc.
set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()    { printf "${CYAN}[+]${NC} %s\n" "$1"; }
warn()    { printf "${YELLOW}[!]${NC} %s\n" "$1" >&2; }
error()   { printf "${RED}[x]${NC} %s\n" "$1" >&2; }
success() { printf "${GREEN}[+]${NC} %s\n" "$1"; }

# Safe .env file loader - does NOT use 'source', validates variable names
# Usage: load_env "/path/to/.env"
load_env() {
    local env_file="${1:-.env}"
    [ -f "$env_file" ] || { error "Env file not found: $env_file"; return 1; }
    while IFS='=' read -r key value; do
        # Skip comments and blank lines
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        # Strip leading/trailing whitespace from key
        key=$(echo "$key" | xargs)
        # Validate variable name
        if [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            # Strip surrounding quotes from value
            value="${value%\"}" ; value="${value#\"}"
            value="${value%\'}" ; value="${value#\'}"
            export "${key}=${value}"
        fi
    done < <(grep -v '^\s*#' "${env_file}" | grep -v '^\s*$')
}

# Safe .env writer - uses grep + printf, NOT sed
# Usage: save_env "KEY" "VALUE" "/path/to/.env"
save_env() {
    local key="$1" value="$2" env_file="${3:-.env}"

    if [ ! -f "$env_file" ]; then
        touch "$env_file"
        chmod 600 "$env_file"
    fi

    local tmpfile
    tmpfile=$(mktemp "${env_file}.XXXXXX")

    # Copy all lines except the one we're updating
    if [ -f "$env_file" ]; then
        grep -v "^${key}=" "$env_file" > "$tmpfile" 2>/dev/null || true
    fi

    # Append the new value (unquoted for Docker Compose compatibility)
    printf '%s=%s\n' "${key}" "${value}" >> "$tmpfile"

    # Atomic replace
    mv "$tmpfile" "$env_file"
    chmod 600 "$env_file"
}
