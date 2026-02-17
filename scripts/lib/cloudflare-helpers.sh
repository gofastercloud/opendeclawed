#!/usr/bin/env bash
# Shared Cloudflare API helpers for OpenDeclawed scripts
set -euo pipefail

# Cloudflare API helper
# Usage: cf_api METHOD ENDPOINT [extra_curl_args...]
cf_api() {
    local method="$1" endpoint="$2"; shift 2
    local resp
    resp=$(curl -sfL -X "$method" \
        "https://api.cloudflare.com/client/v4${endpoint}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        "$@" 2>&1) || { error "Cloudflare API call failed: $method $endpoint"; return 1; }

    local ok
    ok=$(printf '%s' "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',False))" 2>/dev/null) || ok="False"
    if [ "$ok" != "True" ]; then
        error "Cloudflare API error on $method $endpoint"
        printf '%s\n' "$resp" | python3 -c "import sys,json; [print(f'  - {e[\"message\"]}') for e in json.load(sys.stdin).get('errors',[])]" 2>/dev/null || true
        return 1
    fi
    printf '%s' "$resp"
}

# Safe JSON payload builder using jq with python3 fallback
# Usage: json_obj key1 val1 key2 val2 ...
json_obj() {
    if command -v jq &>/dev/null; then
        local args=()
        local template="{"
        local first=true
        while [ $# -ge 2 ]; do
            local k="$1" v="$2"; shift 2
            args+=(--arg "$k" "$v")
            if [ "$first" = true ]; then
                template+="$k:\$$k"
                first=false
            else
                template+=",$k:\$$k"
            fi
        done
        template+="}"
        jq -n "${args[@]}" "$template"
    else
        # Python3 fallback
        python3 -c "
import json, sys
args = sys.argv[1:]
d = {}
for i in range(0, len(args), 2):
    d[args[i]] = args[i+1]
print(json.dumps(d))
" "$@"
    fi
}
