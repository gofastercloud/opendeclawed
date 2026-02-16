#!/usr/bin/env bash
###############################################################################
# opendeclawed — Setup Script
#
# Interactive or non-interactive setup for the hardened OpenClaw stack.
# Collects ALL credentials up front with secure input (no screen echo),
# stores them with strict permissions, and starts the stack.
#
# Usage:
#   Interactive:     ./scripts/setup.sh
#   Non-interactive: ./scripts/setup.sh --non-interactive
#
# Non-interactive mode reads all values from environment variables or .env file.
# Interactive mode prompts for missing values using secure (silent) input for
# all secrets.
###############################################################################
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }
header(){ echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }
dim()   { echo -e "${DIM}    $*${NC}"; }

# ── Defaults ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"
CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${HOME}/.openclaw}"
WORKSPACE_DIR="${OPENCLAW_WORKSPACE_DIR:-${CONFIG_DIR}/workspace}"
COMPOSE_FILE="${REPO_DIR}/docker-compose.yml"
ENV_FILE="${REPO_DIR}/.env"
MODELS_DIR="${REPO_DIR}/models"
INTERACTIVE=true

EMBED_MODEL="${EMBED_MODEL_FILE:-nomic-embed-text-v1.5.Q5_K_M.gguf}"
EMBED_URL="https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/resolve/main/${EMBED_MODEL}"
CHAT_MODEL="${CHAT_MODEL_FILE:-Llama-3.2-3B-Instruct-Q5_K_M.gguf}"
CHAT_URL="https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/${CHAT_MODEL}"

# Credential vars — populated by prompts or environment
ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
CLOUDFLARE_TOKEN="${CLOUDFLARE_TOKEN:-}"
NORDVPN_TOKEN="${NORDVPN_TOKEN:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
DISCORD_BOT_TOKEN="${DISCORD_BOT_TOKEN:-}"
DISCORD_GUILD_ID="${DISCORD_GUILD_ID:-}"
INGRESS_MODE="${INGRESS_MODE:-local}"

# ── Parse arguments ───────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --non-interactive) INTERACTIVE=false ;;
        --help|-h)
            echo "Usage: $0 [--non-interactive] [--help]"
            echo ""
            echo "  --non-interactive  Read all config from env vars / .env file"
            echo "  --help             Show this help"
            echo ""
            echo "Environment variables for non-interactive mode:"
            echo "  ANTHROPIC_API_KEY      Anthropic API key (required)"
            echo "  VIRUSTOTAL_API_KEY     VirusTotal API key (recommended)"
            echo "  INGRESS_MODE           local|tunnel|meshnet (default: local)"
            echo "  CLOUDFLARE_TOKEN       Cloudflare tunnel token (if tunnel)"
            echo "  NORDVPN_TOKEN          NordVPN token (if meshnet)"
            echo "  TELEGRAM_BOT_TOKEN     Telegram bot token (optional)"
            echo "  DISCORD_BOT_TOKEN      Discord bot token (optional)"
            echo "  DISCORD_GUILD_ID       Discord server ID (if Discord)"
            exit 0
            ;;
    esac
done

###############################################################################
# ── Secure input helpers ──────────────────────────────────────────────────
###############################################################################

# Prompt for a secret value. Input is NOT echoed to the screen.
# Usage: ask_secret VAR_NAME "prompt text" [required|optional]
ask_secret() {
    local var_name="$1" prompt="$2" required="${3:-optional}"
    local current_val="${!var_name:-}"

    # If already set from env, keep it
    if [ -n "${current_val}" ]; then
        return 0
    fi

    # Non-interactive: skip optional, error on required
    if [ "${INTERACTIVE}" != true ]; then
        if [ "${required}" = "required" ]; then
            error "${var_name} is required but not set. Export it or use interactive mode."
        fi
        return 0
    fi

    echo ""
    if [ "${required}" = "required" ]; then
        echo -e "  ${BOLD}${prompt}${NC} ${RED}(required)${NC}"
    else
        echo -e "  ${prompt} ${DIM}(Enter to skip)${NC}"
    fi

    while true; do
        # -s = silent (no echo), -r = raw (no backslash escape)
        read -rsp "  > " current_val
        echo ""  # newline after silent input

        if [ -z "${current_val}" ]; then
            if [ "${required}" = "required" ]; then
                warn "This credential is required. Please enter a value."
                continue
            else
                dim "Skipped."
                return 0
            fi
        fi

        # Confirm by asking to type again
        read -rsp "  Confirm (paste again): " confirm_val
        echo ""

        if [ "${current_val}" = "${confirm_val}" ]; then
            # SECURITY: use printf -v instead of eval to prevent shell injection
            # eval would allow crafted inputs like '; rm -rf / #' to execute
            printf -v "$var_name" '%s' "$current_val"
            info "Saved. (${#current_val} characters)"
            return 0
        else
            warn "Values don't match. Try again."
        fi
    done
}

# Prompt for a non-secret value (echoed normally).
ask_plain() {
    local var_name="$1" prompt="$2" default="${3:-}"
    local current_val="${!var_name:-${default}}"

    if [ "${INTERACTIVE}" = true ] && [ -z "${current_val}" ]; then
        read -rp "  ${prompt}: " current_val
    fi
    current_val="${current_val:-${default}}"
    printf -v "$var_name" '%s' "$current_val"
}

###############################################################################
header "Step 1/11 — Prerequisites"
###############################################################################

command -v docker >/dev/null 2>&1 || error "Docker not found. Install OrbStack (https://orbstack.dev) or Docker Desktop."
docker compose version >/dev/null 2>&1 || error "Docker Compose V2 not found."

DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
info "Docker Engine: ${DOCKER_VERSION}"

if pgrep -q OrbStack 2>/dev/null; then
    info "Runtime: OrbStack"
elif pgrep -q Docker 2>/dev/null || pgrep -q com.docker 2>/dev/null; then
    info "Runtime: Docker Desktop"
else
    info "Runtime: native Docker (or undetected)"
fi

###############################################################################
header "Step 2/11 — Secrets detection (TruffleHog)"
###############################################################################

# Install trufflehog if missing
if command -v trufflehog >/dev/null 2>&1; then
    info "TruffleHog: $(trufflehog --version 2>&1 | head -1)"
else
    info "Installing TruffleHog (secrets scanner)..."
    if command -v brew >/dev/null 2>&1; then
        brew install trufflehog 2>/dev/null || warn "brew install trufflehog failed — install manually"
    else
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | sh -s -- -b /usr/local/bin 2>/dev/null \
            || warn "TruffleHog auto-install failed. Install manually: https://github.com/trufflesecurity/trufflehog#installation"
    fi
    if command -v trufflehog >/dev/null 2>&1; then
        info "TruffleHog installed."
    else
        warn "TruffleHog not available — secrets scanning will be skipped."
        warn "Install later: brew install trufflehog"
    fi
fi

# Install pre-commit if missing
if command -v pre-commit >/dev/null 2>&1; then
    info "pre-commit: $(pre-commit --version 2>&1)"
else
    info "Installing pre-commit (git hook framework)..."
    if command -v pip3 >/dev/null 2>&1; then
        pip3 install pre-commit 2>/dev/null || true
    elif command -v brew >/dev/null 2>&1; then
        brew install pre-commit 2>/dev/null || true
    fi
fi

# Install git hooks if this is a git repo
if [ -d "${REPO_DIR}/.git" ] && command -v pre-commit >/dev/null 2>&1; then
    (cd "${REPO_DIR}" && pre-commit install 2>/dev/null) && info "Pre-commit hooks installed." || true
else
    dim "Not a git repo yet or pre-commit missing — run 'pre-commit install' after git init."
fi

###############################################################################
header "Step 3/11 — Config directories"
###############################################################################

mkdir -p "${CONFIG_DIR}" "${WORKSPACE_DIR}"
chmod 700 "${CONFIG_DIR}"
chmod 700 "${WORKSPACE_DIR}"
info "Config: ${CONFIG_DIR} (mode 700)"

###############################################################################
header "Step 4/11 — Credentials"
###############################################################################

echo ""
echo -e "${BOLD}  All secrets use secure input — nothing is echoed to screen.${NC}"
echo -e "${DIM}  Each secret is confirmed by pasting a second time.${NC}"
echo -e "${DIM}  See docs/prerequisites.md for how to obtain each key.${NC}"

# ── Required ──
echo ""
echo -e "  ${BOLD}── Required ──${NC}"
dim "Anthropic API key powers all Claude model calls."
dim "Get one at: https://console.anthropic.com → Settings → API Keys"
dim "Or use a Claude Pro/Max OAuth token from the onboarding wizard."
ask_secret ANTHROPIC_API_KEY "Anthropic API key (sk-ant-...)" required

# ── Recommended ──
echo ""
echo -e "  ${BOLD}── Recommended ──${NC}"
dim "VirusTotal API key enables skill scanning before install."
dim "Free: https://www.virustotal.com → avatar → API key"
ask_secret VIRUSTOTAL_API_KEY "VirusTotal API key"

# ── Ingress ──
echo ""
echo -e "  ${BOLD}── Ingress mode ──${NC}"
if [ "${INTERACTIVE}" = true ] && [ -z "${CLOUDFLARE_TOKEN}" ] && [ -z "${NORDVPN_TOKEN}" ]; then
    echo ""
    echo "  How will you access OpenClaw?"
    echo "    1) local    — 127.0.0.1 only (default, most secure)"
    echo "    2) tunnel   — Cloudflare Tunnel (zero exposed ports, internet-accessible)"
    echo "    3) meshnet  — NordVPN Meshnet (P2P, no public DNS)"
    echo ""
    read -rp "  Choose [1]: " ingress_choice
    case "${ingress_choice}" in
        2|tunnel)
            INGRESS_MODE="tunnel"
            dim "Create a tunnel at: https://one.dash.cloudflare.com → Tunnels"
            dim "See docs/setup-guide.md for Cloudflare Access + GitHub OAuth setup."
            ask_secret CLOUDFLARE_TOKEN "Cloudflare Tunnel token (eyJ...)" required
            ;;
        3|meshnet)
            INGRESS_MODE="meshnet"
            dim "Get token at: https://my.nordaccount.com → Services → NordVPN → Access Token"
            ask_secret NORDVPN_TOKEN "NordVPN service token" required
            ;;
        *)
            INGRESS_MODE="local"
            info "Ingress: local-only (127.0.0.1:18789)"
            ;;
    esac
else
    if [ -n "${CLOUDFLARE_TOKEN}" ]; then INGRESS_MODE="tunnel"; fi
    if [ -n "${NORDVPN_TOKEN}" ]; then INGRESS_MODE="meshnet"; fi
    info "Ingress: ${INGRESS_MODE} (from environment)"
fi

# ── Messaging (optional) ──
echo ""
echo -e "  ${BOLD}── Messaging channels (optional) ──${NC}"
dim "Configure at least one to interact with OpenClaw remotely."

# Telegram
if [ "${INTERACTIVE}" = true ] && [ -z "${TELEGRAM_BOT_TOKEN}" ]; then
    echo ""
    read -rp "  Set up Telegram bot? [y/N]: " setup_telegram
    if [[ "${setup_telegram}" =~ ^[Yy] ]]; then
        dim "Create a bot: message @BotFather on Telegram → /newbot"
        dim "Then /setjoingroups → Disable, /setprivacy → Enable"
        ask_secret TELEGRAM_BOT_TOKEN "Telegram bot token (123456789:ABC...)"
    fi
fi

# Discord
if [ "${INTERACTIVE}" = true ] && [ -z "${DISCORD_BOT_TOKEN}" ]; then
    echo ""
    read -rp "  Set up Discord bot? [y/N]: " setup_discord
    if [[ "${setup_discord}" =~ ^[Yy] ]]; then
        dim "Create at: https://discord.com/developers/applications → New App → Bot"
        dim "Enable Message Content Intent under Privileged Gateway Intents."
        ask_secret DISCORD_BOT_TOKEN "Discord bot token"
        ask_plain  DISCORD_GUILD_ID   "Discord server (guild) ID"
    fi
fi

###############################################################################
header "Step 5/11 — Gateway token"
###############################################################################

if [ -f "${CONFIG_DIR}/.gateway-token" ]; then
    OPENCLAW_GATEWAY_TOKEN="$(cat "${CONFIG_DIR}/.gateway-token")"
    info "Using existing gateway token."
elif [ -n "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    echo -n "${OPENCLAW_GATEWAY_TOKEN}" > "${CONFIG_DIR}/.gateway-token"
    chmod 600 "${CONFIG_DIR}/.gateway-token"
    info "Saved gateway token from environment."
else
    OPENCLAW_GATEWAY_TOKEN="$(openssl rand -hex 32)"
    echo -n "${OPENCLAW_GATEWAY_TOKEN}" > "${CONFIG_DIR}/.gateway-token"
    chmod 600 "${CONFIG_DIR}/.gateway-token"
    info "Generated new gateway token (64 hex chars)."
fi

###############################################################################
header "Step 6/11 — Download local models"
###############################################################################

mkdir -p "${MODELS_DIR}"

# Known-good SHA256 checksums for default models.
# Update these when changing default models in the vars above.
# To get a checksum: sha256sum models/<file>
declare -A MODEL_CHECKSUMS=(
    ["nomic-embed-text-v1.5.Q5_K_M.gguf"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Llama-3.2-3B-Instruct-Q5_K_M.gguf"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
)

download_model() {
    local name="$1" url="$2" dest="${MODELS_DIR}/$1"
    if [ -f "${dest}" ]; then
        info "Cached: ${name}"
    else
        info "Downloading ${name}..."
        curl -L --progress-bar -o "${dest}" "${url}" || error "Failed to download ${name}"
        info "Downloaded: ${name}"
    fi
}

verify_model() {
    local name="$1" dest="${MODELS_DIR}/$1"
    local expected="${MODEL_CHECKSUMS[$name]:-}"

    if [ -z "${expected}" ] || [ "${expected}" = "PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD" ]; then
        local actual
        actual=$(sha256sum "${dest}" | cut -d' ' -f1)
        warn "No checksum on record for ${name}"
        warn "  Computed: ${actual}"
        warn "  Update MODEL_CHECKSUMS in setup.sh with this value after verifying the file."
        return 0
    fi

    info "Verifying integrity: ${name}..."
    local actual
    actual=$(sha256sum "${dest}" | cut -d' ' -f1)
    if [ "${actual}" = "${expected}" ]; then
        info "Checksum OK: ${name}"
    else
        error "CHECKSUM MISMATCH for ${name}!\n  Expected: ${expected}\n  Got:      ${actual}\n  The model file may be corrupted or tampered with. Delete it and re-run."
    fi
}

download_model "${EMBED_MODEL}" "${EMBED_URL}"
download_model "${CHAT_MODEL}" "${CHAT_URL}"
verify_model "${EMBED_MODEL}"
verify_model "${CHAT_MODEL}"

###############################################################################
header "Step 7/11 — Write openclaw.json"
###############################################################################

OPENCLAW_JSON="${CONFIG_DIR}/openclaw.json"

if [ -f "${OPENCLAW_JSON}" ]; then
    info "Config exists, not overwriting: ${OPENCLAW_JSON}"
    info "Delete it and re-run to regenerate."
else
    # SECURITY: Pass all secrets via environment variables to Python, NOT via
    # shell interpolation into code. Shell interpolation breaks on quotes,
    # backslashes, and $ chars in API keys, and is an injection vector.
    ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
    TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}" \
    DISCORD_BOT_TOKEN="${DISCORD_BOT_TOKEN}" \
    DISCORD_GUILD_ID="${DISCORD_GUILD_ID}" \
    OPENCLAW_JSON_PATH="${OPENCLAW_JSON}" \
    python3 << 'PYEOF'
import json, os

config = {
    "agent": {
        "model": "anthropic/claude-sonnet-4-5-20250929"
    },
    "heartbeat": {
        "enabled": True,
        "intervalMinutes": 60,
        "model": "anthropic/claude-haiku-4-5-20251001"
    },
    "models": {
        "routing": {
            "default":   "anthropic/claude-sonnet-4-5-20250929",
            "heartbeat": "anthropic/claude-haiku-4-5-20251001",
            "quick":     "anthropic/claude-haiku-4-5-20251001",
            "reasoning": "anthropic/claude-opus-4-6",
            "embedding": "local/nomic-embed"
        }
    },
    "providers": {
        "anthropic": {
            "type": "api-key",
        },
        "local-llm": {
            "type": "openai-compatible",
            "baseUrl": "http://llama-chat:8091/v1",
            "apiKey": "not-needed",
            "models": ["local/llama-3.2-3b"]
        },
        "local-embed": {
            "type": "openai-compatible",
            "baseUrl": "http://llama-embed:8090/v1",
            "apiKey": "not-needed",
            "models": ["local/nomic-embed"]
        }
    },
    "security": {
        "dmPolicy": "pairing",
        "allowlist": [],
        "elevated": False,
        "sandbox": "strict"
    },
    "gateway": {
        "bind": "0.0.0.0",
        "port": 18789,
        "tailscale": False
    },
    "telemetry": {
        "enabled": False
    }
}

# Inject Anthropic API key (read from env — never from shell interpolation)
api_key = os.environ.get("ANTHROPIC_API_KEY", "")
if api_key:
    config["providers"]["anthropic"]["apiKey"] = api_key

# Inject channel configs (all read from env vars)
telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
discord_token = os.environ.get("DISCORD_BOT_TOKEN", "")
discord_guild = os.environ.get("DISCORD_GUILD_ID", "")

if telegram_token or discord_token:
    config["channels"] = {}
    if telegram_token:
        config["channels"]["telegram"] = {
            "enabled": True,
            "botToken": telegram_token,
            "dmPolicy": "pairing",
            "allowFrom": []
        }
    if discord_token:
        config["channels"]["discord"] = {
            "enabled": True,
            "botToken": discord_token,
            "guildId": discord_guild,
            "dmPolicy": "pairing",
            "allowFrom": []
        }

out_path = os.environ.get("OPENCLAW_JSON_PATH", os.path.expanduser("~/.openclaw/openclaw.json"))
with open(out_path, "w") as f:
    json.dump(config, f, indent=2)
PYEOF

    chmod 600 "${OPENCLAW_JSON}"
    info "Written: ${OPENCLAW_JSON} (mode 600)"
fi

###############################################################################
header "Step 8/11 — Write .env"
###############################################################################

if [ -f "${ENV_FILE}" ]; then
    info ".env exists, not overwriting. Delete to regenerate."
else
    cat > "${ENV_FILE}" << ENVEOF
# Generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# See .env.example for all available options.
# Permissions: 600 (owner read/write only)

# ── Core ──
OPENCLAW_GATEWAY_TOKEN=${OPENCLAW_GATEWAY_TOKEN}
OPENCLAW_CONFIG_DIR=${CONFIG_DIR}
OPENCLAW_WORKSPACE_DIR=${WORKSPACE_DIR}

# ── Models ──
EMBED_MODEL_FILE=${EMBED_MODEL}
CHAT_MODEL_FILE=${CHAT_MODEL}

# ── Ingress ──
CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
NORDVPN_TOKEN=${NORDVPN_TOKEN}

# ── Skills security ──
VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
ENVEOF

    chmod 600 "${ENV_FILE}"
    info "Written: ${ENV_FILE} (mode 600)"
fi

###############################################################################
header "Step 9/11 — Load models into Docker volume"
###############################################################################

info "Loading models into Docker volume..."
docker volume create llama-models 2>/dev/null || true
docker run --rm \
    -v "${MODELS_DIR}:/src:ro" \
    -v llama-models:/dst \
    alpine sh -c "cp /src/*.gguf /dst/ 2>/dev/null || true"
info "Models loaded."

###############################################################################
header "Step 10/11 — Start stack"
###############################################################################

# Onboarding (interactive only)
if [ "${INTERACTIVE}" = true ]; then
    echo ""
    read -rp "  Run OpenClaw onboarding wizard? [Y/n]: " run_onboard
    if [[ ! "${run_onboard}" =~ ^[Nn] ]]; then
        info "Starting onboarding wizard..."
        docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" \
            run --rm --profile cli openclaw-cli onboard --no-install-daemon \
            || warn "Onboarding exited. Re-run: docker compose run --rm --profile cli openclaw-cli onboard"
    fi
fi

# Build profile flags
PROFILES=""
case "${INGRESS_MODE}" in
    tunnel)  PROFILES="--profile tunnel" ;;
    meshnet) PROFILES="--profile meshnet" ;;
esac

# Ask about monitoring
ENABLE_MONITOR="${ENABLE_MONITOR:-}"
if [ "${INTERACTIVE}" = true ] && [ -z "${ENABLE_MONITOR}" ]; then
    echo ""
    read -rp "  Enable Uptime Kuma + Watchtower monitoring? [Y/n]: " enable_mon
    if [[ ! "${enable_mon}" =~ ^[Nn] ]]; then
        PROFILES="${PROFILES} --profile monitor"
    fi
elif [ "${ENABLE_MONITOR}" = "true" ]; then
    PROFILES="${PROFILES} --profile monitor"
fi

info "Starting stack..."
docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ${PROFILES} up -d

###############################################################################
header "Step 11/11 — Validate"
###############################################################################

sleep 3

docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" ps --format '{{.Name}}\t{{.Status}}' 2>/dev/null \
    | while IFS=$'\t' read -r name status; do
        info "  ${name}: ${status}"
    done

# Firewall check
GATEWAY_ID=$(docker ps -q -f name=openclaw-gateway 2>/dev/null || true)
if [ -n "${GATEWAY_ID}" ]; then
    if docker exec "${GATEWAY_ID}" wget -q --spider --timeout=3 http://192.168.1.1/ 2>/dev/null; then
        warn "FIREWALL CHECK FAILED — containers can reach LAN!"
    else
        info "FIREWALL CHECK PASSED — LAN unreachable from containers"
    fi
fi

# Secrets scan — verify nothing leaked into tracked files
if command -v trufflehog >/dev/null 2>&1; then
    info "Running TruffleHog secrets scan on working tree..."
    if trufflehog filesystem "${REPO_DIR}" \
        --exclude-paths="${REPO_DIR}/.trufflehog-config.yaml" \
        --no-update --fail 2>/dev/null; then
        info "SECRETS SCAN PASSED — no credentials detected in repo files"
    else
        warn "SECRETS SCAN FLAGGED ISSUES — review: ./scripts/scan-secrets.sh"
    fi
else
    dim "TruffleHog not installed — skipping secrets scan."
fi

###############################################################################
# ── Summary ──
###############################################################################

echo ""
echo "======================================================================"
echo -e "  ${BOLD}${GREEN}Setup complete.${NC}"
echo "======================================================================"
echo ""
echo "  Credentials stored:"
echo "    Anthropic API key:  ~/.openclaw/openclaw.json"
[ -n "${VIRUSTOTAL_API_KEY}" ] && \
echo "    VirusTotal API key: .env"
[ -n "${CLOUDFLARE_TOKEN}" ] && \
echo "    Cloudflare token:   .env"
[ -n "${NORDVPN_TOKEN}" ] && \
echo "    NordVPN token:      .env"
[ -n "${TELEGRAM_BOT_TOKEN}" ] && \
echo "    Telegram bot token: ~/.openclaw/openclaw.json"
[ -n "${DISCORD_BOT_TOKEN}" ] && \
echo "    Discord bot token:  ~/.openclaw/openclaw.json"
echo "    Gateway token:      ~/.openclaw/.gateway-token"
echo ""
echo "  File permissions:"
echo "    ~/.openclaw/            → 700 (owner only)"
echo "    ~/.openclaw/openclaw.json → 600"
echo "    .env                    → 600"
echo "    ~/.openclaw/.gateway-token → 600"
echo ""
echo "  Ingress: ${INGRESS_MODE}"
case "${INGRESS_MODE}" in
    local)   echo "  Access:  http://127.0.0.1:${GATEWAY_PORT:-18789}/" ;;
    tunnel)  echo "  Access:  via your Cloudflare Tunnel hostname" ;;
    meshnet) echo "  Access:  via NordVPN Meshnet peer address" ;;
esac
echo ""
echo "  Commands:"
echo "    Logs:    docker compose logs -f"
echo "    Stop:    docker compose down"
echo "    Doctor:  docker compose run --rm --profile cli openclaw-cli doctor"
echo "    Health:  curl http://127.0.0.1:${GATEWAY_PORT:-18789}/health"
echo "    Secrets: ./scripts/scan-secrets.sh        (scan working tree)"
echo "             ./scripts/scan-secrets.sh --full  (scan git history)"
[ -n "${VIRUSTOTAL_API_KEY}" ] && \
echo "    Install: \"install skill <name>\" via Telegram (safe-install skill)"
echo "======================================================================"
