#!/bin/sh
set -eu

# ── Validate environment ────────────────────────────────────────────
if [ -z "${NORDVPN_TOKEN:-}" ]; then
    echo "ERROR: NORDVPN_TOKEN is required" >&2
    exit 1
fi

CADDY_IP="${CADDY_IP:-}"
CADDY_PORT="${CADDY_PORT:-443}"

# ── Start NordVPN daemon ────────────────────────────────────────────
# The daemon manages the WireGuard tunnel for meshnet.
cleanup() {
    echo "Shutting down NordVPN meshnet..."
    # NOTE: Do NOT call "nordvpn logout" — it revokes the access token permanently.
    # Session state is preserved in the nordvpn-state volume for next startup.
    kill "${DAEMON_PID:-}" 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

nordvpnd &
DAEMON_PID=$!

# Wait for daemon to be ready
echo "Waiting for NordVPN daemon..."
for i in $(seq 1 30); do
    if nordvpn status >/dev/null 2>&1; then
        echo "NordVPN daemon ready."
        break
    fi
    if [ "$i" = "30" ]; then
        echo "ERROR: NordVPN daemon failed to start" >&2
        exit 1
    fi
    sleep 1
done

# ── Disable telemetry prompt (must happen before login) ───────────
# NordVPN CLI asks for analytics consent interactively on first run.
# Disable it non-interactively to prevent the container from hanging.
nordvpn set analytics off 2>/dev/null || true

# ── Login and enable meshnet ────────────────────────────────────────
# Try login with token. If already logged in from a previous run
# (state persisted in nordvpn-state volume), skip login.
# NOTE: Do NOT logout — NordVPN revokes access tokens on logout.
if nordvpn account >/dev/null 2>&1; then
    echo "Already logged in (session from volume)."
else
    nordvpn login --token "${NORDVPN_TOKEN}"
fi

# Enable meshnet (peer-to-peer, no full VPN tunnel)
nordvpn set meshnet on || echo "Meshnet already enabled."

echo "Meshnet enabled. Waiting for interface..."

# ── Detect meshnet IP ───────────────────────────────────────────────
# The meshnet IP is assigned to the nordlynx WireGuard interface.
MESH_IP=""
for i in $(seq 1 30); do
    MESH_IP=$(ip -4 addr show nordlynx 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}') || true
    if [ -n "${MESH_IP}" ]; then
        echo "Meshnet IP: ${MESH_IP}"
        break
    fi
    sleep 2
done

if [ -z "${MESH_IP}" ]; then
    echo "WARNING: Could not detect meshnet IP. DNAT rules not installed." >&2
    echo "Check: ip addr show nordlynx" >&2
fi

# ── iptables DNAT: forward meshnet:443 → caddy ─────────────────────
# Only meshnet peers can reach this IP. Caddy handles TLS + reverse proxy.
if [ -n "${MESH_IP}" ] && [ -n "${CADDY_IP}" ]; then
    iptables -t nat -A PREROUTING \
        -d "${MESH_IP}" -p tcp --dport "${CADDY_PORT}" \
        -j DNAT --to-destination "${CADDY_IP}:${CADDY_PORT}"
    iptables -t nat -A POSTROUTING -j MASQUERADE
    echo "DNAT installed: ${MESH_IP}:${CADDY_PORT} -> ${CADDY_IP}:${CADDY_PORT}"
else
    echo "WARNING: DNAT not installed (MESH_IP=${MESH_IP}, CADDY_IP=${CADDY_IP})" >&2
fi

# ── Keep alive ──────────────────────────────────────────────────────
echo "NordVPN meshnet running. PID: ${DAEMON_PID}"
wait "${DAEMON_PID}"
