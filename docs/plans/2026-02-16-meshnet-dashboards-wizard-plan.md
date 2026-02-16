# Meshnet, Dashboard Proxying, Wizard Skip & IP Detection — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire up Tailscale and NordVPN meshnet ingress with dashboard proxying, generate a complete openclaw.json to skip the onboarding wizard, and detect mesh IPs at startup.

**Architecture:** Three ingress methods (Cloudflare Tunnel, Tailscale, NordVPN Meshnet) each proxy the same three services (gateway, Uptime Kuma, Dozzle) via consistent sub-paths. A new isolated `openclaw-meshnet` network keeps NordVPN traffic separated from other containers, with Caddy as the sole bridge. The setup script generates a fully populated openclaw.json so the OpenClaw wizard is never triggered.

**Tech Stack:** Docker Compose, Bash, Python 3 (inline in setup.sh), Caddy (reverse proxy), NordVPN CLI, Tailscale Serve

**Design doc:** `docs/plans/2026-02-16-meshnet-dashboards-wizard-design.md`

---

## Important: Network Discovery

Uptime Kuma and Dozzle are currently on `openclaw-internal` only. All three ingress services (cloudflared, tailscale, caddy) are on `openclaw-egress`. For ingress to reach dashboards, Kuma and Dozzle need `openclaw-egress` as a second network. This is addressed in Task 1.

---

### Task 1: Add Kuma and Dozzle to egress network

Dashboard services need to be reachable by all ingress methods (cloudflared, tailscale, caddy), which live on `openclaw-egress`. Add egress as a second network.

**Files:**
- Modify: `docker-compose.yml:742-775` (uptime-kuma service)
- Modify: `docker-compose.yml:851-885` (dozzle service)
- Modify: `docker-compose.yml:864` (DOZZLE_BASE env var)

**Step 1: Add openclaw-egress network to uptime-kuma**

In `docker-compose.yml`, change the uptime-kuma networks block from:
```yaml
    networks:
      openclaw-internal: {}
```
to:
```yaml
    networks:
      openclaw-internal: {}
      openclaw-egress: {}
```

**Step 2: Add openclaw-egress network to dozzle**

Same change for the dozzle service — add `openclaw-egress: {}` to its networks block.

**Step 3: Set Dozzle sub-path base**

Change `DOZZLE_BASE=/` to `DOZZLE_BASE=/logs` in the dozzle environment section. This makes Dozzle serve its UI under `/logs/` when accessed via ingress proxies.

Note: Uptime Kuma does not natively support sub-path hosting. The reverse proxies (Caddy, Tailscale Serve, cloudflared) will strip the `/kuma` prefix before forwarding. Caddy uses `handle_path`, Tailscale Serve handles this natively, cloudflared uses path-based ingress rules.

**Step 4: Validate compose syntax**

Run: `docker compose config > /dev/null`
Expected: exits 0, no errors

**Step 5: Commit**

```bash
git add docker-compose.yml
git commit -m "Add egress network to Kuma/Dozzle for ingress proxy access

Dashboard services need to be reachable by ingress proxies (cloudflared,
tailscale, caddy) which live on openclaw-egress. Also set DOZZLE_BASE=/logs
for sub-path hosting behind reverse proxies."
```

---

### Task 2: Update Tailscale Serve to proxy dashboards

The Tailscale service currently only proxies the gateway. Add Kuma and Dozzle routes.

**Files:**
- Modify: `docker-compose.yml:555-578` (tailscale entrypoint serve config)

**Step 1: Update the Tailscale Serve JSON**

Replace the current serve.json generation in the tailscale entrypoint (the `cat > /config/serve.json` heredoc) with:

```json
{
  "TCP": {
    "443": {
      "HTTPS": true
    }
  },
  "Web": {
    "$${TS_HOSTNAME:-openclaw}.$${TS_CERT_DOMAIN:-ts.net}:443": {
      "Handlers": {
        "/": {
          "Proxy": "http://openclaw-gateway:${GATEWAY_PORT:-18789}"
        },
        "/kuma/": {
          "Proxy": "http://opendeclawed-uptime-kuma:3001"
        },
        "/logs/": {
          "Proxy": "http://opendeclawed-dozzle:${DOZZLE_PORT:-5005}"
        }
      }
    }
  }
}
```

Note: Use container names (`opendeclawed-uptime-kuma`, `opendeclawed-dozzle`) since Docker DNS resolves by container name on the egress network.

**Step 2: Validate compose syntax**

Run: `docker compose config > /dev/null`
Expected: exits 0

**Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "Add Kuma and Dozzle routes to Tailscale Serve config

Tailscale now proxies /kuma/ to Uptime Kuma and /logs/ to Dozzle in
addition to the gateway at /. All accessible only to tailnet members."
```

---

### Task 3: Update Cloudflare Tunnel for multi-service ingress

Replace the simple `tunnel run --token` command with a config file approach that routes multiple paths to different backend services.

**Files:**
- Modify: `docker-compose.yml:483-512` (cloudflared service)
- Modify: `scripts/setup.sh` (cloudflared config generation, near line 862-900)

**Step 1: Update cloudflared entrypoint in docker-compose.yml**

Replace the cloudflared command with a config-file approach. The entrypoint generates a config file then runs the tunnel:

```yaml
  cloudflared:
    image: "${CLOUDFLARED_IMAGE:-cloudflare/cloudflared:latest}"
    container_name: opendeclawed-cloudflared
    profiles:
      - tunnel
    entrypoint: |
      /bin/sh -c '
        mkdir -p /etc/cloudflared
        cat > /etc/cloudflared/config.yml << CFGEOF
      tunnel: ${CLOUDFLARE_TUNNEL_NAME:-openclaw}
      ingress:
        - hostname: "${CLOUDFLARE_TUNNEL_ROUTE:-openclaw.example.com}"
          path: "/kuma/*"
          service: "http://opendeclawed-uptime-kuma:3001"
        - hostname: "${CLOUDFLARE_TUNNEL_ROUTE:-openclaw.example.com}"
          path: "/logs/*"
          service: "http://opendeclawed-dozzle:${DOZZLE_PORT:-5005}"
        - hostname: "${CLOUDFLARE_TUNNEL_ROUTE:-openclaw.example.com}"
          service: "http://openclaw-gateway:${GATEWAY_PORT:-18789}"
        - service: http_status:404
      CFGEOF
        exec cloudflared tunnel --config /etc/cloudflared/config.yml run --token ${CLOUDFLARE_TOKEN}
      '
    networks:
      openclaw-egress: {}
    # ... rest of service definition unchanged
```

Note: Token-based tunnels may ignore the local config file's ingress rules (Cloudflare dashboard config takes precedence). If so, the user configures ingress rules in the Cloudflare dashboard instead. The local config file is a fallback for locally-managed tunnels. Investigate and document during implementation.

**Step 2: Validate compose syntax**

Run: `docker compose config > /dev/null`
Expected: exits 0

**Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "Add multi-service ingress to Cloudflare Tunnel config

cloudflared now routes /kuma/ and /logs/ to dashboard services in
addition to the gateway. Uses config file approach for path-based routing."
```

---

### Task 4: Create NordVPN meshnet Dockerfile

Build a minimal container with just the NordVPN CLI for meshnet functionality.

**Files:**
- Create: `nordvpn/Dockerfile`

**Step 1: Create the nordvpn directory**

Run: `mkdir -p nordvpn`

**Step 2: Write the Dockerfile**

Create `nordvpn/Dockerfile`:

```dockerfile
# NordVPN Meshnet — minimal container for peer-to-peer mesh networking
# Only the NordVPN CLI is installed; no full VPN tunnel is used.
# Meshnet provides a routable IP for inbound connections from your devices.
FROM debian:bookworm-slim

# Install NordVPN CLI from official repo
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl ca-certificates gpg iptables iproute2 \
    && curl -fsSL https://repo.nordvpn.com/gpg/nordvpn_public.asc \
        | gpg --dearmor -o /usr/share/keyrings/nordvpn.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nordvpn.gpg] https://repo.nordvpn.com/deb/nordvpn/debian stable main" \
        > /etc/apt/sources.list.d/nordvpn.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nordvpn \
    && apt-get purge -y curl gpg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=60s \
    CMD nordvpn meshnet peer list >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
```

**Step 3: Commit**

```bash
git add nordvpn/Dockerfile
git commit -m "Add NordVPN meshnet Dockerfile

Debian slim base with NordVPN CLI only. Used for meshnet peer-to-peer
connectivity — no full VPN tunnel. Healthcheck validates meshnet status."
```

---

### Task 5: Create NordVPN meshnet entrypoint script

The entrypoint logs in, enables meshnet, sets up iptables DNAT to forward traffic to Caddy, and keeps the container alive.

**Files:**
- Create: `nordvpn/entrypoint.sh`

**Step 1: Write the entrypoint**

Create `nordvpn/entrypoint.sh`:

```bash
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

# ── Login and enable meshnet ────────────────────────────────────────
# Token login (non-interactive, no browser)
nordvpn login --token "${NORDVPN_TOKEN}"

# Enable meshnet (peer-to-peer, no full VPN tunnel)
nordvpn set meshnet on
nordvpn set mesh-receive on

echo "Meshnet enabled. Waiting for peer connections..."

# ── Detect meshnet IP ───────────────────────────────────────────────
MESH_IP=""
for i in $(seq 1 30); do
    MESH_IP=$(nordvpn meshnet peer list 2>/dev/null \
        | grep -oE 'Address: [0-9.]+' | head -1 | awk '{print $2}') || true
    if [ -n "${MESH_IP}" ]; then
        echo "Meshnet IP: ${MESH_IP}"
        break
    fi
    sleep 2
done

if [ -z "${MESH_IP}" ]; then
    echo "WARNING: Could not detect meshnet IP. DNAT rules not installed." >&2
    echo "Check: nordvpn meshnet peer list" >&2
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
# Trap signals for clean shutdown
trap 'nordvpn logout; kill ${DAEMON_PID} 2>/dev/null; exit 0' TERM INT
echo "NordVPN meshnet running. PID: ${DAEMON_PID}"
wait ${DAEMON_PID}
```

**Step 2: Make executable**

Run: `chmod +x nordvpn/entrypoint.sh`

**Step 3: Commit**

```bash
git add nordvpn/entrypoint.sh
git commit -m "Add NordVPN meshnet entrypoint script

Handles daemon startup, token login, meshnet enable, IP detection,
and iptables DNAT to forward inbound meshnet traffic to Caddy."
```

---

### Task 6: Create Caddy reverse proxy config

Caddyfile that proxies gateway, Kuma, and Dozzle with self-signed TLS.

**Files:**
- Create: `nordvpn/Caddyfile`

**Step 1: Write the Caddyfile**

Create `nordvpn/Caddyfile`:

```caddyfile
# Meshnet reverse proxy — TLS termination for inbound meshnet traffic
# Self-signed TLS by default (meshnet peers trust manually).
# To use Let's Encrypt, replace :443 with your domain name.

:443 {
	tls internal

	# Gateway API (default route)
	handle /* {
		reverse_proxy openclaw-gateway:{$GATEWAY_PORT:18789}
	}

	# Uptime Kuma dashboard
	handle_path /kuma/* {
		reverse_proxy opendeclawed-uptime-kuma:3001
	}

	# Dozzle log viewer
	# Dozzle is configured with DOZZLE_BASE=/logs so it expects /logs prefix
	handle /logs/* {
		reverse_proxy opendeclawed-dozzle:{$DOZZLE_PORT:5005}
	}
}
```

Note: `handle_path` strips the prefix before forwarding (needed for Kuma which doesn't support sub-paths). `handle` preserves the path (needed for Dozzle which has `DOZZLE_BASE=/logs`).

**Step 2: Commit**

```bash
git add nordvpn/Caddyfile
git commit -m "Add Caddy reverse proxy config for meshnet ingress

Routes /kuma/ to Uptime Kuma (path stripped), /logs/ to Dozzle
(path preserved, matches DOZZLE_BASE), and / to gateway. Self-signed TLS."
```

---

### Task 7: Add NordVPN meshnet and Caddy services to docker-compose.yml

Add both compose services, the new network, and the new volume.

**Files:**
- Modify: `docker-compose.yml` — add services after tailscale (line ~605), add network after openclaw-egress (line ~973), add volume after tailscale-state (line ~991)

**Step 1: Add the nordvpn-meshnet service**

Insert after the tailscale service block (after line 605), before the docker-socket-proxy comment:

```yaml
  # ─────────────────────────────────────────────────────────────────────
  # NORDVPN MESHNET: Peer-to-peer mesh VPN ingress (optional, profile: meshnet)
  # ─────────────────────────────────────────────────────────────────────
  # Provides a routable meshnet IP for inbound connections from your
  # NordVPN meshnet peers. Only meshnet traffic passes through this
  # container — regular internet egress is unaffected.
  #
  # Profile: "meshnet"
  #  - Enable with: docker compose --profile meshnet up -d
  #  - Requires NORDVPN_TOKEN env var
  #
  # Security:
  #  - Isolated to openclaw-meshnet network (cannot reach internal or egress)
  #  - Traffic is inbound only (your devices → dashboards)
  #  - iptables DNAT forwards meshnet:443 → caddy (sole bridge to services)
  #  - cap_add: NET_ADMIN + NET_RAW (required for WireGuard + iptables)
  #  - Read-only root, all other caps dropped
  #  - Persistent state volume avoids re-auth on restart
  nordvpn-meshnet:
    build:
      context: ./nordvpn
      dockerfile: Dockerfile
    image: "${NORDVPN_IMAGE:-opendeclawed-nordvpn:local}"
    container_name: opendeclawed-nordvpn
    profiles:
      - meshnet
    networks:
      openclaw-meshnet: {}
    volumes:
      - nordvpn-state:/var/lib/nordvpn
    tmpfs:
      - /tmp:size=64m,noexec,nosuid,nodev
      - /run:size=32m,noexec,nosuid,nodev
    environment:
      - NORDVPN_TOKEN=${NORDVPN_TOKEN:-}
      - CADDY_IP=${CADDY_IP:-}
      - CADDY_PORT=443
    deploy:
      resources:
        limits:
          cpus: "${NORDVPN_CPUS:-0.5}"
          memory: "${NORDVPN_MEM:-256m}"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
      - NET_RAW
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 3
    restart: unless-stopped
    depends_on:
      egress-firewall:
        condition: service_started
    labels:
      - "com.centurylinklabs.watchtower.enable=false"

  # ─────────────────────────────────────────────────────────────────────
  # MESHNET-CADDY: TLS reverse proxy for meshnet ingress (profile: meshnet)
  # ─────────────────────────────────────────────────────────────────────
  # Bridges openclaw-meshnet (receives traffic from nordvpn DNAT) and
  # openclaw-egress (proxies to gateway, Kuma, Dozzle). This is the ONLY
  # container that spans both networks — the sole path from meshnet to services.
  #
  # Security:
  #  - Self-signed TLS by default (meshnet peers trust manually)
  #  - Read-only root, all caps dropped
  #  - No internet access (openclaw-meshnet is internal, egress is firewall-controlled)
  meshnet-caddy:
    image: "${CADDY_IMAGE:-caddy:alpine}"
    container_name: opendeclawed-meshnet-caddy
    profiles:
      - meshnet
    networks:
      openclaw-meshnet: {}
      openclaw-egress: {}
    volumes:
      - ./nordvpn/Caddyfile:/etc/caddy/Caddyfile:ro
    tmpfs:
      - /tmp:size=32m,noexec,nosuid,nodev
      - /data:size=64m
      - /config:size=16m
    environment:
      - GATEWAY_PORT=${GATEWAY_PORT:-18789}
      - DOZZLE_PORT=${DOZZLE_PORT:-5005}
    deploy:
      resources:
        limits:
          cpus: "${CADDY_CPUS:-0.25}"
          memory: "${CADDY_MEM:-64m}"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: json-file
      options:
        max-size: 5m
        max-file: 2
    restart: unless-stopped
    depends_on:
      nordvpn-meshnet:
        condition: service_healthy
      openclaw-gateway:
        condition: service_healthy
    labels:
      - "com.centurylinklabs.watchtower.enable=false"
```

**Step 2: Add the openclaw-meshnet network**

Insert after the openclaw-egress network definition (after line ~973):

```yaml
  # ─────────────────────────────────────────────────────────────────────
  # OPENCLAW-MESHNET: Isolated NordVPN mesh network (no internet)
  # ─────────────────────────────────────────────────────────────────────
  # Dedicated network for NordVPN meshnet container and Caddy proxy.
  # Internal (no internet access). Only meshnet-caddy bridges this to
  # openclaw-egress where services live. No other container can reach
  # meshnet peers.
  openclaw-meshnet:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: "${MESHNET_SUBNET:-172.29.0.0/24}"
```

**Step 3: Add the nordvpn-state volume**

Insert after tailscale-state volume (after line ~991):

```yaml
  # ─────────────────────────────────────────────────────────────────────
  # NORDVPN-STATE: Persistent NordVPN auth and meshnet state
  # ─────────────────────────────────────────────────────────────────────
  # Stores login credentials and WireGuard keys. Persisting this avoids
  # re-authentication on container restart.
  nordvpn-state:
    driver: local
```

**Step 4: Update the header comment**

Update the PROFILES section in the file header (around line 54-59) to include meshnet:

```
#  - "meshnet": Enable NordVPN Meshnet ingress (peer-to-peer, profile: meshnet)
```

**Step 5: Validate compose syntax**

Run: `docker compose config > /dev/null`
Expected: exits 0

**Step 6: Commit**

```bash
git add docker-compose.yml
git commit -m "Add NordVPN meshnet and Caddy services to compose

New profile 'meshnet' adds nordvpn-meshnet (mesh VPN endpoint) and
meshnet-caddy (TLS reverse proxy). Isolated on openclaw-meshnet network
with Caddy as the sole bridge to services on openclaw-egress."
```

---

### Task 8: Update .env.example with new variables

Add NordVPN and Caddy configuration variables.

**Files:**
- Modify: `.env.example`

**Step 1: Add NordVPN meshnet section**

Insert after the Tailscale section (after line ~214), before TELEMETRY:

```bash
# ─────────────────────────────────────────────────────────────────────────
# NORDVPN MESHNET (optional, requires --profile meshnet)
# ─────────────────────────────────────────────────────────────────────────
# Expose openclaw-gateway to your NordVPN meshnet peers via peer-to-peer
# WireGuard tunnels. Only devices on your meshnet can connect.
#
# Setup:
#  1. Go to https://my.nordaccount.com → Services → NordVPN → Access Token
#  2. Generate a service token
#  3. Set NORDVPN_TOKEN below
#  4. Run: docker compose --profile meshnet up -d
#  5. On your device: nordvpn meshnet peer connect <hostname>

# NordVPN service token (required to enable meshnet)
NORDVPN_TOKEN=

# Resource limits
NORDVPN_CPUS=0.5
NORDVPN_MEM=256m

# Caddy reverse proxy (used by meshnet profile)
CADDY_IMAGE=caddy:alpine
CADDY_CPUS=0.25
CADDY_MEM=64m
```

**Step 2: Add MESHNET_SUBNET to network section**

Insert after `EGRESS_SUBNET` in the network configuration section (around line 132):

```bash
# openclaw-meshnet network (NordVPN meshnet + Caddy proxy, no internet)
MESHNET_SUBNET=172.29.0.0/24
```

**Step 3: Commit**

```bash
git add .env.example
git commit -m "Add NordVPN meshnet and Caddy vars to .env.example"
```

---

### Task 9: Expand openclaw.json config generator (wizard skip)

Update the Python config generator in setup.sh to emit all fields that the OpenClaw onboarding wizard would populate.

**Files:**
- Modify: `scripts/setup.sh:643-777` (Step 7 — Write openclaw.json)
- Modify: `scripts/setup.sh:838-851` (Step 10 — onboarding prompt)

**Step 1: Add gateway token generation before the Python block**

Insert before the Python heredoc (before line 655):

```bash
# Generate gateway auth token (24 bytes hex = 48 chars)
if [ -z "${OPENCLAW_GATEWAY_TOKEN:-}" ]; then
    OPENCLAW_GATEWAY_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(24))")
    save_env OPENCLAW_GATEWAY_TOKEN "${OPENCLAW_GATEWAY_TOKEN}"
fi

# Save gateway token to dedicated file (matches OpenClaw convention)
GATEWAY_TOKEN_FILE="${CONFIG_DIR}/.gateway-token"
printf '%s' "${OPENCLAW_GATEWAY_TOKEN}" > "${GATEWAY_TOKEN_FILE}"
chmod 600 "${GATEWAY_TOKEN_FILE}"
```

**Step 2: Pass new env vars to the Python block**

Add to the environment variable list before `python3 << 'PYEOF'`:

```bash
    OPENCLAW_GATEWAY_TOKEN="${OPENCLAW_GATEWAY_TOKEN}" \
    INGRESS_MODE="${INGRESS_MODE}" \
    TS_HOSTNAME="${TS_HOSTNAME:-openclaw}" \
```

(INGRESS_MODE is already passed; add OPENCLAW_GATEWAY_TOKEN and TS_HOSTNAME)

**Step 3: Rewrite the Python config generator**

Replace the Python heredoc content (between `python3 << 'PYEOF'` and `PYEOF`) with:

```python
import json, os, secrets
from datetime import datetime, timezone

litellm_port = os.environ.get("LITELLM_PORT", "4000")
litellm_key  = os.environ.get("LITELLM_MASTER_KEY", "sk-opendeclawed-internal")
ingress_mode = os.environ.get("INGRESS_MODE", "local")
gateway_token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", secrets.token_hex(24))
ts_hostname  = os.environ.get("TS_HOSTNAME", "openclaw")

now = datetime.now(timezone.utc).isoformat()

config = {
    "meta": {
        "lastTouchedVersion": "2026.2.14",
        "lastTouchedAt": now
    },
    "wizard": {
        "lastRunAt": now,
        "lastRunVersion": "2026.2.14",
        "lastRunCommand": "onboard",
        "lastRunMode": ingress_mode
    },
    "env": {},
    "models": {
        "providers": {
            "litellm": {
                "baseUrl": f"http://litellm:{litellm_port}/v1",
                "apiKey": litellm_key,
                "api": "openai-completions",
                "models": [
                    {
                        "id": "local/local-chat",
                        "name": "Local Chat (via LiteLLM)",
                        "contextWindow": 4096,
                        "maxTokens": 2048
                    },
                    {
                        "id": "local/local-embed",
                        "name": "Local Embed (via LiteLLM)",
                        "contextWindow": 8192,
                        "maxTokens": 512
                    }
                ]
            }
        }
    },
    "agents": {
        "defaults": {
            "model": {
                "primary": "anthropic/claude-sonnet-4-5-20250929",
                "fallbacks": [
                    "anthropic/claude-haiku-4-5-20251001"
                ]
            },
            "models": {
                "anthropic/claude-sonnet-4-5-20250929": {"alias": "Sonnet"},
                "anthropic/claude-haiku-4-5-20251001":  {"alias": "Haiku"},
                "anthropic/claude-opus-4-6":            {"alias": "Opus"}
            },
            "workspace": "/home/node/.openclaw/workspace",
            "heartbeat": {
                "every": "60m",
                "target": "last"
            },
            "sandbox": {
                "mode": "non-main",
                "scope": "agent"
            }
        }
    },
    "commands": {
        "native": "auto",
        "nativeSkills": "auto"
    },
    "gateway": {
        "port": 18789,
        "mode": ingress_mode,
        "bind": "loopback" if ingress_mode == "local" else "lan",
        "auth": {
            "mode": "token",
            "token": gateway_token
        },
        "tailscale": {
            "mode": "serve" if ingress_mode == "tailscale" else "off",
            "resetOnExit": False
        }
    }
}

# Inject Anthropic API key
api_key = os.environ.get("ANTHROPIC_API_KEY", "")
if api_key:
    config["env"]["ANTHROPIC_API_KEY"] = api_key

# Inject channel configs with secure defaults
telegram_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
discord_token  = os.environ.get("DISCORD_BOT_TOKEN", "")
discord_guild  = os.environ.get("DISCORD_GUILD_ID", "")

if telegram_token or discord_token:
    config["channels"] = {}
    config["plugins"] = {"entries": {}}

    if telegram_token:
        config["channels"]["telegram"] = {
            "enabled": True,
            "dmPolicy": "pairing",
            "botToken": telegram_token,
            "groupPolicy": "allowlist",
            "streamMode": "partial"
        }
        config["plugins"]["entries"]["telegram"] = {"enabled": True}

    if discord_token:
        discord_cfg = {
            "enabled": True,
            "token": discord_token,
            "groupPolicy": "allowlist"
        }
        if discord_guild:
            discord_cfg["guilds"] = {
                discord_guild: {"requireMention": True}
            }
        config["channels"]["discord"] = discord_cfg
        config["plugins"]["entries"]["discord"] = {"enabled": True}

# Remove empty env/plugins if nothing was set
if not config["env"]:
    del config["env"]
if "plugins" in config and not config["plugins"]["entries"]:
    del config["plugins"]

out_path = os.environ.get("OPENCLAW_JSON_PATH",
                          os.path.expanduser("~/.openclaw/openclaw.json"))
with open(out_path, "w") as f:
    json.dump(config, f, indent=2)
```

**Step 4: Invert the onboarding wizard prompt**

Replace the onboarding block (lines 838-851):

```bash
# Onboarding — config is pre-populated, wizard should not be needed.
# Offer to run it anyway in interactive mode (default: skip).
if [ "${INTERACTIVE}" = true ]; then
    echo ""
    dim "Config is fully pre-populated. The onboarding wizard is not required."
    read -rp "  Run OpenClaw onboarding wizard anyway? [y/N]: " run_onboard
    if [[ "${run_onboard}" =~ ^[Yy] ]]; then
        info "Starting onboarding wizard..."
        docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" --profile cli \
            run --rm openclaw-cli onboard --no-install-daemon \
            || warn "Onboarding exited. Re-run: docker compose --profile cli run --rm openclaw-cli onboard"
        docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" down --remove-orphans 2>/dev/null || true
    fi
fi
```

**Step 5: Validate the script syntax**

Run: `bash -n scripts/setup.sh`
Expected: exits 0 (no syntax errors)

**Step 6: Commit**

```bash
git add scripts/setup.sh
git commit -m "Generate complete openclaw.json to skip onboarding wizard

Config generator now emits meta, wizard, gateway.auth, commands, plugins,
and channel defaults. Generates a random gateway auth token saved to
.gateway-token and .env. Wizard prompt inverted to default-skip."
```

---

### Task 10: Add IP detection to setup.sh

Detect Tailscale/meshnet IPs after stack startup and print access URLs.

**Files:**
- Modify: `scripts/setup.sh:992-1009` (summary output section)

**Step 1: Add IP detection function**

Insert before the summary section (before "Setup complete" output, around line 965):

```bash
# ── Detect ingress IPs ───────────────────────────────────────────────
# Wait for mesh/tunnel containers to establish connections, then
# extract assigned IPs for the access URL summary.

detect_ingress_ip() {
    local mode="${1}"
    local max_wait=30
    local elapsed=0

    case "${mode}" in
        tailscale)
            printf "  Waiting for Tailscale to connect"
            while [ "${elapsed}" -lt "${max_wait}" ]; do
                TS_IP=$(docker exec opendeclawed-tailscale tailscale ip -4 2>/dev/null) && break
                printf "."
                sleep 2
                elapsed=$((elapsed + 2))
            done
            echo ""
            if [ -n "${TS_IP:-}" ]; then
                TS_FQDN=$(docker exec opendeclawed-tailscale tailscale status --json 2>/dev/null \
                    | python3 -c "import sys,json; print(json.load(sys.stdin)['Self']['DNSName'].rstrip('.'))" 2>/dev/null) || true
                info "Tailscale IP: ${TS_IP}"
                [ -n "${TS_FQDN:-}" ] && info "Tailscale FQDN: ${TS_FQDN}"
            else
                warn "Tailscale not connected yet. Check: docker logs opendeclawed-tailscale"
            fi
            ;;
        meshnet)
            printf "  Waiting for NordVPN meshnet"
            while [ "${elapsed}" -lt "${max_wait}" ]; do
                MESH_IP=$(docker exec opendeclawed-nordvpn nordvpn meshnet peer list 2>/dev/null \
                    | grep -oE 'Address: [0-9.]+' | head -1 | awk '{print $2}') && [ -n "${MESH_IP}" ] && break
                printf "."
                sleep 2
                elapsed=$((elapsed + 2))
            done
            echo ""
            if [ -n "${MESH_IP:-}" ]; then
                info "Meshnet IP: ${MESH_IP}"
            else
                warn "Meshnet not ready yet. Check: docker logs opendeclawed-nordvpn"
            fi
            ;;
    esac
}

# Run detection for active ingress mode
case "${INGRESS_MODE}" in
    tailscale|meshnet) detect_ingress_ip "${INGRESS_MODE}" ;;
esac
```

**Step 2: Update the summary access URLs**

Replace the static access URL block (lines 992-998) with:

```bash
echo "  Ingress: ${INGRESS_MODE}"
echo ""
case "${INGRESS_MODE}" in
    local)
        echo "  Access URLs:"
        echo "    Gateway:      http://127.0.0.1:${GATEWAY_PORT:-18789}/"
        echo "    Uptime Kuma:  http://127.0.0.1:${KUMA_PORT:-3001}/"
        echo "    Dozzle Logs:  http://127.0.0.1:${DOZZLE_PORT:-5005}/"
        ;;
    tunnel)
        TUNNEL_HOST="${CLOUDFLARE_TUNNEL_ROUTE:-openclaw.example.com}"
        echo "  Access URLs:"
        echo "    Gateway:      https://${TUNNEL_HOST}/"
        echo "    Uptime Kuma:  https://${TUNNEL_HOST}/kuma/"
        echo "    Dozzle Logs:  https://${TUNNEL_HOST}/logs/"
        ;;
    tailscale)
        BASE="${TS_FQDN:-${TS_HOSTNAME:-openclaw}.<your-tailnet>.ts.net}"
        echo "  Access URLs:"
        echo "    Gateway:      https://${BASE}/"
        echo "    Uptime Kuma:  https://${BASE}/kuma/"
        echo "    Dozzle Logs:  https://${BASE}/logs/"
        [ -n "${TS_IP:-}" ] && echo "    Tailscale IP: ${TS_IP}"
        ;;
    meshnet)
        echo "  Access URLs:"
        if [ -n "${MESH_IP:-}" ]; then
            echo "    Gateway:      https://${MESH_IP}/"
            echo "    Uptime Kuma:  https://${MESH_IP}/kuma/"
            echo "    Dozzle Logs:  https://${MESH_IP}/logs/"
            echo "    Meshnet IP:   ${MESH_IP}"
        else
            echo "    (Meshnet IP not yet available — check docker logs opendeclawed-nordvpn)"
        fi
        ;;
esac
```

**Step 3: Validate script syntax**

Run: `bash -n scripts/setup.sh`
Expected: exits 0

**Step 4: Commit**

```bash
git add scripts/setup.sh
git commit -m "Add IP detection and dashboard access URLs to setup output

Detects Tailscale IP/FQDN and NordVPN meshnet IP after stack startup
(30s timeout with spinner). Prints access URLs for gateway, Uptime Kuma,
and Dozzle for all ingress modes."
```

---

### Task 11: Update openclaw.example.json template

Update the example config to reflect the full schema.

**Files:**
- Modify: `examples/openclaw.example.json`

**Step 1: Rewrite the example config**

Replace the entire file with a template showing all fields:

```json
{
  "meta": {
    "lastTouchedVersion": "2026.2.14",
    "lastTouchedAt": "2026-01-01T00:00:00.000Z"
  },
  "wizard": {
    "lastRunAt": "2026-01-01T00:00:00.000Z",
    "lastRunVersion": "2026.2.14",
    "lastRunCommand": "onboard",
    "lastRunMode": "local"
  },
  "env": {
    "ANTHROPIC_API_KEY": "sk-ant-REPLACE_ME"
  },
  "models": {
    "providers": {
      "litellm": {
        "baseUrl": "http://litellm:4000/v1",
        "apiKey": "sk-opendeclawed-internal",
        "api": "openai-completions",
        "models": [
          {
            "id": "local/local-chat",
            "name": "Local Chat (via LiteLLM)",
            "contextWindow": 4096,
            "maxTokens": 2048
          },
          {
            "id": "local/local-embed",
            "name": "Local Embed (via LiteLLM)",
            "contextWindow": 8192,
            "maxTokens": 512
          }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "anthropic/claude-sonnet-4-5-20250929",
        "fallbacks": [
          "anthropic/claude-haiku-4-5-20251001"
        ]
      },
      "models": {
        "anthropic/claude-sonnet-4-5-20250929": { "alias": "Sonnet" },
        "anthropic/claude-haiku-4-5-20251001":  { "alias": "Haiku" },
        "anthropic/claude-opus-4-6":            { "alias": "Opus" }
      },
      "workspace": "/home/node/.openclaw/workspace",
      "heartbeat": {
        "every": "60m",
        "target": "last"
      },
      "sandbox": {
        "mode": "non-main",
        "scope": "agent"
      }
    }
  },
  "commands": {
    "native": "auto",
    "nativeSkills": "auto"
  },
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "REPLACE_ME_WITH_RANDOM_HEX"
    },
    "tailscale": {
      "mode": "off",
      "resetOnExit": false
    }
  },
  "channels": {
    "telegram": {
      "enabled": false,
      "dmPolicy": "pairing",
      "botToken": "",
      "groupPolicy": "allowlist",
      "streamMode": "partial"
    },
    "discord": {
      "enabled": false,
      "token": "",
      "groupPolicy": "allowlist"
    }
  },
  "plugins": {
    "entries": {
      "telegram": { "enabled": false },
      "discord": { "enabled": false }
    }
  }
}
```

**Step 2: Commit**

```bash
git add examples/openclaw.example.json
git commit -m "Update example config to show full schema with all fields

Adds meta, wizard, gateway.auth, commands, plugins, channel defaults,
and workspace path to match what setup.sh now generates."
```

---

### Task 12: Add logo to README

**Files:**
- Modify: `README.md:1-3` (add logo above title)

**Step 1: Add logo image**

Insert at the very top of README.md, before the `# OpenDeclawed` heading:

```markdown
<p align="center">
  <img src="images/opendeclawed.png" alt="OpenDeclawed" width="200">
</p>

# OpenDeclawed
```

**Step 2: Update deployment modes list**

In the "Multiple Deployment Modes" section (around line 22-26), add the meshnet and tailscale entries:

```markdown
  - **Tailscale** (--profile tailscale): Tailscale mesh VPN, WireGuard-based, ACL-controlled
  - **Meshnet** (--profile meshnet): NordVPN Meshnet, peer-to-peer, no public DNS
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "Add logo to README and document meshnet/tailscale modes"
```

---

## Execution Order

Tasks 1-3 (network + proxy updates) can be done in parallel. Tasks 4-6 (NordVPN container files) can be done in parallel. Task 7 depends on 4-6. Tasks 8-12 are independent of each other but 9-10 both modify setup.sh so should be sequential.

Recommended sequence:
1. Task 1 (Kuma/Dozzle egress network)
2. Task 2 (Tailscale Serve update)
3. Task 3 (Cloudflare Tunnel update)
4. Tasks 4, 5, 6 in parallel (NordVPN Dockerfile, entrypoint, Caddyfile)
5. Task 7 (compose services)
6. Task 8 (.env.example)
7. Task 9 (wizard skip)
8. Task 10 (IP detection)
9. Task 11 (example config)
10. Task 12 (README logo)

Final validation: `docker compose config > /dev/null` with all profiles enabled.
