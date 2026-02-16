# Design: Meshnet Wiring, Dashboard Proxying, Wizard Skip & IP Detection

**Date**: 2026-02-16
**Status**: Approved

## Overview

Three interconnected changes to OpenDeclawed:

1. **NordVPN Meshnet container** — new compose service (profile: `meshnet`) with Caddy TLS proxy
2. **Unified dashboard proxying** — all three ingress methods (Cloudflare Tunnel, Tailscale, NordVPN Meshnet) proxy gateway + Uptime Kuma + Dozzle
3. **Wizard skip** — setup.sh generates a complete `openclaw.json` so OpenClaw's onboarding wizard has nothing to prompt for
4. **IP detection** — setup.sh detects mesh/tailscale IPs after startup and prints access URLs

## Principles

- Dashboards (Kuma, Dozzle) must NOT be internet-accessible. Only reachable via private ingress (Tailscale, Meshnet, or Cloudflare Tunnel with Access policies).
- Meshnet traffic is inbound only — from user devices to dashboards.
- Regular container internet access goes through the existing egress-firewall, not through NordVPN.
- All ingress methods are optional profiles; local mode (127.0.0.1) remains the default.

## 1. NordVPN Meshnet Container

### Container: `nordvpn-meshnet`

- **Base**: Debian slim (NordVPN CLI only ships .deb packages)
- **Image**: Custom Dockerfile at `nordvpn/Dockerfile`
- **Profile**: `meshnet`
- **Network**: `openclaw-meshnet` only (isolated, no access to egress or internal networks)
- **Capabilities**: `NET_ADMIN`, `NET_RAW` (required for WireGuard tunnel)
- **Hardening**: `read_only: true`, `cap_drop: ALL` (then add back NET_ADMIN/NET_RAW), `no-new-privileges`, tmpfs with noexec
- **Volume**: `nordvpn-state` for persistent auth/meshnet state
- **Entrypoint** (`nordvpn/entrypoint.sh`):
  1. Login with `NORDVPN_TOKEN`
  2. `nordvpn set meshnet on`
  3. `nordvpn set mesh-receive on`
  4. Set up iptables DNAT: forward meshnet-ip:443 to caddy's IP on openclaw-meshnet
  5. Health loop (sleep infinity)
- **Healthcheck**: `nordvpn meshnet peer list` exits 0

### Container: `meshnet-caddy`

- **Image**: `caddy:alpine`
- **Profile**: `meshnet`
- **Networks**: `openclaw-meshnet` + `openclaw-egress` (bridges the two)
- **Hardening**: `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, tmpfs
- **Config**: `nordvpn/Caddyfile.template` with reverse proxy routes
- **Depends on**: `nordvpn-meshnet` (healthy), `openclaw-gateway` (healthy)

### Network: `openclaw-meshnet`

- `internal: true` (no internet access)
- Dedicated subnet (e.g. `172.29.0.0/24`)
- Only `nordvpn-meshnet` and `meshnet-caddy` live here

### Network isolation

```
Meshnet peers (your devices)
    |
    v (WireGuard tunnel, inbound only)
+---------------------------+
|  nordvpn-meshnet          |
|  network: openclaw-meshnet|  <-- only meshnet network, no egress
|  iptables DNAT :443 ------+--> caddy on openclaw-meshnet
+---------------------------+

+---------------------------+
|  meshnet-caddy            |
|  networks:                |
|    openclaw-meshnet  <----+-- receives forwarded traffic from nordvpn
|    openclaw-egress   -----+--> proxies to gateway:18789, kuma:3001, dozzle:5005
+---------------------------+
```

No other container on openclaw-egress can reach meshnet peers (nordvpn isn't on egress). Caddy is the sole bridge.

### Caddy routes (all ingress methods use the same path layout)

| Path | Backend | Port |
|------|---------|------|
| `/` | openclaw-gateway | 18789 |
| `/kuma/*` | uptime-kuma | 3001 |
| `/logs/*` | dozzle | 5005 |

Self-signed TLS by default. User can configure a domain for Let's Encrypt.

## 2. Unified Dashboard Proxying

All three ingress methods proxy the same three services with identical paths.

### Cloudflare Tunnel

Replace `tunnel run --token` with a local config file approach. Generate `cloudflared/config.yml` in setup.sh:

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/credentials.json
ingress:
  - hostname: <CLOUDFLARE_TUNNEL_ROUTE>
    path: /kuma/*
    service: http://uptime-kuma:3001
  - hostname: <CLOUDFLARE_TUNNEL_ROUTE>
    path: /logs/*
    service: http://dozzle:5005
  - hostname: <CLOUDFLARE_TUNNEL_ROUTE>
    service: http://openclaw-gateway:18789
  - service: http_status:404
```

Cloudflare Access policies gate authorization (zero-trust layer, configured in Cloudflare dashboard).

Note: Cloudflare's token-based tunnel run may not support multi-service ingress inline. If so, we switch to named tunnel with a config file. Investigate during implementation.

### Tailscale Serve

Update the Tailscale Serve config JSON to proxy all three paths (currently only does `/`):

```json
{
  "TCP": { "443": { "HTTPS": true } },
  "Web": {
    "<hostname>.<tailnet>:443": {
      "Handlers": {
        "/":      { "Proxy": "http://openclaw-gateway:18789" },
        "/kuma/": { "Proxy": "http://uptime-kuma:3001" },
        "/logs/": { "Proxy": "http://dozzle:5005" }
      }
    }
  }
}
```

Tailscale container needs access to kuma and dozzle. Both are on `openclaw-egress` (via monitor profile), so Tailscale's existing `openclaw-egress` membership is sufficient.

### Dozzle and Kuma sub-path configuration

- **Dozzle**: Set `DOZZLE_BASE=/logs` env var for sub-path hosting
- **Uptime Kuma**: May need `--webpath=/kuma` or similar. Investigate exact flag during implementation. If Kuma doesn't support sub-path natively, Caddy/Tailscale Serve can strip the prefix.

## 3. Wizard Skip (Full Config Generation)

### Missing fields to add to setup.sh Python config generator

```python
config["meta"] = {
    "lastTouchedVersion": version_string,  # detect or hardcode
    "lastTouchedAt": datetime.now(timezone.utc).isoformat()
}

config["wizard"] = {
    "lastRunAt": config["meta"]["lastTouchedAt"],
    "lastRunVersion": config["meta"]["lastTouchedVersion"],
    "lastRunCommand": "onboard",
    "lastRunMode": ingress_mode
}

config["gateway"] = {
    "port": 18789,
    "mode": ingress_mode,
    "bind": "loopback" if ingress_mode == "local" else "lan",
    "auth": {
        "mode": "token",
        "token": secrets.token_hex(24)
    },
    "tailscale": {
        "mode": "serve" if ingress_mode == "tailscale" else "off",
        "resetOnExit": False
    }
}

config["commands"] = {"native": "auto", "nativeSkills": "auto"}

config["agents"]["defaults"]["workspace"] = "/home/node/.openclaw/workspace"
```

### Channel defaults (when configured)

```python
# Telegram
"dmPolicy": "pairing",
"groupPolicy": "allowlist",
"streamMode": "partial"

# Discord
"groupPolicy": "allowlist"
```

### Plugins block (when channels configured)

```python
config["plugins"] = {"entries": {}}
if telegram_token:
    config["plugins"]["entries"]["telegram"] = {"enabled": True}
if discord_token:
    config["plugins"]["entries"]["discord"] = {"enabled": True}
```

### Gateway auth token

- Generated with `secrets.token_hex(24)`
- Saved to `~/.openclaw/.gateway-token` (mode 600)
- Saved to `.env` as `OPENCLAW_GATEWAY_TOKEN`
- Injected into `gateway.auth.token` in openclaw.json

### Onboarding prompt change

- Non-interactive mode: skip wizard entirely (config is complete)
- Interactive mode: invert the default — "Config is pre-populated. Run wizard anyway? [y/N]:"
- Also investigate `--skip-onboard` or similar CLI flag for belt-and-suspenders

## 4. IP Detection (Setup Script Output)

### Detection logic (after docker-compose up, in Step 11)

**Tailscale**:
```bash
TS_IP=$(docker exec opendeclawed-tailscale tailscale ip -4)
TS_FQDN=$(docker exec opendeclawed-tailscale tailscale status --json | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['Self']['DNSName'].rstrip('.'))")
```

**NordVPN Meshnet**:
```bash
MESH_IP=$(docker exec opendeclawed-nordvpn nordvpn meshnet peer list | \
  grep -oE 'IP: [0-9.]+' | head -1 | cut -d' ' -f2)
```

### Timeout handling

Wait up to 30s with a spinner for IP detection. If not available, print fallback message directing user to check `docker logs`.

### Output format

```
  Ingress: tailscale

  Access URLs:
    Gateway:      https://openclaw.tail1234.ts.net/
    Uptime Kuma:  https://openclaw.tail1234.ts.net/kuma/
    Dozzle Logs:  https://openclaw.tail1234.ts.net/logs/
    Tailscale IP: 100.64.x.x
```

```
  Ingress: meshnet

  Access URLs:
    Gateway:      https://<meshnet-ip>/
    Uptime Kuma:  https://<meshnet-ip>/kuma/
    Dozzle Logs:  https://<meshnet-ip>/logs/
    Meshnet IP:   10.x.x.x
```

```
  Ingress: tunnel

  Access URLs:
    Gateway:      https://openclaw.example.com/
    Uptime Kuma:  https://openclaw.example.com/kuma/
    Dozzle Logs:  https://openclaw.example.com/logs/
```

Local mode stays as `http://127.0.0.1:18789/` with localhost URLs for kuma/dozzle.

## Files to create/modify

### New files
- `nordvpn/Dockerfile` — Debian slim + NordVPN CLI
- `nordvpn/entrypoint.sh` — Login, meshnet enable, iptables DNAT, health loop
- `nordvpn/Caddyfile.template` — Reverse proxy config

### Modified files
- `docker-compose.yml` — Add nordvpn-meshnet, meshnet-caddy services; add openclaw-meshnet network; add nordvpn-state volume; update Tailscale Serve config; update Dozzle DOZZLE_BASE env
- `scripts/setup.sh` — Expand Python config generator (Step 7); add IP detection (Step 11); invert wizard prompt; generate cloudflared config for multi-service routing
- `.env.example` — Add MESHNET_SUBNET, NORDVPN_IMAGE, CADDY_IMAGE vars; document new env vars
- `examples/openclaw.example.json` — Update template to show full schema with new fields
