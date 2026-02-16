# OpenDeclawed — Complete Setup Guide

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Ingress Option A: Cloudflare Tunnel + GitHub OAuth](#ingress-option-a-cloudflare-tunnel--github-oauth)
4. [Ingress Option B: NordVPN Meshnet](#ingress-option-b-nordvpn-meshnet)
5. [Dedicated Gmail Account Setup](#dedicated-gmail-account)
6. [Container Image Hardening](#container-image-hardening)
7. [Messaging Integration: Telegram](#messaging-telegram)
8. [Messaging Integration: Discord](#messaging-discord)
9. [Messaging Integration: WhatsApp](#messaging-whatsapp)
10. [Additional Security Hardening](#additional-security-hardening)
11. [Operational Security Checklist](#operational-security-checklist)
12. [Maintenance & Monitoring](#maintenance--monitoring)

---

## Architecture Overview

```
                     ┌──────────────────────────────────────┐
                     │         YOUR ACCESS OPTIONS          │
                     ├──────────────────────────────────────┤
                     │  Option A: Cloudflare Tunnel         │
                     │    Internet → CF Edge → GitHub OAuth │
                     │    → cloudflared → gateway           │
                     │                                      │
                     │  Option B: NordVPN Meshnet           │
                     │    Your device → Meshnet P2P tunnel  │
                     │    → nordvpn container → gateway     │
                     │    (never touches public internet)   │
                     └──────────┬───────────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │      openclaw-egress network                │
         │  ┌────────────┐  ┌──────────────────────┐   │
         │  │ cloudflared │  │  openclaw-gateway    │   │
         │  │ OR nordvpn  │  │  (Anthropic API out) │   │
         │  └────────────┘  └──────────┬───────────┘   │
         │                             │               │
         │  egress-firewall: persistent sidecar         │
         │  (60s loop, survives Docker restarts)       │
         │  blocky: DNS firewall (threat blocklists)   │
         └─────────────────────────────┼───────────────┘
                                       │
         ┌─────────────────────────────┼───────────────┐
         │  openclaw-internal (no internet)            │
         │  ┌────────────┐  ┌────────────┐             │
         │  │ llama-embed │  │ llama-chat │             │
         │  │ (embeddings)│  │ (light LLM)│             │
         │  └────────────┘  └────────────┘             │
         └─────────────────────────────────────────────┘
```

---

## Prerequisites

- macOS with OrbStack installed (https://orbstack.dev)
- Docker Compose V2 (included with OrbStack)
- ~10GB disk for models + containers
- An Anthropic API key OR Claude Pro/Max subscription
- A domain on Cloudflare (Option A) OR NordVPN subscription (Option B)

---

## Ingress Option A: Cloudflare Tunnel + GitHub OAuth

This is the "internet-accessible" option. Cloudflare handles DDoS, WAF, and authentication at their edge before any traffic touches your machine. Zero ports exposed on your host.

### Step 1: Create a Cloudflare Tunnel

1. Go to https://one.dash.cloudflare.com
2. **Networks → Tunnels → Create a tunnel**
3. Connector type: **Cloudflared**
4. Name: `openclaw-prod`
5. Copy the **Tunnel Token** (long base64 string)
6. Add a **Public Hostname** route:
   - Subdomain: `openclaw` (or your preference)
   - Domain: `yourdomain.com`
   - Service type: **HTTP**
   - URL: `openclaw-gateway:18789`

### Step 2: Add GitHub as Identity Provider

1. **Create a GitHub OAuth App:**
   - Go to https://github.com/settings/developers
   - Click **New OAuth App**
   - Application name: `OpenClaw Access`
   - Homepage URL: `https://openclaw.yourdomain.com`
   - Authorization callback URL: `https://<YOUR-TEAM>.cloudflareaccess.com/cdn-cgi/access/callback`
   - Copy the **Client ID** and **Client Secret**

2. **Configure Cloudflare Access:**
   - In Zero Trust dashboard: **Settings → Authentication → Login methods**
   - Click **Add new → GitHub**
   - Paste Client ID + Client Secret from GitHub
   - Save and test

### Step 3: Create an Access Application

1. **Access → Applications → Add an application**
2. Type: **Self-hosted**
3. Application domain: `openclaw.yourdomain.com`
4. Create a policy:
   - Name: `github-only`
   - Action: **Allow**
   - Include → Login Methods → **GitHub**
   - (Recommended) Add a second rule: Require → Emails ending in `@yourdomain.com` or specific GitHub usernames
5. Session duration: **24 hours** (forces re-auth daily)
6. Save

### Step 4: Run the setup script

```bash
chmod +x setup.sh && ./setup.sh
```

The script will prompt for your tunnel token and configure everything.

---

## Ingress Option B: NordVPN Meshnet

This is the "private access" option. Your OpenClaw instance gets its own Meshnet IP address, accessible only from your other NordVPN Meshnet devices. Traffic never touches the public internet — it's a direct P2P encrypted tunnel between your devices.

### Why this is arguably more secure than Cloudflare

- **Zero public attack surface**: No DNS record, no public hostname, nothing to discover or probe
- **No third-party trust**: Traffic doesn't flow through Cloudflare's infrastructure
- **P2P encrypted**: NordLynx (WireGuard) directly between your devices
- **IP masking**: OpenClaw's outbound API calls exit through NordVPN, not your home IP
- **No authentication layer needed**: Only your Meshnet peers can reach it at all

### Why Cloudflare may still be better

- **Mobile access**: Meshnet requires NordVPN running on every client device
- **Sharing**: Can't easily give someone else access without adding them to your Meshnet
- **Uptime**: If your home network goes down, Cloudflare can show a friendly error page; Meshnet just fails silently

### Setup: NordVPN Meshnet in Docker

Replace the `cloudflared` service in `docker-compose.yml` with:

```yaml
  # =========================================================================
  # NordVPN Meshnet — P2P encrypted access, replaces Cloudflare Tunnel
  # =========================================================================
  nordvpn:
    image: ghcr.io/bubuntux/nordvpn:latest
    container_name: nordvpn-meshnet
    restart: unless-stopped
    networks:
      - openclaw-egress
    cap_add:
      - NET_ADMIN               # required for VPN tunnel creation
      - NET_RAW                 # required for NordLynx
      - SYS_MODULE              # required for WireGuard kernel module
    sysctls:
      - net.ipv6.conf.all.disable_ipv6=1   # prevent IPv6 leaks
    environment:
      - TOKEN=${NORDVPN_TOKEN}              # NordVPN service token
      - MESHNET=1                           # enable Meshnet
      - CONNECT=1                           # connect to VPN on start
      - TECHNOLOGY=NordLynx                 # WireGuard-based protocol
      - DNS=1.1.1.1,9.9.9.9                # non-Nord DNS for container resolution
      - ALLOWLIST_PORTS=18789               # only expose gateway port via Meshnet
      - LAN_DISCOVERY=off                   # prevent LAN discovery
      - FIREWALL=on
      - KILLSWITCH=on                       # block all traffic if VPN drops
    # Note: nordvpn container needs more privileges than cloudflared
    # because it creates actual network tunnel interfaces
    mem_limit: 512m
    cpus: "1.0"
    pids_limit: 64
    security_opt:
      - no-new-privileges:true
    depends_on:
      egress-firewall:
        condition: service_started
      openclaw-gateway:
        condition: service_healthy
```

Then modify `openclaw-gateway` to route through NordVPN:

```yaml
  openclaw-gateway:
    # ... keep all existing config ...
    # ADD: route through NordVPN for outbound traffic
    network_mode: "service:nordvpn"  # share NordVPN's network namespace
    # REMOVE: the separate networks config when using network_mode
    depends_on:
      - nordvpn
      - llama-embed
      - llama-chat
```

**Important**: When using `network_mode: "service:nordvpn"`, the gateway shares NordVPN's network stack. All outbound traffic (including Anthropic API calls) exits through the VPN. Your home IP is never exposed to Anthropic.

### Getting your NordVPN token

1. Log in at https://my.nordaccount.com
2. Go to **Services → NordVPN**
3. Under **Access Token**, generate a new token
4. Add to your `.env`: `NORDVPN_TOKEN=<token>`

### Accessing via Meshnet

After the container starts:

```bash
# Get the Meshnet hostname
docker exec nordvpn-meshnet nordvpn meshnet peer list
```

Your OpenClaw instance will be accessible at `http://<meshnet-hostname>:18789` from any device in your Meshnet. On your phone, just have NordVPN running with Meshnet enabled.

---

## Dedicated Gmail Account

**Why**: You don't want OpenClaw sending emails from or authenticated as your personal account. A dedicated account provides identity isolation, limits blast radius if compromised, and gives you a clean audit trail.

### Step 1: Create a dedicated Google account

1. Go to https://accounts.google.com/signup
2. Create: `yourname.openclaw@gmail.com` (or similar)
3. **DO NOT** link it to your personal account or recovery email initially
4. Enable 2FA immediately (use a hardware key if you have one)

### Step 2: Generate an App Password

1. Go to https://myaccount.google.com/apppasswords (on the new account)
2. App: **Mail**, Device: **Other** → name it `openclaw`
3. Copy the 16-character app password
4. Store it in `~/.openclaw/openclaw.json` under a mail provider config

### Step 3: Configure OpenClaw for email

Add to your `openclaw.json`:

```json
{
  "email": {
    "smtp": {
      "host": "smtp.gmail.com",
      "port": 465,
      "secure": true,
      "auth": {
        "user": "yourname.openclaw@gmail.com",
        "pass": "<APP_PASSWORD>"
      }
    },
    "from": "yourname.openclaw@gmail.com"
  }
}
```

### Step 4: Lock down the Gmail account

- **Forwarding**: Disable all forwarding rules
- **Less secure apps**: Keep disabled (app passwords bypass this)
- **Recovery**: Set recovery phone to your real phone, but NOT your personal email
- **Filters**: Create a filter to auto-archive sent items older than 30 days
- **Google Workspace**: If budget allows, use a Workspace account on your domain instead — gives you SPF/DKIM/DMARC control

---

## Container Image Hardening

Beyond the runtime hardening already in our docker-compose, here's what you can do at the image level.

### 1. Pin images by digest (not tag)

Tags are mutable. Someone could push a compromised image to `alpine/openclaw:latest`. Pin by SHA256 digest:

```bash
# Get the current digest
docker pull alpine/openclaw:latest
docker inspect --format='{{index .RepoDigests 0}}' alpine/openclaw:latest
# Output: alpine/openclaw@sha256:abc123...

# Use in docker-compose.yml
image: alpine/openclaw@sha256:abc123def456...
```

Do this for every image: `cloudflare/cloudflared`, `ghcr.io/ggml-org/llama.cpp:server`, `alpine:3.20`.

### 2. Scan images with Trivy before deployment

```bash
# Install Trivy
brew install trivy

# Scan for HIGH and CRITICAL vulnerabilities
trivy image --severity HIGH,CRITICAL alpine/openclaw:latest
trivy image --severity HIGH,CRITICAL ghcr.io/ggml-org/llama.cpp:server
trivy image --severity HIGH,CRITICAL cloudflare/cloudflared:latest

# Fail on any critical
trivy image --exit-code 1 --severity CRITICAL alpine/openclaw:latest
```

Add this as a pre-deployment step in your workflow. Don't deploy images with CRITICAL CVEs.

### 3. Verify image signatures with Cosign

```bash
# Install Cosign
brew install cosign

# Verify Cloudflare's image (if signed)
cosign verify cloudflare/cloudflared:latest

# For images that publish SBOMs
cosign verify-attestation --type spdxjson alpine/openclaw:latest
```

### 4. Generate SBOMs

```bash
# Install Syft
brew install syft

# Generate SBOM for each image
syft alpine/openclaw:latest -o spdx-json > sbom-openclaw.json
syft ghcr.io/ggml-org/llama.cpp:server -o spdx-json > sbom-llama.json
```

Keep these in version control. If a new CVE drops, you can immediately check if you're affected without pulling images.

### 5. Use Docker Hardened Images (DHI) where available

Docker launched open-source hardened images in 2025. Check if any of your base images have DHI equivalents:

```bash
# Check Docker Hub for hardened variants
docker search --format "{{.Name}}" openclaw | grep hardened
```

### 6. Custom seccomp profile (advanced)

The default Docker seccomp profile blocks ~44 dangerous syscalls. You can make it stricter:

```bash
# Generate the default profile
docker run --rm alpine cat /etc/docker/seccomp.json > custom-seccomp.json
```

Edit to additionally block: `mount`, `umount`, `pivot_root`, `reboot`, `settimeofday`, `sethostname`, `keyctl`.

Apply in docker-compose:

```yaml
security_opt:
  - no-new-privileges:true
  - seccomp:custom-seccomp.json
```

---

## Messaging: Telegram

Telegram is the easiest channel to set up. It uses the official Bot API — no scraping, no QR codes, no phone numbers.

### Step 1: Create a Telegram bot

1. Open Telegram and message **@BotFather**
2. Send `/newbot`
3. Choose a name: `OpenClaw Assistant`
4. Choose a username: `yourname_openclaw_bot` (must end in `bot`)
5. Copy the **bot token** (format: `123456789:ABCdefGHIjklMNOpqrSTUvwxyz`)

### Step 2: Lock down the bot

Message @BotFather again:
- `/setjoingroups` → Disable (prevents adding to random groups)
- `/setprivacy` → Enable (bot only sees messages directed at it in groups)
- `/setcommands` → Set relevant commands

### Step 3: Configure in OpenClaw

During onboarding, select Telegram when prompted. Or add manually to `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "telegram": {
      "enabled": true,
      "botToken": "<BOT_TOKEN>",
      "dmPolicy": "pairing",
      "allowFrom": []
    }
  }
}
```

### Step 4: Pair your account

After starting the stack, message your bot on Telegram. It will respond with a pairing code. Approve it:

```bash
docker compose run --rm --profile cli openclaw-cli pairing approve telegram <CODE>
```

### Security notes for Telegram

- The bot token is equivalent to a password — treat it as a secret
- `dmPolicy: "pairing"` means strangers who find your bot get a pairing code prompt (not access)
- Never set `dmPolicy: "open"` — this lets anyone with your bot's username talk to your AI agent
- The bot communicates via HTTPS to Telegram's API servers (outbound only, no webhooks needed)

---

## Messaging: Discord

### Step 1: Create a Discord application + bot

1. Go to https://discord.com/developers/applications
2. Click **New Application** → name it `OpenClaw`
3. Go to **Bot** tab → Click **Add Bot**
4. Copy the **Bot Token**
5. Under **Privileged Gateway Intents**, enable:
   - **Message Content Intent** (required to read messages)
   - **Server Members Intent** (optional, for user resolution)

### Step 2: Invite bot to your server

1. Go to **OAuth2 → URL Generator**
2. Scopes: `bot`, `applications.commands`
3. Bot Permissions: `Send Messages`, `Read Message History`, `View Channels`, `Embed Links`, `Attach Files`
4. Copy the generated URL and open it in your browser
5. Select your server and authorize

### Step 3: Get your Guild (Server) ID

1. In Discord: **Settings → Advanced → Enable Developer Mode**
2. Right-click your server name → **Copy Server ID**

### Step 4: Configure in OpenClaw

```json
{
  "channels": {
    "discord": {
      "enabled": true,
      "botToken": "<BOT_TOKEN>",
      "guildId": "<GUILD_ID>",
      "dmPolicy": "pairing",
      "allowFrom": []
    }
  }
}
```

### Step 5: Pair

Message the bot in Discord. Approve the pairing code:

```bash
docker compose run --rm --profile cli openclaw-cli pairing approve discord <CODE>
```

### Security notes for Discord

- Create a **private server** for your OpenClaw bot — don't add it to public servers
- The bot token grants full access to the bot — store securely
- Discord bot tokens don't expire by default — rotate manually if compromised
- `dmPolicy: "pairing"` is critical here since Discord bots are publicly discoverable

---

## Messaging: WhatsApp

WhatsApp is the most complex channel. It uses the Baileys library (reverse-engineered WhatsApp Web protocol), not an official API.

### Step 1: Get a dedicated phone number

**CRITICAL: Never use your personal WhatsApp number.** If WhatsApp detects automation, they may ban the number.

Options:
- Buy a cheap prepaid SIM ($5-10)
- Use a Google Voice number (US only)
- Use a VoIP number (Twilio, etc.)

Register this number with WhatsApp on a spare phone or WhatsApp Business.

### Step 2: Configure in OpenClaw

```json
{
  "channels": {
    "whatsapp": {
      "enabled": true,
      "selfChatMode": true,
      "dmPolicy": "pairing",
      "allowFrom": ["+1234567890"]
    }
  }
}
```

`selfChatMode: true` lets you interact by messaging yourself (the dedicated number) from your personal WhatsApp.

### Step 3: Link device via QR code

When OpenClaw starts with WhatsApp enabled, it displays a QR code in the logs:

```bash
docker compose logs -f openclaw-gateway
```

On the phone with the dedicated number:
1. Open WhatsApp → **Settings → Linked Devices → Link a Device**
2. Scan the QR code from the terminal

### Step 4: Pair your personal number

Add your personal phone number to `allowFrom` in the config, then message the dedicated number from your personal WhatsApp. Approve the pairing:

```bash
docker compose run --rm --profile cli openclaw-cli pairing approve whatsapp <CODE>
```

### Security notes for WhatsApp

- WhatsApp sessions expire if the linked device is inactive for ~14 days — you may need to re-scan
- The Baileys library stores session keys in `~/.openclaw/` — protect this directory (already mode 700)
- WhatsApp may flag automated accounts — keep message volume reasonable
- `allowFrom` acts as a whitelist — only listed numbers can interact
- End-to-end encryption is maintained (Baileys uses the Signal Protocol)

---

## Additional Security Hardening

### 1. Filesystem integrity monitoring

Add a read-only hash of your config files:

```bash
# After setup, create a baseline
sha256sum ~/.openclaw/openclaw.json > ~/.openclaw/.config-checksum
sha256sum docker-compose.yml >> ~/.openclaw/.config-checksum
sha256sum .env >> ~/.openclaw/.config-checksum

# Check for tampering (add to a cron job)
sha256sum -c ~/.openclaw/.config-checksum
```

### 2. Log forwarding

Docker logs should go somewhere persistent. Add to your docker-compose:

```yaml
# Add to any service
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
    tag: "openclaw-{{.Name}}"
```

Review logs regularly for unexpected outbound connections or auth failures.

### 3. DNS-over-HTTPS via blocky

The `blocky` DNS firewall handles this automatically. All container DNS queries go through blocky, which forwards them to Cloudflare DNS and Quad9 via DNS-over-HTTPS. No plaintext DNS leaves your network. See section 5 below for full blocky configuration.

If you need to customize Docker-level DNS as well (e.g., for containers outside this stack), add to OrbStack's Docker daemon config (`~/.orbstack/config/docker.json`):

```json
{
  "dns": ["1.1.1.1", "9.9.9.9"]
}
```

### 4. Automatic image updates with Watchtower (via socket proxy)

Watchtower auto-updates container images, but mounting `/var/run/docker.sock` directly is root-equivalent access. Instead, we route it through a least-privilege Docker socket proxy (tecnativa) that only exposes the API endpoints Watchtower needs:

```yaml
  docker-socket-proxy:
    image: tecnativa/docker-socket-proxy:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      - CONTAINERS=1    # List/inspect containers
      - IMAGES=1        # Pull images
      - VERSION=1       # API version check
      - EVENTS=1        # Watch for changes
      - POST=1          # Restart containers
      - EXEC=0          # DENIED: no exec into containers
      - VOLUMES=0       # DENIED: no volume access
      - NETWORKS=0      # DENIED: no network changes
      - SECRETS=0       # DENIED: no secret access

  watchtower:
    image: containrrr/watchtower
    environment:
      - DOCKER_HOST=tcp://docker-socket-proxy:2375
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_SCHEDULE=0 0 4 * * *
      - WATCHTOWER_LABEL_ENABLE=true
    # No docker.sock mount — communicates via proxy only
```

Add `com.centurylinklabs.watchtower.enable=true` label to containers you want auto-updated. The proxy blocks dangerous operations (exec, volumes, networks, secrets) even if Watchtower is compromised.

### 5. DNS firewall with blocky

The `blocky` DNS firewall filters all container DNS queries against threat intelligence blocklists (malware, phishing, C2, cryptomining). Upstream resolvers use DNS-over-HTTPS for privacy.

Configuration is in `examples/blocky-config.yml`. Key features:
- **Blocklists**: StevenBlack/hosts, URLhaus, PhishingArmy, FireBog RPiList, CoinBlockerLists
- **Allowlist**: Legitimate API domains (Anthropic, VirusTotal, Telegram, Discord, Cloudflare, HuggingFace, GitHub)
- **DoH upstream**: Cloudflare DNS + Quad9 — no plaintext DNS leaks to your ISP
- **Query logging**: 7-day retention for forensic analysis
- **4-hour refresh**: Blocklists auto-update

```bash
# Copy blocky config to its volume
mkdir -p ~/.openclaw/blocky
cp examples/blocky-config.yml ~/.openclaw/blocky/config.yml
```

### 6. Restrict Docker socket access

If you're paranoid about Docker socket exposure (and you should be), ensure:

```bash
# Docker socket should be root:docker only
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 ... /var/run/docker.sock

# Your user should be in the docker group — but nothing else
groups $(whoami)
```

With the socket proxy in place, only the proxy container has direct socket access — Watchtower and all other services communicate through the filtered API.

### 7. macOS-level hardening

Since this runs on your Mac via OrbStack:

- Enable **FileVault** (full-disk encryption) — protects config files at rest
- Enable **Firewall** in System Settings → Network → Firewall
- Set **Stealth Mode** (don't respond to ICMP/pings from unrecognized devices)
- Review **Login Items** — remove anything unnecessary
- Keep macOS updated — OrbStack's VM inherits host kernel patches

### 8. Network segmentation (if your router supports it)

If you have a prosumer router (UniFi, pfSense, OPNsense, MikroTik):

- Put your OpenClaw host on a **dedicated VLAN**
- Firewall rules: allow outbound HTTPS (443) only, deny all inbound, deny LAN-to-LAN
- This provides defense-in-depth even if the Docker egress firewall fails

---

## Operational Security Checklist

### Pre-deployment

- [ ] OrbStack installed and updated
- [ ] FileVault enabled on Mac
- [ ] Dedicated Gmail account created with 2FA
- [ ] Dedicated phone number for WhatsApp (not personal)
- [ ] Anthropic API key generated with minimal permissions
- [ ] All images scanned with Trivy (zero CRITICAL CVEs)
- [ ] Images pinned by SHA256 digest in docker-compose.yml

### Post-deployment

- [ ] `docker compose ps` shows no host port mappings (Cloudflare mode)
- [ ] `docker exec openclaw-gateway wget --timeout=3 http://192.168.1.1/` FAILS (firewall working)
- [ ] `docker exec openclaw-gateway wget --timeout=3 http://10.0.0.1/` FAILS
- [ ] `openclaw doctor` reports no issues
- [ ] DM policy is `pairing` (not `open`)
- [ ] Elevated access is `false`
- [ ] Telemetry is disabled
- [ ] All secret files are mode 600
- [ ] Config directory is mode 700
- [ ] Cloudflare Access or Meshnet access tested from external device
- [ ] Messaging channels paired and working
- [ ] Config file checksums recorded

### Monthly maintenance

- [ ] Run `trivy image` on all images
- [ ] Check for OpenClaw updates: `docker compose pull`
- [ ] Review Docker logs for anomalies
- [ ] Rotate Anthropic API key
- [ ] Rotate gateway token
- [ ] Verify config file checksums
- [ ] Check WhatsApp session hasn't expired
- [ ] Review Cloudflare Access logs for unauthorized attempts

---

## Maintenance & Monitoring

### Useful commands

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs -f openclaw-gateway

# Check resource usage
docker stats

# Run OpenClaw health check
docker compose run --rm --profile cli openclaw-cli doctor

# Check firewall rules are active
docker run --rm --net host alpine sh -c "apk add iptables && iptables -L DOCKER-USER -v -n"

# Restart after config change
docker compose down && docker compose up -d

# Full teardown (preserves volumes)
docker compose down

# Nuclear teardown (destroys everything)
docker compose down -v
```

### If something breaks

1. **Gateway won't start**: Check `docker compose logs openclaw-gateway` — likely a config JSON error
2. **Tunnel won't connect**: Check `docker compose logs cloudflared` — token may be expired
3. **WhatsApp disconnected**: Re-scan QR code via `docker compose logs -f openclaw-gateway`
4. **Firewall rules missing**: The persistent sidecar re-checks every 60 seconds, so rules self-heal. If needed: `docker compose restart egress-firewall`
5. **Models not loading**: Check `docker volume inspect llama-models` — re-run the model copy step from setup.sh
