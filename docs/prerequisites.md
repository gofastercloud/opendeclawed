# Prerequisites & API Key Guide

Everything you need before running `setup.sh`. Each section covers what the credential is, how to get it, and how to store it safely.

**Note**: The setup script validates all credentials against their expected format (e.g., Anthropic keys must start with `sk-ant-`, VirusTotal keys must be 64-char hex). Credentials are persisted to `.env` immediately as you enter them — if the script crashes, you won't need to re-enter anything on the next run.

---

## Runtime Requirements

**Docker Engine 20.10+** with Compose v2. On macOS, [OrbStack](https://orbstack.dev) is recommended (lighter than Docker Desktop). On Linux, install via your distro's package manager or Docker's official repo.

Verify:

```bash
docker --version        # 20.10+
docker compose version  # 2.0+
```

**RAM**: 4GB minimum for the Docker stack. LLM inference is handled by Ollama on the host (install separately via https://ollama.com).

**Disk**: ~4GB free — container images (~3GB), runtime volumes (~1GB).

**Kernel**: Linux with iptables support and the DOCKER-USER chain. OrbStack and Docker Desktop both provide this. Native Linux works out of the box.

---

## Required Credentials

### 1. Anthropic API Key

This is how OpenClaw talks to Claude (Sonnet, Haiku, Opus).

**Option A — API Console (pay-per-token)**

1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Sign in or create an account
3. **Settings → API Keys → Create Key**
4. Name it `openclaw-prod` (helps you identify it later)
5. Copy the key immediately — it's shown only once
6. Format: `sk-ant-api03-...`

Billing: You'll need to add a payment method. Set a **monthly spend limit** (Settings → Limits) to prevent runaway costs. $20/month covers moderate personal use.

**Option B — Claude Pro/Max subscription (OAuth flow)**

If you have a Claude Pro ($20/mo) or Max ($100/mo) subscription, you can use that instead of a separate API key. During `setup.sh`, select the OAuth option and follow the browser-based auth flow. The script stores the resulting token at `~/.openclaw/anthropic.token`.

**Least privilege**: The API key doesn't support scoping to specific models. Mitigate by setting a low spend limit and rotating the key monthly.

### 2. VirusTotal API Key

Used by the `safe-install` skill to scan skill archives before installation. Optional but strongly recommended — 341 malicious skills were found on ClawHub in 2025.

1. Go to [virustotal.com](https://www.virustotal.com)
2. Create a free account (email verification required)
3. Click your avatar → **API key**
4. Copy the key — format: 64-character hex string

Free tier: 4 lookups/minute, 500/day, 15.5K/month. More than enough for skill vetting.

---

## Optional Credentials (pick your ingress method)

### 3. Cloudflare Tunnel Token

Required only if you want internet-accessible OpenClaw with zero exposed ports. Needs a domain on Cloudflare.

1. Go to [one.dash.cloudflare.com](https://one.dash.cloudflare.com)
2. **Networks → Tunnels → Create a tunnel**
3. Connector: **Cloudflared**
4. Name: `openclaw-prod`
5. Copy the **tunnel token** (long base64 string starting with `eyJ...`)
6. Add a public hostname route:
   - Subdomain: `openclaw`
   - Domain: your Cloudflare domain
   - Service: `HTTP`, URL: `openclaw-gateway:18789`

For authentication, set up **Cloudflare Access** with GitHub OAuth — see `docs/setup-guide.md` for the full walkthrough.

### 4. Tailscale Auth Key

Required only if you prefer WireGuard-based mesh VPN access. Tailscale is zero-config and provides automatic HTTPS.

1. Go to [login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys)
2. Click **Generate auth key**
3. Enable **Reusable** (so container survives restarts without re-auth)
4. Optionally tag it `tag:openclaw` for ACL targeting
5. Copy the key — format: `tskey-auth-...`

See `docs/setup-guide.md` for ACL configuration and Tailscale Serve setup.

### 5. Telegram Bot Token

Required if you want to interact with OpenClaw via Telegram (the recommended messaging channel — simplest to set up).

1. Open Telegram and message **@BotFather**
2. Send `/newbot`
3. Name: `OpenClaw Assistant`
4. Username: `yourname_openclaw_bot` (must end in `bot`)
5. Copy the bot token — format: `123456789:ABCdefGHIjklMNOpqrSTUvwxyz`

Lock down the bot immediately:

```
/setjoingroups  → Disable
/setprivacy     → Enable
```

---

## Blocky DNS Firewall Config

The stack includes a `blocky` DNS firewall that filters container DNS queries against threat intelligence blocklists. No additional credentials are needed, but you need to copy the config file before first run:

```bash
mkdir -p ~/.openclaw/blocky
cp examples/blocky-config.yml ~/.openclaw/blocky/config.yml
```

The default config blocks malware, phishing, C2, and cryptomining domains while allowing known-good API endpoints (Anthropic, VirusTotal, Telegram, Cloudflare, HuggingFace, GitHub). Customize the allowlist in `~/.openclaw/blocky/config.yml` if your skills need to reach additional domains.

Upstream DNS uses DNS-over-HTTPS (Cloudflare + Quad9) so no plaintext DNS queries leak to your ISP.

---


## Storing Secrets Securely

All secrets end up in two places: your `.env` file and `~/.openclaw/`. Here's how to protect them.

### File permissions

```bash
# .env contains API keys — restrict to owner only
chmod 600 .env

# OpenClaw config directory
chmod 700 ~/.openclaw
chmod 600 ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/skills.allowlist.json
```

### What goes where

| Secret | Storage location | Set by |
|---|---|---|
| Anthropic API key | `~/.openclaw/openclaw.json` | `setup.sh` |
| VirusTotal API key | `.env` (`VIRUSTOTAL_API_KEY`) | You, manually |
| Cloudflare tunnel token | `.env` (`CLOUDFLARE_TOKEN`) | You, manually |
| Tailscale auth key | `.env` (`TS_AUTHKEY`) | `setup.sh` |
| Telegram bot token | `~/.openclaw/openclaw.json` | `setup.sh` |
| Gateway pairing secret | `~/.openclaw/openclaw.json` | `setup.sh` (auto-generated) |

### Never commit secrets

The repo's `.gitignore` already excludes `.env`, `*.token`, and the `~/.openclaw/` directory. Double-check before pushing:

```bash
# Verify no secrets in staged files
git diff --cached --name-only | xargs grep -l "sk-ant\|eyJ\|VIRUSTOTAL" 2>/dev/null
# Should return nothing
```

### Secret rotation schedule

| Secret | Rotate every | How |
|---|---|---|
| Anthropic API key | 30 days | Console → revoke old → create new → update `openclaw.json` → restart gateway |
| VirusTotal API key | 90 days | VT dashboard → regenerate → update `.env` |
| Cloudflare tunnel token | 90 days | CF dashboard → rotate token → update `.env` → restart cloudflared |
| Tailscale auth key | 90 days | TS admin console → revoke → generate new → update `.env` → restart tailscale |
| Telegram bot token | On suspicion of compromise | @BotFather → `/revoke` → create new → update `openclaw.json` |
| Gateway pairing secret | 90 days | `setup.sh` regenerates → restart gateway → re-pair devices |

### macOS: additional protections

If you're running on macOS (likely with OrbStack):

- **FileVault**: Enable full-disk encryption (System Settings → Privacy & Security → FileVault). Protects secrets at rest if your laptop is stolen.
- **Keychain (advanced)**: For extra paranoia, store the `.env` values in Keychain and load them at runtime:

```bash
# Store
security add-generic-password -s "openclaw" -a "ANTHROPIC_API_KEY" -w "sk-ant-..."

# Retrieve into env at startup (add to a wrapper script)
export ANTHROPIC_API_KEY=$(security find-generic-password -s "openclaw" -a "ANTHROPIC_API_KEY" -w)
```

### Linux: additional protections

- **LUKS**: Ensure `/home` or the directory containing `.env` is on an encrypted partition
- **systemd-creds (advanced)**: If running as a systemd service, use encrypted credentials instead of plaintext `.env`

---

## Pre-flight Checklist

Before running `setup.sh`, confirm:

- [ ] Docker 20.10+ and Compose v2 installed and working
- [ ] 4GB+ RAM available for Docker containers (Ollama uses additional host RAM)
- [ ] ~4GB free disk space
- [ ] Anthropic API key ready (with spend limit set)
- [ ] VirusTotal API key ready (free tier is fine)
- [ ] Blocky DNS config copied to `~/.openclaw/blocky/config.yml`
- [ ] Ingress method chosen: local-only, Cloudflare tunnel, or Tailscale
- [ ] If tunnel: Cloudflare token and domain configured
- [ ] If Tailscale: Auth key generated (reusable recommended)
- [ ] If Telegram: Bot created and locked down via @BotFather
- [ ] `.env` file created from `.env.example` with your values
- [ ] `.env` permissions set to `600`
- [ ] FileVault / LUKS enabled on host
- [ ] TruffleHog installed (`brew install trufflehog`) — setup.sh auto-installs if missing
- [ ] pre-commit installed (`pip install pre-commit`) — setup.sh auto-installs if missing

Then:

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```
