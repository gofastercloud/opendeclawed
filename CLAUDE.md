# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenDeclawed is a security-hardened Docker deployment for OpenClaw, an AI agent platform. It combines local LLM inference (llama.cpp) with OpenAI-compatible routing (LiteLLM), secured behind kernel-level egress control, DNS filtering (Blocky), container hardening, and multiple private ingress options (Cloudflare Tunnel, Tailscale).

## Common Commands

```bash
# First-time setup (interactive)
./scripts/setup.sh

# Non-interactive setup
./scripts/setup.sh --non-interactive

# Run services (local mode, 127.0.0.1:18789)
docker-compose up -d

# Run with profiles (combinable)
docker-compose --profile tunnel up -d      # Cloudflare Tunnel
docker-compose --profile tailscale up -d   # Tailscale mesh VPN
docker-compose --profile monitor up -d     # Watchtower + Dozzle log viewer
docker-compose --profile cli run openclaw-cli bash

# Validate compose syntax
docker compose config

# Secrets scan
./scripts/scan-secrets.sh              # Working tree
./scripts/scan-secrets.sh --full       # Full git history
./scripts/scan-secrets.sh --staged     # Pre-commit

# Stop
docker-compose down
docker-compose down -v  # Remove volumes too
```

## Architecture

**Network topology** — two isolated Docker networks:
- `openclaw-internal` (172.27.0.0/24, `internal: true`): llama-embed, llama-chat, blocky — no internet access
- `openclaw-egress` (172.28.0.0/24): gateway, litellm, cloudflared, tailscale, dozzle — egress-firewall controlled

**Request flow**: External → Cloudflare Tunnel/Tailscale → openclaw-gateway:18789 → LiteLLM:4000 → llama-chat:8091 / llama-embed:8090

**Egress firewall**: Persistent sidecar (not one-shot init) with 60s iptables re-check loop on DOCKER-USER chain. Drops RFC1918, link-local, multicast. Gateway and all egress containers use blocky:53 (static IP 172.27.0.53) for DNS-level threat filtering.

**LiteLLM abstraction**: `litellm_config.yaml` routes model names to backends. Swap llama.cpp ↔ MLX ↔ Ollama without changing openclaw config.

## Key Files

- `docker-compose.yml` — Main orchestration (~1000 lines, heavily commented)
- `.env.example` — Master config template (40+ parameterized variables with defaults)
- `litellm_config.yaml` — LLM provider routing config
- `scripts/setup.sh` — Interactive/non-interactive setup (~1000 lines)
- `scripts/scan-secrets.sh` — TruffleHog credential scanner
- `examples/blocky-config.yml` — DNS firewall rules with threat blocklists
- `examples/openclaw.example.json` — Agent configuration template
- `examples/skills.allowlist.json` — Skills vetting allowlist (SHA256 + VirusTotal)
- `examples/skills/safe-install/safe_install.py` — Skill vetting pipeline (static analysis → VirusTotal → allowlist)

## Security Patterns (Required)

These patterns are enforced by the project. Follow them in all contributions:

1. **Container hardening baseline**: `read_only: true`, `cap_drop: ALL`, `no_new_privileges: true`, `user: "65534:65534"`, `ipc: private`, resource limits, `tmpfs` with `noexec,nosuid,nodev`
2. **Never mount Docker socket directly** — use `tecnativa/docker-socket-proxy` with least-privilege env flags
3. **Persistent firewall sidecar** — `restart: unless-stopped` with loop, not one-shot init container
4. **DNS filtering** — all egress-network containers must use `dns: blocky`
5. **Shell injection prevention** — use `printf -v "$var"` instead of `eval`; quoted heredocs (`'EOF'`) for secrets
6. **TOCTOU-safe installation** — verify then install from verified bytes, never re-download
7. **Zip-slip protection** — validate archive paths with `os.path.normpath`; reject `../` and absolute paths

## Tech Stack

- **Docker Compose v2.0+** (not v3.x) with profiles for modular deployment
- **Bash** for setup/utility scripts (POSIX-compatible where possible)
- **Python 3** for skill vetting pipeline
- **YAML** for Docker Compose, LiteLLM config, Blocky config, pre-commit
- **GGUF models** for local inference (llama.cpp)

## Pre-commit Hooks

TruffleHog v3.93+ (800+ secret detectors) and standard pre-commit checks (large file detection, merge conflicts, private key detection, EOL/trailing-whitespace fixers). Install with `pre-commit install`.
