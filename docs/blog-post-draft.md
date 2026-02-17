# Deploying a Self-Hosted AI Agent Without Getting Owned

<p align="center">
  <img src="../images/opendeclawed.png" alt="OpenDeclawed" width="200">
</p>

*How to run OpenClaw in Docker with zero container escape, zero lateral movement, and zero exposed ports.*

---

Most guides for self-hosted AI agents go something like: install the thing, expose a port, maybe add a password. That's fine if your threat model is "my cat walking on the keyboard." It's not fine if you're running an AI agent with access to your files, messaging accounts, and API keys on the same network as the rest of your life.

This post walks through a hardened deployment pattern for OpenClaw — but the principles apply to any self-hosted AI agent (Open Interpreter, AutoGPT, etc.). We'll cover container hardening, network isolation, egress firewalling, and zero-trust ingress, all using standard Docker tooling.

## The Problem

Self-hosted AI agents are uniquely dangerous because they combine three things that security engineers hate to see together: broad tool access (files, shell, network), persistent credentials (API keys, messaging tokens), and internet connectivity (for API calls).

A compromised agent — or even a sufficiently creative prompt injection — could exfiltrate data, pivot to your LAN, or use your API keys for someone else's benefit.

## The Architecture

We use a three-tier network design inside Docker:

**Tier 1: Internal-only** — The LiteLLM proxy lives on a Docker bridge network marked `internal: true`, routing LLM requests to Ollama running natively on the host (via `host.docker.internal`). The internal network itself has no internet access.

**Tier 2: Egress-controlled** — The main agent gateway and the tunnel connector live on a second bridge network. An init container installs iptables rules in Docker's `DOCKER-USER` chain that DROP all traffic to RFC1918 private ranges (10.0.0.0/8, 192.168.0.0/16), link-local, multicast, and the Docker gateway IP. Containers can reach the internet (for API calls), but cannot reach your LAN, your NAS, your printer, or anything else on your home network.

**Tier 3: Zero-trust ingress** — Instead of exposing a port, we support two remote access options: Cloudflare Tunnel (GitHub OAuth at Cloudflare's edge, zero exposed ports) or Tailscale mesh VPN (WireGuard-based, ACL-controlled, automatic HTTPS). Both eliminate port exposure; pick the one that fits your trust model.

```
Internet → Cloudflare Edge → GitHub OAuth → cloudflared → gateway
                                                              ↕
                                                           litellm
                                                     (LLM router/proxy)
                                                              ↕
                                                    Ollama on host machine
```

## Container Hardening

Every container in the stack enforces:

- **Read-only root filesystem** — Prevents an attacker from writing malware or modifying binaries. Writable tmpfs mounts are provided where needed, marked `noexec,nosuid,nodev`.
- **`cap_drop: ALL`** — Zero Linux capabilities. We selectively add back only `NET_BIND_SERVICE` (for the gateway) and `NET_ADMIN`/`NET_RAW` (for the egress firewall sidecar).
- **`no-new-privileges: true`** — Prevents escalation via setuid/setgid binaries.
- **Resource limits** — Memory, CPU, and PID limits on every container. A fork bomb inside a container can't OOM your host.
- **Non-root user** — cloudflared runs as `nobody:nogroup` (65534:65534).
- **Isolated PID/IPC namespaces** — No shared PID or IPC namespaces between containers. Each container has its own `/proc` view and cannot read other containers' environment variables or attach to shared memory segments.

## The Egress Firewall Trick

This is the most reusable pattern in the whole stack. Docker's `DOCKER-USER` iptables chain is evaluated before Docker's own routing rules, making it the right place for custom firewall logic.

We run a **persistent Alpine sidecar** with `network_mode: host` and `cap_add: NET_ADMIN` that installs iptables rules, then enters a 60-second re-check loop. If Docker flushes the rules (e.g., after a daemon restart), the sidecar reinstalls them within a minute. No more firewall gaps.

The rules allow established/related traffic (so outbound API calls get responses), DNS resolution, and inter-container communication, then DROP everything destined for private IP space. The result: containers can talk to Anthropic's API and Cloudflare's edge, but can't scan your LAN, access your router, or reach your other Docker services.

This pattern works for *any* Docker Compose stack where you want internet egress without LAN access. Steal it.

## DNS Firewall

Egress rules block private IP ranges, but what about known-malicious public domains? A compromised skill or prompt injection could phone home to a C2 server. We solve this with `blocky` — a lightweight DNS firewall that filters all container DNS queries against curated threat intelligence blocklists (StevenBlack/hosts, URLhaus, PhishingArmy, FireBog, CoinBlockerLists).

Upstream resolvers use DNS-over-HTTPS (Cloudflare + Quad9), so no plaintext DNS queries leak to your ISP. An explicit allowlist ensures legitimate API domains (Anthropic, VirusTotal, Telegram, GitHub, HuggingFace) are never blocked.

## Docker Socket Proxy

Watchtower needs Docker API access for auto-updates, but mounting `/var/run/docker.sock` directly is effectively root access — any container with the socket can `docker exec` into other containers and read their environment variables (including API keys).

We route Watchtower through a `tecnativa/docker-socket-proxy` that only exposes the endpoints Watchtower needs (containers, images, version, events) and denies everything dangerous (exec, volumes, networks, secrets). The socket proxy is the only container with direct socket access.

## Skill Vetting Pipeline

AI agent skill marketplaces are the next npm — and just as susceptible to supply chain attacks. Our `safe-install` skill implements a 6-step vetting pipeline before any skill touches your system: static analysis (dangerous imports, shell commands, network calls), VirusTotal scanning (67 antivirus engines), allowlist enforcement (hash-based, so a modified skill fails even if the name matches), and TOCTOU-safe local archive installation (the vetted bytes are what gets installed, not a fresh download). Zip-slip protection prevents path traversal in skill archives.

## Cost-Optimized Model Routing

Running every task through Opus 4.6 is like hiring a lawyer to check your mailbox. We configure model routing so cheap tasks use cheap models:

- **Heartbeat checks** (runs hourly, simple context scan): Haiku 4.5 — ~$0.005/day instead of $0.24/day
- **Quick tasks** (reminders, simple lookups): Haiku 4.5
- **Default chat**: Sonnet 4.5
- **Deep reasoning** (analysis, multi-step planning): Opus 4.6
- **Embeddings**: Local via Ollama — zero cost, zero latency, zero data leaving your machine

## Local Inference

LLM inference is handled by Ollama running natively on the host machine, accessed by the Docker stack through the LiteLLM proxy via `host.docker.internal:11434`. This replaces the need for containerized inference servers.

Ollama manages model downloads, quantization, and GPU acceleration natively. The LiteLLM proxy inside the Docker stack presents a single OpenAI-compatible endpoint to OpenClaw, routing requests to Ollama transparently. You can run any Ollama-supported model (Llama 3, Mistral, Nomic Embed, etc.) without changes to the Docker configuration — just update `litellm_config.yaml` with the model names.

## Getting Started

The full stack is available as an open-source repo with a one-command setup:

```bash
git clone https://github.com/YOUR_USERNAME/opendeclawed
cd opendeclawed
cp .env.example .env
# Edit .env with your tokens
./scripts/setup.sh
```

The setup script supports both interactive and `--non-interactive` modes (for CI/server deployments). Everything is parameterized via environment variables — model choices, resource limits, network subnets, container images.

## What This Doesn't Protect Against

No security architecture is complete without an honest limitations section:

- **Novel C2 domains**: blocky blocks known-bad domains but can't catch zero-day C2 infrastructure. The egress firewall blocks RFC1918 but allows public internet (necessary for API calls).
- **Compromised upstream images**: Mitigated by Trivy scanning and pinning images by SHA256 digest, but you're still trusting the image authors.
- **Docker daemon vulnerabilities**: If Docker itself is compromised, game over. Keep it updated.
- **Host OS exploits**: Out of scope for container-level hardening. Use FileVault/LUKS, keep your OS patched.
- **Egress firewall privileges**: The sidecar needs `network_mode: host` + `NET_ADMIN` — mitigated by Alpine digest pinning and Trivy scanning.
- **docker inspect secret leakage**: Users in the docker group can read env vars via `docker inspect` — mitigated by socket proxy for automated tools.

## Conclusion

Self-hosted AI agents are powerful tools that deserve the same security rigor we apply to production infrastructure. The patterns in this post — read-only containers, capability dropping, persistent egress firewalling, DNS threat filtering, Docker socket proxying, skill supply chain vetting, zero-trust ingress, and local inference via Ollama — aren't novel individually, but combining them into a single Docker Compose stack makes defense-in-depth accessible to anyone comfortable with `docker compose up`.

The full repo, including Cloudflare Tunnel and Tailscale mesh VPN ingress options, opt-in telemetry, and messaging channel integration guides, is available on GitHub.

---

*Built with paranoia and a healthy distrust of `--privileged`.*
