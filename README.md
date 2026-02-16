# OpenDeclawed

Production-grade, security-hardened Docker deployment for OpenClaw, an AI agent platform. Fully parameterized with sensible defaults, kernel-level egress control, and optional Cloudflare tunnel ingress.

## Features

- **Security-First Design**
  - Persistent egress firewall sidecar (iptables DOCKER-USER rules, survives Docker restarts)
  - DNS firewall (blocky) with threat blocklists — blocks malware C2, phishing, cryptomining
  - DNS-over-HTTPS upstream (Cloudflare + Quad9) — no plaintext DNS to ISP
  - Docker socket proxy for Watchtower — least-privilege API access, no raw socket
  - All containers: unprivileged user (65534:65534), cap_drop ALL, read-only rootfs, isolated PID/IPC namespaces
  - Network isolation: internal network (no internet) + egress-controlled network
  - Skills allowlist with safe-install vetting pipeline (static analysis + VirusTotal + TOCTOU protection)
  - Model file integrity verification (SHA256 checksums)

- **Fully Parameterized**
  - 40+ environment variables with sensible defaults
  - Secure credential collection (setup.sh with silent input, no screen echo)
  - CPU-only or GPU-accelerated deployment

- **Multiple Deployment Modes**
  - **Local** (default): Gateway on 127.0.0.1:18789
  - **Tunnel** (--profile tunnel): Cloudflare Tunnel, zero exposed ports
  - **Monitor** (--profile monitor): Uptime Kuma + Watchtower via socket proxy
  - **CLI** (--profile cli): Interactive shell for onboarding/debugging

- **Production-Ready**
  - Docker Compose v3.9+ with resource limits and reservations
  - Healthchecks with automatic restart (unless-stopped)
  - JSON file logging with rotation (10MB, 3 files)
  - Label-gated Watchtower auto-updates

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                  CLOUDFLARE TUNNEL (Optional)                       │
│                 Profile: "tunnel" (opt-in)                          │
│                    cloudflared ←→ Tunnel                            │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                     openclaw-gateway                                │
│  (REST API, WebSocket, health checks)                              │
│  DNS: blocky (threat filtering + DoH)                              │
│  Networks: openclaw-internal + openclaw-egress                     │
└─────────┬──────────────────┬──────────────────┬─────────────────────┘
          │                  │                  │
    ┌─────▼───────┐   ┌─────▼──────┐   ┌──────▼──────┐
    │ llama-embed  │   │ llama-chat │   │   blocky    │
    │ (embeddings) │   │ (chat LLM) │   │(DNS firewall│
    │ internal-only│   │internal-only│   │ DoH + block)│
    └──────────────┘   └────────────┘   └─────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│            EGRESS FIREWALL (Persistent Sidecar, 60s loop)           │
│  iptables DOCKER-USER: DROP RFC1918 | Survives Docker restarts     │
└──────────────────────────────────────────────────────────────────────┘

┌─ MONITOR PROFILE (optional) ────────────────────────────────────────┐
│  uptime-kuma → gateway /health       watchtower → socket-proxy     │
│  (127.0.0.1:3001)                    (no raw docker.sock access)   │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Prerequisites

- Docker Engine 20.10+ with Compose v2.0+
- 8GB+ RAM (CPU-only) or 16GB+ (GPU)
- Linux kernel with iptables support (DOCKER-USER chain)

**See [`docs/prerequisites.md`](docs/prerequisites.md) for the full guide**: how to get every API key (Anthropic, VirusTotal, Cloudflare, NordVPN, Telegram, Discord), download models, and store secrets securely.

### 2. Local Mode (No Cloudflare)

```bash
# Clone repo
git clone https://github.com/yourusername/opendeclawed.git
cd opendeclawed

# Copy environment template and customize
cp .env.example .env
# Edit .env with your model filenames, resource limits, etc.

# Download GGUF model files
mkdir -p models
# Download embedding model (e.g., nomic-embed-text-v1.5.f16.gguf, ~500MB)
# Download chat model (e.g., mistral-7b-instruct-v0.2.Q6_K.gguf, ~5.8GB)

# Start containers (local mode only)
docker-compose up -d

# Check status
docker-compose ps
docker-compose logs openclaw-gateway

# Test API
curl http://127.0.0.1:18789/health
```

### 3. Tunnel Mode (Cloudflare)

```bash
# Setup Cloudflare tunnel
# 1. Go to https://dash.cloudflare.com/ → Tunnels → Create tunnel
# 2. Name: "openclaw"
# 3. Copy tunnel token

# Set token in .env
echo "CLOUDFLARE_TOKEN=eyJhIjoiXXXXXX..." >> .env

# Start with tunnel profile
docker-compose --profile tunnel up -d

# Verify tunnel is connected
docker-compose logs cloudflared | tail -20
```

### 4. CLI Mode (Onboarding)

```bash
# Interactive shell for onboarding/debugging
docker-compose --profile cli run openclaw-cli bash

# Inside container:
openclaw agent list
openclaw playground
openclaw config show
```

## Configuration

### Environment Variables

See `.env.example` for comprehensive documentation. Key variables:

**Images**
- `OPENCLAW_IMAGE`: Gateway and CLI image
- `LLAMA_IMAGE`: llama.cpp server image
- `CLOUDFLARED_IMAGE`: Cloudflare tunnel image
- `ALPINE_IMAGE`: Base image for egress firewall init

**Models**
- `EMBED_MODEL_FILE`: GGUF embedding model filename
- `CHAT_MODEL_FILE`: GGUF chat model filename

**Inference**
- `LLAMA_THREADS`: CPU thread count
- `LLAMA_GPU_LAYERS`: GPU layer offload (0 = CPU-only)
- `EMBED_CTX`: Embedding context size (tokens)
- `CHAT_CTX`: Chat context size (tokens)

**Resources**
- `LLAMA_EMBED_MEM`, `LLAMA_CHAT_MEM`, `GATEWAY_MEM`: Memory limits
- `LLAMA_EMBED_CPUS`, `LLAMA_CHAT_CPUS`, `GATEWAY_CPUS`: CPU limits
- Reservation variants for QoS guarantees

**Network**
- `GATEWAY_PORT`: REST API port (default: 18789)
- `EMBED_PORT`: Embedding server port (default: 8090, internal only)
- `CHAT_PORT`: Chat server port (default: 8091, internal only)
- `INTERNAL_SUBNET`: llama backend network (default: 172.27.0.0/16)
- `EGRESS_SUBNET`: egress-controlled network (default: 172.28.0.0/24)

**Cloudflare Tunnel (optional)**
- `CLOUDFLARE_TOKEN`: Tunnel authentication token
- `CLOUDFLARE_TUNNEL_NAME`: Tunnel name (for logging)
- `CLOUDFLARE_TUNNEL_ROUTE`: Public hostname (for reference)

### Resource Sizing

**Minimal (CPU-only, 8GB RAM)**
```env
LLAMA_THREADS=4
LLAMA_GPU_LAYERS=0
LLAMA_EMBED_MEM=1g
LLAMA_CHAT_MEM=4g
GATEWAY_MEM=2g
EMBED_MODEL_FILE=nomic-embed-text-v1.5.f16.gguf
CHAT_MODEL_FILE=mistral-7b-instruct-v0.2.Q6_K.gguf
```

**Standard (CPU-only, 16GB RAM)**
```env
LLAMA_THREADS=8
LLAMA_GPU_LAYERS=0
LLAMA_EMBED_MEM=2g
LLAMA_CHAT_MEM=6g
GATEWAY_MEM=4g
```

**GPU-Accelerated (NVIDIA CUDA, 24GB VRAM)**
```env
LLAMA_IMAGE=ghcr.io/ggerganov/llama.cpp:latest-cuda
LLAMA_THREADS=16
LLAMA_GPU_LAYERS=40
LLAMA_EMBED_MEM=2g
LLAMA_CHAT_MEM=8g
GATEWAY_MEM=4g
```

## Security Details

### Egress Firewall

The `egress-firewall` service installs kernel-level iptables rules in the DOCKER-USER chain on startup. This prevents containers from reaching:

- RFC1918 private ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
- Link-local (169.254.0.0/16)
- Multicast (224.0.0.0/4)
- Reserved (240.0.0.0/4)
- Host gateway IP (172.17.0.1)

Allowed traffic:
- Established/related connections (stateful)
- DNS queries (:53)
- Inter-container traffic (openclaw-egress network)
- Docker bridge traffic (172.17.0.0/16)

### Network Isolation

**openclaw-internal** (bridge, internal=true):
- llama-embed, llama-chat, openclaw-gateway
- No internet access (internal: true)
- Services communicate on private network only

**openclaw-egress** (bridge):
- openclaw-gateway, cloudflared
- Subject to egress firewall rules
- Allows outbound to external APIs (with restrictions)

### Container Hardening

All services (except egress-firewall):
- User: 65534:65534 (nobody:nogroup)
- Capabilities: drop ALL (no special kernel access)
- Read-only filesystem with minimal tmpfs mounts
- no_new_privileges: true (cannot escalate privileges)
- ipc: private or shareable (isolated inter-process communication)
- pid: service:egress-firewall (shared process namespace, safer than host)

### Healthchecks

**openclaw-gateway**:
```
wget -q -O - http://127.0.0.1:18789/health
interval: 10s, timeout: 5s, retries: 3, start_period: 30s
```

Cloudflared depends on this healthcheck (service_healthy) before starting.

## Troubleshooting

### Containers crash on startup

**Check logs:**
```bash
docker-compose logs openclaw-gateway
docker-compose logs llama-embed
docker-compose logs llama-chat
```

**Common issues:**
- Model files not found: Ensure models are in `./models/` directory
- Out of memory: Increase `LLAMA_EMBED_MEM`, `LLAMA_CHAT_MEM` in .env
- Port conflicts: Change `GATEWAY_PORT`, `EMBED_PORT`, `CHAT_PORT`

### Egress firewall blocks legitimate traffic

The firewall is intentionally strict. To debug:

```bash
# Check DOCKER-USER rules
docker exec openclaw-egress-firewall iptables -L DOCKER-USER -vn
docker exec openclaw-egress-firewall ip6tables -L DOCKER-USER -vn

# To modify rules, edit docker-compose.yml egress-firewall entrypoint:
# 1. Restart containers to apply changes:
docker-compose down
docker-compose up -d
```

### API not responding

```bash
# Check gateway health
curl http://127.0.0.1:18789/health

# Check internal connectivity
docker exec openclaw-gateway wget -q -O - http://llama-embed:8090/status
docker exec openclaw-gateway wget -q -O - http://llama-chat:8091/status

# Check if gateway is on both networks
docker network inspect openclaw-internal
docker network inspect openclaw-egress
```

### Cloudflare tunnel not connecting

```bash
# Check tunnel logs
docker-compose logs cloudflared

# Verify token is set
echo $CLOUDFLARE_TOKEN

# Check gateway is healthy (tunnel depends on this)
docker-compose ps
curl http://127.0.0.1:18789/health
```

## Advanced Usage

### Custom Egress Rules

Edit the `egress-firewall` service's `entrypoint` in `docker-compose.yml` to:
- Allow specific external IPs/ranges
- Add protocol-specific rules
- Monitor traffic with logging

```bash
# Example: Allow external API calls to api.example.com
iptables -I DOCKER-USER 1 -d api.example.com -j ACCEPT
```

Then restart:
```bash
docker-compose down && docker-compose up -d
```

### Using Different Models

Download from Hugging Face (GGUF quantizations):

```bash
mkdir -p models

# Embedding models
# https://huggingface.co/nomic-ai/nomic-embed-text-v1.5
wget -O models/nomic-embed-text-v1.5.f16.gguf \
  https://huggingface.co/nomic-ai/nomic-embed-text-v1.5/resolve/main/gguf/nomic-embed-text-v1.5.f16.gguf

# Chat models
# https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.2
wget -O models/mistral-7b-instruct-v0.2.Q6_K.gguf \
  https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.2/resolve/main/...

# Update .env
echo "EMBED_MODEL_FILE=nomic-embed-text-v1.5.f16.gguf" >> .env
echo "CHAT_MODEL_FILE=mistral-7b-instruct-v0.2.Q6_K.gguf" >> .env

docker-compose up -d
```

### Monitoring

```bash
# Real-time resource usage
docker stats openclaw-gateway llama-embed llama-chat

# Logs with follow
docker-compose logs -f openclaw-gateway

# Check resource limits
docker inspect openclaw-gateway | grep -A 20 "HostConfig"
```

### Backup and Restore

```bash
# Backup gateway home directory
docker run --rm -v openclaw-home:/data -v $(pwd):/backup \
  alpine tar czf /backup/openclaw-home.tar.gz -C /data .

# Restore
docker run --rm -v openclaw-home:/data -v $(pwd):/backup \
  alpine tar xzf /backup/openclaw-home.tar.gz -C /data
```

## Contributing

Contributions welcome! Please:
1. Test security changes with egress firewall (iptables)
2. Verify all env vars have sensible defaults
3. Update .env.example for new parameters
4. Keep docker-compose.yml comments current

## License

See LICENSE file (typically MIT or Apache 2.0 for open-source AI projects).

## Security Reporting

For security issues, email security@example.com or use GitHub security advisory.
Do NOT open public issues for security vulnerabilities.

## References

- OpenClaw: https://github.com/openagentsinc/openclaw
- llama.cpp: https://github.com/ggerganov/llama.cpp
- Docker Compose: https://docs.docker.com/compose/
- Cloudflare Tunnels: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/
- Linux Capabilities: https://man7.org/linux/man-pages/man7/capabilities.7.html
- iptables: https://linux.die.net/man/8/iptables
