# Security Architecture

This document details the security hardening mechanisms in OpenDeclawed. The deployment uses defense-in-depth with kernel-level, container-level, and network-level controls.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Kernel-Level Egress Control](#kernel-level-egress-control)
3. [Container Hardening](#container-hardening)
4. [Network Isolation](#network-isolation)
5. [Access Control](#access-control)
6. [Secrets Management](#secrets-management)
7. [Deployment Security Checklist](#deployment-security-checklist)

## Threat Model

### Assumptions

- **Host**: Untrusted (assumes container breakout is possible)
- **Network**: Untrusted (assumes network eavesdropping possible)
- **Models**: Trusted (GGUF files are verified before deployment)
- **API Clients**: Partially trusted (can be rate-limited, not authenticated in basic setup)

### Mitigated Threats

| Threat | Mitigation | Severity |
|--------|-----------|----------|
| Container breakout to host | Unprivileged user, dropped capabilities, no write access, isolated PID/IPC namespaces | Critical |
| Container reads arbitrary host files | Bind mounts restricted to ~/.openclaw (config + workspace only); no Docker socket access prevents runtime volume creation | Critical |
| Container reach private networks | iptables DOCKER-USER persistent sidecar (60s re-check loop, survives Docker restarts) | Critical |
| Container reach host via gateway IP | Explicit DROP rule for 172.17.0.1 | Critical |
| Docker socket as root escalation | docker-socket-proxy (tecnativa) with least-privilege API filtering for Watchtower | Critical |
| LLM backend direct internet access | Internal network isolation (internal: true) | High |
| DNS exfiltration / C2 callbacks | blocky DNS firewall with threat blocklists (malware, phishing, cryptomining) + DoH upstream | High |
| Malicious skill installation | safe-install pipeline: static analysis → VirusTotal → allowlist → local archive install (TOCTOU-safe) | High |
| Skill archive path traversal | Zip-slip protection: pre-extraction path validation, reject `../` and absolute paths | High |
| Model file tampering | Read-only mounts, SHA256 checksum verification in setup.sh | High |
| Cross-container process snooping | Isolated PID namespaces (no shared `pid:` directives) | High |
| Shared memory attacks | All containers use `ipc: private` (no shareable IPC) | Medium |
| Gateway API compromise | Limited egress, DNS-filtered, internal llama network only | Medium |
| Secrets committed to git | TruffleHog pre-commit hook (800+ detectors, entropy analysis) + scan-secrets.sh | High |
| Cloudflare tunnel token leak | Token in .env (mode 600), not in image | Medium |
| Tailscale auth key leak | Key in .env (mode 600), reusable keys scoped by tag ACLs | Medium |
| Telemetry data exfiltration | Telemetry disabled by default (opt-in); no credentials or PII transmitted when enabled | Low |
| LiteLLM proxy compromise | Internal network only, stateless (no DB), read-only root, all caps dropped, internal-only master key | Low |
| Log viewer exposes sensitive data | Dozzle bound to 127.0.0.1, monitor profile only, DOZZLE_FILTER=opendeclawed-*, read-only socket, no analytics | Low |
| Meshnet peer reaches internal services | NordVPN container isolated to `openclaw-meshnet` network; Caddy is the sole bridge to service network; no other container can route to meshnet peers | Medium |
| Resource exhaustion (CPU/memory) | Deploy resource limits and reservations on every container | Medium |

### Not Mitigated (Accepted Risks)

- **Novel C2 domains**: blocky blocks known-bad domains but cannot catch zero-day C2 infrastructure
- **Full outbound internet**: Egress blocks RFC1918 but allows public internet (necessary for API calls)
- **Egress-firewall privileges**: Requires `network_mode: host` + `NET_ADMIN` — mitigated by Alpine digest pinning + Trivy scanning
- **docker inspect secret leakage**: Users in the docker group can read env vars via `docker inspect` — mitigated by socket proxy for automated tools
- **API authentication**: Basic setup has no auth; add Cloudflare Access or reverse proxy
- **Encryption in transit**: Local-only mode uses unencrypted HTTP; tunnel mode uses HTTPS via Cloudflare; Tailscale mode uses WireGuard + auto-TLS; Meshnet mode uses NordLynx (WireGuard) + Caddy self-signed TLS
- **Side-channel attacks**: Timing/power analysis not addressed

## Kernel-Level Egress Control

The `egress-firewall` persistent sidecar installs and maintains iptables rules in the DOCKER-USER chain. Unlike a one-shot init container, the sidecar runs a 60-second re-check loop that reinstalls rules if Docker flushes them (e.g., after a daemon restart). This ensures the firewall is **always** in place, not just at startup.

### Why a Persistent Sidecar?

A one-shot init container (`restart: "no"`) installs rules once and exits. If the Docker daemon restarts, it flushes iptables — leaving a window with no firewall. The sidecar pattern (`restart: unless-stopped`) solves this by continuously verifying and reinstalling rules every 60 seconds.

### Why DOCKER-USER?

Docker automatically inserts jump rules from FORWARD/OUTPUT to DOCKER-USER, making it the correct place for custom egress policies that:
- Survive Docker daemon restarts (with the sidecar pattern)
- Apply to all containers (not just this compose file)
- Don't interfere with Docker's internal rules

### Rule Order (First Match Wins)

```
1. STATEFUL: Accept established/related connections
2. ALLOW: DNS (:53 udp/tcp)
3. ALLOW: Inter-container (EGRESS_SUBNET)
4. ALLOW: Docker bridge (172.17.0.0/16)
5. DROP: RFC1918 private (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
6. DROP: Link-local (169.254.0.0/16)
7. DROP: Multicast (224.0.0.0/4)
8. DROP: Reserved (240.0.0.0/4)
9. DROP: Gateway IP (172.17.0.1)
```

### Why Block These Ranges?

**RFC1918 (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)**
- Prevents container→host breakout attempts
- Blocks metadata service access (cloud environments)
- Stops lateral movement to internal networks

**Link-local (169.254.0.0/16)**
- Blocks cloud instance metadata (AWS, GCP, Azure)
- Example: AWS metadata service at 169.254.169.254

**Multicast (224.0.0.0/4)**
- Prevents broadcast-based discovery attacks
- Blocks mDNS (224.0.0.251:5353)

**Reserved (240.0.0.0/4)**
- Prevents misuse of reserved address space
- Future-proofs against new attack vectors

**Gateway IP (172.17.0.1)**
- Explicit block: containers can still reach via docker0 (172.17.0.0/16)
- Prevents bypassing other rules

### Stateful Inspection

```bash
iptables -m state --state ESTABLISHED,RELATED -j ACCEPT
```

Allows responses to legitimate outbound connections:
- Container initiates connection → packet allowed out
- Response comes back → ESTABLISHED state → allowed in
- Related protocols (e.g., ICMP errors) → allowed

### Modifying Rules

The egress-firewall sidecar checks rules every 60 seconds and reinstalls if missing. To apply new rules:

```bash
# Edit docker-compose.yml egress-firewall entrypoint
# Add a new rule:
iptables -I DOCKER-USER 1 -d 203.0.113.0/24 -j ACCEPT

# Restart containers to reload rules
docker-compose down
docker-compose up -d
```

**Important**: Rules are idempotent; editing and restarting is safe.

## Container Hardening

### Unprivileged User

All services run as **user 65534:65534** (nobody:nogroup):

```yaml
user: "65534:65534"
```

**Effect**:
- Cannot create files in directories owned by root
- Cannot access files with restrictive permissions
- Reduces impact of container breakout

### Dropped Capabilities

All services drop **ALL** capabilities:

```yaml
cap_drop:
  - ALL
```

Then selectively add only required capabilities:

| Service | Capability | Why |
|---------|-----------|-----|
| egress-firewall | NET_ADMIN, NET_RAW | Modify iptables rules |
| llama-embed | None | No special permissions needed |
| llama-chat | None | No special permissions needed |
| openclaw-gateway | NET_BIND_SERVICE | Bind to ports <1024 (if configured) |
| cloudflared | None | No special permissions needed |
| openclaw-cli | NET_RAW | For ping/traceroute diagnostics |

**Linux capabilities reference**:
- **CAP_NET_ADMIN**: Modify network rules (iptables, routing)
- **CAP_NET_RAW**: Raw socket access (ping, traceroute, packet crafting)
- **CAP_NET_BIND_SERVICE**: Bind sockets to ports <1024
- **CAP_SETUID/SETGID**: Change process user/group
- **CAP_SYS_ADMIN**: Admin operations (mount, namespace, etc.)
- **Others**: Not needed for this deployment

### Read-Only Filesystems

All services mount root filesystem as read-only:

```yaml
read_only: true
```

Then allow write access only where needed:

```yaml
volumes:
  - openclaw-home:/home/openclaw:rw  # Gateway config
tmpfs:
  - /tmp:size=2g,noexec,nosuid,nodev
  - /run:size=512m,noexec,nosuid,nodev
```

**tmpfs options**:
- **noexec**: Cannot execute files (prevents binary drops)
- **nosuid**: SUID bit ignored (prevents privilege escalation)
- **nodev**: Device files ignored (prevents device access)

### no_new_privileges

```yaml
no_new_privileges: true
```

Prevents processes from gaining additional privileges via:
- SUID binaries (even if present)
- Capabilities gained via execve()
- Privilege escalation attacks

Once set, cannot be undone in child processes.

### Isolated Process Namespaces

```yaml
ipc: private       # llama services: no shared memory
ipc: shareable     # gateway: can expose for inter-process communication
pid: service:egress-firewall  # Share process namespace with init container
```

**IPC modes**:
- **private**: Cannot use System V semaphores, message queues, shared memory with other containers
- **shareable**: Can be joined by other containers
- **host**: Can access host IPC (dangerous, not used)

**PID modes**:
- **service:egress-firewall**: Join egress-firewall's PID namespace
  - All containers see egress-firewall as PID 1
  - Enables graceful shutdown signaling
  - Prevents zombie process accumulation

## Network Isolation

### Network Architecture

```
openclaw-internal (internal=true)
├── llama-embed     (can only reach DNS, internal services)
├── llama-chat      (can only reach DNS, internal services)
└── openclaw-gateway (can reach llama services via private IPs)

openclaw-egress
├── openclaw-gateway (can reach DNS, established/related, inter-container)
└── cloudflared     (can reach Cloudflare edge, DNS)

openclaw-meshnet (internal=true, profile: meshnet)
├── nordvpn-meshnet  (meshnet ingress, inbound only from peers)
└── meshnet-caddy    (TLS reverse proxy, bridges to egress network)

docker0 (host bridge)
└── Only for Docker infrastructure
```

### Why Two Networks?

**openclaw-internal** (internal=true):
- LLM backends isolated from internet
- No accidental external calls from embedding/chat models
- Gateway can reach both networks (broker model)
- Enforced at bridge level (no internet route)

**openclaw-egress**:
- Gateway needs outbound access (external API calls)
- Subject to egress firewall rules (no RFC1918)
- Cloudflared needs access to Cloudflare edge
- Allows legitimate external traffic with restrictions

**openclaw-meshnet** (internal=true, profile: meshnet):
- Dedicated network for NordVPN meshnet container
- No internet route — inbound only from meshnet peers
- Caddy is the sole bridge between meshnet and egress networks
- Prevents meshnet peers from reaching internal services directly

### IP Addressing

- **internal network**: 172.27.0.0/16 (configurable: INTERNAL_SUBNET)
- **egress network**: 172.28.0.0/24 (configurable: EGRESS_SUBNET)
- **docker0 (host bridge)**: 172.17.0.0/16 (Docker default)

Use non-overlapping ranges to avoid conflicts.

### DNS Resolution

Both networks allow DNS queries (:53 udp/tcp):

```bash
iptables -I DOCKER-USER 2 -p udp --dport 53 -j ACCEPT
iptables -I DOCKER-USER 3 -p tcp --dport 53 -j ACCEPT
```

**Why allow DNS?**
- Containers need to resolve service names (llama-embed, llama-chat)
- External APIs need hostname resolution
- Critical for container operation

**Note**: Egress firewall only controls outbound. DNS responses are allowed via ESTABLISHED state.

## Access Control

### Local Mode (Default)

Gateway exposed on 127.0.0.1 only:

```yaml
ports:
  - "127.0.0.1:${GATEWAY_PORT:-18789}:${GATEWAY_PORT:-18789}"
```

**Effect**:
- Only local processes can reach API
- Cannot be accessed from other machines
- Safe for development/testing
- Still protected by egress firewall

### Tunnel Mode (--profile tunnel)

Cloudflare tunnel replaces localhost port binding:

```yaml
ports: []  # No localhost binding
```

**Flow**:
1. Container initiates outbound connection to Cloudflare edge
2. Cloudflare routes inbound traffic through tunnel
3. Users access via public hostname (e.g., openclaw.example.com)
4. HTTPS encryption provided by Cloudflare

**Security advantages**:
- No host port exposure
- DDoS protection via Cloudflare
- Free SSL/TLS certificate
- Easy to enable/disable

### CLI Mode (--profile cli)

Interactive container for onboarding:

```yaml
profiles:
  - cli
stdin_open: true
tty: true
```

**Usage**:
```bash
docker-compose --profile cli run openclaw-cli bash
```

**Security notes**:
- Only runs on-demand
- Can access both networks (for debugging)
- Can use NET_RAW (ping/traceroute)
- Still subject to egress firewall

## Secrets Management

### Anti-Patterns (Don't Do This)

```bash
# ❌ DON'T: Pass sensitive data as env vars in compose
environment:
  - API_KEY=sk-1234567890

# ❌ DON'T: Bake secrets into images
docker build --build-arg API_KEY=sk-xxx -t myimage .

# ❌ DON'T: Store plaintext in git
git add .env  # Never do this!
```

### Best Practices

**1. Use environment variables only**
```bash
# .env (add to .gitignore)
CLOUDFLARE_TOKEN=eyJhIjoiXXXXXX...

# Load from command line instead:
export CLOUDFLARE_TOKEN=$(cat /secure/path/token)
docker-compose up -d
```

**2. Restrict file permissions**
```bash
# .env should be owner-read only
chmod 600 .env
```

**3. Use secrets management system**

For production, use:
- **Docker Secrets** (Docker Swarm)
- **HashiCorp Vault** (recommended)
- **AWS Secrets Manager** / **Azure Key Vault**
- **Kubernetes Secrets** (if using K8s)

**4. Rotate secrets regularly**

Cloudflare tokens should be rotated every 90 days:

```bash
# Revoke old token in dashboard
# Create new token
CLOUDFLARE_TOKEN=eyJhIjoiWWWWWW... docker-compose up -d
```

**5. Write-as-you-go credential persistence**

The setup script writes each credential to `.env` immediately after collection via the `save_env` helper. If the script crashes mid-way (e.g., during model download), all previously entered credentials survive. On re-run, they're loaded from `.env` and `openclaw.json` automatically — no re-entry needed.

**6. Token format validation**

Before accepting a credential, the setup script validates it against known patterns:

| Credential | Expected pattern |
|---|---|
| Anthropic API key | Starts with `sk-ant-` |
| VirusTotal API key | 64-character hex string |
| Cloudflare tunnel token | Starts with `eyJ` (base64 JWT) |
| Telegram bot token | `123456789:ABC...` (numeric ID + colon + alphanumeric) |
| Discord bot token | 60+ characters |
| NordVPN token | 20+ characters |

If the format doesn't match, the user is warned and can either re-enter or explicitly accept (for edge cases like OAuth tokens in place of API keys).

**7. Pre-commit secrets detection (TruffleHog)**

TruffleHog scans every commit for leaked credentials before they reach git history. It covers 800+ detector patterns (including Anthropic API keys, Cloudflare tokens, Discord/Telegram bot tokens natively) plus high-entropy string detection.

```bash
# Install (setup.sh does this automatically)
brew install trufflehog
pip install pre-commit
pre-commit install

# The pre-commit hook runs TruffleHog on every git commit.
# For manual scans:
./scripts/scan-secrets.sh              # scan working tree
./scripts/scan-secrets.sh --full       # scan entire git history
./scripts/scan-secrets.sh --staged     # scan staged files only
```

Configuration lives in `.pre-commit-config.yaml` (hook definition) and `.trufflehog-config.yaml` (path exclusions for templates/docs). False positives can be suppressed by adding paths to `.trufflehog-config.yaml`.

### Environment Variables in Logs

**Risk**: Sensitive data may appear in container logs.

**Mitigation**:
```yaml
logging:
  driver: json-file
  options:
    max-size: 10m  # Rotate logs
    max-file: 3    # Keep 3 generations
```

**Better**: Aggregate logs to external system with redaction:
```bash
# Send to centralized logging (ELK, Splunk, etc.)
# Apply log filters to remove secrets
```

## Deployment Security Checklist

Before running in production:

- [ ] **Model Verification**
  - [ ] Download GGUF files from official sources
  - [ ] Verify checksums (sha256sum)
  - [ ] Scan with ClamAV or similar
  - [ ] Keep models in separate volume (not in git)

- [ ] **Environment Configuration**
  - [ ] Create `.env` from `.env.example`
  - [ ] Set strong resource limits (avoid runaway processes)
  - [ ] Use specific image tags (not 'latest')
  - [ ] Review all parameterized values

- [ ] **Secrets**
  - [ ] Cloudflare token in `.env` (not committed)
  - [ ] `.env` file permissions: chmod 600
  - [ ] Use secrets manager for production
  - [ ] Rotate tokens every 90 days

- [ ] **Network**
  - [ ] Choose non-overlapping subnets (INTERNAL_SUBNET, EGRESS_SUBNET)
  - [ ] Verify no conflicts with host networks
  - [ ] Test egress firewall rules (iptables -L DOCKER-USER)
  - [ ] Document firewall exceptions (if any)

- [ ] **Access Control**
  - [ ] Use tunnel mode for public access (not localhost port binding)
  - [ ] Enable API authentication (reverse proxy)
  - [ ] Use HTTPS for all external traffic
  - [ ] Implement rate limiting

- [ ] **Monitoring**
  - [ ] Setup container log aggregation
  - [ ] Enable Docker healthchecks
  - [ ] Monitor resource usage (CPU, memory, network)
  - [ ] Alert on service failures

- [ ] **Hardening**
  - [ ] Verify all containers run as 65534:65534
  - [ ] Confirm all capabilities dropped
  - [ ] Test read-only filesystems
  - [ ] Validate no_new_privileges is set

- [ ] **Testing**
  - [ ] Test in local mode first
  - [ ] Verify healthchecks work
  - [ ] Test egress firewall (curl to internal IPs should fail)
  - [ ] Load test with expected traffic
  - [ ] Simulate container failure (docker kill)

- [ ] **Documentation**
  - [ ] Document custom firewall rules (if any)
  - [ ] Create runbook for incident response
  - [ ] Record all secrets in secure location (not git)
  - [ ] Keep audit log of access/changes

## Incident Response

### Container Compromised

If you suspect a container is compromised:

```bash
# 1. Stop all containers immediately
docker-compose down

# 2. Preserve logs for analysis
docker-compose logs > incident-logs.txt

# 3. Inspect volumes (do not execute containers)
docker run --rm -v openclaw-home:/data alpine ls -la /data

# 4. Review docker logs
journalctl -u docker --since "2 hours ago"

# 5. Check iptables (egress firewall)
iptables -L DOCKER-USER -vn
ip6tables -L DOCKER-USER -vn

# 6. Investigate if egress firewall was bypassed
# Look for unexpected outbound connections in logs
```

### Egress Firewall Blocked Legitimate Traffic

If containers cannot reach needed external service:

```bash
# 1. Identify the blocked traffic
docker-compose logs openclaw-gateway | grep "Connection refused"

# 2. Get IP address of target
docker exec openclaw-gateway wget -O - http://api.example.com 2>&1 | grep -i "name"

# 3. Check firewall rules
docker exec openclaw-egress-firewall iptables -L DOCKER-USER -vn

# 4. Add exception (if needed)
# Edit docker-compose.yml egress-firewall entrypoint:
# iptables -I DOCKER-USER 1 -d 203.0.113.0/24 -j ACCEPT

# 5. Restart with new rules
docker-compose down && docker-compose up -d
```

### Tunnel Connection Lost

If cloudflared cannot connect to Cloudflare:

```bash
# 1. Check tunnel logs
docker-compose logs cloudflared

# 2. Verify token is correct
echo $CLOUDFLARE_TOKEN

# 3. Check egress network can reach Cloudflare
docker exec openclaw-gateway nslookup tunnel.cloudflare.com

# 4. Check gateway is healthy (tunnel depends on this)
docker-compose logs openclaw-gateway | grep health
curl http://127.0.0.1:18789/health

# 5. Restart tunnel
docker-compose --profile tunnel restart cloudflared
```

## References

- **Linux Capabilities**: man 7 capabilities
- **iptables**: man 8 iptables
- **Docker Security**: https://docs.docker.com/engine/security/
- **CIS Docker Benchmark**: https://www.cisecurity.org/
- **OWASP Container Security**: https://owasp.org/Container-Security/
