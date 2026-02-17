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
- **Models**: Trusted (managed by Ollama or external backend)
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
| DNS exfiltration / C2 callbacks | blocky DNS firewall with threat blocklists + port 53 locked to Blocky only + DoH resolver IPs blocked | High |
| Malicious skill installation | safe-install pipeline: static analysis → VirusTotal → allowlist → local archive install (TOCTOU-safe) | High |
| Skill archive path traversal | Zip-slip protection: pre-extraction path validation, reject `../` and absolute paths | High |
| Model file tampering | Models managed by Ollama or external backend; not mounted into containers | High |
| Cross-container process snooping | Isolated PID namespaces (no shared `pid:` directives) | High |
| Shared memory attacks | All containers use `ipc: private` (no shareable IPC) | Medium |
| Gateway API compromise | Limited egress, DNS-filtered, internal network only | Medium |
| Secrets committed to git | TruffleHog pre-commit hook (800+ detectors, entropy analysis) + scan-secrets.sh | High |
| Cloudflare tunnel token leak | Token in .env (mode 600), not in image | Medium |
| Tailscale auth key leak | Key in .env (mode 600), reusable keys scoped by tag ACLs | Medium |
| Telemetry data exfiltration | Telemetry disabled by default (opt-in); no credentials or PII transmitted when enabled | Low |
| LiteLLM proxy compromise | Internal network only, stateless (no DB), read-only root, all caps dropped, internal-only master key | Low |
| Log viewer exposes sensitive data | Dozzle bound to 127.0.0.1, monitor profile only, DOZZLE_FILTER=opendeclawed-*, read-only socket, no analytics | Low |
| Agent web search data leak | SearXNG self-hosted (no third-party search API keys), DNS-filtered via blocky, egress-firewall controlled | Medium |
| Resource exhaustion (CPU/memory) | Deploy resource limits and reservations on every container | Medium |

### Not Mitigated (Accepted Risks)

- **Novel C2 domains**: blocky blocks known-bad domains but cannot catch zero-day C2 infrastructure
- **Full outbound internet**: Egress blocks RFC1918 but allows public internet (necessary for API calls)
- **Egress-firewall privileges**: Requires `network_mode: host` + `NET_ADMIN` — mitigated by Alpine digest pinning + Trivy scanning
- **docker inspect secret leakage**: Users in the docker group can read env vars via `docker inspect` — mitigated by socket proxy for automated tools
- **API authentication**: Local mode has token auth only; tunnel mode adds Cloudflare Access (GitHub OAuth) as a pre-authentication gate
- **Encryption in transit**: Local mode uses unencrypted HTTP on 127.0.0.1; tunnel mode uses HTTPS via Cloudflare with `allowInsecureAuth: true` (safe — see [Tunnel Mode](#tunnel-mode---profile-tunnel)); Tailscale mode uses WireGuard + auto-TLS
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

### Least-Privileged User

Services run as the least-privileged user their function allows. Most run as **65534:65534** (nobody:nogroup), but some require elevated users for specific operations:

| Service | User | Why |
|---------|------|-----|
| litellm | 65534:65534 | No special file access needed |
| cloudflared | 65534:65534 | No special file access needed |
| blocky | 65534:65534 | No special file access needed |
| dozzle | 65534:65534 | No special file access needed |
| openclaw-gateway | 1000:1000 | Upstream image sets USER node (uid 1000); must match for /app file access |
| openclaw-cli | 1000:1000 | Same upstream image as gateway |
| egress-firewall | root | Required for iptables rule installation via `apk add` and `iptables` |
| docker-socket-proxy | root | Required for binding to port 2375 and Docker socket access |
| watchtower | root | Required for Docker API interactions via socket proxy |
| searxng | 65534:65534 | No special file access needed |
| tailscale | root | Required for WireGuard tunnel setup (NET_ADMIN) |

**Effect** (for unprivileged services):
- Cannot create files in directories owned by root
- Cannot access files with restrictive permissions
- Reduces impact of container breakout

### Dropped Capabilities

All services drop **ALL** capabilities, then selectively add only what is required:

```yaml
cap_drop:
  - ALL
cap_add:
  - <only what's needed>
```

Per-service capability grants:

| Service | Capability | Why |
|---------|-----------|-----|
| egress-firewall | NET_ADMIN, NET_RAW | Modify iptables rules |
| litellm | None | No special permissions needed |
| openclaw-gateway | NET_BIND_SERVICE | Bind to ports <1024 (if configured) |
| cloudflared | None | No special permissions needed |
| tailscale | NET_ADMIN, NET_RAW | WireGuard tunnel setup |
| docker-socket-proxy | None | No special permissions needed |
| blocky | NET_BIND_SERVICE | Bind to DNS port 53 |
| watchtower | None | No special permissions needed |
| dozzle | None | No special permissions needed |
| searxng | None | No special permissions needed |
| openclaw-cli | NET_RAW | Ping/traceroute diagnostics |

**Linux capabilities reference**:
- **CAP_NET_ADMIN**: Modify network rules (iptables, routing)
- **CAP_NET_RAW**: Raw socket access (ping, traceroute, packet crafting)
- **CAP_NET_BIND_SERVICE**: Bind sockets to ports <1024
- **CAP_SETUID/SETGID**: Change process user/group
- **CAP_SYS_ADMIN**: Admin operations (mount, namespace, etc.)
- **Others**: Not needed for this deployment

### Read-Only Filesystems

Most services mount root filesystem as read-only:

```yaml
read_only: true
```

**Exceptions**:
- **egress-firewall**: Needs writable root for `apk add iptables` at startup. Mitigated by Alpine image pinned by tag and Trivy scanning.
- **docker-socket-proxy**: Needs writable root because its entrypoint generates `haproxy.cfg` from a template. Mitigated by cap_drop ALL and no-new-privileges.
- **openclaw-gateway**: Node.js app writes temp files to `/app/.cache`, etc. Mitigated by no-new-privileges, cap_drop ALL, non-root user (1000:1000), and tmpfs mounts.
- **openclaw-cli**: Interactive debugging container; same image as gateway.

Services with `read_only: true` allow write access only where needed:

```yaml
volumes:
  - ~/.openclaw:/home/node/.openclaw:rw  # Gateway config (bind mount)
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

### Isolated IPC Namespaces

```yaml
ipc: private       # All services: no shared memory between containers
```

**IPC modes**:
- **private**: Cannot use System V semaphores, message queues, shared memory with other containers
- **host**: Can access host IPC (dangerous, not used)

## Network Isolation

### Network Architecture

```
openclaw-internal (internal=true, 172.27.0.0/24)
├── litellm            (LLM router, internal only)
├── openclaw-gateway   (bridges internal + egress)
├── blocky             (DNS firewall, pinned to 172.27.0.53)
├── docker-socket-proxy (Docker API filter, internal only)
├── watchtower         (auto-updater, internal only)
├── dozzle             (log viewer, bridges internal + egress)
├── cloudflared        (tunnel, bridges internal + egress)
├── tailscale          (mesh VPN, bridges internal + egress)
├── searxng             (metasearch, bridges internal + egress)
└── openclaw-cli       (debugging, bridges internal + egress)

openclaw-egress (172.28.0.0/24)
├── openclaw-gateway   (outbound API calls, egress-firewall controlled)
├── blocky             (upstream DoH resolution)
├── cloudflared        (Cloudflare edge connectivity)
├── tailscale          (WireGuard tunnel)
├── dozzle             (port binding on 127.0.0.1:5005)
├── searxng             (upstream search engine queries)
└── openclaw-cli       (network diagnostics)

host network
└── egress-firewall    (network_mode: host, iptables DOCKER-USER rules)

docker0 (host bridge)
└── Only for Docker infrastructure
```

### Why Two Networks?

**openclaw-internal** (internal=true):
- Internal services isolated from internet (LLM backends run externally via Ollama)
- Gateway can reach both networks (broker model)
- Enforced at bridge level (no internet route)

**openclaw-egress**:
- Gateway needs outbound access (external API calls)
- Subject to egress firewall rules (no RFC1918)
- Cloudflared needs access to Cloudflare edge
- Blocky needs outbound for upstream DoH DNS resolution
- Tailscale needs outbound for WireGuard coordination
- SearXNG needs outbound for upstream search engine queries
- Dozzle and openclaw-cli also bridge both networks
- Allows legitimate external traffic with restrictions

### IP Addressing

- **internal network**: 172.27.0.0/24 (configurable: INTERNAL_SUBNET)
- **egress network**: 172.28.0.0/24 (configurable: EGRESS_SUBNET)
- **docker0 (host bridge)**: 172.17.0.0/16 (Docker default)

Use non-overlapping ranges to avoid conflicts.

### DNS Resolution & Bypass Prevention

DNS is restricted to two allowed destinations:

```bash
# Only Blocky (172.27.0.53) and Docker's internal resolver (127.0.0.11)
iptables -A DOCKER-USER -p udp --dport 53 -d 172.27.0.53 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 53 -d 172.27.0.53 -j ACCEPT
iptables -A DOCKER-USER -p udp --dport 53 -d 127.0.0.11 -j ACCEPT
iptables -A DOCKER-USER -p tcp --dport 53 -d 127.0.0.11 -j ACCEPT
# All other DNS traffic is dropped
iptables -A DOCKER-USER -p udp --dport 53 -j DROP
iptables -A DOCKER-USER -p tcp --dport 53 -j DROP
```

**Why restrict DNS?**
- Containers must use Blocky for DNS, which applies threat blocklists (malware, phishing, cryptomining)
- Unrestricted port 53 access would let a compromised container bypass Blocky entirely
- Docker's 127.0.0.11 resolver is allowed for container name resolution

**DNS-over-HTTPS (DoH) prevention:**

Well-known public DNS resolvers are blocked on all ports to prevent DoH bypass:
- Google: 8.8.8.8, 8.8.4.4
- Cloudflare: 1.1.1.1, 1.0.0.1
- Quad9: 9.9.9.9, 149.112.112.112
- OpenDNS: 208.67.222.222, 208.67.220.220
- AdGuard: 94.140.14.14, 94.140.15.15
- Control D: 76.76.2.0, 76.76.10.0

**Note**: DoH to non-blocked resolvers remains a theoretical bypass vector. Blocky itself uses DoH upstream for its own resolution (via the egress network).

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
2. Cloudflare Access enforces GitHub OAuth authentication
3. Authenticated traffic routes through tunnel to gateway
4. HTTPS encryption provided by Cloudflare (edge-to-user and edge-to-tunnel)

**Security advantages**:
- No host port exposure
- DDoS protection via Cloudflare
- Free SSL/TLS certificate
- Pre-authenticated access via Cloudflare Access + GitHub OAuth
- Easy to enable/disable

#### allowInsecureAuth in Tunnel Mode

In tunnel mode, `allowInsecureAuth` is set to `true` in the generated `openclaw.json`. This enables code-based device pairing over HTTP between the gateway and the tunnel connector (both running on the same Docker network).

**Why this is safe:**
- The gateway is **not** exposed to the internet directly. The only ingress path is through the Cloudflare Tunnel.
- Cloudflare Access enforces **GitHub OAuth authentication** before any request reaches the tunnel. Unauthenticated users are redirected to the OAuth login page and never reach the gateway.
- All traffic between the user's browser and Cloudflare is **HTTPS-encrypted**.
- The gateway **token** (`?token=...`) is still required for pairing, providing a second authentication factor.
- The HTTP segment is purely internal: tunnel connector (cloudflared) to gateway, both on the same `openclaw-internal` Docker network with no internet route.

**Why other modes default to `false`:**
- **Local mode**: Traffic is plaintext HTTP on `127.0.0.1`. While only accessible locally, pairing codes could be observed by other processes on the host.
- **Tailscale mode**: WireGuard provides transport encryption, but there is no pre-authentication gate equivalent to Cloudflare Access. As defense-in-depth, `allowInsecureAuth` remains `false`.

### mDNS/Bonjour Discovery

The OpenClaw gateway broadcasts its presence via mDNS by default, which can leak operational details (filesystem paths, SSH ports, CLI paths) to the local network. Since the gateway runs inside a Docker container with no need for local network discovery, OpenDeclawed disables this entirely:

```json
{
  "discovery": {
    "mdns": {
      "mode": "off"
    }
  }
}
```

This is set automatically by `setup.sh` for all ingress modes.

### Security Audit

OpenClaw provides a built-in security audit tool. Run it after deployment to verify the configuration:

```bash
docker compose --profile cli run --rm openclaw-cli openclaw security audit --deep
```

The `--fix` flag can automatically tighten permissive settings. The `--deep` flag performs live probing of the running gateway.

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

If the format doesn't match, the user is warned and can either re-enter or explicitly accept (for edge cases like OAuth tokens in place of API keys).

**7. Pre-commit secrets detection (TruffleHog)**

TruffleHog scans every commit for leaked credentials before they reach git history. It covers 800+ detector patterns (including Anthropic API keys, Cloudflare tokens, Telegram bot tokens natively) plus high-entropy string detection.

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
  - [ ] Verify all containers run as least-privileged user (see user table above)
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
ls -la ~/.openclaw

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
docker exec opendeclawed-gateway curl -sf http://api.example.com 2>&1

# 3. Check firewall rules
docker exec opendeclawed-egress-firewall iptables -L DOCKER-USER -vn

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
docker exec opendeclawed-gateway nslookup tunnel.cloudflare.com

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
