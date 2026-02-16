# Contributing to OpenDeclawed

Thanks for your interest in contributing! This project aims to provide a secure, hardened Docker deployment for OpenClaw. We welcome contributions that improve security, add ingress options, expand platform support, or enhance documentation.

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.** Please refer to [SECURITY.md](./SECURITY.md) for responsible disclosure procedures.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally: `git clone https://github.com/YOUR_USERNAME/opendeclawed.git`
3. **Create a branch** for your work: `git checkout -b feature/your-feature-name`
4. **Make your changes** and test thoroughly
5. **Push** to your fork and **open a pull request** against the main repository

## What We're Looking For

### We enthusiastically welcome:

- **Security hardening improvements** — stricter defaults, better isolation, reduced attack surface
- **Ingress options** — Caddy, Traefik, Headscale, or other secure ingress layers (Cloudflare Tunnel and Tailscale are already supported)
- **Platform support** — ARM64, NixOS, Kubernetes, or other deployment targets
- **Model configuration examples** — documentation and templates for different AI models
- **Bug fixes** — include clear reproduction steps and rationale
- **Documentation improvements** — clearer setup instructions, security guidelines, troubleshooting

### We probably won't merge:

- Relaxing security defaults (e.g., `cap_add`, removing `read_only`, disabling user namespaces)
- Services requiring direct Docker socket access (use the socket proxy pattern instead)
- Vendor-specific integrations that add complexity without clear benefit
- Changes that conflict with the hardened-by-default philosophy

## Security Patterns

When contributing new services or modifying existing ones, follow these established patterns:

### Persistent firewall sidecar
The egress firewall runs as a `restart: unless-stopped` sidecar with a 60-second re-check loop — not a one-shot init container. This ensures iptables rules survive Docker daemon restarts. New egress rules should be idempotent (check before insert) and added to the sidecar's entrypoint.

### Docker socket proxy
Never mount `/var/run/docker.sock` directly into application containers. Route Docker API access through `tecnativa/docker-socket-proxy` with least-privilege environment flags. Deny `EXEC`, `VOLUMES`, `NETWORKS`, `SECRETS` unless there's an explicit need.

### DNS filtering via blocky
All containers on the egress network should use `dns: blocky` for DNS resolution. If your service needs to reach a new external domain, add it to the allowlist in `examples/blocky-config.yml` and document why.

### Shell injection prevention
Never use `eval` for variable assignment in shell scripts. Use `printf -v "$var_name" '%s' "$value"` instead. When embedding secrets in heredocs, use quoted heredocs (`'EOF'`) and pass secrets via environment variables — never shell interpolation.

### TOCTOU-safe installation
When downloading and installing external artifacts (skills, plugins, models), always verify the local copy and install from the verified bytes. Never re-download after verification — that creates a time-of-check-time-of-use gap.

### Zip-slip protection
When extracting archives, validate all paths before extraction using `tar tzf` + `os.path.normpath`. Reject entries containing `../` or absolute paths.

### Container hardening baseline
Every new container must include: `read_only: true`, `cap_drop: ALL`, `no_new_privileges: true`, `user: "65534:65534"`, `ipc: private`, resource limits (`mem_limit`, `cpus`, `pids_limit`), and `noexec,nosuid,nodev` on tmpfs mounts.

### Secrets detection (TruffleHog)
A pre-commit hook runs TruffleHog on every commit to catch leaked API keys, tokens, and high-entropy strings. Install with `pre-commit install` after cloning. For manual scans: `./scripts/scan-secrets.sh`. If your change triggers a false positive, add the path to `.trufflehog-config.yaml`.

## Testing Expectations

Before opening a pull request:

1. **Test on at least one platform:**
   - OrbStack (macOS)
   - Docker Desktop (macOS/Windows)
   - Native Linux (Ubuntu, Debian, Fedora, etc.)

2. **Verify egress firewall rules** — ensure that any new outbound connections work as intended with the existing egress filters

3. **Validate YAML:** Run `docker compose config` to catch syntax errors

4. **Run secrets scan:** `./scripts/scan-secrets.sh` — ensure no credentials are committed

5. **Document platform-specific gotchas** — note any OS or architecture differences in your PR description

## Code Style

- **Compose files:** Keep them well-commented. Explain why security options are set the way they are.
- **Scripts:** Write POSIX-compatible shell scripts where possible. Avoid Bash-isms unless necessary. Include comments for complex logic.
- **Environment variables:** Use `.env.example` for new configuration options and document their purpose.

## License

By contributing, you agree that your work will be licensed under the [MIT License](./LICENSE).

## Questions?

Open an issue to discuss your idea before investing significant effort. We're happy to provide feedback early.
