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
