#!/usr/bin/env bash
# Automated IPv6 Security Hardening Script for Embedded Linux Nodes
# Author: Fahd BELHIBA

set -euo pipefail

echo "[+] Applying sysctl IPv6 security parameters..."

# Load sysctl hardening parameters
SYSCTL_CONF="/etc/sysctl.d/99-ipv6-security-hardening.conf"

cat << 'EOF' > "${SYSCTL_CONF}"
# Disable IPv6 Source Routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 ICMP Redirects to prevent MitM routing attacks
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.send_redirects = 0
net.ipv6.conf.default.send_redirects = 0

# Enable Privacy Extensions (RFC 4941 / RFC 8981) - prefer temporary address
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2

# Limit Maximum Router Advertisement Hops
net.ipv6.conf.all.accept_ra = 1
net.ipv6.conf.default.accept_ra = 1
EOF

sysctl --system > /dev/null 2>&1 || sysctl -p "${SYSCTL_CONF}"

echo "[✓] IPv6 sysctl hardening applied successfully."
