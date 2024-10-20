#!/usr/bin/env bash
# IPv6 Defensive Firewall Rule Set (ip6tables)
# Author: Fahd BELHIBA

set -euo pipefail

echo "[+] Flushing existing ip6tables rules..."
ip6tables -F
ip6tables -X
ip6tables -Z

# Default Policies
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT ACCEPT

# Allow Loopback Interface
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# Allow Established and Related Traffic
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Essential ICMPv6 Traffic (Neighbor Discovery & Ping)
ip6tables -A INPUT -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -m limit --limit 5/sec -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-reply -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT
ip6tables -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Log & Drop Unwanted IPv6 Traffic
ip6tables -A INPUT -j LOG --log-prefix "IP6-DROP: " --log-level 4
ip6tables -A INPUT -j DROP

echo "[✓] IPv6 ip6tables firewall rules active."
