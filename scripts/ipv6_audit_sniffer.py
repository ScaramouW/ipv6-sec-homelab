#!/usr/bin/env python3
"""
IPv6 ICMPv6 & NDP Traffic Auditor
Author: Fahd BELHIBA
Description: Real-time sniffer to audit Neighbor Discovery Protocol (NDP),
Router Advertisements (RA), and ICMPv6 anomalies on Linux and Android interfaces.
"""

import sys
import argparse
from datetime import datetime

try:
    from scapy.all import sniff, IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptPrefixInfo
except ImportError:
    print("[!] Error: Scapy is required. Run 'pip install scapy' to install.")
    sys.exit(1)

def audit_packet(packet):
    if not packet.haslayer(IPv6):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IPv6].src
    dst_ip = packet[IPv6].dst

    # Check Router Advertisement (RA)
    if packet.haslayer(ICMPv6ND_RA):
        ra = packet[ICMPv6ND_RA]
        print(f"[{timestamp}] [ALERT - RA] Router Advertisement from {src_ip} -> {dst_ip}")
        print(f"    ├─ Hop Limit: {ra.chlim}")
        print(f"    ├─ M-Flag (Managed): {ra.M} | O-Flag (Other): {ra.O}")
        print(f"    └─ Router Lifetime: {ra.routerlifetime}s")
        if packet.haslayer(ICMPv6NDOptPrefixInfo):
            prefix_info = packet[ICMPv6NDOptPrefixInfo]
            print(f"    └─ Advertised Prefix: {prefix_info.prefix}/{prefix_info.prefixlen}")

    # Check Neighbor Solicitation (NS)
    elif packet.haslayer(ICMPv6ND_NS):
        ns = packet[ICMPv6ND_NS]
        print(f"[{timestamp}] [NDP - NS] Neighbor Solicitation: {src_ip} probing {ns.tgt}")

    # Check Neighbor Advertisement (NA)
    elif packet.haslayer(ICMPv6ND_NA):
        na = packet[ICMPv6ND_NA]
        is_override = bool(na.O)
        is_router = bool(na.R)
        flag_str = f"R={is_router}, S={na.S}, O={is_override}"
        print(f"[{timestamp}] [NDP - NA] Neighbor Advertisement: {src_ip} ({flag_str}) target {na.tgt}")

def main():
    parser = argparse.ArgumentParser(description="IPv6 ICMPv6 & NDP Traffic Audit Tool")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to sniff on (default: eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    print(f"[*] Starting IPv6 ICMPv6/NDP Audit Sniffer on interface: {args.interface}")
    print("[*] Monitoring Router Advertisements (RA), Neighbor Solicitations (NS), and Advertisements (NA)...")
    print("-" * 75)

    try:
        sniff(iface=args.interface, filter="icmp6", prn=audit_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        print("\n[*] Audit session terminated by user.")
    except Exception as e:
        print(f"[!] Error sniffing interface {args.interface}: {e}")

if __name__ == "__main__":
    main()
