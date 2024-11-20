# 🌐 IPv6 Compatibility & Security Hardening Home Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Linux / Android AOSP](https://img.shields.io/badge/Platform-Embedded_Linux_%7C_Android_AOSP-green.svg)]()
[![Tools: Wireshark / tcpdump / Scapy](https://img.shields.io/badge/Tools-Wireshark_%7C_tcpdump_%7C_Scapy-orange.svg)]()

## 📌 Executive Overview
This repository contains the source code, security configuration templates, packet analysis tooling, and audit reports for the **IPv6 Compatibility & Hardening Testbed Project**.

The primary objective of this project is to evaluate, audit, and harden IPv6 protocol stack implementations across **Embedded Linux** (Debian/Yocto/Ubuntu) and **Android (AOSP)** platforms.

---

## 🛠️ Key Technical Features

1. **ICMPv6 & NDP Hardening**: Mitigation scripts against rogue Router Advertisements (RAs) and Neighbor Discovery Protocol (NDP) spoofing/cache poisoning.
2. **Privacy Extensions (RFC 8981 / RFC 4941)**: Automated dynamic interface identifier generation to prevent user tracking across subnets.
3. **Kernel Level Hardening (`sysctl`)**: Production-ready security profiles disabling IPv6 source routing, restricting ICMP redirects, and enforcing strict reverse path filtering.
4. **Network Traffic Auditing (`ipv6_audit_sniffer.py`)**: Python Scapy sniffer targeting ICMPv6 Neighbor Solicitations (NS), Neighbor Advertisements (NA), and Router Solicitations (RS).
5. **Firewall Rule Sets (`ip6tables` / `nftables`)**: Strict IPv6 input/forwarding policies designed for embedded mobile gateways.

---

## 📂 Project Architecture

```
ipv6-sec-homelab/
├── README.md
├── configs/
│   ├── sysctl-ipv6-hardening.conf     # Production sysctl parameters for IPv6
│   └── ip6tables_rules.sh            # Defensive ip6tables firewall script
├── scripts/
│   ├── apply_ipv6_hardening.sh       # Automated Linux kernel hardening runner
│   └── ipv6_audit_sniffer.py         # Real-time ICMPv6 / NDP audit script (Scapy)
└── docs/
    └── IPv6_Security_Audit_Report.md  # Detailed RFC compliance & vulnerability analysis report
```

---

## ⚡ Quick Start

### 1. Run Automated IPv6 Kernel Hardening
```bash
chmod +x scripts/apply_ipv6_hardening.sh
sudo ./scripts/apply_ipv6_hardening.sh
```

### 2. Launch ICMPv6 Packet Auditor
```bash
# Ensure Scapy is installed
pip install scapy

# Execute packet capture audit (requires root / CAP_NET_RAW)
sudo python3 scripts/ipv6_audit_sniffer.py --interface eth0
```

### 3. Deploy IPv6 Firewall Rules
```bash
chmod +x configs/ip6tables_rules.sh
sudo ./configs/ip6tables_rules.sh
```

---

## 📊 Comparative Platform Matrix

| Platform | IPv6 Privacy Ext. | RA Guard | Systemd-networkd / netd | Hardening Status |
| :--- | :---: | :---: | :---: | :---: |
| **Embedded Linux** | ✅ Enforced (`tempaddr=2`) | ✅ Sysctl + Firewall | Native `systemd-networkd` | **Hardened** |
| **Android AOSP** | ✅ Managed by `netd` | ✅ Kernel + SELinux | Native `netd` daemon | **Patched & Verified** |

---

## 👤 Author & Contact
- **Author:** Fahd BELHIBA
- **Degree:** Master Student in IT for Smart & Sustainable Mobility (INSA Hauts-de-France)
- **Email:** `belhibafahed@outlook.fr`
- **GitHub:** [@ScaramouW](https://github.com/ScaramouW)
