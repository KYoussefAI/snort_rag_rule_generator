#!/usr/bin/env python
"""Generate tiny synthetic lab PCAP placeholders for Snort replay workflows.

The packets are synthetic Ethernet/IP/TCP/UDP/ICMP frames with educational
payloads. They are not captured real traffic and must not be described as
production network evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import time


SCENARIOS = {
    "port_scan": b"SYN scan lab packet",
    "ssh_bruteforce": b"SSH-2.0 repeated login lab packet",
    "sql_injection": b"GET /search?q=union%20select HTTP/1.1\r\nHost: lab\r\n\r\n",
    "xss": b"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: lab\r\n\r\n",
    "command_injection": b"GET /?cmd=whoami;id HTTP/1.1\r\nHost: lab\r\n\r\n",
    "directory_traversal": b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: lab\r\n\r\n",
    "dns_tunneling": b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.lab.example",
    "icmp_sweep": b"ICMP echo sweep lab packet",
    "malware_c2": b"GET /gate.php HTTP/1.1\r\nHost: c2.lab\r\nUser-Agent: lab-beacon\r\n\r\n",
    "benign_traffic": b"GET /health HTTP/1.1\r\nHost: lab\r\n\r\n",
}


def _write_pcap(path: Path, payload: bytes) -> None:
    ts = int(time.time())
    frame = b"\x00" * 14 + payload
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        handle.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
        handle.write(frame)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=Path("tests") / "pcaps" / "generated")
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for scenario, payload in SCENARIOS.items():
        path = out_dir / f"{scenario}.pcap"
        _write_pcap(path, payload)
        manifest.append({
            "pcap": str(path),
            "scenario": scenario,
            "synthetic": True,
            "expected_attack_type": scenario,
        })
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {len(manifest)} synthetic lab PCAP files to {out_dir}")


if __name__ == "__main__":
    main()
