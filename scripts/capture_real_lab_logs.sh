#!/usr/bin/env bash
# Capture controlled lab logs from generated PCAP replay.
#
# These logs are real controlled-lab artifacts produced from local commands and
# protocol-valid generated PCAPs. They are sanitized and deterministic. They are
# not enterprise production logs and must not be described as such.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$PROJECT_ROOT/data/logs/real_lab_logs}"
PCAP_DIR="${PCAP_DIR:-$PROJECT_ROOT/tests/pcaps/generated}"
RULES_FILE="${RULES_FILE:-$PROJECT_ROOT/data/processed/person1_rules_snort3.rules}"
SNORT_BIN="${SNORT_BIN:-$PROJECT_ROOT/tools/snort3-docker}"
SNORT_CONFIG="${SNORT_CONFIG:-/home/snorty/snort3/etc/snort/snort.lua}"

mkdir -p "$OUT_DIR"

container_path() {
  local path="$1"
  if [[ "$SNORT_BIN" == *"tools/snort3-docker" && "$path" == "$PROJECT_ROOT"* ]]; then
    printf '/work/%s' "${path#$PROJECT_ROOT/}"
  else
    printf '%s' "$path"
  fi
}

RULES_ARG="$(container_path "$RULES_FILE")"
SNORT_ALERT_LOG="$OUT_DIR/snort_alert_fast.log"
: > "$SNORT_ALERT_LOG"

for pcap in "$PCAP_DIR"/*.pcap; do
  scenario="$(basename "$pcap" .pcap)"
  pcap_arg="$(container_path "$pcap")"
  {
    echo "### scenario=$scenario pcap=$pcap"
    "$SNORT_BIN" -q -r "$pcap_arg" -R "$RULES_ARG" -A alert_fast -c "$SNORT_CONFIG"
    echo
  } >> "$SNORT_ALERT_LOG"
done

PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" python - "$PROJECT_ROOT" "$OUT_DIR" "$PCAP_DIR" <<'PY'
from __future__ import annotations

import csv
import sys
from pathlib import Path

try:
    from scapy.all import DNS, ICMP, IP, Raw, TCP, UDP, rdpcap  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"scapy is required to parse generated lab PCAPs: {exc}")

project_root = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
pcap_dir = Path(sys.argv[3])

rows: list[dict[str, str]] = []
http_lines: list[str] = []
ssh_lines: list[str] = []
dns_lines: list[str] = []
icmp_lines: list[str] = []

expected_labels = {
    "benign_traffic": "benign",
}


def add_row(log_id: str, attack_type: str, log_example: str, source_file: str, method: str) -> None:
    rows.append({
        "id": log_id,
        "attack_type": attack_type,
        "expected_label": expected_labels.get(attack_type, "malicious"),
        "log_example": log_example,
        "source_file": source_file,
        "capture_method": method,
    })


for pcap_path in sorted(pcap_dir.glob("*.pcap")):
    attack_type = pcap_path.stem
    packets = rdpcap(str(pcap_path))
    source_file = pcap_path.name

    if attack_type in {"sql_injection", "xss", "command_injection", "directory_traversal", "malware_c2", "benign_traffic"}:
        for packet in packets:
            if packet.haslayer(Raw) and packet.haslayer(TCP):
                payload = bytes(packet[Raw].load).decode("latin-1", errors="replace")
                if payload.startswith("GET "):
                    request = payload.splitlines()[0]
                    src = packet[IP].src
                    dst = packet[IP].dst
                    dport = int(packet[TCP].dport)
                    line = (
                        f'lab-http src={src} dst={dst} dpt={dport} request="{request}" '
                        f'scenario={attack_type} source_pcap={source_file}'
                    )
                    http_lines.append(line)
                    add_row(f"REAL-LAB-{attack_type.upper().replace('_', '-')}", attack_type, line, "http_access.log", "parsed_from_lab_pcap_payload")
                    break

    elif attack_type == "ssh_bruteforce":
        ssh_payloads = 0
        src = dst = ""
        for packet in packets:
            if packet.haslayer(Raw) and packet.haslayer(TCP) and int(packet[TCP].dport) == 22:
                payload = bytes(packet[Raw].load).decode("latin-1", errors="replace")
                if "SSH-2.0" in payload:
                    ssh_payloads += 1
                    src = packet[IP].src
                    dst = packet[IP].dst
        line = (
            f"lab-sshd sshd[2200]: Failed password for admin from {src} "
            f"to {dst} repeated={ssh_payloads} scenario=ssh_bruteforce source_pcap={source_file}"
        )
        ssh_lines.append(line)
        add_row("REAL-LAB-SSH-BRUTEFORCE", attack_type, line, "ssh_auth.log", "derived_from_lab_pcap_ssh_payload_count")

    elif attack_type == "dns_tunneling":
        for packet in packets:
            if packet.haslayer(DNS) and packet.haslayer(UDP):
                qname = packet[DNS].qd.qname.decode("latin-1", errors="replace").rstrip(".") if packet[DNS].qd else ""
                line = (
                    f"lab-dns src={packet[IP].src} dst={packet[IP].dst} qtype=A "
                    f"query={qname} note=long DNS query encoded subdomain scenario=dns_tunneling source_pcap={source_file}"
                )
                dns_lines.append(line)
                add_row("REAL-LAB-DNS-TUNNELING", attack_type, line, "dns_lab.log", "parsed_from_lab_pcap_dns_query")
                break

    elif attack_type == "icmp_sweep":
        echo_requests = [
            packet for packet in packets
            if packet.haslayer(ICMP) and int(packet[ICMP].type) == 8 and packet.haslayer(IP)
        ]
        targets = sorted({packet[IP].dst for packet in echo_requests})
        src = echo_requests[0][IP].src if echo_requests else ""
        line = (
            f"lab-icmp src={src} targets={','.join(targets[:5])} target_count={len(targets)} "
            f"type=echo-request note=ICMP ping sweep scenario=icmp_sweep source_pcap={source_file}"
        )
        icmp_lines.append(line)
        add_row("REAL-LAB-ICMP-SWEEP", attack_type, line, "icmp_lab.log", "parsed_from_lab_pcap_icmp_echo_requests")

    elif attack_type == "port_scan":
        syn_packets = [
            packet for packet in packets
            if packet.haslayer(TCP) and packet.haslayer(IP) and int(packet[TCP].flags) & 0x02
        ]
        ports = sorted({str(int(packet[TCP].dport)) for packet in syn_packets})
        src = syn_packets[0][IP].src if syn_packets else ""
        dst = syn_packets[0][IP].dst if syn_packets else ""
        line = (
            f"lab-fw scan_event src={src} dst={dst} flags=SYN scan_ports={','.join(ports)} "
            f"note=multiple ports scenario=port_scan source_pcap={source_file}"
        )
        http_lines.append(line)
        add_row("REAL-LAB-PORT-SCAN", attack_type, line, "http_access.log", "parsed_from_lab_pcap_syn_scan")


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


write_lines(out_dir / "http_access.log", http_lines)
write_lines(out_dir / "ssh_auth.log", ssh_lines)
write_lines(out_dir / "dns_lab.log", dns_lines)
write_lines(out_dir / "icmp_lab.log", icmp_lines)

fieldnames = ["id", "attack_type", "expected_label", "log_example", "source_file", "capture_method"]
with (out_dir / "real_lab_logs_index.csv").open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(sorted(rows, key=lambda row: row["attack_type"]))

(out_dir / "README.md").write_text(
    "# Real Lab Logs\n\n"
    "These logs are sanitized controlled-lab artifacts generated from local PCAP replay and PCAP parsing commands. "
    "They demonstrate executable integration with lab-captured logs, not enterprise production telemetry.\n\n"
    "- `snort_alert_fast.log`: Snort alert output captured by replaying generated PCAPs through Snort 3.\n"
    "- `http_access.log`: HTTP/access-style and firewall-style lines parsed from controlled lab PCAP payloads.\n"
    "- `ssh_auth.log`: SSH auth-style summary derived from SSH lab PCAP payload counts.\n"
    "- `dns_lab.log`: DNS query log line parsed from the DNS tunneling lab PCAP.\n"
    "- `icmp_lab.log`: ICMP sweep summary parsed from ICMP lab packets.\n"
    "- `real_lab_logs_index.csv`: normalized index used by `scripts/run_real_log_integration_eval.py`.\n",
    encoding="utf-8",
)

print(f"Wrote {len(rows)} normalized real-lab log rows to {out_dir / 'real_lab_logs_index.csv'}")
PY

echo "Wrote controlled lab logs to $OUT_DIR"
