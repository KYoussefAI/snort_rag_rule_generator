#!/usr/bin/env python
"""Evaluate realistic network logs against generated Snort RAG evidence.

The script does not execute Snort or synthesize alert counts. It connects the
sample network logs to existing generated-rule artifacts and real PCAP replay
results so the log-to-rule integration path is executable and auditable.
"""
from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path
from typing import Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACK_ORDER = [
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
FIELDNAMES = [
    "log_id",
    "raw_log",
    "expected_attack_type",
    "expected_label",
    "predicted_attack_type",
    "matched_query",
    "retrieved_context_used",
    "source_doc_ids",
    "generated_rule",
    "generated_sid",
    "rule_status",
    "snort3_rule_exists",
    "pcap_scenario",
    "pcap_alert_count",
    "pcap_triggered_sids",
    "final_status",
    "notes",
]
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [{key: value or "" for key, value in row.items()} for row in csv.DictReader(handle)]


def extract_sid(rule: str) -> str:
    match = SID_RE.search(rule or "")
    return match.group(1) if match else ""


def load_snort3_sids(path: Path) -> set[str]:
    return {sid for sid in (extract_sid(line) for line in path.read_text(encoding="utf-8").splitlines()) if sid}


def predict_attack_type(raw_log: str) -> str:
    text = raw_log.lower()
    if any(token in text for token in ("union select", " or 1=1", " sql", "information_schema", "sqlmap")):
        return "sql_injection"
    if any(token in text for token in ("<script", "alert(1)", "onerror", "<svg", "javascript:")):
        return "xss"
    if any(token in text for token in ("cmd=", "whoami", "wget", "curl", ";id", "; id", "/bin/sh", "powershell")):
        return "command_injection"
    if any(token in text for token in ("../", "..%2f", "passwd", "win.ini")):
        return "directory_traversal"
    if any(token in text for token in ("long dns query", "encoded subdomain", "dns tunnel", "long subdomain", "base64 burst", "segment")):
        return "dns_tunneling"
    if any(token in text for token in ("icmp", "echo request", "echo-request", "ping sweep")):
        return "icmp_sweep"
    if any(token in text for token in ("gate.php", "beacon", " c2", "command and control", "callback")):
        return "malware_c2"
    if any(token in text for token in ("ssh", "login failures", "failed password", "brute force", "bruteforce")):
        return "ssh_bruteforce"
    if any(token in text for token in ("scan", "syn", "multiple ports", "scan_ports")):
        return "port_scan"
    if any(token in text for token in ("health", "normal https", "normal user", "successful get", "no suspicious marker", "category=benign")):
        return "benign_traffic"
    return "benign_traffic"


def representative_logs(rows: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    by_attack: dict[str, dict[str, str]] = {}
    for row in rows:
        attack_type = row.get("attack_type", "")
        if attack_type and attack_type not in by_attack:
            by_attack[attack_type] = row

    selected = [by_attack[attack] for attack in ATTACK_ORDER if attack in by_attack]
    if "benign_traffic" not in by_attack:
        selected.append({
            "id": "SYNTHETIC-BENIGN-LOG-EVAL",
            "attack_type": "benign_traffic",
            "expected_label": "benign",
            "log_example": "Synthetic evaluation-only benign log: successful GET /health over normal HTTPS with no suspicious marker.",
        })
    return selected


def generated_examples_by_attack(rows: Iterable[dict[str, str]]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for row in rows:
        attack_type = row.get("attack_type", "")
        if attack_type and attack_type not in output:
            output[attack_type] = row
    return output


def pcap_results_by_attack(rows: Iterable[dict[str, str]]) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for row in rows:
        expected = row.get("expected_attack", "")
        if expected:
            output[expected] = row
    return output


def build_eval_rows(
    log_rows: list[dict[str, str]],
    generated_rows: list[dict[str, str]],
    pcap_rows: list[dict[str, str]],
    snort3_sids: set[str],
) -> list[dict[str, str]]:
    generated_by_attack = generated_examples_by_attack(generated_rows)
    pcap_by_attack = pcap_results_by_attack(pcap_rows)
    output: list[dict[str, str]] = []

    for log_row in representative_logs(log_rows):
        expected_attack = log_row.get("attack_type", "")
        raw_log = log_row.get("log_example", "")
        expected_label = log_row.get("expected_label", "")
        predicted_attack = predict_attack_type(raw_log)
        generated = generated_by_attack.get(predicted_attack, {})
        pcap = pcap_by_attack.get(expected_attack, {})

        generated_rule = generated.get("generated_rule", "")
        generated_sid = extract_sid(generated_rule)
        pcap_alert_count = int(pcap.get("alert_count") or 0)
        is_benign = expected_attack == "benign_traffic" or expected_label == "benign"
        snort3_rule_exists = bool(generated_sid and generated_sid in snort3_sids)

        notes: list[str] = []
        if not generated:
            notes.append("no generated rule example found for predicted attack type")
        if not pcap:
            notes.append("no PCAP replay row found for expected attack type")
        if log_row.get("id") == "SYNTHETIC-BENIGN-LOG-EVAL":
            notes.append("synthetic benign row used only in evaluation output")

        if is_benign:
            final_pass = predicted_attack == expected_attack and generated_rule in {"", "NO_RULE_RECOMMENDED"} and pcap_alert_count == 0
        else:
            final_pass = (
                predicted_attack == expected_attack
                and bool(generated_rule)
                and generated_rule != "NO_RULE_RECOMMENDED"
                and pcap_alert_count > 0
            )

        if not final_pass:
            if predicted_attack != expected_attack:
                notes.append("predicted attack type does not match expected attack type")
            if not is_benign and (not generated_rule or generated_rule == "NO_RULE_RECOMMENDED"):
                notes.append("missing malicious generated rule")
            if not is_benign and pcap_alert_count <= 0:
                notes.append("missing positive PCAP alert evidence")
            if is_benign and pcap_alert_count != 0:
                notes.append("benign PCAP produced alerts")

        output.append({
            "log_id": log_row.get("id", ""),
            "raw_log": raw_log,
            "expected_attack_type": expected_attack,
            "expected_label": expected_label,
            "predicted_attack_type": predicted_attack,
            "matched_query": generated.get("query", ""),
            "retrieved_context_used": generated.get("retrieved_context_used", ""),
            "source_doc_ids": generated.get("source_doc_ids", ""),
            "generated_rule": generated_rule,
            "generated_sid": generated_sid,
            "rule_status": "NO_RULE_RECOMMENDED" if generated_rule == "NO_RULE_RECOMMENDED" else generated.get("valid_rule", ""),
            "snort3_rule_exists": str(snort3_rule_exists),
            "pcap_scenario": pcap.get("pcap", ""),
            "pcap_alert_count": str(pcap_alert_count),
            "pcap_triggered_sids": pcap.get("triggered_sids", ""),
            "final_status": "PASS" if final_pass else "FAIL",
            "notes": " | ".join(notes),
        })
    return output


def print_summary(rows: list[dict[str, str]]) -> None:
    status_counts = Counter(row["final_status"] for row in rows)
    correct = sum(1 for row in rows if row["predicted_attack_type"] == row["expected_attack_type"])
    malicious_rows = [row for row in rows if row["expected_attack_type"] != "benign_traffic"]
    malicious_with_alerts = sum(1 for row in malicious_rows if int(row["pcap_alert_count"]) > 0)
    benign_false_positives = sum(
        1 for row in rows
        if row["expected_attack_type"] == "benign_traffic" and int(row["pcap_alert_count"]) > 0
    )

    print(f"total evaluated logs: {len(rows)}")
    print("final_status counts: " + ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items())))
    print(f"classification accuracy: {correct / max(1, len(rows)):.3f}")
    print(f"malicious logs with alert evidence: {malicious_with_alerts}/{len(malicious_rows)}")
    print(f"benign false positives: {benign_false_positives}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", default=PROJECT_ROOT / "data" / "logs" / "sample_network_logs.csv")
    parser.add_argument("--generated", default=PROJECT_ROOT / "results" / "generated_rule_examples.csv")
    parser.add_argument("--pcap-results", default=PROJECT_ROOT / "results" / "pcap_test_results.csv")
    parser.add_argument("--rules", default=PROJECT_ROOT / "data" / "processed" / "person1_rules_snort3.rules")
    parser.add_argument("--out", default=PROJECT_ROOT / "results" / "network_log_integration_eval.csv")
    args = parser.parse_args()

    rows = build_eval_rows(
        log_rows=read_csv(Path(args.logs)),
        generated_rows=read_csv(Path(args.generated)),
        pcap_rows=read_csv(Path(args.pcap_results)),
        snort3_sids=load_snort3_sids(Path(args.rules)),
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}")
    print_summary(rows)


if __name__ == "__main__":
    main()
