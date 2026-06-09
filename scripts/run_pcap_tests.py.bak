#!/usr/bin/env python
"""Replay generated PCAPs through Snort when available and summarize alerts."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil
import subprocess


def _triggered_sids(alert_text: str) -> list[str]:
    values = re.findall(r"\[\*\*\]\s+\[\d+:(\d+):\d+\]", alert_text)
    output: list[str] = []
    seen: set[str] = set()
    for sid in values:
        if sid not in seen:
            output.append(sid)
            seen.add(sid)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snort-bin", default="snort")
    parser.add_argument("--config", default="")
    parser.add_argument("--rules", default=Path("data") / "processed" / "person1_rules.rules")
    parser.add_argument("--pcap-dir", default=Path("tests") / "pcaps" / "generated")
    parser.add_argument("--out", default=Path("results") / "pcap_test_results.csv")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir = out_path.parent / "snort_alert_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    snort_path = shutil.which(args.snort_bin)
    rows = []
    timestamp = datetime.now(timezone.utc).isoformat()

    pcaps = sorted(Path(args.pcap_dir).glob("*.pcap"))
    if not pcaps:
        rows.append({
            "timestamp": timestamp,
            "pcap": "",
            "expected_attack": "",
            "status": "SKIPPED",
            "snort_bin": args.snort_bin,
            "snort_bin_found": bool(snort_path),
            "config_used": args.config,
            "rules_path": str(args.rules),
            "alert_count": "",
            "triggered_sids": "",
            "benign_alert": "",
            "command": "",
            "stderr_excerpt": "no pcap files found",
        })
    for pcap in pcaps:
        expected = pcap.stem
        base_command = [args.snort_bin, "-r", str(pcap), "-R", str(args.rules), "-A", "alert_fast", "-l", str(log_dir)]
        if args.config:
            base_command.extend(["-c", args.config])
        if not snort_path:
            rows.append({
                "timestamp": timestamp,
                "pcap": str(pcap),
                "expected_attack": expected,
                "status": "SKIPPED",
                "snort_bin": args.snort_bin,
                "snort_bin_found": False,
                "config_used": args.config,
                "rules_path": str(args.rules),
                "alert_count": "",
                "triggered_sids": "",
                "benign_alert": "",
                "command": " ".join(base_command),
                "stderr_excerpt": "snort binary not found",
            })
            continue
        command = [snort_path, "-r", str(pcap), "-R", str(args.rules), "-A", "alert_fast", "-l", str(log_dir)]
        if args.config:
            command.extend(["-c", args.config])
        proc = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
        alert_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in log_dir.glob("alert*"))
        alert_count = sum(1 for line in alert_text.splitlines() if line.strip())
        sids = _triggered_sids(alert_text)
        rows.append({
            "timestamp": timestamp,
            "pcap": str(pcap),
            "expected_attack": expected,
            "status": "PASS" if proc.returncode == 0 else "FAIL",
            "snort_bin": snort_path,
            "snort_bin_found": True,
            "config_used": args.config,
            "rules_path": str(args.rules),
            "alert_count": alert_count,
            "triggered_sids": "|".join(sids),
            "benign_alert": expected == "benign_traffic" and alert_count > 0,
            "command": " ".join(command),
            "stderr_excerpt": (proc.stderr or proc.stdout)[0:500],
        })

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["pcap"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
