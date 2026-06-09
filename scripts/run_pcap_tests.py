#!/usr/bin/env python
"""Replay generated PCAPs through Snort 3 and collect alert evidence.

This script uses Snort 3 console alert output (-A cmg), because some Docker
images do not write alert_fast files in the expected location.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
from pathlib import Path


SID_RE = re.compile(r"\[\d+:(\d+):\d+\]")


def scenario_from_pcap(path: Path) -> str:
    return path.stem


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snort-bin", default="snort")
    parser.add_argument("--config", default="")
    parser.add_argument("--rules", default="data/processed/person1_rules_snort3.rules")
    parser.add_argument("--pcap-dir", default="tests/pcaps/generated")
    parser.add_argument("--out", default="results/pcap_test_results.csv")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    snort_path = shutil.which(args.snort_bin) or args.snort_bin
    rules_path = Path(args.rules)
    pcap_dir = Path(args.pcap_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pcaps = sorted(pcap_dir.glob("*.pcap"))
    rows = []

    if not pcaps:
        rows.append({
            "pcap": "",
            "expected_attack": "",
            "status": "SKIPPED",
            "alert_count": 0,
            "triggered_sids": "",
            "benign_alert": False,
            "command": "",
            "stdout_excerpt": "",
            "stderr_excerpt": f"no pcap files found in {pcap_dir}",
        })
    else:
        for pcap in pcaps:
            expected = scenario_from_pcap(pcap)
            cmd = [
                snort_path,
                "-r", str(pcap),
                "-R", str(rules_path),
                "-A", "cmg",
            ]
            if args.config:
                cmd.extend(["-c", args.config])

            try:
                result = subprocess.run(
                    cmd,
                    text=True,
                    capture_output=True,
                    timeout=args.timeout,
                )
                output = (result.stdout or "") + "\n" + (result.stderr or "")
                sids = sorted(set(SID_RE.findall(output)))
                alert_count = len(SID_RE.findall(output))
                benign_alert = expected == "benign_traffic" and alert_count > 0

                # Runtime PASS means Snort processed the PCAP without command failure.
                # Detection evidence is represented by alert_count and triggered_sids.
                status = "PASS" if result.returncode == 0 and not benign_alert else "FAIL"

                rows.append({
                    "pcap": str(pcap),
                    "expected_attack": expected,
                    "status": status,
                    "alert_count": alert_count,
                    "triggered_sids": ",".join(sids),
                    "benign_alert": benign_alert,
                    "command": " ".join(cmd),
                    "stdout_excerpt": output[:4000],
                    "stderr_excerpt": result.stderr[:1000] if result.stderr else "",
                })
            except FileNotFoundError:
                rows.append({
                    "pcap": str(pcap),
                    "expected_attack": expected,
                    "status": "SKIPPED",
                    "alert_count": 0,
                    "triggered_sids": "",
                    "benign_alert": False,
                    "command": " ".join(cmd),
                    "stdout_excerpt": "",
                    "stderr_excerpt": "snort binary not found",
                })
            except subprocess.TimeoutExpired as exc:
                output = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + "\n" + ((exc.stderr or "") if isinstance(exc.stderr, str) else "")
                rows.append({
                    "pcap": str(pcap),
                    "expected_attack": expected,
                    "status": "FAIL",
                    "alert_count": 0,
                    "triggered_sids": "",
                    "benign_alert": False,
                    "command": " ".join(cmd),
                    "stdout_excerpt": output[:4000],
                    "stderr_excerpt": "timeout",
                })

    fieldnames = [
        "pcap",
        "expected_attack",
        "status",
        "alert_count",
        "triggered_sids",
        "benign_alert",
        "command",
        "stdout_excerpt",
        "stderr_excerpt",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
