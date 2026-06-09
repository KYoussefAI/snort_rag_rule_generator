#!/usr/bin/env python
"""Validate Snort rules with a real Snort binary when available."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from snort_rag.rule_parser import extract_sid, validate_rule


def _rules(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snort-bin", default="snort")
    parser.add_argument("--config", default="")
    parser.add_argument("--rules", default=PROJECT_ROOT / "data" / "processed" / "person1_rules.rules")
    parser.add_argument("--out", default=PROJECT_ROOT / "results" / "snort_runtime_validation.csv")
    args = parser.parse_args()

    rules_path = Path(args.rules)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    snort_path = shutil.which(args.snort_bin)
    rows = []
    rules = _rules(rules_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    base_command = [args.snort_bin, "-T", "-R", str(rules_path)]
    if args.config:
        base_command.extend(["-c", args.config])
    command_text = " ".join(base_command)

    if not snort_path:
        for rule in rules:
            local_valid, local_errors = validate_rule(rule)
            rows.append({
                "timestamp": timestamp,
                "sid": extract_sid(rule) or "",
                "status": "SKIPPED",
                "snort_bin": args.snort_bin,
                "snort_bin_found": False,
                "config_used": args.config,
                "rules_path": str(rules_path),
                "runtime_valid": "",
                "local_valid": local_valid,
                "local_errors": "; ".join(local_errors),
                "stderr_excerpt": "snort binary not found",
                "stdout_excerpt": "",
                "command": command_text,
            })
    else:
        command = [snort_path, "-T", "-R", str(rules_path)]
        if args.config:
            command.extend(["-c", args.config])
        proc = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
        runtime_valid = proc.returncode == 0
        for rule in rules:
            local_valid, local_errors = validate_rule(rule)
            rows.append({
                "timestamp": timestamp,
                "sid": extract_sid(rule) or "",
                "status": "PASS" if runtime_valid else "FAIL",
                "snort_bin": snort_path,
                "snort_bin_found": True,
                "config_used": args.config,
                "rules_path": str(rules_path),
                "runtime_valid": runtime_valid,
                "local_valid": local_valid,
                "local_errors": "; ".join(local_errors),
                "stderr_excerpt": proc.stderr[:500],
                "stdout_excerpt": proc.stdout[:500],
                "command": " ".join(command),
            })

    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["status"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
