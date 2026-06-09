#!/usr/bin/env python
"""Evaluate controlled real-lab logs against generated Snort RAG evidence."""
from __future__ import annotations

import argparse
from pathlib import Path

from run_log_integration_eval import (
    FIELDNAMES,
    PROJECT_ROOT,
    build_eval_rows,
    load_snort3_sids,
    print_summary,
    read_csv,
)
import csv


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", default=PROJECT_ROOT / "data" / "logs" / "real_lab_logs" / "real_lab_logs_index.csv")
    parser.add_argument("--generated", default=PROJECT_ROOT / "results" / "generated_rule_examples.csv")
    parser.add_argument("--pcap-results", default=PROJECT_ROOT / "results" / "pcap_test_results.csv")
    parser.add_argument("--rules", default=PROJECT_ROOT / "data" / "processed" / "person1_rules_snort3.rules")
    parser.add_argument("--out", default=PROJECT_ROOT / "results" / "real_lab_log_integration_eval.csv")
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
