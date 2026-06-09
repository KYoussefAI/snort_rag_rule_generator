from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "results" / "network_log_integration_eval.csv"


def test_log_integration_eval_outputs_real_evidence():
    subprocess.run(
        [sys.executable, "scripts/run_log_integration_eval.py"],
        cwd=PROJECT_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    assert OUTPUT.exists()
    with OUTPUT.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    represented = {row["expected_attack_type"] for row in rows}
    assert len(represented - {"benign_traffic"}) >= 9
    assert {row["final_status"] for row in rows} == {"PASS"}

    correct = sum(1 for row in rows if row["predicted_attack_type"] == row["expected_attack_type"])
    assert correct / len(rows) == 1.0

    malicious_rows = [row for row in rows if row["expected_attack_type"] != "benign_traffic"]
    assert malicious_rows
    assert all(int(row["pcap_alert_count"]) > 0 for row in malicious_rows)

    benign_rows = [row for row in rows if row["expected_attack_type"] == "benign_traffic"]
    assert benign_rows
    assert all(int(row["pcap_alert_count"]) == 0 for row in benign_rows)
