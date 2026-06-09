from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REAL_LOG_DIR = PROJECT_ROOT / "data" / "logs" / "real_lab_logs"
INDEX = REAL_LOG_DIR / "real_lab_logs_index.csv"
OUTPUT = PROJECT_ROOT / "results" / "real_lab_log_integration_eval.csv"


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_real_lab_logs_are_present_and_indexed():
    required_files = {
        "README.md",
        "snort_alert_fast.log",
        "http_access.log",
        "ssh_auth.log",
        "dns_lab.log",
        "icmp_lab.log",
        "real_lab_logs_index.csv",
    }
    assert REAL_LOG_DIR.is_dir()
    assert required_files.issubset({path.name for path in REAL_LOG_DIR.iterdir()})

    snort_alerts = (REAL_LOG_DIR / "snort_alert_fast.log").read_text(encoding="utf-8")
    assert "[1:9100181:1]" in snort_alerts
    assert "[1:9100182:1]" in snort_alerts
    assert "[1:9100183:1]" in snort_alerts
    assert "unable to open rules file" not in snort_alerts
    assert "Fatal Error" not in snort_alerts

    rows = _read_rows(INDEX)
    represented = {row["attack_type"] for row in rows}
    assert len(rows) >= 10
    assert len(represented - {"benign_traffic"}) >= 9
    assert "benign_traffic" in represented
    assert {row["expected_label"] for row in rows} <= {"malicious", "benign"}
    assert all(row["source_file"] for row in rows)
    assert all(row["capture_method"] for row in rows)


def test_real_lab_log_integration_eval_passes():
    subprocess.run(
        [sys.executable, "scripts/run_real_log_integration_eval.py"],
        cwd=PROJECT_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    assert OUTPUT.exists()
    rows = _read_rows(OUTPUT)
    assert {row["final_status"] for row in rows} == {"PASS"}
    correct = sum(1 for row in rows if row["predicted_attack_type"] == row["expected_attack_type"])
    assert correct / len(rows) == 1.0

    malicious_rows = [row for row in rows if row["expected_attack_type"] != "benign_traffic"]
    assert all(int(row["pcap_alert_count"]) > 0 for row in malicious_rows)

    benign_rows = [row for row in rows if row["expected_attack_type"] == "benign_traffic"]
    assert benign_rows
    assert all(int(row["pcap_alert_count"]) == 0 for row in benign_rows)
