import subprocess
import sys
from pathlib import Path


def test_snort_validation_skips_missing_binary(tmp_path):
    rules = tmp_path / "rules.rules"
    rules.write_text('alert tcp any any -> any 80 (msg:"x"; content:"x"; sid:1; rev:1;)\n', encoding="utf-8")
    out = tmp_path / "runtime.csv"

    subprocess.run(
        [
            sys.executable,
            "scripts/run_snort_validation.py",
            "--snort-bin",
            "definitely_missing_snort_binary",
            "--rules",
            str(rules),
            "--out",
            str(out),
        ],
        check=True,
    )

    text = out.read_text(encoding="utf-8")
    assert "SKIPPED" in text
    assert "snort binary not found" in text
