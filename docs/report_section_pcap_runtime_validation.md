# Snort 3 Runtime, PCAP Replay, and Lab Log Validation

Runtime claims in this project are based on a real Snort 3 engine executed through the Docker wrapper `tools/snort3-docker`. The wrapper invokes `/home/snorty/snort3/bin/snort` inside the container and uses `/home/snorty/snort3/etc/snort/snort.lua` for validation and PCAP replay.

## Commands

```bash
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated

PYTHONPATH=src python scripts/run_snort_validation.py \
  --snort-bin ./tools/snort3-docker \
  --config /home/snorty/snort3/etc/snort/snort.lua \
  --rules data/processed/person1_rules_snort3.rules \
  --out results/snort_runtime_validation.csv

PYTHONPATH=src python scripts/run_pcap_tests.py \
  --snort-bin ./tools/snort3-docker \
  --config /home/snorty/snort3/etc/snort/snort.lua \
  --rules data/processed/person1_rules_snort3.rules \
  --pcap-dir tests/pcaps/generated \
  --out results/pcap_test_results.csv

scripts/capture_real_lab_logs.sh
PYTHONPATH=src python scripts/run_real_log_integration_eval.py
```

## Current Evidence

- `results/snort_runtime_validation.csv`: 183 Snort 3-compatible rules validated with 183 PASS rows and `runtime_valid=True`.
- `results/pcap_test_results.csv`: protocol-valid lab PCAP replay produced PASS rows for all 10 scenarios, with 9/9 malicious attack categories detected and benign traffic alert count 0.
- `data/logs/real_lab_logs/snort_alert_fast.log`: Snort alert output captured from replaying the generated lab PCAPs through the real Snort 3 container.
- `data/logs/real_lab_logs/real_lab_logs_index.csv`: normalized index of controlled lab log lines used by `scripts/run_real_log_integration_eval.py`.

## Separation of Evidence Sources

- `data/processed/final_snort_dataset.csv` is the personal RAG dataset.
- `data/knowledge_base/trusted_rule_kb.csv` is an optional trusted-source Snort reference KB.
- `data/logs/sample_network_logs.csv` contains realistic synthetic academic logs used for dataset construction and synthetic integration evaluation.
- `data/logs/real_lab_logs/` contains controlled lab-captured/parsing artifacts produced from local PCAP replay and packet parsing. These logs are real lab artifacts, not enterprise production logs.

## SKIPPED Results

If the Docker wrapper, Snort image, or Snort config is unavailable, runtime validation cannot be claimed. The result should be marked `SKIPPED` or failed honestly. Local structural validation must not be described as equivalent to Snort runtime validation.

## Limitations

The PCAPs are protocol-valid synthetic educational lab captures. The real-lab logs are controlled local lab artifacts derived from those captures and Snort replay, not production network telemetry. The benign replay result is useful false-positive evidence for this lab corpus, but it is not a full enterprise false-positive study.
