# Snort Runtime and PCAP Validation

Runtime validation must be executed with a real Snort binary before making strong claims about rule acceptance or alert behavior.

Commands:

```bash
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated
PYTHONPATH=src python scripts/run_snort_validation.py --snort-bin snort --rules data/processed/person1_rules.rules --out results/snort_runtime_validation.csv
PYTHONPATH=src python scripts/run_pcap_tests.py --snort-bin snort --rules data/processed/person1_rules.rules --pcap-dir tests/pcaps/generated --out results/pcap_test_results.csv
```

If Snort is unavailable, the scripts write `SKIPPED` rows. In that case the report must say: runtime Snort validation was not executed in this environment; only local structural validation was executed.

## SKIPPED Results

When `results/snort_runtime_validation.csv` contains only `SKIPPED`, no runtime Snort syntax claim is made. The CSV still records the attempted command, timestamp, binary lookup result, config path, rules path, and local structural validation status.

When `results/pcap_test_results.csv` contains only `SKIPPED`, synthetic lab PCAPs were generated but replay through Snort was not executed because Snort was unavailable.

## Executed PASS/FAIL Results

After Snort is installed, the report should summarize:

- Snort command and timestamp
- rule count, PASS/FAIL/SKIPPED counts, and stderr/stdout excerpts
- PCAP path, expected attack, alert count, triggered SIDs, and benign alert flag
- benign PCAP alert count, malicious PCAP alert counts, unexpected alerts, and missed detections

If the benign PCAP triggers alerts, keep the row and discuss it as empirical false-positive evidence.
