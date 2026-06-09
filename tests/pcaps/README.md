# PCAP Test Files

PCAP files are not included by default.

PCAPs must be generated or captured in a lab.

Do not include sensitive real network traffic.

Use synthetic/lab traffic only.

No detection result should be claimed unless Snort was actually run on the PCAP.
# Synthetic Lab PCAPs

Generate local educational PCAPs with:

```bash
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated
```

These files are synthetic lab traffic, not captured real network data. Do not commit sensitive production PCAPs. Runtime alert behavior must be tested with:

```bash
PYTHONPATH=src python scripts/run_pcap_tests.py --pcap-dir tests/pcaps/generated
```

If Snort is not installed, the result file must show `SKIPPED` rather than a fake pass.
