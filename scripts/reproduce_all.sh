#!/usr/bin/env bash
set -euo pipefail

PYTHONPATH=src python scripts/validate_dataset.py
PYTHONPATH=src python scripts/benchmark_retrieval.py
PYTHONPATH=src python scripts/plot_retrieval_benchmark.py
PYTHONPATH=src python -m snort_rag.run_devoir3
PYTHONPATH=src python scripts/run_clustering_analysis.py
PYTHONPATH=src python scripts/benchmark_llms.py --models mock
PYTHONPATH=src python scripts/generate_generation_examples.py
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated
PYTHONPATH=src python scripts/run_snort_validation.py --out results/snort_runtime_validation.csv || true
PYTHONPATH=src python scripts/run_pcap_tests.py --out results/pcap_test_results.csv || true
PYTHONPATH=src pytest tests/
