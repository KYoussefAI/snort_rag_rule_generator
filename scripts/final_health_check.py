#!/usr/bin/env python
"""Summarize final evidence readiness without requiring Snort or Ollama."""
from __future__ import annotations

import ast
import csv
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _parse_ids(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        try:
            parsed = ast.literal_eval(value)
        except Exception:
            parsed = value.split("|")
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    return [str(parsed)]


def _has_conflict_markers() -> bool:
    for path in [PROJECT_ROOT / "README.md"]:
        text = path.read_text(encoding="utf-8")
        if any(marker in text for marker in ("<<<<<<<", "=======", ">>>>>>>")):
            return True
    return False


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []

    if _has_conflict_markers():
        errors.append("README contains merge conflict markers")

    examples = _read_csv(PROJECT_ROOT / "results" / "generated_rule_examples.csv")
    if not examples:
        errors.append("results/generated_rule_examples.csv is missing or empty")
    for row in examples:
        ids = _parse_ids(row.get("source_doc_ids", ""))
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate source_doc_ids in generated example query: {row.get('query', '')}")
            break

    llm_summary = _read_csv(PROJECT_ROOT / "results" / "llm_benchmark_summary.csv")
    if not llm_summary:
        errors.append("results/llm_benchmark_summary.csv is missing or empty")
    elif {row.get("model_spec", "") for row in llm_summary} <= {"mock"}:
        warnings.append("LLM benchmark is mock-only; run Ollama/local models for final evidence")

    snort_rows = _read_csv(PROJECT_ROOT / "results" / "snort_runtime_validation.csv")
    if not snort_rows:
        errors.append("results/snort_runtime_validation.csv is missing or empty")
    elif all(row.get("status") == "SKIPPED" for row in snort_rows):
        warnings.append("Snort runtime validation is all SKIPPED")

    pcap_rows = _read_csv(PROJECT_ROOT / "results" / "pcap_test_results.csv")
    if not pcap_rows:
        errors.append("results/pcap_test_results.csv is missing or empty")
    elif all(row.get("status") == "SKIPPED" for row in pcap_rows):
        warnings.append("PCAP replay is all SKIPPED")

    required_files = [
        PROJECT_ROOT / "results" / "clustering_metrics.csv",
        PROJECT_ROOT / "results" / "retrieval_backend_proof.json",
        PROJECT_ROOT / "data" / "processed" / "DATASET_CARD.md",
        PROJECT_ROOT / "data" / "processed" / "dataset_manifest.json",
    ]
    for path in required_files:
        if not path.exists():
            errors.append(f"missing required artifact: {path.relative_to(PROJECT_ROOT)}")

    print("FINAL HEALTH CHECK")
    print("==================")
    if errors:
        print("ERRORS:")
        for item in errors:
            print(f"- {item}")
    else:
        print("ERRORS: none")
    if warnings:
        print("WARNINGS:")
        for item in warnings:
            print(f"- {item}")
    else:
        print("WARNINGS: none")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
