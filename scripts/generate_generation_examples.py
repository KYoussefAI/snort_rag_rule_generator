from __future__ import annotations

import csv
import json
from pathlib import Path
import sys

# This export uses the local TF-IDF/BM25 pipeline only and avoids loading heavy
# optional embedding backends at import time.
sys.modules.setdefault("sentence_transformers", None)
sys.modules.setdefault("faiss", None)

from snort_rag.architectures import SnortRAGArchitectures


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
RESULTS_DIR = PROJECT_ROOT / "results"
RULE_EXAMPLES_CSV = RESULTS_DIR / "generated_rule_examples.csv"
FALSE_POSITIVE_CSV = RESULTS_DIR / "false_positive_analysis.csv"

DEMO_QUERIES = [
    "Generate a Snort rule for repeated SSH brute force attempts on port 22",
    "Detect SQL injection with UNION SELECT in HTTP URI",
    "Detect XSS attack where the URI contains <script>alert(1)</script>",
    "Detect a TCP SYN port scan against our web server",
    "Detect DNS tunneling using long encoded subdomains",
    "Detect ICMP ping sweep against internal network",
    "Alert when someone tries ../../../../etc/passwd directory traversal",
    "Detect command injection with cmd parameter and whoami in HTTP request",
    "Detect malware command and control beacon to /gate.php",
    "A user connects normally to the company website using HTTPS",
]


def _serialize(value: object) -> str:
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if value is None:
        return ""
    return str(value)


def _rule_example_row(result: dict[str, object], query: str) -> dict[str, str]:
    return {
        "query": query,
        "attack_type": _serialize(result.get("attack_type", "")),
        "generated_rule": _serialize(result.get("generated_rule", "")),
        "valid_rule": _serialize(result.get("valid_rule", False)),
        "validation_errors": _serialize(result.get("validation_errors", [])),
        "detected_options": _serialize(result.get("detected_options", [])),
        "missing_options": _serialize(result.get("missing_options", [])),
        "explanation": _serialize(result.get("explanation", "")),
        "source_doc_ids": _serialize(result.get("source_doc_ids", [])),
        "retrieved_context_used": _serialize(result.get("retrieved_context_used", False)),
        "hallucination_risk": _serialize(result.get("hallucination_risk", 0.0)),
        "option_coverage": _serialize(result.get("option_coverage", 0.0)),
    }


def _false_positive_row(result: dict[str, object], query: str) -> dict[str, str]:
    return {
        "query": query,
        "attack_type": _serialize(result.get("attack_type", "")),
        "generated_rule": _serialize(result.get("generated_rule", "")),
        "false_positive_risk": _serialize(result.get("false_positive_risk", "")),
        "false_positive_score": _serialize(result.get("false_positive_score", 0.0)),
        "risk_factors": _serialize(result.get("risk_factors", [])),
        "improvement_suggestions": _serialize(result.get("improvement_suggestions", [])),
    }


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not DATASET.exists():
        raise SystemExit(f"Dataset not found: {DATASET}")

    rag = SnortRAGArchitectures(DATASET)
    rule_rows: list[dict[str, str]] = []
    fp_rows: list[dict[str, str]] = []

    for query in DEMO_QUERIES:
        result = rag.agentic_rag(query)
        rule_rows.append(_rule_example_row(result, query))
        fp_rows.append(_false_positive_row(result, query))

    _write_csv(
        RULE_EXAMPLES_CSV,
        rule_rows,
        [
            "query",
            "attack_type",
            "generated_rule",
            "valid_rule",
            "validation_errors",
            "detected_options",
            "missing_options",
            "explanation",
            "source_doc_ids",
            "retrieved_context_used",
            "hallucination_risk",
            "option_coverage",
        ],
    )
    _write_csv(
        FALSE_POSITIVE_CSV,
        fp_rows,
        [
            "query",
            "attack_type",
            "generated_rule",
            "false_positive_risk",
            "false_positive_score",
            "risk_factors",
            "improvement_suggestions",
        ],
    )

    print(f"Wrote {RULE_EXAMPLES_CSV}")
    print(f"Wrote {FALSE_POSITIVE_CSV}")


if __name__ == "__main__":
    main()
