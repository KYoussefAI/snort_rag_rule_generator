#!/usr/bin/env python
"""Benchmark controlled RAG+LLM generation over an evaluation query set."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.evaluation import TEST_QUERIES
from snort_rag.llm_clients import build_llm_client


def _load_queries(path: Path) -> list[dict[str, str]]:
    if path.exists():
        return pd.read_csv(path).fillna("").to_dict("records")
    return [
        {
            "id": f"BUILTIN-{idx:03d}",
            "query": item["query"],
            "expected_attack_type": item["expected_attack_type"],
            "expected_family": "",
            "language": "",
            "difficulty": "",
            "notes": "built-in fallback query",
        }
        for idx, item in enumerate(TEST_QUERIES, 1)
    ]


def _run_model(rag: SnortRAGArchitectures, model: str, query_rows: list[dict[str, str]], prompt_variant: str, k: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    try:
        client = build_llm_client(model)
    except Exception as exc:
        return [{
            "id": item.get("id", ""),
            "query": str(item["query"]),
            "expected_attack_type": str(item.get("expected_attack_type", "")),
            "expected_family": item.get("expected_family", ""),
            "language": item.get("language", ""),
            "difficulty": item.get("difficulty", ""),
            "model_name": model,
            "model_spec": model,
            "prompt_variant": prompt_variant,
            "status": "error",
            "error": f"failed to build client: {exc}",
            "predicted_attack_type": "",
            "attack_type_correct": False,
            "valid_rule": False,
            "generation_mode": "",
            "repair_attempts": 0,
            "retrieval_grounding_rate": 0.0,
            "false_positive_score": "",
            "option_coverage": "",
            "latency_ms": "",
            "generated_rule": "",
            "source_doc_ids": "",
        } for item in query_rows]
    for item in query_rows:
        query = str(item["query"])
        expected = str(item.get("expected_attack_type", ""))
        try:
            result = rag.rag_llm_generate(query, k=k, client=client, prompt_variant=prompt_variant)
            status = "ok"
            error = ""
        except Exception as exc:
            result = {}
            status = "error"
            error = str(exc)
        predicted = str(result.get("attack_type", ""))
        used_ids = result.get("used_source_doc_ids") or result.get("source_doc_ids") or []
        retrieved_ids = set(str(x) for x in result.get("retrieved_ids", []))
        grounding_ok = all(str(doc_id) in retrieved_ids for doc_id in used_ids)
        rows.append({
            "id": item.get("id", ""),
            "query": query,
            "expected_attack_type": expected,
            "expected_family": item.get("expected_family", ""),
            "language": item.get("language", ""),
            "difficulty": item.get("difficulty", ""),
            "model_name": result.get("model_name", model),
            "model_spec": model,
            "prompt_variant": prompt_variant,
            "status": status,
            "error": error,
            "predicted_attack_type": predicted,
            "attack_type_correct": predicted == expected,
            "valid_rule": bool(result.get("valid_rule", False)),
            "generation_mode": result.get("generation_mode", ""),
            "repair_attempts": result.get("repair_attempts", 0),
            "retrieval_grounding_rate": 1.0 if grounding_ok else 0.0,
            "false_positive_score": result.get("false_positive_score", ""),
            "option_coverage": result.get("option_coverage", ""),
            "latency_ms": result.get("latency_ms", ""),
            "generated_rule": result.get("generated_rule", ""),
            "source_doc_ids": "|".join(str(x) for x in used_ids),
        })
    return rows


def _write_summary(rows: list[dict[str, object]], out_path: Path) -> None:
    df = pd.DataFrame(rows)
    if df.empty:
        pd.DataFrame().to_csv(out_path, index=False)
        return
    summary = df.groupby(["model_spec", "prompt_variant"], dropna=False).agg(
        queries=("query", "count"),
        ok_rows=("status", lambda s: int((s == "ok").sum())),
        error_rows=("status", lambda s: int((s == "error").sum())),
        valid_rule_rate=("valid_rule", "mean"),
        attack_type_accuracy=("attack_type_correct", "mean"),
        retrieval_grounding_rate=("retrieval_grounding_rate", "mean"),
        avg_latency_ms=("latency_ms", lambda s: pd.to_numeric(s, errors="coerce").mean()),
    ).reset_index()
    summary.to_csv(out_path, index=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv")
    parser.add_argument("--queries", default=PROJECT_ROOT / "data" / "evaluation" / "snort_eval_queries.csv")
    parser.add_argument("--models", nargs="+", default=["mock"])
    parser.add_argument("--prompt-variants", nargs="+", default=["strict_json", "strict_json_repair"])
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--out", default=PROJECT_ROOT / "results" / "llm_benchmark.csv")
    parser.add_argument("--summary-out", default=PROJECT_ROOT / "results" / "llm_benchmark_summary.csv")
    args = parser.parse_args()

    rag = SnortRAGArchitectures(args.dataset)
    query_rows = _load_queries(Path(args.queries))
    all_rows: list[dict[str, object]] = []
    for model in args.models:
        for variant in args.prompt_variants:
            all_rows.extend(_run_model(rag, model, query_rows, variant, args.k))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(all_rows[0].keys()) if all_rows else ["status"]
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    _write_summary(all_rows, Path(args.summary_out))
    print(f"Wrote {len(all_rows)} benchmark rows to {out_path}")


if __name__ == "__main__":
    main()
