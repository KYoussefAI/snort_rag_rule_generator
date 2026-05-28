from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Callable

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.evaluation import TEST_QUERIES
from snort_rag.retrieval import RetrievedDoc

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
RESULTS_DIR = PROJECT_ROOT / "results"
BENCHMARK_PATH = RESULTS_DIR / "embedding_benchmark.csv"
TOPK_PATH = RESULTS_DIR / "retrieval_topk_examples.csv"
PROOF_PATH = RESULTS_DIR / "retrieval_backend_proof.json"


def precision_at_k(labels: list[str], expected: str, k: int) -> float:
    top_labels = labels[:k]
    if not top_labels:
        return 0.0
    return sum(label == expected for label in top_labels) / len(top_labels)


def hit_at_k(labels: list[str], expected: str, k: int) -> float:
    return 1.0 if expected in labels[:k] else 0.0


def recall_at_k(labels: list[str], expected: str, k: int) -> float:
    return hit_at_k(labels, expected, k)


def reciprocal_rank(labels: list[str], expected: str) -> float:
    for index, label in enumerate(labels, start=1):
        if label == expected:
            return 1.0 / index
    return 0.0


def safe_text(value: object, max_len: int = 250) -> str:
    text = str(value or "")
    text = text.replace("\n", " ").replace("\r", " ")
    return text[:max_len]


def build_method_specs(rag: SnortRAGArchitectures) -> list[dict[str, object]]:
    def hybrid_alpha(alpha: float) -> Callable[[str, int], list[RetrievedDoc]]:
        def retrieve(query: str, k: int = 5) -> list[RetrievedDoc]:
            return rag.kb.hybrid_retrieve(query, k=k, alpha=alpha)

        return retrieve

    def hybrid_rerank_alpha(alpha: float) -> Callable[[str, int], list[RetrievedDoc]]:
        def retrieve(query: str, k: int = 5) -> list[RetrievedDoc]:
            initial_docs = rag.kb.hybrid_retrieve(query, k=max(8, k), alpha=alpha)
            return rag.kb.rerank(query, initial_docs, k=k)

        return retrieve

    def dense_rerank(query: str, k: int = 5) -> list[RetrievedDoc]:
        initial_docs = rag.kb.dense_retrieve(query, k=max(8, k))
        return rag.kb.rerank(query, initial_docs, k=k)

    return [
        {"method": "bm25", "backend": "bm25", "retriever": rag.kb.bm25_retrieve, "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "dense_tfidf", "backend": "tfidf", "retriever": rag.kb.dense_retrieve, "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "dense_tfidf_rerank", "backend": "tfidf_rerank", "retriever": dense_rerank, "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_best", "backend": "hybrid_tfidf_bm25_rerank", "retriever": rag.kb.hybrid_rerank_retrieve, "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_alpha_0.25", "backend": "hybrid_tfidf_bm25", "retriever": hybrid_alpha(0.25), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_alpha_0.50", "backend": "hybrid_tfidf_bm25", "retriever": hybrid_alpha(0.50), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_alpha_0.55", "backend": "hybrid_tfidf_bm25", "retriever": hybrid_alpha(0.55), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_alpha_0.75", "backend": "hybrid_tfidf_bm25", "retriever": hybrid_alpha(0.75), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_alpha_0.90", "backend": "hybrid_tfidf_bm25", "retriever": hybrid_alpha(0.90), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_0.25", "backend": "hybrid_tfidf_bm25_rerank", "retriever": hybrid_rerank_alpha(0.25), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_0.50", "backend": "hybrid_tfidf_bm25_rerank", "retriever": hybrid_rerank_alpha(0.50), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_0.55", "backend": "hybrid_tfidf_bm25_rerank", "retriever": hybrid_rerank_alpha(0.55), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_0.75", "backend": "hybrid_tfidf_bm25_rerank", "retriever": hybrid_rerank_alpha(0.75), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "hybrid_rerank_0.90", "backend": "hybrid_tfidf_bm25_rerank", "retriever": hybrid_rerank_alpha(0.90), "requires_sentence_bert": False, "requires_faiss": False},
        {"method": "sentence_bert", "backend": "sentence_bert_cosine", "retriever": rag.kb.sentence_bert_retrieve, "requires_sentence_bert": True, "requires_faiss": False},
        {"method": "sentence_bert_faiss", "backend": "sentence_bert_faiss_ip", "retriever": rag.kb.sentence_bert_faiss_retrieve, "requires_sentence_bert": True, "requires_faiss": True},
    ]


def main() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    rag = SnortRAGArchitectures(DATASET_PATH)
    method_specs = build_method_specs(rag)
    k_values = [1, 3, 5]
    benchmark_rows: list[dict[str, object]] = []
    topk_rows: list[dict[str, object]] = []
    proof = {
        "dataset_path": str(DATASET_PATH),
        "sentence_bert_runtime_available": rag.kb.sentence_bert_runtime_available(),
        "faiss_runtime_available": rag.kb.faiss_runtime_available(),
        "sentence_bert_model": rag.kb.embedding_backend_info()["sentence_bert_model"],
        "methods": [],
    }

    for spec in method_specs:
        method_name = str(spec["method"])
        retrieve_fn = spec["retriever"]
        backend = str(spec["backend"])
        requires_sentence_bert = bool(spec["requires_sentence_bert"])
        requires_faiss = bool(spec["requires_faiss"])
        status = "ready"
        error_message = ""
        if requires_sentence_bert and not rag.kb.sentence_bert_runtime_available():
            status = "unavailable"
            error_message = "sentence-transformers is not installed"
        elif requires_faiss and not rag.kb.faiss_runtime_available():
            status = "unavailable"
            error_message = "faiss is not installed"
        elif status == "ready":
            try:
                retrieve_fn(TEST_QUERIES[0]["query"], k=max(k_values))
            except Exception as exc:
                status = "error"
                error_message = str(exc)
        method_proof = {
            "method": method_name,
            "backend": backend,
            "requires_sentence_bert": requires_sentence_bert,
            "requires_faiss": requires_faiss,
            "status": status,
            "error_message": error_message,
        }
        for k in k_values:
            if status != "ready":
                benchmark_rows.append({
                    "method": method_name,
                    "backend": backend,
                    "k": k,
                    "status": status,
                    "sentence_bert_runtime_available": rag.kb.sentence_bert_runtime_available(),
                    "faiss_runtime_available": rag.kb.faiss_runtime_available(),
                    "sentence_bert_model": rag.kb.embedding_backend_info()["sentence_bert_model"],
                    "faiss_enabled": requires_faiss,
                    "error_message": error_message,
                    "hit_at_k": "",
                    "precision_at_k": "",
                    "recall_at_k": "",
                    "mrr": "",
                    "avg_latency_ms": "",
                })
                continue
            hits = []
            precisions = []
            recalls = []
            reciprocal_ranks = []
            latencies_ms = []

            for item in TEST_QUERIES:
                query = item["query"]
                expected = item["expected_attack_type"]
                start = time.perf_counter()
                try:
                    docs = retrieve_fn(query, k=k)
                except Exception as exc:
                    status = "error"
                    error_message = str(exc)
                    method_proof["status"] = status
                    method_proof["error_message"] = error_message
                    docs = []
                    break
                elapsed_ms = (time.perf_counter() - start) * 1000
                labels = [doc.attack_type for doc in docs]
                hits.append(hit_at_k(labels, expected, k))
                precisions.append(precision_at_k(labels, expected, k))
                recalls.append(recall_at_k(labels, expected, k))
                reciprocal_ranks.append(reciprocal_rank(labels, expected))
                latencies_ms.append(elapsed_ms)

                for rank, doc in enumerate(docs, start=1):
                    topk_rows.append({
                        "query": query,
                        "expected_attack_type": expected,
                        "method": method_name,
                        "backend": backend,
                        "k": k,
                        "rank": rank,
                        "doc_id": doc.id,
                        "retrieved_attack_type": doc.attack_type,
                        "is_relevant": doc.attack_type == expected,
                        "status": status,
                        "sentence_bert_model": rag.kb.embedding_backend_info()["sentence_bert_model"],
                        "faiss_enabled": requires_faiss,
                        "description_naturelle": safe_text(doc.description_naturelle),
                        "log_example": safe_text(doc.log_example),
                        "snort_rule_reference": safe_text(doc.snort_rule_reference),
                    })

            if status != "ready":
                benchmark_rows.append({
                    "method": method_name,
                    "backend": backend,
                    "k": k,
                    "status": status,
                    "sentence_bert_runtime_available": rag.kb.sentence_bert_runtime_available(),
                    "faiss_runtime_available": rag.kb.faiss_runtime_available(),
                    "sentence_bert_model": rag.kb.embedding_backend_info()["sentence_bert_model"],
                    "faiss_enabled": requires_faiss,
                    "error_message": error_message or rag.kb.embedding_backend_info()["embedding_backend_error"],
                    "hit_at_k": "",
                    "precision_at_k": "",
                    "recall_at_k": "",
                    "mrr": "",
                    "avg_latency_ms": "",
                })
                continue

            n = len(hits) or 1
            benchmark_rows.append({
                "method": method_name,
                "backend": backend,
                "k": k,
                "status": status,
                "sentence_bert_runtime_available": rag.kb.sentence_bert_runtime_available(),
                "faiss_runtime_available": rag.kb.faiss_runtime_available(),
                "sentence_bert_model": rag.kb.embedding_backend_info()["sentence_bert_model"],
                "faiss_enabled": requires_faiss,
                "error_message": error_message,
                "hit_at_k": sum(hits) / n,
                "precision_at_k": sum(precisions) / n,
                "recall_at_k": sum(recalls) / n,
                "mrr": sum(reciprocal_ranks) / n,
                "avg_latency_ms": sum(latencies_ms) / n,
            })
        proof["methods"].append(method_proof)

    with BENCHMARK_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(benchmark_rows[0].keys()))
        writer.writeheader()
        writer.writerows(benchmark_rows)

    with TOPK_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(topk_rows[0].keys()))
        writer.writeheader()
        writer.writerows(topk_rows)

    PROOF_PATH.write_text(json.dumps(proof, indent=2), encoding="utf-8")

    print(f"Saved benchmark: {BENCHMARK_PATH}")
    print(f"Saved top-k examples: {TOPK_PATH}")
    print(f"Saved backend proof: {PROOF_PATH}")
    print("\nBenchmark summary:")
    for row in benchmark_rows:
        print(row)


if __name__ == "__main__":
    main()
