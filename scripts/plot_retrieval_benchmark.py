from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results"
BENCHMARK_PATH = RESULTS_DIR / "embedding_benchmark.csv"
PLOT_PATH = RESULTS_DIR / "retrieval_benchmark_k3.png"
BEST_TABLE_PATH = RESULTS_DIR / "retrieval_benchmark_k3_summary.csv"


def main() -> None:
    df = pd.read_csv(BENCHMARK_PATH)
    k3 = df[(df["k"] == 3) & (df["status"] == "ready")].copy()
    selected_methods = [
        "bm25",
        "dense_tfidf",
        "dense_tfidf_rerank",
        "hybrid_rerank_best",
        "sentence_bert",
        "sentence_bert_faiss",
        "hybrid_alpha_0.25",
        "hybrid_alpha_0.55",
        "hybrid_rerank_0.25",
    ]
    k3 = k3[k3["method"].isin(selected_methods)].copy()
    k3 = k3.sort_values(["mrr", "precision_at_k", "hit_at_k"], ascending=False)
    k3.to_csv(BEST_TABLE_PATH, index=False)

    metrics = ["hit_at_k", "precision_at_k", "recall_at_k", "mrr"]
    ax = k3.set_index("method")[metrics].plot(kind="bar", figsize=(12, 6))
    ax.set_title("Retrieval benchmark comparison at k=3")
    ax.set_xlabel("Retrieval method")
    ax.set_ylabel("Score")
    ax.set_ylim(0, 1.1)
    ax.legend(title="Metric", loc="lower right")
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    plt.savefig(PLOT_PATH, dpi=200)
    print(f"Saved plot: {PLOT_PATH}")
    print(f"Saved summary table: {BEST_TABLE_PATH}")
    print()
    print(k3)


if __name__ == "__main__":
    main()
