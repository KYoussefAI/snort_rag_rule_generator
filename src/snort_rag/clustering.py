"""Attack-family clustering utilities for the Snort RAG dataset."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from sklearn.cluster import AgglomerativeClustering, KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.manifold import TSNE
from sklearn.metrics import (
    adjusted_rand_score,
    completeness_score,
    homogeneity_score,
    normalized_mutual_info_score,
    silhouette_score,
    v_measure_score,
)


def _compose_text(df: pd.DataFrame) -> list[str]:
    cols = ["description_naturelle", "attack_type", "attack_family", "log_example", "snort_rule_reference", "expected_explanation"]
    return df.fillna("").apply(lambda row: " ".join(str(row.get(col, "")) for col in cols), axis=1).tolist()


def _metrics(name: str, labels_true: list[str], cluster_labels: Any, matrix: Any) -> dict[str, object]:
    n_clusters = len(set(int(x) for x in cluster_labels))
    return {
        "method": name,
        "n_clusters": n_clusters,
        "silhouette": silhouette_score(matrix, cluster_labels) if n_clusters > 1 else 0.0,
        "ari": adjusted_rand_score(labels_true, cluster_labels),
        "nmi": normalized_mutual_info_score(labels_true, cluster_labels),
        "homogeneity": homogeneity_score(labels_true, cluster_labels),
        "completeness": completeness_score(labels_true, cluster_labels),
        "v_measure": v_measure_score(labels_true, cluster_labels),
    }


def run_clustering(dataset_path: Path, out_dir: Path, n_clusters: int | None = None) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(dataset_path).fillna("")
    labels = df["attack_type"].astype(str).tolist()
    n_clusters = n_clusters or max(2, min(10, df["attack_type"].nunique()))
    texts = _compose_text(df)
    tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=12000).fit_transform(texts)
    svd_components = min(50, max(2, tfidf.shape[0] - 1), max(2, tfidf.shape[1] - 1))
    dense = TruncatedSVD(n_components=svd_components, random_state=42).fit_transform(tfidf)

    methods = {
        "tfidf_svd_kmeans": KMeans(n_clusters=n_clusters, random_state=42, n_init=10).fit_predict(dense),
        "tfidf_svd_agglomerative": AgglomerativeClustering(n_clusters=n_clusters).fit_predict(dense),
    }
    rows = [_metrics(name, labels, clusters, dense) for name, clusters in methods.items()]
    metrics = pd.DataFrame(rows)
    metrics.to_csv(out_dir / "clustering_metrics.csv", index=False)

    best_name = metrics.sort_values("nmi", ascending=False).iloc[0]["method"]
    best_labels = methods[str(best_name)]
    confusion = pd.crosstab(pd.Series(best_labels, name="cluster"), pd.Series(labels, name="attack_type"))
    confusion.to_csv(out_dir / "clustering_confusion_matrix.csv")

    perplexity = max(5, min(30, len(df) // 5))
    coords = TSNE(n_components=2, random_state=42, init="random", perplexity=perplexity, learning_rate="auto").fit_transform(dense)
    plt.figure(figsize=(10, 7))
    for cluster in sorted(set(best_labels)):
        idx = [i for i, label in enumerate(best_labels) if label == cluster]
        plt.scatter(coords[idx, 0], coords[idx, 1], s=18, alpha=0.75, label=f"cluster {cluster}")
    plt.title("Attack-family clustering over Snort RAG dataset")
    plt.xlabel("t-SNE 1")
    plt.ylabel("t-SNE 2")
    plt.legend(fontsize=7)
    plt.tight_layout()
    plt.savefig(out_dir / "clustering_tsne.png", dpi=160)
    plt.close()
    return metrics
