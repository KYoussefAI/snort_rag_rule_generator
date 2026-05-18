"""Metrics and visualizations for Devoir 3."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.manifold import TSNE
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.rule_parser import validate_rule

TEST_QUERIES = [
    {"query": "Detect a TCP SYN port scan against our web server with many ports touched in one minute", "expected_attack_type": "port_scan"},
    {"query": "Generate a Snort rule for repeated SSH brute force attempts on port 22", "expected_attack_type": "ssh_bruteforce"},
    {"query": "Détecter une injection SQL UNION SELECT dans une URL HTTP", "expected_attack_type": "sql_injection"},
    {"query": "Detect XSS attack where the URI contains <script>alert(1)</script>", "expected_attack_type": "xss"},
    {"query": "Alert when someone tries ../../../../etc/passwd directory traversal", "expected_attack_type": "directory_traversal"},
    {"query": "Detect command injection with cmd parameter and whoami in HTTP request", "expected_attack_type": "command_injection"},
    {"query": "Detect ${jndi:ldap://evil} Log4Shell payload in HTTP headers", "expected_attack_type": "log4shell"},
    {"query": "Detect DNS tunneling using long encoded subdomains", "expected_attack_type": "dns_tunneling"},
    {"query": "Detect AXFR DNS zone transfer attempt", "expected_attack_type": "dns_axfr"},
    {"query": "Detect ICMP ping sweep against internal network", "expected_attack_type": "icmp_sweep"},
    {"query": "Detect malware command and control beacon to /gate.php", "expected_attack_type": "malware_c2"},
    {"query": "Normal HTTP health check from the monitoring server, no attack", "expected_attack_type": "benign"},
]


def evaluate_architectures(rag: SnortRAGArchitectures, out_dir: Path) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, object]] = []
    detailed: List[Dict[str, object]] = []
    architectures = ["baseline", "rag_classic", "rag_rerank", "rag_hybrid", "multi_hop", "graph_rag", "agentic_rag"]

    for item in TEST_QUERIES:
        query = item["query"]
        expected = item["expected_attack_type"]
        results = rag.run_all(query)
        for arch in architectures:
            res = results[arch]
            predicted = str(res["attack_type"])
            valid_rule = bool(res["valid_rule"]) or predicted == "benign"
            retrieval_hit = expected in res.get("retrieved_attack_types", [])[:3] if arch != "baseline" else False
            detailed.append({
                "query": query,
                "expected_attack_type": expected,
                "architecture": arch,
                "predicted_attack_type": predicted,
                "attack_type_correct": predicted == expected,
                "valid_rule_or_benign": valid_rule,
                "retrieval_hit_at_3": retrieval_hit,
                "option_coverage": float(res.get("option_coverage", 0.0)),
                "hallucination_risk": float(res.get("hallucination_risk", 0.0)),
                "generated_rule": res.get("generated_rule", ""),
            })

    detail_df = pd.DataFrame(detailed)
    detail_df.to_csv(out_dir / "detailed_devoir3_results.csv", index=False)

    for arch, group in detail_df.groupby("architecture"):
        y_true = group["expected_attack_type"].tolist()
        y_pred = group["predicted_attack_type"].tolist()
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
        rows.append({
            "architecture": arch,
            "attack_accuracy": accuracy_score(y_true, y_pred),
            "macro_precision": precision,
            "macro_recall": recall,
            "macro_f1": f1,
            "valid_rule_rate": group["valid_rule_or_benign"].mean(),
            "retrieval_hit_at_3": group["retrieval_hit_at_3"].mean(),
            "avg_option_coverage": group["option_coverage"].mean(),
            "avg_hallucination_risk": group["hallucination_risk"].mean(),
        })
    summary = pd.DataFrame(rows).sort_values(["macro_f1", "retrieval_hit_at_3"], ascending=False)
    summary.to_csv(out_dir / "comparison_metrics.csv", index=False)
    return summary


def plot_tsne(rag: SnortRAGArchitectures, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = min(80, len(rag.kb.texts))
    X_sparse = rag.kb.tfidf[:n]
    labels = rag.kb.df.iloc[:n]["attack_type"].tolist()
    n_components = min(30, max(2, n - 1), X_sparse.shape[1] - 1)
    X = TruncatedSVD(n_components=n_components, random_state=42).fit_transform(X_sparse)
    perplexity = max(5, min(15, n // 5))
    coords = TSNE(n_components=2, random_state=42, init="random", perplexity=perplexity, max_iter=300, learning_rate="auto", method="exact").fit_transform(X)
    plt.figure(figsize=(10, 7))
    unique = sorted(set(labels))
    for label in unique:
        idx = [i for i, lab in enumerate(labels) if lab == label]
        plt.scatter(coords[idx, 0], coords[idx, 1], s=20, label=label, alpha=0.75)
    plt.title("t-SNE visualization of Snort RAG dataset vectors")
    plt.xlabel("t-SNE 1")
    plt.ylabel("t-SNE 2")
    plt.legend(fontsize=7, loc="best")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()
