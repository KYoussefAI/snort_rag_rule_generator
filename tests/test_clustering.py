import csv

from snort_rag.clustering import run_clustering


def test_clustering_outputs_metrics(tmp_path):
    dataset = tmp_path / "dataset.csv"
    fieldnames = ["id", "description_naturelle", "attack_type", "attack_family", "log_example", "snort_rule_reference", "expected_explanation"]
    rows = []
    for idx in range(12):
        label = "sql_injection" if idx < 6 else "ssh_bruteforce"
        rows.append({
            "id": f"R{idx}",
            "description_naturelle": f"{label} example {idx}",
            "attack_type": label,
            "attack_family": "web" if label == "sql_injection" else "auth",
            "log_example": "union select" if label == "sql_injection" else "ssh login",
            "snort_rule_reference": "NO_RULE_RECOMMENDED",
            "expected_explanation": label,
        })
    with dataset.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    metrics = run_clustering(dataset, tmp_path, n_clusters=2)

    assert not metrics.empty
    assert (tmp_path / "clustering_metrics.csv").exists()
    assert (tmp_path / "clustering_confusion_matrix.csv").exists()
