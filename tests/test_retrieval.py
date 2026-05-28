import csv

from snort_rag.retrieval import SnortKnowledgeBase


def test_hybrid_rerank_retrieve_preserves_dataset_context(tmp_path):
    dataset_path = tmp_path / "dataset.csv"
    fieldnames = [
        "id",
        "description_naturelle",
        "attack_type",
        "attack_family",
        "protocol",
        "src_port",
        "dst_port",
        "severity",
        "log_example",
        "snort_rule_reference",
        "false_positive_context",
        "source_type",
        "expected_explanation",
    ]
    rows = [
        {
            "id": "ROW-1",
            "description_naturelle": "Detect SQL injection with UNION SELECT in HTTP URI",
            "attack_type": "sql_injection",
            "attack_family": "web_attack",
            "protocol": "http",
            "src_port": "any",
            "dst_port": "80",
            "severity": "high",
            "log_example": 'GET /search?q=union%20select HTTP/1.1',
            "snort_rule_reference": 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQLi"; content:"union select"; sid:9100001; rev:1;)',
            "false_positive_context": "developer staging payload",
            "source_type": "manual",
            "expected_explanation": "Union select payload indicates SQL injection.",
        },
        {
            "id": "ROW-2",
            "description_naturelle": "Normal HTTP health check from monitoring server",
            "attack_type": "benign_traffic",
            "attack_family": "benign",
            "protocol": "http",
            "src_port": "any",
            "dst_port": "80",
            "severity": "low",
            "log_example": 'GET /health HTTP/1.1',
            "snort_rule_reference": "NO_RULE_RECOMMENDED",
            "false_positive_context": "scheduled monitoring",
            "source_type": "manual",
            "expected_explanation": "Benign request.",
        },
    ]

    with dataset_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    kb = SnortKnowledgeBase(dataset_path)
    docs = kb.hybrid_rerank_retrieve("Need a Snort rule for union select SQL injection", k=1)

    assert len(docs) == 1
    assert docs[0].id == "ROW-1"
    assert docs[0].description_naturelle == rows[0]["description_naturelle"]
    assert docs[0].log_example == rows[0]["log_example"]
    assert docs[0].snort_rule_reference == rows[0]["snort_rule_reference"]
