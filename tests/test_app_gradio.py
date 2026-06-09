from pathlib import Path

import pandas as pd

from snort_rag import app_gradio


def test_app_gradio_imports():
    assert app_gradio.DATASET.exists()
    assert app_gradio.demo is None or app_gradio.gr is not None


def test_safe_load_csv_handles_missing_file(tmp_path):
    missing = tmp_path / "missing.csv"

    df = app_gradio.safe_load_csv(missing)

    assert isinstance(df, pd.DataFrame)
    assert df.empty


def test_evidence_summary_handles_missing_result_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(app_gradio, "RESULTS_DIR", tmp_path)

    summary = app_gradio.build_evidence_summary()

    assert summary["Snort runtime validation"] == "Not available"
    assert summary["PCAP replay"] == "Not available"
    assert summary["Available LLM benchmark models"] == "Not available"


def test_dataset_stats_uses_project_dataset():
    summary, attack_counts, source_counts, preview = app_gradio.dataset_stats()

    assert "Rows:" in summary
    assert "Personal RAG dataset" in summary
    assert not attack_counts.empty
    assert not source_counts.empty
    assert not preview.empty
    assert "benign_traffic" in set(attack_counts["attack_type"])
