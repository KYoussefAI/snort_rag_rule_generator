from __future__ import annotations

from pathlib import Path

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.evaluation import evaluate_architectures, plot_tsne

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    dataset = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
    if not dataset.exists():
        raise SystemExit("Dataset not found. Expected official Person 1 dataset at data/processed/final_snort_dataset.csv")
    rag = SnortRAGArchitectures(dataset)
    out_dir = PROJECT_ROOT / "results"
    summary = evaluate_architectures(rag, out_dir)
    plot_tsne(rag, out_dir / "embedding_tsne.png")
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
