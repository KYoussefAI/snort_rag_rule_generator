#!/usr/bin/env python
from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from snort_rag.clustering import run_clustering


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv")
    parser.add_argument("--out-dir", default=PROJECT_ROOT / "results")
    parser.add_argument("--clusters", type=int, default=None)
    args = parser.parse_args()
    metrics = run_clustering(Path(args.dataset), Path(args.out_dir), n_clusters=args.clusters)
    print(metrics.to_string(index=False))


if __name__ == "__main__":
    main()
