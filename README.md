# Snort RAG Rule Generator - NLP Mini Project

Defensive NLP/RAG project for generating valid Snort IDS rules from natural-language network-attack descriptions.

## What this project contains

- An **official Person 1 retrieval dataset** stored in `data/processed/final_snort_dataset.csv`.
- A **trusted-source knowledge base** of real Snort rules stored in `data/knowledge_base/`.
- A legacy script to **expand trusted rules into experiment rows**: `python -m snort_rag.generate_dataset --multiplier 20`.
- Seven Devoir 3 architectures:
  - baseline without RAG
  - classic RAG
  - RAG with re-ranking
  - hybrid RAG (TF-IDF dense fallback + BM25 fusion)
  - multi-hop RAG
  - graph RAG
  - agentic RAG
- Metrics and comparison table in `results/comparison_metrics.csv`.
- t-SNE embedding visualization in `results/embedding_tsne.png`.
- Gradio dashboard with PDF upload to extend the knowledge base.
- Technical report in `docs/`.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Build the real-rule knowledge base

```bash
python scripts/fetch_real_sources.py
```

Outputs:

- `data/knowledge_base/trusted_rule_kb.csv`
- `data/knowledge_base/trusted_rule_kb.jsonl`
- `data/knowledge_base/fetch_summary.json`

## Official Person 1 dataset

The official dataset used by the application, Devoir 3 runner, and retrieval layer is:

- `data/processed/final_snort_dataset.csv`
- `data/processed/final_snort_dataset.jsonl`
- `data/processed/dataset_summary.json`
- `data/processed/person1_rules.rules`

This dataset is personal, controlled, manually reviewable, and is the main dataset for Person 1 and the default retrieval corpus across the project.

The exported Person 1 rules are locally pre-validated with a strengthened validator. This does not replace Snort runtime validation.

Submission status:

- The official Person 1 dataset is `data/processed/final_snort_dataset.csv`.
- The final dataset is personal, controlled, balanced across 10 attack types, and contains 200 rows.
- The legacy trusted-rule expansion generator remains in the repository only as experimental code.
- The old 500k-row generated files are not included in the final submitted project.

## Legacy dataset generator

The legacy generator requires the trusted real-rule knowledge base and creates
multiple natural-language rows per real rule for older experiments only.

```bash
python -m snort_rag.generate_dataset --multiplier 10
# bigger dataset
python -m snort_rag.generate_dataset --multiplier 30
```

Legacy outputs if you run the experiment manually:

- `data/experiments/legacy_generated/snort_generated_dataset.csv`
- `data/experiments/legacy_generated/snort_generated_dataset.json`
- `data/experiments/legacy_generated/snort_generated_dataset.jsonl`
- `data/experiments/legacy_generated/snort_generated_dataset_summary.json`

These files are legacy experimental artifacts only. The legacy generator no longer writes into `data/processed/` and must not be used as the official Person 1 dataset workflow.

## Run Devoir 3 comparison

```bash
python -m snort_rag.run_devoir3
```

Outputs:

- `results/comparison_metrics.csv`
- `results/detailed_devoir3_results.csv`
- `results/embedding_tsne.png`

## Launch dashboard

```bash
python -m snort_rag.app_gradio
```

The dashboard lets you choose a RAG architecture, generate a Snort rule, inspect retrieved documents and add a PDF as a new knowledge source.

## Project structure

```text
src/snort_rag/                 package source code
data/knowledge_base/           persisted trusted-source real Snort rules
data/raw/                      source manifest
data/processed/                official Person 1 dataset
data/experiments/legacy_generated/ legacy trusted-rule expansion outputs only
notebooks/                     Devoir 3 notebook
results/                       metrics and t-SNE plot
docs/                          report files
scripts/fetch_real_sources.py  trusted-source rule ingestion
```

## Example

```python
from snort_rag.architectures import SnortRAGArchitectures
rag = SnortRAGArchitectures("data/processed/final_snort_dataset.csv")
result = rag.agentic_rag("Detect SQL injection with UNION SELECT in HTTP URI")
print(result["generated_rule"])
print(result["explanation"])
```

## Disclaimer

This is a defensive IDS rule generation project for education. Every generated rule must still be validated in a real Snort installation using Snort's configuration test mode before production use.
