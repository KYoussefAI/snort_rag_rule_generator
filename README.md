# Snort RAG Rule Generator - NLP Mini Project + Devoir 3

Defensive NLP/RAG project for generating valid Snort IDS rules from natural-language network-attack descriptions.

## What this project contains

- A **student-owned structured dataset** of Snort scenarios generated from manually curated attack cases and legitimate Snort rule-writing sources.
- A script to **generate and increase the dataset**: `python -m snort_rag.generate_dataset --multiplier 20`.
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

## Important academic constraint

The assignment forbids direct black-box LLM use and forbids OpenAI/Mistral/Ollama API usage for Devoir 3. Therefore this project uses a **local transparent generator** based on retrieved context + Snort templates. The code still implements the complete RAG pipeline: query encoding, retrieval, prompt construction, generation, explanation and evaluation.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Generate or increase the dataset

```bash
python -m snort_rag.generate_dataset --multiplier 10
# bigger dataset
python -m snort_rag.generate_dataset --multiplier 30
```

Output:

- `data/processed/snort_generated_dataset.csv`
- `data/processed/snort_generated_dataset.json`
- `data/processed/snort_generated_dataset.jsonl`
- `data/processed/dataset_summary.json`

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

## Optional: fetch real public rule sources

The environment used to package this project did not have direct Internet access from Python, so the project ships a reproducible script:

```bash
python scripts/fetch_real_sources.py
```

It can download public/open rule archives from Snort/ET Open and stores only rule metadata skeletons, not a copied public dataset. This respects the cahier de charge: the final dataset is built by the student using manual seeds + synthetic enrichment.

## Project structure

```text
src/snort_rag/                 package source code
data/raw/                      source manifest and optional extracted metadata
data/processed/                generated personal dataset
notebooks/                     Devoir 3 notebook
results/                       metrics and t-SNE plot
docs/                          report files
scripts/fetch_real_sources.py  optional Internet source extraction
```

## Example

```python
from snort_rag.architectures import SnortRAGArchitectures
rag = SnortRAGArchitectures("data/processed/snort_generated_dataset.csv")
result = rag.agentic_rag("Detect Log4Shell ${jndi:ldap://evil} in HTTP headers")
print(result["generated_rule"])
print(result["explanation"])
```

## Disclaimer

This is a defensive IDS rule generation project for education. Every generated rule must still be validated in a real Snort installation using Snort's configuration test mode before production use.
