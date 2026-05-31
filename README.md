# Snort RAG Rule Generator

## Overview
This repository contains an academic NLP/RAG project for generating Snort IDS rules from natural-language descriptions of suspicious network activity. The system is designed as a controlled, defensive pipeline: it retrieves relevant examples from a local corpus, selects or adapts Snort-like rules from retrieved context when possible, and otherwise falls back to deterministic local templates. The project also includes local syntax validation, automatic explanation generation, and heuristic false-positive analysis.

The repository is intended for coursework and technical reporting. It is not presented as a production IDS engineering framework.

## Objectives
The project addresses the following goals:
- transform a textual attack description into a structured Snort-like detection rule
- compare several Retrieval-Augmented Generation architectures in a reproducible local setting
- maintain a personal, reviewable dataset consistent with academic project constraints
- provide interpretable outputs through validation metadata, explanations, and false-positive indicators

## Scope of the Repository
The current repository includes:
- a personal final retrieval dataset in `data/processed/final_snort_dataset.csv`
- a retrieval and generation package in `src/snort_rag/`
- multiple Devoir 3 architectures, including baseline, classic RAG, reranking, hybrid, multi-hop, graph-based, and agentic variants
- a local Snort-like parser/validator
- a false-positive analysis module for generated rules
- evaluation scripts, generated example artifacts, and report sections in `docs/` and `results/`

## Methodology
The generation workflow follows this sequence:

natural-language query  
→ retrieval of Top-k relevant documents  
→ controlled prompt and template logic  
→ rule selection or deterministic rule generation  
→ local syntax validation  
→ automatic explanation  
→ false-positive analysis

This is not a direct external-LLM generation workflow. The repository does not depend on OpenAI, Claude, Mistral, Ollama, or other hosted LLM APIs for final rule generation.

## Main Components

### 1. Retrieval Corpus
The official project dataset is:
- `data/processed/final_snort_dataset.csv`
- `data/processed/final_snort_dataset.jsonl`
- `data/processed/dataset_summary.json`
- `data/processed/person1_rules.rules`

This dataset is the default retrieval corpus for the application and evaluation pipeline. It is personal, limited in size, manually reviewable, and suitable for controlled academic experimentation.

### 2. Generation Module
The generation logic is primarily implemented in:
- `src/snort_rag/generator.py`
- `src/snort_rag/templates.py`
- `src/snort_rag/rule_parser.py`
- `src/snort_rag/false_positive.py`

The generator returns both legacy and enriched fields, including:
- `generated_rule`
- `attack_type`
- `valid_rule`
- `validation_errors`
- `syntax_validation`
- `detected_options`
- `missing_options`
- `false_positive_risk`
- `false_positive_score`
- `improvement_suggestions`
- `explanation`
- `source_doc_ids`
- `retrieved_context_used`
- `hallucination_risk`
- `option_coverage`

### 3. RAG Architectures
The repository evaluates seven configurations:
- baseline without RAG
- classic RAG
- RAG with re-ranking
- hybrid RAG
- multi-hop RAG
- graph RAG
- agentic RAG

### 4. Evaluation and Artifacts
Relevant outputs include:
- `results/comparison_metrics.csv`
- `results/detailed_devoir3_results.csv`
- `results/generated_rule_examples.csv`
- `results/false_positive_analysis.csv`
- `results/embedding_tsne.png`

## Installation
Create a virtual environment and install the project locally:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Reproducible Commands

### Run the Devoir 3 evaluation
```bash
python -m snort_rag.run_devoir3
```

Expected outputs:
- `results/comparison_metrics.csv`
- `results/detailed_devoir3_results.csv`
- `results/embedding_tsne.png`

### Generate example rules and false-positive artifacts
```bash
PYTHONPATH=src python scripts/generate_generation_examples.py
```

Expected outputs:
- `results/generated_rule_examples.csv`
- `results/false_positive_analysis.csv`

### Run focused tests
```bash
PYTHONPATH=src pytest tests/test_generator.py tests/test_rule_parser.py tests/test_retrieval.py tests/test_generate_dataset.py
```

### Launch the dashboard
```bash
python -m snort_rag.app_gradio
```

The dashboard provides a simple interface for:
- entering an attack description
- selecting a RAG architecture
- generating a rule
- reviewing retrieved documents
- extending the in-memory knowledge base with an uploaded PDF

## Trusted-Source Knowledge Base
If external rule references are needed for the optional trusted-rule knowledge base workflow, use:

```bash
python scripts/fetch_real_sources.py
```

This produces:
- `data/knowledge_base/trusted_rule_kb.csv`
- `data/knowledge_base/trusted_rule_kb.jsonl`
- `data/knowledge_base/fetch_summary.json`

These artifacts serve as reference material and optional experimental support. They are distinct from the official personal dataset used by the submitted project workflow.

## Repository Structure
```text
src/snort_rag/                         source package
data/processed/                        official project dataset and exported rules
data/knowledge_base/                   trusted-source rule reference artifacts
data/experiments/legacy_generated/     legacy experimental outputs
results/                               evaluation and generation artifacts
docs/                                  report sections and technical notes
scripts/                               reproducible project scripts
tests/                                 unit and integration-style tests
```

## Example Usage
```python
from snort_rag.architectures import SnortRAGArchitectures

rag = SnortRAGArchitectures("data/processed/final_snort_dataset.csv")
result = rag.agentic_rag("Detect SQL injection with UNION SELECT in HTTP URI")

print(result["generated_rule"])
print(result["explanation"])
print(result["false_positive_risk"])
```

## Validation Status and Limitations
This repository includes local Snort-like validation, but it does not claim that local validation is equivalent to runtime validation by the Snort engine.

Important limitations:
- the validator is structural and local only
- generated rules remain educational Snort-like outputs until verified in a real Snort environment
- false-positive analysis is heuristic, not empirical
- PCAP-based validation is still necessary to confirm actual detection behavior
- retrieval quality can still affect the final selected rule

## Academic Positioning
This repository is written for an academic context and emphasizes:
- reproducibility
- interpretability
- controlled local generation
- explicit limitations
- separation between personal dataset construction and external rule references

## Disclaimer
This is a defensive cybersecurity project for educational use. Generated rules should not be deployed operationally without real Snort runtime validation and behavior testing on representative traffic.
