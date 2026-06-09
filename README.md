# Snort RAG Rule Generator - NLP/RAG Mini Project

## Overview
This repository contains an academic NLP/RAG project for generating Snort IDS rules from natural-language descriptions of suspicious network activity. The system is designed as a controlled, defensive pipeline: it retrieves relevant examples from a local corpus, builds an enriched prompt, uses an LLM only inside that RAG context when configured, validates the output, and falls back explicitly to deterministic local templates if the LLM output is unavailable or invalid. The project also includes local syntax validation, automatic explanation generation, and heuristic false-positive analysis.

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
→ controlled enriched prompt  
→ LLM generation inside RAG, or explicit deterministic fallback  
→ local syntax validation and optional repair  
→ automatic explanation  
→ false-positive analysis

This is not a direct black-box LLM answer workflow. The final LLM path is constrained by retrieved documents, a strict JSON schema, parser validation, repair attempts, and explicit fallback metadata. The deterministic generator remains available as a baseline and fallback.

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
- `src/snort_rag/llm_clients.py`
- `src/snort_rag/prompting.py`
- `src/snort_rag/llm_generator.py`
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
- `model_name`
- `generation_mode`
- `repair_attempts`
- `prompt_variant`

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

### Run controlled LLM benchmarking
```bash
PYTHONPATH=src python scripts/benchmark_llms.py --models mock
```

For a real local LLM runtime, use an Ollama-compatible model spec:

```bash
ollama serve
ollama pull mistral
ollama pull llama3
ollama pull qwen2.5
PYTHONPATH=src python scripts/benchmark_llms.py --models ollama:mistral ollama:llama3 ollama:qwen2.5
```

The `mock` client is only a smoke-test client. Final LLM evidence should contain real local model rows, not only `model_spec=mock`.

Expected outputs:
- `results/llm_benchmark.csv`
- `results/llm_benchmark_summary.csv`

### Run attack-family clustering
```bash
PYTHONPATH=src python scripts/run_clustering_analysis.py
```

Expected outputs:
- `results/clustering_metrics.csv`
- `results/clustering_confusion_matrix.csv`
- `results/clustering_tsne.png`

### Generate lab PCAPs and run Snort validation
```bash
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated
PYTHONPATH=src python scripts/run_snort_validation.py --rules data/processed/person1_rules.rules
PYTHONPATH=src python scripts/run_pcap_tests.py --pcap-dir tests/pcaps/generated
```

If Snort is not installed, the runtime scripts write `SKIPPED` rows instead of claiming success.

The final report should include the exact Snort command, date, PASS/FAIL/SKIPPED counts, and triggered SIDs when Snort has actually run.

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
- selecting a controlled LLM model spec such as `mock` or `ollama:mistral`
- generating a rule
- reviewing retrieved documents
- inspecting the enriched prompt, raw LLM output, validation metadata, and false-positive metadata
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
- PCAP-based validation must be executed in a Snort-capable environment to confirm actual detection behavior
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
