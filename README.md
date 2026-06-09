# Snort RAG Rule Generator - NLP/RAG Mini Project

## Overview
This repository contains an academic NLP/RAG project for generating Snort IDS rules from natural-language descriptions and realistic network-log examples. The system is defensive and controlled: it classifies the suspected attack type, retrieves relevant examples from a local corpus, builds a constrained RAG prompt, accepts LLM output only when it passes strict validation, and otherwise falls back to deterministic templates for safety and reproducibility.

The current project state includes real Snort 3 validation through Docker, protocol-valid synthetic lab PCAP replay, synthetic academic log evaluation, and a separate controlled real-lab-log workflow. It is still an educational project, not a production IDS engineering framework.

## Current Validation Evidence
| Evidence area | Current result | Main artifacts |
| --- | ---: | --- |
| Snort 3 syntax/runtime validation | 183/183 PASS | `tools/snort3-docker`, `data/processed/person1_rules_snort3.rules`, `results/snort_runtime_validation.csv`, `results/snort3_syntax_test.txt` |
| PCAP replay | 9/9 attack categories detected, 0 benign false positives | `scripts/generate_lab_pcaps.py`, `scripts/run_pcap_tests.py`, `tests/pcaps/generated/`, `results/pcap_test_results.csv` |
| Synthetic network log integration | 10/10 PASS, 1.000 classification accuracy | `data/logs/sample_network_logs.csv`, `scripts/run_log_integration_eval.py`, `results/network_log_integration_eval.csv` |
| Controlled real-lab log integration | 10/10 PASS, 1.000 classification accuracy | `data/logs/real_lab_logs/`, `scripts/capture_real_lab_logs.sh`, `scripts/run_real_log_integration_eval.py`, `results/real_lab_log_integration_eval.csv` |
| LLM benchmarking | qwen2.5, mistral, llama3.2 through Ollama | `results/llm_benchmark.csv`, `results/llm_benchmark_summary.csv` |
| Automated tests | run with `PYTHONPATH=src pytest tests/` | `tests/` |

Real Snort execution uses the Docker wrapper `tools/snort3-docker`, which invokes `/home/snorty/snort3/bin/snort` inside the container. The validated Snort config is `/home/snorty/snort3/etc/snort/snort.lua`.

If the Docker image or wrapper is unavailable, real runtime validation cannot be claimed. In that case validation results should be marked `SKIPPED` or failed honestly, not inferred from local parsing.

## Objectives
- Generate educational Snort 3-compatible rules from network-security descriptions or log examples.
- Compare retrieval and RAG generation strategies in a reproducible local setting.
- Keep the dataset and generated evidence reviewable for academic reporting.
- Record validation metadata, retrieved context, explanations, false-positive indicators, Snort 3 runtime checks, and PCAP replay evidence.

## Methodology
The current workflow is:

network log or natural-language input  
-> attack type classification  
-> retrieval/RAG context  
-> controlled LLM generation or deterministic fallback  
-> rule validation and repair  
-> Snort 3 syntax/runtime validation  
-> PCAP replay evidence  
-> false-positive review

The LLM path is intentionally constrained by retrieved documents, strict JSON parsing, rule validation, repair attempts, and fallback metadata. Some raw LLM responses are rejected by schema or rule validation and replaced by deterministic fallback output; this is intentional for safety, reproducibility, and honest reporting.

## Main Components

### Dataset and Logs
- `data/processed/final_snort_dataset.csv`
- `data/processed/final_snort_dataset.jsonl`
- `data/processed/person1_rules_snort3.rules`
- `data/logs/sample_network_logs.csv`
- `data/logs/real_lab_logs/`

The processed dataset is the personal retrieval corpus used by the RAG pipeline. `data/logs/sample_network_logs.csv` contains realistic synthetic academic logs used during dataset construction and synthetic log integration evaluation. `data/logs/real_lab_logs/` contains small sanitized controlled lab logs produced from local PCAP replay and PCAP parsing commands; these are real lab artifacts, not enterprise production logs.

### Generation and RAG Modules
- `src/snort_rag/generator.py`
- `src/snort_rag/llm_generator.py`
- `src/snort_rag/llm_clients.py`
- `src/snort_rag/prompting.py`
- `src/snort_rag/retrieval.py`
- `src/snort_rag/templates.py`
- `src/snort_rag/rule_parser.py`
- `src/snort_rag/false_positive.py`

The generator returns structured fields such as `generated_rule`, `attack_type`, `valid_rule`, `validation_errors`, `detected_options`, `source_doc_ids`, `retrieved_context_used`, `generation_mode`, and false-positive metadata.

### Evaluated Architectures
The project includes baseline generation, classic RAG, reranking RAG, hybrid RAG, multi-hop RAG, graph RAG, and agentic RAG variants.

### Evidence Artifacts
- `results/generated_rule_examples.csv`
- `results/false_positive_analysis.csv`
- `results/snort_runtime_validation.csv`
- `results/pcap_test_results.csv`
- `results/network_log_integration_eval.csv`
- `results/real_lab_log_integration_eval.csv`
- `results/llm_benchmark.csv`
- `results/llm_benchmark_summary.csv`
- `results/embedding_benchmark.csv`
- `results/clustering_metrics.csv`
- `results/clustering_confusion_matrix.csv`
- `results/clustering_tsne.png`

## Installation
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

Docker is required for the provided Snort 3 wrapper.

## Reproducible Commands

### Run the main Devoir 3 evaluation
```bash
PYTHONPATH=src python -m snort_rag.run_devoir3
```

### Generate rule examples and false-positive artifacts
```bash
PYTHONPATH=src python scripts/generate_generation_examples.py
```

### Run quick local LLM benchmarks
Existing benchmark artifacts already include Ollama `qwen2.5`, `mistral`, and `llama3.2` results. To refresh a small local benchmark without forcing a long run, use the quick evaluation data and selected local models:

```bash
ollama serve
ollama pull qwen2.5
ollama pull mistral
ollama pull llama3.2
PYTHONPATH=src python scripts/benchmark_llms.py \
  --queries data/evaluation/snort_eval_quick_10.csv \
  --models ollama:qwen2.5 ollama:mistral ollama:llama3.2
```

LLM results should be interpreted with the strict-validation policy in mind: invalid raw model outputs may be rejected and replaced by deterministic fallback rules.

### Run Snort 3 runtime validation
```bash
PYTHONPATH=src python scripts/run_snort_validation.py \
  --snort-bin ./tools/snort3-docker \
  --config /home/snorty/snort3/etc/snort/snort.lua \
  --rules data/processed/person1_rules_snort3.rules \
  --out results/snort_runtime_validation.csv
```

### Generate and replay protocol-valid lab PCAPs
```bash
PYTHONPATH=src python scripts/generate_lab_pcaps.py --out tests/pcaps/generated

PYTHONPATH=src python scripts/run_pcap_tests.py \
  --snort-bin ./tools/snort3-docker \
  --config /home/snorty/snort3/etc/snort/snort.lua \
  --rules data/processed/person1_rules_snort3.rules \
  --pcap-dir tests/pcaps/generated \
  --out results/pcap_test_results.csv
```

### Run network log integration evaluation
```bash
PYTHONPATH=src python scripts/run_log_integration_eval.py
```

### Capture and evaluate controlled real-lab logs
```bash
scripts/capture_real_lab_logs.sh
PYTHONPATH=src python scripts/run_real_log_integration_eval.py
```

### Run retrieval and clustering evaluations
```bash
PYTHONPATH=src python scripts/benchmark_retrieval.py
PYTHONPATH=src python scripts/run_clustering_analysis.py
```

### Run all tests
```bash
PYTHONPATH=src pytest tests/
```

### Launch the dashboard
```bash
PYTHONPATH=src python -m snort_rag.app_gradio
```

The dashboard is organized into six tabs:
- Rule Generator: attack description input, architecture selection, Top-k retrieval, model selection, generated rule display, validity status, fallback warning, and export of the latest `.rules`/JSON result.
- Retrieval Details: retrieved document IDs, retrieval scores, context metadata, grounding flags, hallucination risk, option coverage, and prompt preview.
- Validation & False Positives: syntax validation, validation errors, detected/missing Snort options, false-positive risk, risk factors, and improvement suggestions.
- Dataset / Knowledge Base: personal RAG dataset statistics plus clear separation between synthetic academic logs, controlled real-lab logs, and optional trusted-source references.
- Benchmarks & Evidence: tables loaded from existing Snort runtime, PCAP replay, log integration, LLM, embedding, and clustering result files.
- PDF Upload: temporary in-memory knowledge-base extension for retrieval during the current session.

See `docs/dashboard_usage.md` for a short usage guide and suggested screenshots for the final report.

## Trusted-Source Knowledge Base
Optional trusted-source rule references can be refreshed with:

```bash
PYTHONPATH=src python scripts/fetch_real_sources.py
```

This produces `data/knowledge_base/trusted_rule_kb.csv`, `data/knowledge_base/trusted_rule_kb.jsonl`, and `data/knowledge_base/fetch_summary.json`. These references are separate from the official personal dataset used for the submitted workflow.

## Repository Structure
```text
src/snort_rag/                         source package
data/processed/                        project dataset and Snort 3-compatible exported rules
data/logs/sample_network_logs.csv      realistic synthetic academic network logs
data/logs/real_lab_logs/               controlled lab-captured/parsing log artifacts
data/knowledge_base/                   optional trusted-source rule reference artifacts
results/                               evaluation, validation, and benchmarking artifacts
docs/                                  report sections and technical notes
scripts/                               reproducible project scripts
tests/                                 unit and integration-style tests
tests/pcaps/generated/                 protocol-valid synthetic lab PCAPs
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

## Limitations
- The PCAPs are protocol-valid synthetic educational lab captures, not production traffic.
- `data/logs/sample_network_logs.csv` contains realistic synthetic academic examples, not private production logs.
- `data/logs/real_lab_logs/` contains real controlled lab logs and log-style summaries generated from local PCAP replay/parsing. They satisfy lab integration evidence, but they are not enterprise production logs.
- False-positive analysis combines heuristics with benign lab replay evidence; it is not a full enterprise deployment study.
- LLM outputs may be rejected by strict schema/rule validation and replaced by deterministic fallback output. This is intentional and should be reported as fallback behavior, not as raw LLM success.
- Snort 3 runtime evidence depends on the Docker wrapper and image being available. If Snort cannot run, runtime validation must be marked `SKIPPED` or failed honestly.
- Generated rules are educational artifacts and should not be deployed operationally without broader environment-specific testing.

## Academic Positioning
This repository emphasizes reproducibility, interpretability, controlled local generation, explicit validation evidence, and honest limitations. It is suitable for academic reporting on NLP/RAG-assisted defensive rule generation, not for direct production IDS deployment.

## Disclaimer
This is a defensive cybersecurity project for educational use. Generated rules should be independently reviewed and tested before any operational use.
