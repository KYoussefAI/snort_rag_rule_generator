# Strict Compliance Matrix

| Requirement | Project artifact | Status |
| --- | --- | --- |
| Personal dataset | `data/processed/final_snort_dataset.csv`, `DATASET_CARD.md`, `dataset_manifest.json` | Implemented |
| Separation of personal dataset and optional external references | Personal RAG dataset in `data/processed/`; optional trusted-source KB in `data/knowledge_base/trusted_rule_kb.csv` | Implemented |
| Retrieval with BM25 and embeddings | `src/snort_rag/retrieval.py`, `scripts/benchmark_retrieval.py` | Implemented, optional dense backends depend on install |
| LLM generation from query + retrieved docs | `src/snort_rag/llm_generator.py`, `src/snort_rag/prompting.py` | Implemented, real model execution required for final report |
| LLM benchmarking | `scripts/benchmark_llms.py` | Implemented, run with local models for final evidence |
| Full RAG pipeline | `src/snort_rag/architectures.py` | Implemented |
| Classification and clustering | `src/snort_rag/templates.py`, `src/snort_rag/clustering.py` | Implemented |
| Rule explanation | `src/snort_rag/generator.py`, `src/snort_rag/llm_generator.py` | Implemented |
| False-positive optimization | `src/snort_rag/false_positive.py`, `results/pcap_test_results.csv` benign replay row | Implemented heuristics plus controlled benign PCAP replay evidence; not an enterprise deployment study |
| Snort 3 runtime validation | `tools/snort3-docker`, `data/processed/person1_rules_snort3.rules`, `results/snort_runtime_validation.csv` | Implemented with real Snort 3 Docker execution when Docker image is available |
| Protocol-valid PCAP integration | `scripts/generate_lab_pcaps.py`, `scripts/run_pcap_tests.py`, `tests/pcaps/generated/`, `results/pcap_test_results.csv` | Implemented; PCAPs are synthetic educational lab captures |
| Synthetic academic log integration | `data/logs/sample_network_logs.csv`, `scripts/run_log_integration_eval.py`, `results/network_log_integration_eval.csv` | Implemented; clearly labeled synthetic academic logs |
| Controlled real-lab log integration | `scripts/capture_real_lab_logs.sh`, `data/logs/real_lab_logs/`, `scripts/run_real_log_integration_eval.py`, `results/real_lab_log_integration_eval.csv`, `tests/test_real_log_integration.py` | Implemented; real controlled lab artifacts, not enterprise production logs |
| Dashboard with PDF upload | `src/snort_rag/app_gradio.py` | Implemented |
| Technical report sections | `docs/report_section_*.md` | Draft sections present |
