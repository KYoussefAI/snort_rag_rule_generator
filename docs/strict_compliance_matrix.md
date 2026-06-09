# Strict Compliance Matrix

| Requirement | Project artifact | Status |
| --- | --- | --- |
| Personal dataset | `data/processed/final_snort_dataset.csv`, `DATASET_CARD.md`, `dataset_manifest.json` | Implemented |
| Retrieval with BM25 and embeddings | `src/snort_rag/retrieval.py`, `scripts/benchmark_retrieval.py` | Implemented, optional dense backends depend on install |
| LLM generation from query + retrieved docs | `src/snort_rag/llm_generator.py`, `src/snort_rag/prompting.py` | Implemented, real model execution required for final report |
| LLM benchmarking | `scripts/benchmark_llms.py` | Implemented, run with local models for final evidence |
| Full RAG pipeline | `src/snort_rag/architectures.py` | Implemented |
| Classification and clustering | `src/snort_rag/templates.py`, `src/snort_rag/clustering.py` | Implemented |
| Rule explanation | `src/snort_rag/generator.py`, `src/snort_rag/llm_generator.py` | Implemented |
| False-positive optimization | `src/snort_rag/false_positive.py` | Implemented heuristics; empirical results require PCAP run |
| Real logs/PCAP integration | `scripts/generate_lab_pcaps.py`, `scripts/run_pcap_tests.py` | Implemented scripts; execute with Snort for final evidence |
| Dashboard with PDF upload | `src/snort_rag/app_gradio.py` | Implemented |
| Technical report sections | `docs/report_section_*.md` | Draft sections present |
