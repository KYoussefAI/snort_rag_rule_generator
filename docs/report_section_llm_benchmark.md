# LLM Benchmarking Methodology

The reported LLM evidence is for a controlled RAG rule-generation pipeline, not for raw LLM perfection. Each query is matched against the personal Snort dataset, retrieved context is inserted into a strict prompt, and the returned JSON is parsed, validated, repaired when possible, or replaced by a deterministic fallback when strict validation rejects the raw response.

Current benchmark artifacts:
- `results/llm_benchmark.csv`
- `results/llm_benchmark_summary.csv`

The benchmark includes local Ollama models such as `qwen2.5`, `mistral`, and `llama3.2`. Metrics include valid rule rate, attack-type accuracy, retrieval grounding, false-positive score, option coverage, latency, model name, prompt variant, generation mode, and repair attempts. Rows should therefore be interpreted as controlled pipeline outcomes, including fallback behavior, rather than as claims that every raw model response was directly usable.

Example command for a short local benchmark:

```bash
PYTHONPATH=src python scripts/benchmark_llms.py \
  --models ollama:qwen2.5 ollama:mistral ollama:llama3.2 \
  --eval data/evaluation/snort_eval_quick_10.csv \
  --out results/llm_benchmark.csv \
  --summary-out results/llm_benchmark_summary.csv
```

The benchmark writes `status=error` rows if a local model runtime is unavailable, so one failed model does not abort the full comparison.
