# LLM Benchmarking Methodology

The final generation module uses an LLM only inside a controlled RAG pipeline. The query is first matched against the personal Snort dataset, Top-k documents are inserted into a strict JSON prompt, and the generated rule is parsed and validated before being accepted.

Run:

```bash
PYTHONPATH=src python scripts/benchmark_llms.py --models mock
```

For final submission in a Snort/LLM-capable environment, replace `mock` with local model specs such as:

```bash
ollama serve
ollama pull mistral
ollama pull llama3
ollama pull qwen2.5
PYTHONPATH=src python scripts/benchmark_llms.py --models ollama:mistral ollama:llama3 ollama:qwen2.5
```

Required outputs:

- `results/llm_benchmark.csv`
- `results/llm_benchmark_summary.csv`

Metrics include valid rule rate, attack-type accuracy, retrieval grounding, false-positive score, option coverage, latency, model name, prompt variant, generation mode, and repair attempts.

The `mock` client is only a smoke-test client for schema, prompt, validation, and artifact generation. If only the mock client is executed, the report must state: "The LLM pipeline was smoke-tested with a mock client; real local LLM benchmarking remains to be executed."

The benchmark writes `status=error` rows if a local model runtime is unavailable, so one failed model does not abort the full comparison.
