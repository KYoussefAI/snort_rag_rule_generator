# Dashboard Usage

Launch the dashboard from the repository root:

```bash
PYTHONPATH=src python -m snort_rag.app_gradio
```

The dashboard is an academic prototype interface for the controlled Snort RAG pipeline. It is not a production IDS console.

## Tabs

1. **Rule Generator** accepts an attack description, architecture, Top-k value, and model spec. Use `mock` only for smoke testing. For local LLM tests, use examples such as `ollama:qwen2.5`, `ollama:mistral`, or `ollama:llama3.2`. The tab shows the generated rule, attack type, generation mode, model name, validity status, fallback warning, explanation, and downloadable latest result files.
2. **Retrieval Details** shows retrieved document IDs, scores, context metadata, whether retrieved context was used, hallucination risk, option coverage, and prompt preview. This demonstrates that generation is grounded in retrieved context, not direct black-box LLM output.
3. **Validation & False Positives** shows syntax validation, validation errors, detected and missing Snort options, false-positive risk, score, risk factors, and improvement suggestions. `NO_RULE_RECOMMENDED` is expected for benign traffic.
4. **Dataset / Knowledge Base** summarizes the personal RAG dataset and separates it from synthetic academic logs, controlled real-lab logs, and optional trusted-source Snort references.
5. **Benchmarks & Evidence** loads existing result artifacts for LLM benchmarking, embedding retrieval, clustering, Snort runtime validation, PCAP replay, and real-lab log integration. Missing files are shown as unavailable rather than invented.
6. **PDF Upload** indexes an uploaded PDF into the in-memory knowledge base for the current session. It reports the uploaded file name, chunks added, new knowledge-base size, and a preview of the first imported chunk when available.

## Suggested Final-Report Screenshots

- Rule generation example using `Agentic RAG`.
- Retrieval Details showing document IDs and context-use metadata.
- Validation & False Positives for a malicious rule and a benign `NO_RULE_RECOMMENDED` example.
- Dataset / Knowledge Base tab showing attack type and source type distributions.
- Benchmarks & Evidence tab showing Snort runtime, PCAP replay, and LLM benchmark tables.
- PDF Upload after importing a small reference PDF.
