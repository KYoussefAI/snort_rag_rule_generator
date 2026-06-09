"""Gradio dashboard for the Snort RAG Rule Generator."""
from __future__ import annotations

from pathlib import Path
import json

try:
    import gradio as gr
except ModuleNotFoundError:  # pragma: no cover
    gr = None

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.llm_clients import build_llm_client

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
rag = SnortRAGArchitectures(DATASET)


def _pcap_empirical_status() -> str:
    path = PROJECT_ROOT / "results" / "pcap_test_results.csv"
    if not path.exists():
        return "not executed"
    try:
        import csv
        with path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    except Exception:
        return "not executed"
    if not rows or all(row.get("status") == "SKIPPED" for row in rows):
        return "not executed"
    benign = [row for row in rows if row.get("expected_attack") == "benign_traffic"]
    benign_alerts = benign[0].get("alert_count", "") if benign else "unknown"
    return f"executed; benign_alert_count={benign_alerts}"


def _retrieved_table(result: dict) -> str:
    return "\n".join(
        f"{i+1}. {doc_id} | {atype} | score={score}"
        for i, (doc_id, atype, score) in enumerate(zip(
            result.get("retrieved_ids", []),
            result.get("retrieved_attack_types", []),
            result.get("retrieval_scores", []),
        ))
    )


def generate(query: str, architecture: str, k: int, model_spec: str):
    if not query.strip():
        return "", "", "", "", "", "", ""
    mapping = {
        "Baseline sans RAG": lambda q: rag.baseline_no_rag(q),
        "RAG classique": lambda q: rag.rag_classic(q, k=k),
        "RAG + re-ranking": lambda q: rag.rag_rerank(q, k=max(k, 5)),
        "RAG hybride": lambda q: rag.rag_hybrid(q, k=k),
        "Multi-hop RAG": lambda q: rag.multi_hop_rag(q, k=k),
        "Graph RAG": lambda q: rag.graph_rag(q, k=k),
        "Agentic RAG": lambda q: rag.agentic_rag(q, k=k),
        "RAG + LLM controle": lambda q: rag.rag_llm_generate(q, k=k, client=build_llm_client(model_spec)),
    }
    fn = mapping[architecture]
    result = fn(query)
    validation = json.dumps({
        "valid_rule": result.get("valid_rule"),
        "generation_mode": result.get("generation_mode", "deterministic_template_or_retrieved_rule"),
        "model_name": result.get("model_name", "none"),
        "repair_attempts": result.get("repair_attempts", 0),
        "validation_errors": result.get("validation_errors", []),
        "false_positive_risk": result.get("false_positive_risk"),
        "false_positive_score": result.get("false_positive_score"),
        "empirical_pcap_results": _pcap_empirical_status(),
    }, indent=2)
    return (
        result["generated_rule"],
        result["attack_type"],
        result["explanation"],
        _retrieved_table(result),
        str(result.get("prompt", "")),
        str(result.get("raw_llm_output", "")),
        validation,
    )


def add_pdf(pdf_file):
    if pdf_file is None:
        return "No PDF uploaded."
    try:
        count = rag.kb.add_pdf_to_kb(pdf_file.name, source_name=Path(pdf_file.name).name)
        return f"Added {count} PDF chunks to the in-memory knowledge base."
    except Exception as exc:
        return f"PDF import failed: {exc}"


def dataset_stats():
    df = rag.kb.df
    counts = df["attack_type"].value_counts().to_string()
    backend = json.dumps(rag.kb.embedding_backend_info(), indent=2)
    return f"Rows: {len(df)}\n\nAttack type counts:\n{counts}\n\nEmbedding backend:\n{backend}"


if gr is not None:
    with gr.Blocks(title="Snort RAG Rule Generator") as demo:
        gr.Markdown("# Snort RAG Rule Generator\nDefensive NLP/RAG system for generating Snort rules from natural-language attack descriptions.")
        with gr.Row():
            with gr.Column(scale=2):
                query = gr.Textbox(label="Attack description", lines=4, placeholder="Detect SQL injection with UNION SELECT in HTTP URI...")
                architecture = gr.Dropdown(
                    ["RAG + LLM controle", "Agentic RAG", "Baseline sans RAG", "RAG classique", "RAG + re-ranking", "RAG hybride", "Multi-hop RAG", "Graph RAG"],
                    value="Agentic RAG",
                    label="Architecture"
                )
                model_spec = gr.Textbox(label="LLM model", value="mock", placeholder="mock or ollama:mistral")
                k = gr.Slider(2, 10, value=5, step=1, label="Top-k retrieval")
                btn = gr.Button("Generate rule")
            with gr.Column(scale=1):
                pdf = gr.File(label="Ajouter un PDF à la base de connaissance", file_types=[".pdf"])
                add_btn = gr.Button("Index uploaded PDF")
                pdf_status = gr.Textbox(label="PDF status")
                stats_btn = gr.Button("Dataset stats")
                stats = gr.Textbox(label="Stats", lines=10)
        rule = gr.Textbox(label="Generated Snort rule", lines=5)
        attack_type = gr.Textbox(label="Detected attack type")
        explanation = gr.Textbox(label="Explanation", lines=4)
        retrieved = gr.Textbox(label="Retrieved documents", lines=8)
        prompt = gr.Textbox(label="Prompt preview", lines=10)
        raw_llm = gr.Textbox(label="Raw LLM output", lines=8)
        validation = gr.Textbox(label="Validation and FP metadata", lines=10)
        btn.click(generate, inputs=[query, architecture, k, model_spec], outputs=[rule, attack_type, explanation, retrieved, prompt, raw_llm, validation])
        add_btn.click(add_pdf, inputs=[pdf], outputs=[pdf_status])
        stats_btn.click(dataset_stats, outputs=[stats])
else:  # pragma: no cover
    demo = None

if __name__ == "__main__":
    if demo is None:
        raise SystemExit("gradio is not installed in this environment")
    demo.launch()
