"""Gradio dashboard for the Snort RAG Rule Generator."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile

try:
    import gradio as gr
except ModuleNotFoundError:  # pragma: no cover
    gr = None

# The dashboard can run entirely on the local TF-IDF/BM25 retrieval path.
sys.modules.setdefault("sentence_transformers", None)
sys.modules.setdefault("faiss", None)

from snort_rag.architectures import SnortRAGArchitectures

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
rag = SnortRAGArchitectures(DATASET)


def generate(query: str, architecture: str, k: int):
    if not query.strip():
        return "", "", "", ""
    mapping = {
        "Baseline sans RAG": rag.llm_no_rag,
        "RAG classique": rag.rag_classic,
        "RAG + re-ranking": rag.rag_rerank,
        "RAG hybride": rag.rag_hybrid,
        "Multi-hop RAG": rag.multi_hop_rag,
        "Graph RAG": rag.graph_rag,
        "Agentic RAG": rag.agentic_rag,
    }
    fn = mapping[architecture]
    result = fn(query)
    retrieved = "\n".join(
        f"{i+1}. {doc_id} | {atype} | score={score}"
        for i, (doc_id, atype, score) in enumerate(zip(result.get("retrieved_ids", []), result.get("retrieved_attack_types", []), result.get("retrieval_scores", [])))
    )
    return result["generated_rule"], result["attack_type"], result["explanation"], retrieved


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
    return f"Rows: {len(df)}\n\nAttack type counts:\n{counts}"


if gr is not None:
    with gr.Blocks(title="Snort RAG Rule Generator") as demo:
        gr.Markdown("# Snort RAG Rule Generator\nDefensive NLP/RAG system for generating Snort rules from natural-language attack descriptions.")
        with gr.Row():
            with gr.Column(scale=2):
                query = gr.Textbox(label="Attack description", lines=4, placeholder="Detect SQL injection with UNION SELECT in HTTP URI...")
                architecture = gr.Dropdown(
                    ["Baseline sans RAG", "RAG classique", "RAG + re-ranking", "RAG hybride", "Multi-hop RAG", "Graph RAG", "Agentic RAG"],
                    value="Agentic RAG",
                    label="Architecture"
                )
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
        btn.click(generate, inputs=[query, architecture, k], outputs=[rule, attack_type, explanation, retrieved])
        add_btn.click(add_pdf, inputs=[pdf], outputs=[pdf_status])
        stats_btn.click(dataset_stats, outputs=[stats])
else:  # pragma: no cover
    demo = None

if __name__ == "__main__":
    if demo is None:
        raise SystemExit("gradio is not installed in this environment")
    demo.launch()
