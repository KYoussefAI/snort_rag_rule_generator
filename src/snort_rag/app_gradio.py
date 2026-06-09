"""Gradio dashboard for the Snort RAG Rule Generator."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

try:
    import gradio as gr
except ModuleNotFoundError:  # pragma: no cover
    gr = None

import pandas as pd

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.llm_clients import build_llm_client

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
RESULTS_DIR = PROJECT_ROOT / "results"
REAL_LAB_LOGS_DIR = PROJECT_ROOT / "data" / "logs" / "real_lab_logs"
SYNTHETIC_LOGS = PROJECT_ROOT / "data" / "logs" / "sample_network_logs.csv"
TRUSTED_KB_DIR = PROJECT_ROOT / "data" / "knowledge_base"

rag = SnortRAGArchitectures(DATASET)
_LATEST_GENERATION: dict[str, Any] = {}


def safe_load_csv(path: Path | str) -> pd.DataFrame:
    """Load a CSV if present, otherwise return an empty DataFrame."""
    csv_path = Path(path)
    if not csv_path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(csv_path)
    except Exception:
        return pd.DataFrame()


def safe_json(value: Any) -> str:
    """Render arbitrary values as readable JSON/markdown-safe text."""
    try:
        return json.dumps(value, indent=2, ensure_ascii=False)
    except TypeError:
        return json.dumps(str(value), indent=2, ensure_ascii=False)


def _status_counts(df: pd.DataFrame, column: str = "status") -> str:
    if df.empty or column not in df.columns:
        return "Not available"
    counts = df[column].fillna("UNKNOWN").astype(str).value_counts().to_dict()
    return ", ".join(f"{key}: {value}" for key, value in counts.items())


def _pass_summary(path: Path, column: str = "status") -> str:
    df = safe_load_csv(path)
    if df.empty or column not in df.columns:
        return "Not available"
    total = len(df)
    passed = int((df[column].astype(str) == "PASS").sum())
    return f"{passed}/{total} PASS"


def _available_llm_models() -> str:
    df = safe_load_csv(RESULTS_DIR / "llm_benchmark_summary.csv")
    if df.empty or "model_spec" not in df.columns:
        return "Not available"
    models = [str(model) for model in df["model_spec"].dropna().unique()]
    return ", ".join(models) if models else "Not available"


def _benign_false_positive_status() -> str:
    df = safe_load_csv(RESULTS_DIR / "pcap_test_results.csv")
    if df.empty or "expected_attack" not in df.columns:
        return "Not available"
    benign = df[df["expected_attack"].astype(str) == "benign_traffic"]
    if benign.empty or "alert_count" not in benign.columns:
        return "Not available"
    parsed_alert_count = pd.to_numeric(benign.iloc[0]["alert_count"], errors="coerce")
    alert_count = 0 if pd.isna(parsed_alert_count) else int(parsed_alert_count)
    return f"PASS, alert_count={alert_count}" if alert_count == 0 else f"REVIEW, alert_count={alert_count}"


def build_evidence_summary() -> dict[str, str]:
    """Build dashboard status cards from existing result files."""
    snort_df = safe_load_csv(RESULTS_DIR / "snort_runtime_validation.csv")
    if snort_df.empty:
        snort_status = "Not available"
    elif "runtime_valid" in snort_df.columns:
        valid = int(snort_df["runtime_valid"].astype(str).str.lower().eq("true").sum())
        snort_status = f"{valid}/{len(snort_df)} runtime_valid"
    else:
        snort_status = _status_counts(snort_df)

    return {
        "Snort runtime validation": snort_status,
        "PCAP replay": _pass_summary(RESULTS_DIR / "pcap_test_results.csv"),
        "Benign false-positive result": _benign_false_positive_status(),
        "Synthetic log integration": _pass_summary(RESULTS_DIR / "network_log_integration_eval.csv", "final_status"),
        "Real-lab log integration": _pass_summary(RESULTS_DIR / "real_lab_log_integration_eval.csv", "final_status"),
        "Available LLM benchmark models": _available_llm_models(),
    }


def evidence_cards_markdown() -> str:
    cards = build_evidence_summary()
    lines = ["<div class='evidence-grid'>"]
    for title, value in cards.items():
        lines.append(
            "<div class='evidence-card'>"
            f"<div class='evidence-title'>{title}</div>"
            f"<div class='evidence-value'>{value}</div>"
            "</div>"
        )
    lines.append("</div>")
    return "\n".join(lines)


def dataset_stats() -> tuple[str, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    df = safe_load_csv(DATASET)
    if df.empty:
        return "Dataset not available.", pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    benign_rows = int((df.get("attack_type", pd.Series(dtype=str)).astype(str) == "benign_traffic").sum())
    malicious_rows = len(df) - benign_rows
    summary = (
        f"Rows: {len(df)}\n"
        f"Malicious rows: {malicious_rows}\n"
        f"Benign rows: {benign_rows}\n\n"
        f"Personal RAG dataset: {DATASET.relative_to(PROJECT_ROOT)}\n"
        f"Synthetic academic logs: {SYNTHETIC_LOGS.relative_to(PROJECT_ROOT)}\n"
        f"Controlled real-lab logs: {REAL_LAB_LOGS_DIR.relative_to(PROJECT_ROOT)}/\n"
        f"Optional trusted-source KB: {TRUSTED_KB_DIR.relative_to(PROJECT_ROOT)}/\n\n"
        "The personal dataset is the official RAG corpus. External trusted references are optional and separate."
    )

    attack_counts = (
        df["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="rows")
        if "attack_type" in df.columns else pd.DataFrame()
    )
    source_counts = (
        df["source_type"].value_counts().rename_axis("source_type").reset_index(name="rows")
        if "source_type" in df.columns else pd.DataFrame()
    )
    preview_cols = [col for col in ["id", "attack_type", "source_type", "description_naturelle"] if col in df.columns]
    preview = df[preview_cols].head(10) if preview_cols else df.head(10)
    return summary, attack_counts, source_counts, preview


def benchmark_tables() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    return (
        safe_load_csv(RESULTS_DIR / "llm_benchmark_summary.csv"),
        safe_load_csv(RESULTS_DIR / "embedding_benchmark.csv"),
        safe_load_csv(RESULTS_DIR / "clustering_metrics.csv"),
        safe_load_csv(RESULTS_DIR / "pcap_test_results.csv"),
        safe_load_csv(RESULTS_DIR / "snort_runtime_validation.csv"),
        safe_load_csv(RESULTS_DIR / "real_lab_log_integration_eval.csv"),
    )


def _retrieved_table(result: dict[str, Any]) -> pd.DataFrame:
    ids = result.get("retrieved_ids", [])
    attack_types = result.get("retrieved_attack_types", [])
    scores = result.get("retrieval_scores", [])
    source_ids = result.get("source_doc_ids", ids)
    rows = []
    for idx, doc_id in enumerate(ids):
        rows.append({
            "rank": idx + 1,
            "doc_id": doc_id,
            "source_doc_id": source_ids[idx] if idx < len(source_ids) else doc_id,
            "attack_type": attack_types[idx] if idx < len(attack_types) else "",
            "score": scores[idx] if idx < len(scores) else "",
        })
    return pd.DataFrame(rows)


def _context_json(result: dict[str, Any]) -> str:
    context_keys = [
        "retrieved_context",
        "retrieved_contexts",
        "retrieved_texts",
        "context_snippets",
        "retrieved_docs",
    ]
    for key in context_keys:
        if result.get(key):
            return safe_json(result[key])
    return safe_json({
        "source_doc_ids": result.get("source_doc_ids", []),
        "retrieved_ids": result.get("retrieved_ids", []),
        "note": "The current backend returned retrieval identifiers and scores, but no full snippet payload.",
    })


def _validation_metadata(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "syntax_validation": result.get("syntax_validation"),
        "valid_rule": result.get("valid_rule"),
        "validation_errors": result.get("validation_errors", []),
        "detected_options": result.get("detected_options", []),
        "missing_options": result.get("missing_options", []),
        "false_positive_risk": result.get("false_positive_risk"),
        "false_positive_score": result.get("false_positive_score"),
        "risk_factors": result.get("risk_factors", []),
        "improvement_suggestions": result.get("improvement_suggestions", []),
    }


def _write_export_files(result: dict[str, Any]) -> tuple[str | None, str | None]:
    if not result:
        return None, None
    export_dir = Path(tempfile.gettempdir()) / "snort_rag_dashboard_exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    rule = str(result.get("generated_rule", ""))
    rule_path = export_dir / "latest_generated_rule.rules"
    json_path = export_dir / "latest_generation_result.json"
    rule_path.write_text("" if rule == "NO_RULE_RECOMMENDED" else rule + "\n", encoding="utf-8")
    json_path.write_text(safe_json(result), encoding="utf-8")
    return str(rule_path), str(json_path)


def generate(query: str, architecture: str, k: int, model_spec: str):
    if not query.strip():
        empty = pd.DataFrame()
        return (
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            empty,
            "{}",
            "",
            "",
            "",
            "",
            "{}",
            "",
            None,
            None,
        )

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
    result = mapping[architecture](query)
    _LATEST_GENERATION.clear()
    _LATEST_GENERATION.update(result)

    rule = result.get("generated_rule", "")
    generation_mode = result.get("generation_mode", "deterministic_template_or_retrieved_rule")
    fallback_warning = (
        "Deterministic fallback was used after controlled validation or because a non-LLM architecture was selected."
        if "fallback" in str(generation_mode).lower() or "deterministic" in str(generation_mode).lower()
        else ""
    )
    benign_note = (
        "NO_RULE_RECOMMENDED is expected for benign traffic; the pipeline avoids creating unnecessary detection rules."
        if rule == "NO_RULE_RECOMMENDED"
        else ""
    )
    rule_status = "VALID" if result.get("valid_rule") else "REVIEW"
    metadata = _validation_metadata(result)
    rule_path, json_path = _write_export_files(result)

    return (
        rule,
        str(result.get("attack_type", "")),
        str(generation_mode),
        str(result.get("model_name", model_spec or "none")),
        rule_status,
        fallback_warning,
        str(result.get("explanation", "")),
        _retrieved_table(result),
        _context_json(result),
        str(result.get("retrieved_context_used", "")),
        str(result.get("hallucination_risk", "")),
        str(result.get("option_coverage", "")),
        str(result.get("prompt", "")),
        safe_json(metadata),
        benign_note,
        rule_path,
        json_path,
    )


def add_pdf(pdf_file):
    if pdf_file is None:
        return "No PDF uploaded.", "", "", ""
    try:
        file_name = Path(pdf_file.name).name
        before = len(rag.kb.df)
        count = rag.kb.add_pdf_to_kb(pdf_file.name, source_name=file_name)
        after = len(rag.kb.df)
        preview = ""
        if after > before and "text" in rag.kb.df.columns:
            preview = str(rag.kb.df.iloc[before].get("text", ""))[:900]
        elif after > before:
            preview = str(rag.kb.df.iloc[before].to_dict())[:900]
        return file_name, str(count), str(after), preview
    except Exception as exc:
        return "PDF import failed", "0", "", str(exc)


CSS = """
.evidence-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
  margin: 12px 0 18px 0;
}
.evidence-card {
  border: 1px solid #d8dee8;
  border-radius: 8px;
  padding: 12px 14px;
  background: #f8fafc;
}
.evidence-title {
  font-size: 12px;
  color: #475569;
  text-transform: uppercase;
  letter-spacing: 0;
}
.evidence-value {
  font-size: 16px;
  font-weight: 650;
  color: #0f172a;
  margin-top: 6px;
}
"""


if gr is not None:
    with gr.Blocks(title="Snort RAG Rule Generator") as demo:
        gr.Markdown(
            "# Snort RAG Rule Generator\n"
            "NLP + Retrieval-Augmented Generation for defensive Snort rule generation\n\n"
            "**Educational academic project, not a production IDS system.**"
        )
        gr.HTML(f"<style>{CSS}</style>")

        with gr.Tabs():
            with gr.Tab("Rule Generator"):
                gr.Markdown(
                    "Generate defensive Snort rules from an attack description. "
                    "`mock` is only for smoke testing; use examples such as "
                    "`ollama:qwen2.5`, `ollama:mistral`, or `ollama:llama3.2` for local LLM runs."
                )
                with gr.Row():
                    with gr.Column(scale=2):
                        query = gr.Textbox(
                            label="Attack description",
                            lines=4,
                            placeholder="Detect SQL injection with UNION SELECT in HTTP URI...",
                        )
                        architecture = gr.Dropdown(
                            [
                                "RAG + LLM controle",
                                "Agentic RAG",
                                "Baseline sans RAG",
                                "RAG classique",
                                "RAG + re-ranking",
                                "RAG hybride",
                                "Multi-hop RAG",
                                "Graph RAG",
                            ],
                            value="Agentic RAG",
                            label="Architecture",
                        )
                    with gr.Column(scale=1):
                        model_spec = gr.Textbox(
                            label="LLM model",
                            value="mock",
                            placeholder="mock, ollama:qwen2.5, ollama:mistral, ollama:llama3.2",
                        )
                        k = gr.Slider(2, 10, value=5, step=1, label="Top-k retrieval")
                        btn = gr.Button("Generate rule", variant="primary")

                rule = gr.Code(label="Generated Snort rule", language=None, lines=6)
                with gr.Row():
                    attack_type = gr.Textbox(label="Attack type")
                    generation_mode = gr.Textbox(label="Generation mode")
                    model_name = gr.Textbox(label="Model name")
                    rule_status = gr.Textbox(label="Validity status")
                fallback_warning = gr.Markdown()
                explanation = gr.Textbox(label="Explanation", lines=5)
                with gr.Row():
                    rule_download = gr.File(label="Download latest .rules export")
                    json_download = gr.File(label="Download latest JSON export")

            with gr.Tab("Retrieval Details"):
                gr.Markdown(
                    "This view exposes retrieved documents, context-use flags, and grounding metadata. "
                    "It demonstrates that generation is not direct black-box LLM output."
                )
                retrieved_docs = gr.Dataframe(label="Retrieved document IDs and scores", interactive=False)
                context_json = gr.Code(label="Retrieved context snippets / metadata", language="json", lines=12)
                with gr.Row():
                    retrieved_context_used = gr.Textbox(label="Retrieved context used")
                    hallucination_risk = gr.Textbox(label="Hallucination risk")
                    option_coverage = gr.Textbox(label="Option coverage")
                prompt_preview = gr.Textbox(label="Prompt preview", lines=10)

            with gr.Tab("Validation & False Positives"):
                validation_json = gr.Code(label="Syntax, validation, and false-positive metadata", language="json", lines=18)
                benign_note = gr.Markdown()

            with gr.Tab("Dataset / Knowledge Base"):
                dataset_summary, attack_counts, source_counts, dataset_preview = dataset_stats()
                gr.Markdown(
                    "The personal dataset is the official RAG corpus. "
                    "Synthetic academic logs, controlled real-lab logs, and optional trusted-source Snort references are separate evidence sources."
                )
                gr.Textbox(label="Dataset and evidence paths", value=dataset_summary, lines=10)
                with gr.Row():
                    gr.Dataframe(value=attack_counts, label="Attack type distribution", interactive=False)
                    gr.Dataframe(value=source_counts, label="Source type distribution", interactive=False)
                gr.Dataframe(value=dataset_preview, label="Dataset preview", interactive=False)

            with gr.Tab("Benchmarks & Evidence"):
                gr.Markdown(
                    "LLM benchmark results represent the controlled RAG pipeline output after parsing, "
                    "validation, repair, and fallback when needed, not raw LLM perfection."
                )
                gr.HTML(evidence_cards_markdown())
                llm_table, embedding_table, clustering_table, pcap_table, snort_table, real_log_table = benchmark_tables()
                gr.Dataframe(value=llm_table, label="LLM benchmark summary", interactive=False)
                gr.Dataframe(value=embedding_table, label="Embedding benchmark", interactive=False)
                gr.Dataframe(value=clustering_table, label="Clustering metrics", interactive=False)
                gr.Dataframe(value=pcap_table, label="PCAP replay results", interactive=False)
                gr.Dataframe(value=snort_table, label="Snort runtime validation", interactive=False)
                gr.Dataframe(value=real_log_table, label="Real-lab log integration", interactive=False)

            with gr.Tab("PDF Upload"):
                gr.Markdown(
                    "Uploaded PDFs are added as an in-memory knowledge-base extension for retrieval during the current session."
                )
                pdf = gr.File(label="Upload PDF", file_types=[".pdf"])
                add_btn = gr.Button("Index uploaded PDF")
                with gr.Row():
                    pdf_name = gr.Textbox(label="Uploaded file name")
                    pdf_chunks = gr.Textbox(label="Chunks added")
                    pdf_total = gr.Textbox(label="New total knowledge-base size")
                pdf_preview = gr.Textbox(label="First imported chunk preview", lines=8)

        btn.click(
            generate,
            inputs=[query, architecture, k, model_spec],
            outputs=[
                rule,
                attack_type,
                generation_mode,
                model_name,
                rule_status,
                fallback_warning,
                explanation,
                retrieved_docs,
                context_json,
                retrieved_context_used,
                hallucination_risk,
                option_coverage,
                prompt_preview,
                validation_json,
                benign_note,
                rule_download,
                json_download,
            ],
        )
        add_btn.click(add_pdf, inputs=[pdf], outputs=[pdf_name, pdf_chunks, pdf_total, pdf_preview])
else:  # pragma: no cover
    demo = None


if __name__ == "__main__":
    if demo is None:
        raise SystemExit("gradio is not installed in this environment")
    demo.launch()
