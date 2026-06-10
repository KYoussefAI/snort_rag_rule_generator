"""Small FastAPI backend exposing the existing Snort RAG pipeline."""
from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from snort_rag.api.schemas import (
    DatasetStatsResponse,
    GenerateRuleRequest,
    GenerateRuleResponse,
    HealthResponse,
    ResultsSummaryResponse,
    RetrieveRequest,
    RetrieveResponse,
    RetrievedDocument,
    ValidateRuleRequest,
    ValidateRuleResponse,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"
RESULTS_DIR = PROJECT_ROOT / "results"

app = FastAPI(
    title="Snort RAG Rule Generator API",
    description="Educational defensive API layer for the existing Snort RAG rule-generation pipeline.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def get_rag():
    from snort_rag.architectures import SnortRAGArchitectures

    return SnortRAGArchitectures(DEFAULT_DATASET)


def _safe_csv(path: Path):
    import pandas as pd

    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def _pass_summary(path: Path, column: str = "status") -> str:
    df = _safe_csv(path)
    if df.empty or column not in df.columns:
        return "Not available"
    total = len(df)
    passed = int((df[column].astype(str) == "PASS").sum())
    return f"{passed}/{total} PASS"


def _status_counts(df: pd.DataFrame, column: str = "status") -> str:
    if df.empty or column not in df.columns:
        return "Not available"
    counts = df[column].fillna("UNKNOWN").astype(str).value_counts().to_dict()
    return ", ".join(f"{key}: {value}" for key, value in counts.items())


def _benign_false_positive_status() -> str:
    df = _safe_csv(RESULTS_DIR / "pcap_test_results.csv")
    if df.empty or "expected_attack" not in df.columns or "alert_count" not in df.columns:
        return "Not available"
    benign = df[df["expected_attack"].astype(str) == "benign_traffic"]
    if benign.empty:
        return "Not available"
    parsed_alert_count = pd.to_numeric(benign.iloc[0]["alert_count"], errors="coerce")
    alert_count = 0 if pd.isna(parsed_alert_count) else int(parsed_alert_count)
    return f"PASS, alert_count={alert_count}" if alert_count == 0 else f"REVIEW, alert_count={alert_count}"


def _results_summary() -> dict[str, str]:
    snort_df = _safe_csv(RESULTS_DIR / "snort_runtime_validation.csv")
    if snort_df.empty:
        snort_status = "Not available"
    elif "runtime_valid" in snort_df.columns:
        valid = int(snort_df["runtime_valid"].astype(str).str.lower().eq("true").sum())
        snort_status = f"{valid}/{len(snort_df)} runtime_valid"
    else:
        snort_status = _status_counts(snort_df)

    llm_df = _safe_csv(RESULTS_DIR / "llm_benchmark_summary.csv")
    if llm_df.empty or "model_spec" not in llm_df.columns:
        llm_models = "Not available"
    else:
        models = [str(model) for model in llm_df["model_spec"].dropna().unique()]
        llm_models = ", ".join(models) if models else "Not available"

    return {
        "Snort runtime validation": snort_status,
        "PCAP replay": _pass_summary(RESULTS_DIR / "pcap_test_results.csv"),
        "Benign false-positive result": _benign_false_positive_status(),
        "Synthetic log integration": _pass_summary(RESULTS_DIR / "network_log_integration_eval.csv", "final_status"),
        "Real-lab log integration": _pass_summary(RESULTS_DIR / "real_lab_log_integration_eval.csv", "final_status"),
        "Available LLM benchmark models": llm_models,
    }


def _doc_to_schema(doc) -> RetrievedDocument:
    return RetrievedDocument(**asdict(doc))


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="snort-rag-rule-generator-api",
        educational_defensive=True,
    )


@app.post("/api/generate-rule", response_model=GenerateRuleResponse)
async def generate_rule(request: GenerateRuleRequest) -> GenerateRuleResponse:
    from snort_rag.llm_clients import build_llm_client

    rag = get_rag()
    mapping: dict[str, Callable[[str], dict[str, object]]] = {
        "baseline_no_rag": rag.baseline_no_rag,
        "rag_classic": lambda query: rag.rag_classic(query, k=request.k),
        "rag_rerank": lambda query: rag.rag_rerank(query, k=max(request.k, 5)),
        "rag_hybrid": lambda query: rag.rag_hybrid(query, k=request.k),
        "multi_hop_rag": lambda query: rag.multi_hop_rag(query, k=request.k),
        "graph_rag": lambda query: rag.graph_rag(query, k=request.k),
        "agentic_rag": lambda query: rag.agentic_rag(query, k=request.k),
    }
    if request.architecture == "rag_llm":
        client = build_llm_client(request.model_spec) if request.model_spec else None
        result = rag.rag_llm_generate(
            request.query,
            k=request.k,
            client=client,
            prompt_variant=request.prompt_variant,
        )
    else:
        result = mapping[request.architecture](request.query)
    return GenerateRuleResponse(result=dict(result))


@app.post("/api/retrieve", response_model=RetrieveResponse)
async def retrieve(request: RetrieveRequest) -> RetrieveResponse:
    kb = get_rag().kb
    try:
        if request.strategy == "dense":
            docs = kb.dense_retrieve(request.query, k=request.k)
        elif request.strategy == "bm25":
            docs = kb.bm25_retrieve(request.query, k=request.k)
        elif request.strategy == "hybrid":
            docs = kb.hybrid_retrieve(request.query, k=request.k)
        elif request.strategy == "sentence_bert":
            docs = kb.sentence_bert_retrieve(request.query, k=request.k)
        elif request.strategy == "sentence_bert_faiss":
            docs = kb.sentence_bert_faiss_retrieve(request.query, k=request.k)
        else:
            docs = kb.hybrid_rerank_retrieve(request.query, k=request.k)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RetrieveResponse(
        query=request.query,
        strategy=request.strategy,
        documents=[_doc_to_schema(doc) for doc in docs],
    )


@app.post("/api/validate-rule", response_model=ValidateRuleResponse)
async def validate_rule_endpoint(request: ValidateRuleRequest) -> ValidateRuleResponse:
    from snort_rag.false_positive import analyze_false_positive_risk
    from snort_rag.rule_parser import (
        detected_option_names,
        missing_required_options,
        normalize_snort3_rule,
        validate_rule,
    )

    normalized = normalize_snort3_rule(request.rule)
    valid, errors = validate_rule(normalized)
    return ValidateRuleResponse(
        normalized_rule=normalized,
        valid=valid,
        errors=errors,
        detected_options=detected_option_names(normalized),
        missing_options=missing_required_options(normalized, attack_type=request.attack_type),
        false_positive=analyze_false_positive_risk(
            normalized,
            query=request.query,
            attack_type=request.attack_type,
        ),
    )


@app.get("/api/dataset/stats", response_model=DatasetStatsResponse)
async def dataset_stats() -> DatasetStatsResponse:
    import pandas as pd

    rag = get_rag()
    df = rag.kb.df
    attack_types = df.get("attack_type", pd.Series(dtype=str)).fillna("").astype(str)
    source_types = df.get("source_type", pd.Series(dtype=str)).fillna("").astype(str)
    benign_rows = int((attack_types == "benign_traffic").sum())
    return DatasetStatsResponse(
        dataset_path=str(rag.kb.dataset_path),
        rows=int(len(df)),
        malicious_rows=int(len(df) - benign_rows),
        benign_rows=benign_rows,
        attack_type_counts={str(k): int(v) for k, v in attack_types.value_counts().to_dict().items()},
        source_type_counts={str(k): int(v) for k, v in source_types.value_counts().to_dict().items()},
        embedding_backend=rag.kb.embedding_backend_info(),
    )


@app.get("/api/results/summary", response_model=ResultsSummaryResponse)
async def results_summary() -> ResultsSummaryResponse:
    return ResultsSummaryResponse(results_dir=str(RESULTS_DIR), summary=_results_summary())
