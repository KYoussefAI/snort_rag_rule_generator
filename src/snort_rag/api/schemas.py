"""Pydantic schemas for the JSON API layer."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


ArchitectureName = Literal[
    "baseline_no_rag",
    "rag_classic",
    "rag_rerank",
    "rag_hybrid",
    "multi_hop_rag",
    "graph_rag",
    "agentic_rag",
    "rag_llm",
]

RetrievalStrategy = Literal[
    "dense",
    "bm25",
    "hybrid",
    "hybrid_rerank",
    "sentence_bert",
    "sentence_bert_faiss",
]


class HealthResponse(BaseModel):
    status: str
    service: str
    educational_defensive: bool


class GenerateRuleRequest(BaseModel):
    query: str = Field(..., min_length=1)
    architecture: ArchitectureName = "rag_llm"
    k: int = Field(5, ge=1, le=20)
    model_spec: str | None = None
    prompt_variant: str = "strict_json"


class GenerateRuleResponse(BaseModel):
    result: dict[str, Any]


class RetrieveRequest(BaseModel):
    query: str = Field(..., min_length=1)
    k: int = Field(5, ge=1, le=20)
    strategy: RetrievalStrategy = "hybrid_rerank"


class RetrievedDocument(BaseModel):
    rank: int
    score: float
    id: str
    text: str
    attack_type: str
    rule: str
    source_name: str
    source_url: str
    log_example: str = ""
    description_naturelle: str = ""
    snort_rule_reference: str = ""


class RetrieveResponse(BaseModel):
    query: str
    strategy: RetrievalStrategy
    documents: list[RetrievedDocument]


class ValidateRuleRequest(BaseModel):
    rule: str = Field(..., min_length=1)
    attack_type: str = ""
    query: str = ""


class ValidateRuleResponse(BaseModel):
    normalized_rule: str
    valid: bool
    errors: list[str]
    detected_options: list[str]
    missing_options: list[str]
    false_positive: dict[str, Any]


class DatasetStatsResponse(BaseModel):
    dataset_path: str
    rows: int
    malicious_rows: int
    benign_rows: int
    attack_type_counts: dict[str, int]
    source_type_counts: dict[str, int]
    embedding_backend: dict[str, Any]


class ResultsSummaryResponse(BaseModel):
    results_dir: str
    summary: dict[str, str]
