"""Controlled RAG+LLM generation with parsing, validation, repair, and fallback."""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Sequence

from snort_rag.generator import build_generation_result, dedupe_preserve_order, generate_from_context
from snort_rag.llm_clients import BaseLLMClient, LLMResponse
from snort_rag.prompting import ALLOWED_ATTACK_TYPES, build_rag_prompt, build_repair_prompt
from snort_rag.retrieval import RetrievedDoc
from snort_rag.rule_parser import validate_rule


def _extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _validate_payload(payload: dict[str, Any], retrieved_docs: Sequence[RetrievedDoc]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    attack_type = str(payload.get("attack_type", ""))
    rule = str(payload.get("generated_rule", ""))
    allowed_doc_ids = {doc.id for doc in retrieved_docs}
    used_ids = payload.get("used_source_doc_ids", [])
    if attack_type not in ALLOWED_ATTACK_TYPES:
        errors.append(f"attack_type must be one of {', '.join(ALLOWED_ATTACK_TYPES)}")
    if not isinstance(used_ids, list):
        errors.append("used_source_doc_ids must be a list")
        used_ids = []
    unknown = [str(doc_id) for doc_id in used_ids if str(doc_id) not in allowed_doc_ids]
    if unknown:
        errors.append("used_source_doc_ids contains ids outside Top-k: " + ", ".join(unknown))
    if attack_type == "benign_traffic" or rule == "NO_RULE_RECOMMENDED":
        if rule != "NO_RULE_RECOMMENDED":
            errors.append("benign_traffic must use NO_RULE_RECOMMENDED")
    else:
        valid, rule_errors = validate_rule(rule)
        if not valid:
            errors.extend(rule_errors)
    return len(errors) == 0, errors


def _dedupe_ids(ids: Sequence[Any], allowed: set[str]) -> list[str]:
    return [doc_id for doc_id in dedupe_preserve_order([str(item) for item in ids]) if doc_id in allowed]


def generate_with_llm_context(
    query: str,
    retrieved_docs: Sequence[RetrievedDoc],
    client: BaseLLMClient,
    *,
    prompt_variant: str = "strict_json",
    max_repair_attempts: int = 1,
) -> Dict[str, object]:
    prompt = build_rag_prompt(query, retrieved_docs, prompt_variant=prompt_variant)
    allowed_ids = {doc.id for doc in retrieved_docs}
    repair_attempts = 0
    raw_outputs: list[str] = []
    validation_errors: list[str] = []
    start = time.perf_counter()

    response: LLMResponse = client.generate(prompt, temperature=0.0, max_new_tokens=512)
    raw_outputs.append(response.text)
    active_prompt = prompt

    for attempt in range(max_repair_attempts + 1):
        try:
            payload = _extract_json(raw_outputs[-1])
        except Exception as exc:
            payload = {}
            validation_errors = [f"LLM output was not valid JSON: {exc}"]
        else:
            valid_payload, validation_errors = _validate_payload(payload, retrieved_docs)
            if valid_payload:
                used_ids = _dedupe_ids(payload.get("used_source_doc_ids", []), allowed_ids)
                result = build_generation_result(
                    query=query,
                    attack_type=str(payload["attack_type"]),
                    rule=str(payload["generated_rule"]),
                    retrieved_docs=list(retrieved_docs),
                    prompt=prompt,
                    explanation=str(payload.get("explanation") or ""),
                )
                result.update({
                    "model_name": response.model_name,
                    "generation_mode": "rag_llm",
                    "prompt_variant": prompt_variant,
                    "repair_attempts": repair_attempts,
                    "raw_llm_output": raw_outputs[-1],
                    "llm_outputs": raw_outputs,
                    "source_doc_ids": used_ids or result.get("source_doc_ids", []),
                    "used_source_doc_ids": used_ids,
                    "false_positive_notes": str(payload.get("false_positive_notes", "")),
                    "confidence": float(payload.get("confidence") or 0.0),
                    "latency_ms": round((time.perf_counter() - start) * 1000, 3),
                    "llm_latency_ms": round(response.latency_ms, 3),
                    "prompt_tokens": response.prompt_tokens,
                    "completion_tokens": response.completion_tokens,
                })
                return result

        if attempt >= max_repair_attempts:
            break
        repair_attempts += 1
        active_prompt = build_repair_prompt(active_prompt, raw_outputs[-1], validation_errors, [doc.id for doc in retrieved_docs])
        response = client.generate(active_prompt, temperature=0.0, max_new_tokens=512)
        raw_outputs.append(response.text)

    fallback = generate_from_context(query, retrieved_docs)
    fallback.update({
        "model_name": client.model_name,
        "generation_mode": "template_fallback_after_llm_failure",
        "prompt_variant": prompt_variant,
        "repair_attempts": repair_attempts,
        "raw_llm_output": raw_outputs[-1] if raw_outputs else "",
        "llm_outputs": raw_outputs,
        "validation_errors": validation_errors,
        "latency_ms": round((time.perf_counter() - start) * 1000, 3),
    })
    return fallback
