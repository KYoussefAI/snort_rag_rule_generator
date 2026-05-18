"""Local generation module for Snort rules.

This is a controlled local generator that behaves like the generation stage of RAG,
but without prohibited external LLM APIs. It builds a transparent prompt, uses
retrieved context, classifies the attack type, fills a valid Snort template and
returns an explanation.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from snort_rag.rule_parser import validate_rule, option_coverage
from snort_rag.templates import CLASSTYPE, detect_attack_type, generate_snort_rule
from snort_rag.retrieval import RetrievedDoc


def build_prompt(query: str, retrieved_docs: Sequence[RetrievedDoc]) -> str:
    context_lines = []
    for doc in retrieved_docs:
        context_lines.append(
            f"[{doc.rank}] id={doc.id}; type={doc.attack_type}; source={doc.source_name}; rule={doc.rule}"
        )
    context = "\n".join(context_lines)
    return (
        "You are a defensive Snort rule generator. Use only the retrieved context and Snort syntax.\n"
        "Generate one rule, explain the rule, and avoid overly broad signatures.\n\n"
        f"User request: {query}\n\nRetrieved context:\n{context}"
    )


def choose_attack_type(query: str, retrieved_docs: Sequence[RetrievedDoc]) -> str:
    direct = detect_attack_type(query)
    if direct != "suspicious_user_agent":
        return direct
    if retrieved_docs:
        counts: Dict[str, float] = {}
        for doc in retrieved_docs[:3]:
            counts[doc.attack_type] = counts.get(doc.attack_type, 0.0) + doc.score
        if counts:
            return max(counts, key=counts.get)
    return direct


def explain_rule(rule: str, attack_type: str, docs: Sequence[RetrievedDoc]) -> str:
    if rule == "NO_RULE_RECOMMENDED":
        return "The request appears benign, so the system recommends no alert rule to avoid false positives."
    valid, errors = validate_rule(rule)
    source_ids = ", ".join(doc.id for doc in docs[:3]) or "no retrieved source"
    status = "valid by internal parser" if valid else "needs Snort -T validation: " + "; ".join(errors)
    return (
        f"Attack type: {attack_type}. The rule uses a conservative classtype "
        f"({CLASSTYPE.get(attack_type, 'unknown')}) and includes msg/sid/rev. "
        f"It was generated after retrieving similar examples: {source_ids}. Parser status: {status}."
    )


def generate_from_context(query: str, retrieved_docs: Sequence[RetrievedDoc], force_attack_type: str | None = None) -> Dict[str, object]:
    attack_type = force_attack_type or choose_attack_type(query, retrieved_docs)
    if attack_type == "benign":
        rule = "NO_RULE_RECOMMENDED"
        valid = False
        errors = ["Benign request"]
    else:
        rule = generate_snort_rule(attack_type, query)
        valid, errors = validate_rule(rule)
    prompt = build_prompt(query, retrieved_docs)
    hallucination_risk = 0.0
    if not retrieved_docs:
        hallucination_risk += 0.4
    if not valid and rule != "NO_RULE_RECOMMENDED":
        hallucination_risk += 0.4
    if attack_type == "suspicious_user_agent" and "user" not in query.lower() and "agent" not in query.lower():
        hallucination_risk += 0.2
    return {
        "query": query,
        "attack_type": attack_type,
        "generated_rule": rule,
        "valid_rule": valid,
        "validation_errors": errors,
        "option_coverage": option_coverage(rule) if rule != "NO_RULE_RECOMMENDED" else 0.0,
        "explanation": explain_rule(rule, attack_type, retrieved_docs),
        "prompt": prompt,
        "hallucination_risk": min(1.0, hallucination_risk),
    }
