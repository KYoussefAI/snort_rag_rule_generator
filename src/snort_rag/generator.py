"""Local generation module for Snort rules.

This is a controlled local generator that behaves like the generation stage of RAG,
but without prohibited external LLM APIs. It builds a transparent prompt, uses
retrieved context, classifies the attack type, fills a valid Snort template and
returns an explanation.
"""
from __future__ import annotations

from typing import Dict, List, Sequence

from snort_rag.false_positive import analyze_false_positive_risk
from snort_rag.rule_parser import (
    detected_option_names,
    missing_required_options,
    option_coverage,
    validate_rule,
)
from snort_rag.templates import CLASSTYPE, detect_attack_type, generate_snort_rule
from snort_rag.retrieval import RetrievedDoc

BENIGN_ATTACK_TYPES = {"benign", "benign_traffic"}


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
    if direct in BENIGN_ATTACK_TYPES:
        return "benign_traffic"
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
        f"It was selected or adapted after retrieving similar examples: {source_ids}. Parser status: {status}."
    )


def choose_rule(query: str, attack_type: str, retrieved_docs: Sequence[RetrievedDoc]) -> str:
    for doc in retrieved_docs:
        if doc.attack_type == attack_type and doc.rule and doc.rule != "NO_RULE_RECOMMENDED":
            valid, _ = validate_rule(doc.rule)
            if valid:
                return doc.rule
    return generate_snort_rule(attack_type, query)


def _hallucination_risk(
    query: str,
    attack_type: str,
    rule: str,
    valid: bool,
    retrieved_docs: Sequence[RetrievedDoc],
) -> float:
    risk = 0.0
    if not retrieved_docs:
        risk += 0.4
    top_attack_types = [doc.attack_type for doc in retrieved_docs[:3]]
    if retrieved_docs and attack_type not in top_attack_types:
        risk += 0.3
    if not valid and rule != "NO_RULE_RECOMMENDED":
        risk += 0.4
    if attack_type == "suspicious_user_agent" and "user" not in query.lower() and "agent" not in query.lower():
        risk += 0.2
    return min(1.0, risk)


def build_generation_result(
    query: str,
    attack_type: str,
    rule: str,
    retrieved_docs: Sequence[RetrievedDoc],
    prompt: str,
    explanation: str | None = None,
) -> Dict[str, object]:
    if attack_type in BENIGN_ATTACK_TYPES or rule == "NO_RULE_RECOMMENDED":
        attack_type = "benign_traffic"
        rule = "NO_RULE_RECOMMENDED"
        valid = True
        errors: List[str] = []
    else:
        valid, errors = validate_rule(rule)

    detected_options = detected_option_names(rule)
    missing_options = missing_required_options(rule, attack_type=attack_type)
    source_doc_ids = [doc.id for doc in retrieved_docs[:3]]
    hallucination_risk = _hallucination_risk(query, attack_type, rule, valid, retrieved_docs)
    fp_analysis = analyze_false_positive_risk(
        rule,
        query=query,
        attack_type=attack_type,
        retrieved_docs=list(retrieved_docs),
    )

    return {
        "query": query,
        "attack_type": attack_type,
        "generated_rule": rule,
        "syntax_validation": {"valid": valid, "errors": list(errors)},
        "valid_rule": valid,
        "validation_errors": list(errors),
        "detected_options": detected_options,
        "missing_options": missing_options,
        "false_positive_risk": fp_analysis["false_positive_risk"],
        "false_positive_score": fp_analysis["false_positive_score"],
        "risk_factors": fp_analysis["risk_factors"],
        "improvement_suggestions": fp_analysis["improvement_suggestions"],
        "option_coverage": option_coverage(rule) if rule != "NO_RULE_RECOMMENDED" else 0.0,
        "explanation": explanation or explain_rule(rule, attack_type, retrieved_docs),
        "source_doc_ids": source_doc_ids,
        "retrieved_context_used": bool(retrieved_docs),
        "prompt": prompt,
        "hallucination_risk": hallucination_risk,
        "retrieved_ids": [doc.id for doc in retrieved_docs],
        "retrieved_attack_types": [doc.attack_type for doc in retrieved_docs],
        "retrieval_scores": [round(doc.score, 4) for doc in retrieved_docs],
    }


def generate_from_context(query: str, retrieved_docs: Sequence[RetrievedDoc], force_attack_type: str | None = None) -> Dict[str, object]:
    attack_type = force_attack_type or choose_attack_type(query, retrieved_docs)
    if attack_type in BENIGN_ATTACK_TYPES:
        rule = "NO_RULE_RECOMMENDED"
    else:
        rule = choose_rule(query, attack_type, retrieved_docs)
    prompt = build_prompt(query, retrieved_docs)
    return build_generation_result(query, attack_type, rule, retrieved_docs, prompt)
