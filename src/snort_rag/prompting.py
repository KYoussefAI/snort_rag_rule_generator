"""Prompt construction for controlled RAG+LLM Snort rule generation."""
from __future__ import annotations

import json
from typing import Sequence

from snort_rag.retrieval import RetrievedDoc

ALLOWED_ATTACK_TYPES = [
    "port_scan",
    "ssh_bruteforce",
    "sql_injection",
    "xss",
    "command_injection",
    "directory_traversal",
    "dns_tunneling",
    "icmp_sweep",
    "malware_c2",
    "benign_traffic",
]


def _doc_payload(doc: RetrievedDoc) -> dict[str, object]:
    return {
        "id": doc.id,
        "rank": doc.rank,
        "retrieval_score": round(float(doc.score), 6),
        "attack_type": doc.attack_type,
        "source": doc.source_name,
        "description": doc.description_naturelle or doc.text,
        "log_example": doc.log_example,
        "snort_rule_reference": doc.snort_rule_reference or doc.rule,
    }


def build_rag_prompt(query: str, retrieved_docs: Sequence[RetrievedDoc], prompt_variant: str = "strict_json") -> str:
    if not retrieved_docs:
        raise ValueError("RAG LLM generation requires retrieved context.")
    context = json.dumps([_doc_payload(doc) for doc in retrieved_docs], indent=2, ensure_ascii=False)
    allowed = ", ".join(ALLOWED_ATTACK_TYPES)
    return f"""SYSTEM:
You are a defensive IDS rule assistant. Generate exactly one educational Snort rule.
Use only the user request and the retrieved documents. Do not invent CVEs, sources,
or runtime validation results. If the traffic is benign, output NO_RULE_RECOMMENDED.

CONSTRAINTS:
- Allowed attack_type labels: {allowed}
- Output JSON only. No Markdown.
- used_source_doc_ids must be selected from the retrieved document ids.
- A malicious rule must include msg, sid, rev, and classtype.
- Prefer precise Snort 3 buffers such as http_uri/http_raw_uri/http_header when the retrieved evidence is HTTP-specific.
- Do not provide exploitation steps or operational offensive instructions.

PROMPT_VARIANT: {prompt_variant}

USER REQUEST:
{query}

RETRIEVED CONTEXT:
{context}

OUTPUT JSON ONLY:
{{
  "attack_type": "one allowed label",
  "generated_rule": "Snort rule or NO_RULE_RECOMMENDED",
  "explanation": "short technical explanation",
  "false_positive_notes": "why it is or is not broad",
  "used_source_doc_ids": ["retrieved ids only"],
  "confidence": 0.0
}}
"""


def build_repair_prompt(
    original_prompt: str,
    bad_output: str,
    validation_errors: Sequence[str],
    allowed_doc_ids: Sequence[str],
) -> str:
    errors = "\n".join(f"- {err}" for err in validation_errors)
    return f"""{original_prompt}

REPAIR TASK:
The previous output was invalid. Return corrected JSON only.
Allowed source ids: {", ".join(allowed_doc_ids)}
Validation errors:
{errors}

PREVIOUS OUTPUT:
{bad_output}
"""
