import pytest

from snort_rag.prompting import build_rag_prompt
from snort_rag.retrieval import RetrievedDoc


def _doc() -> RetrievedDoc:
    return RetrievedDoc(
        rank=1,
        score=0.9,
        id="SNORT-P1-001",
        text="SQL injection UNION SELECT",
        attack_type="sql_injection",
        rule='alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLi"; content:"union select"; http_uri; sid:1; rev:1; classtype:web-application-attack;)',
        source_name="person1_dataset",
        source_url="data/processed/final_snort_dataset.csv",
        log_example="GET /?q=union select",
        description_naturelle="Detect SQL injection",
        snort_rule_reference='alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLi"; content:"union select"; http_uri; sid:1; rev:1; classtype:web-application-attack;)',
    )


def test_prompt_requires_retrieved_context():
    with pytest.raises(ValueError):
        build_rag_prompt("Detect SQLi", [])


def test_prompt_contains_doc_ids_schema_and_benign_escape():
    prompt = build_rag_prompt("Detect SQLi", [_doc()])

    assert "SNORT-P1-001" in prompt
    assert "OUTPUT JSON ONLY" in prompt
    assert "NO_RULE_RECOMMENDED" in prompt
    assert "used_source_doc_ids" in prompt
