from snort_rag.llm_clients import MockDeterministicClient
from snort_rag.llm_generator import generate_with_llm_context
from snort_rag.retrieval import RetrievedDoc


def _doc() -> RetrievedDoc:
    return RetrievedDoc(
        rank=1,
        score=0.9,
        id="SNORT-P1-001",
        text="SQL injection UNION SELECT",
        attack_type="sql_injection",
        rule='alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLi"; flow:to_server,established; content:"union select"; http_uri; sid:1; rev:1; classtype:web-application-attack;)',
        source_name="person1_dataset",
        source_url="data/processed/final_snort_dataset.csv",
        log_example="GET /?q=union select",
        description_naturelle="Detect SQL injection",
        snort_rule_reference='alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQLi"; flow:to_server,established; content:"union select"; http_uri; sid:1; rev:1; classtype:web-application-attack;)',
    )


def test_llm_generator_uses_retrieved_context_and_schema():
    client = MockDeterministicClient(
        '{"attack_type":"sql_injection","generated_rule":"alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\\"LOCAL SQLi\\"; flow:to_server,established; content:\\"union select\\"; http_uri; nocase; classtype:web-application-attack; sid:9900002; rev:1;)","explanation":"Uses URI payload evidence.","false_positive_notes":"Specific URI content.","used_source_doc_ids":["SNORT-P1-001"],"confidence":0.8}'
    )

    result = generate_with_llm_context("Detect UNION SELECT", [_doc()], client)

    assert result["generation_mode"] == "rag_llm"
    assert result["valid_rule"] is True
    assert result["source_doc_ids"] == ["SNORT-P1-001"]
    assert "SNORT-P1-001" in client.prompts[0]


def test_invalid_llm_output_falls_back_explicitly():
    client = MockDeterministicClient("not json")

    result = generate_with_llm_context("Detect UNION SELECT", [_doc()], client, max_repair_attempts=0)

    assert result["generation_mode"] == "template_fallback_after_llm_failure"
    assert result["valid_rule"] is True
    assert result["validation_errors"]
