from pathlib import Path

import pytest

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.false_positive import analyze_false_positive_risk
from snort_rag.generator import build_generation_result, explain_rule
from snort_rag.retrieval import RetrievedDoc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET = PROJECT_ROOT / "data" / "processed" / "final_snort_dataset.csv"


@pytest.fixture(scope="module")
def rag() -> SnortRAGArchitectures:
    return SnortRAGArchitectures(DATASET)


def test_generate_ssh_bruteforce_rule(rag: SnortRAGArchitectures):
    result = rag.agentic_rag("Generate a Snort rule for repeated SSH brute force attempts on port 22")

    assert result["valid_rule"] is True
    assert result["attack_type"] == "ssh_bruteforce"
    assert "22" in result["generated_rule"] or "$SSH_PORTS" in result["generated_rule"]
    assert "false_positive_risk" in result
    assert result["explanation"]


def test_generate_sql_injection_rule(rag: SnortRAGArchitectures):
    result = rag.agentic_rag("Detect SQL injection with UNION SELECT in HTTP URI")

    assert result["valid_rule"] is True
    assert result["attack_type"] == "sql_injection"
    rule = result["generated_rule"]
    assert "content:" in rule or "pcre:" in rule
    assert result["explanation"]


def test_benign_returns_no_rule(rag: SnortRAGArchitectures):
    result = rag.agentic_rag("A user connects normally to the company website using HTTPS")

    assert result["generated_rule"] == "NO_RULE_RECOMMENDED"
    assert result["valid_rule"] is True
    assert result["false_positive_risk"] == "none"
    assert result["false_positive_score"] == 0.0


def test_generate_icmp_sweep_rule(rag: SnortRAGArchitectures):
    result = rag.agentic_rag("Detect ICMP ping sweep against internal network")

    assert result["attack_type"] == "icmp_sweep"
    assert result["valid_rule"] is True
    assert result["generated_rule"].startswith("alert icmp")
    assert "ping -c" not in result["generated_rule"]
    assert "cmd" not in result["generated_rule"]


def test_false_positive_detects_broad_rule():
    rule = 'alert tcp any any -> any any (msg:"too broad"; sid:9000001; rev:1; classtype:misc-activity;)'

    result = analyze_false_positive_risk(rule)

    assert result["false_positive_score"] > 0.5
    assert result["false_positive_risk"] == "high"
    assert result["improvement_suggestions"]


def test_generation_output_contract_has_required_keys(rag: SnortRAGArchitectures):
    result = rag.agentic_rag("Detect malware command and control beacon to /gate.php")

    required_keys = {
        "generated_rule",
        "attack_type",
        "syntax_validation",
        "valid_rule",
        "validation_errors",
        "detected_options",
        "missing_options",
        "false_positive_risk",
        "false_positive_score",
        "risk_factors",
        "improvement_suggestions",
        "explanation",
        "source_doc_ids",
        "retrieved_context_used",
        "hallucination_risk",
        "option_coverage",
    }

    assert required_keys.issubset(result.keys())


def test_source_doc_ids_are_deduplicated():
    doc = RetrievedDoc(
        rank=1,
        score=0.9,
        id="SNORT-P1-DUP",
        text="DNS tunneling",
        attack_type="dns_tunneling",
        rule='alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"DNS"; dsize:>120; classtype:policy-violation; sid:1; rev:1;)',
        source_name="test",
        source_url="test",
    )

    result = build_generation_result(
        query="Detect DNS tunneling",
        attack_type="dns_tunneling",
        rule=doc.rule,
        retrieved_docs=[doc, doc],
        prompt="prompt",
    )

    assert result["source_doc_ids"] == ["SNORT-P1-DUP"]
    assert result["retrieved_ids"] == ["SNORT-P1-DUP"]


def test_explanation_uses_actual_rule_classtype_for_dns():
    rule = 'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"DNS tunnel"; dsize:>120; pcre:"/^[A-Za-z0-9]{40,}\\./"; classtype:policy-violation; sid:900001; rev:1;)'

    explanation = explain_rule(rule, "dns_tunneling", [])

    assert "policy-violation" in explanation
    assert "trojan-activity" not in explanation
