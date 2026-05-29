import sys
from pathlib import Path

import pytest

# Keep generator tests on the deterministic local TF-IDF/BM25 path.
sys.modules.setdefault("sentence_transformers", None)
sys.modules.setdefault("faiss", None)

from snort_rag.architectures import SnortRAGArchitectures
from snort_rag.false_positive import analyze_false_positive_risk


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
